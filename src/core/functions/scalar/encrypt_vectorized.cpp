#define DUCKDB_EXTENSION_MAIN

#include "duckdb/main/extension_util.hpp"
#include "duckdb/main/connection_manager.hpp"
#include "duckdb/main/secret/secret_manager.hpp"
#include "duckdb/function/scalar_function.hpp"
#include "duckdb/common/types.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/encryption_state.hpp"
#include "duckdb/common/vector_operations/generic_executor.hpp"
#include "duckdb/planner/expression/bound_function_expression.hpp"

#include <duckdb/parser/parsed_data/create_scalar_function_info.hpp>

#include "vcrypt_state.hpp"
#include "../etype/encrypted_type.hpp"
#include "vcrypt/core/types.hpp"
#include "vcrypt/core/functions/common.hpp"
#include "vcrypt/core/functions/scalar.hpp"
#include "vcrypt/core/functions/secrets.hpp"
#include "vcrypt/core/functions/scalar/encrypt.hpp"
#include "vcrypt/core/functions/function_data/encrypt_function_data.hpp"

namespace vcrypt {

namespace core {


uint16_t MaskCipher(uint16_t cipher, uint64_t *plaintext_bytes, bool is_null){
//    const uint64_t prime = 10251357202697351;
//    auto const a_plaintext = plaintext_bytes + 1;
//    // (plaintext xor p1) * p2)
//    uint64_t random_val = *a_plaintext * prime;
//
//    // mask the first 8 bits by shifting and cast to uint16_t
//    uint16_t masked_cipher = static_cast<uint16_t>((random_val) >> 56);
//
//    // least significant bit indicates nullability
//    cipher = static_cast<uint16_t>((cipher << 1) | (is_null ? 1 : 0));
//
//    return cipher ^ masked_cipher;
    return cipher;
}

template <typename T>
void EncryptVectorizedFlat(T *input_vector, uint64_t size, ExpressionState &state, Vector &result, uint8_t vector_type) {

  // local, global and encryption state
  auto &lstate = VCryptFunctionLocalState::ResetAndGet(state);
  auto vcrypt_state =
      VCryptBasicFun::GetVCryptState(state);

  auto key = VCryptBasicFun::GetKey(state);
  auto &validity = FlatVector::Validity(result);

  Vector struct_vector(EncryptionTypes::GetEncryptionType(LogicalTypeId(vector_type)), size);
  result.ReferenceAndSetType(struct_vector);

  auto &children = StructVector::GetEntries(result);
  auto &nonce_hi = children[0];
  auto &nonce_lo = children[1];
  auto &counter_vec = children[2];
  auto &cipher_vec = children[3];
  auto &blob_vec = children[4];

  nonce_hi->SetVectorType(VectorType::CONSTANT_VECTOR);
  nonce_lo->SetVectorType(VectorType::CONSTANT_VECTOR);
  counter_vec->SetVectorType(VectorType::FLAT_VECTOR);
  cipher_vec->SetVectorType(VectorType::FLAT_VECTOR);
  blob_vec->SetVectorType(VectorType::FLAT_VECTOR);

  UnifiedVectorFormat nonce_hi_u;
  UnifiedVectorFormat nonce_lo_u;
  UnifiedVectorFormat counter_vec_u;
  UnifiedVectorFormat cipher_vec_u;
  UnifiedVectorFormat blob_vec_u;

  nonce_hi->ToUnifiedFormat(size, nonce_hi_u);
  nonce_lo->ToUnifiedFormat(size, nonce_lo_u);
  counter_vec->ToUnifiedFormat(size, counter_vec_u);
  cipher_vec->ToUnifiedFormat(size, cipher_vec_u);
  blob_vec->ToUnifiedFormat(size, blob_vec_u);

  auto nonce_hi_data = FlatVector::GetData<uint64_t>(*nonce_hi);
  auto nonce_lo_data = FlatVector::GetData<uint32_t>(*nonce_lo);
  auto counter_vec_data = FlatVector::GetData<uint32_t>(*counter_vec);
  auto cipher_vec_data = FlatVector::GetData<uint16_t>(*cipher_vec);
  auto blob_vec_data = FlatVector::GetData<string_t>(*blob_vec);

  // set nonce
  nonce_hi_data[0] = (static_cast<uint64_t>(lstate.iv[0]) << 32) | lstate.iv[1];
  nonce_lo_data[0] = lstate.iv[2];

  lstate.encryption_state->InitializeEncryption(
      reinterpret_cast<const_data_ptr_t>(lstate.iv), 16, key);

  auto batch_size = BATCH_SIZE;
  lstate.to_process = size;
  auto total_size = sizeof(T) * size;

  if (lstate.to_process > batch_size) {
    batch_size = BATCH_SIZE;
  } else {
    batch_size = lstate.to_process;
  }

  lstate.batch_size_in_bytes = batch_size * sizeof(T);
  uint64_t plaintext_bytes;

  auto base_ptr = StringVector::EmptyString(*blob_vec, total_size).GetDataWriteable();

  auto batch_nr = 0;
  auto buffer_offset = 0;

  // TODO: for strings this works different because the string size is variable
  while (lstate.to_process) {

    // TODO: fix for edge case; resulting bytes are less then 64 bits (=8 bytes)
    auto processed = batch_nr * BATCH_SIZE;
    // memcpy(&plaintext_bytes, &input_vector[processed], sizeof(T));
    buffer_offset = batch_nr * lstate.batch_size_in_bytes;

    string_t encrypted_string = StringVector::EmptyString(*blob_vec, lstate.batch_size_in_bytes);

    lstate.encryption_state->Process(
        reinterpret_cast<const unsigned char *>(input_vector) + buffer_offset, lstate.batch_size_in_bytes,
        reinterpret_cast<data_ptr_t>(encrypted_string.GetDataWriteable()), lstate.batch_size_in_bytes);

    encrypted_string.Finalize();

    idx_t current_index = batch_nr * BATCH_SIZE;

    // iterate through a single batch
    for (uint32_t i = 0; i < batch_size; i++) {

      if (!validity.RowIsValid(lstate.index)) {
        continue;
      }

      blob_vec_data[current_index] = encrypted_string;
      cipher_vec_data[current_index] = MaskCipher(i, &plaintext_bytes, false);
      counter_vec_data[current_index] = batch_nr;
      current_index++;
    }

    base_ptr += lstate.batch_size_in_bytes;
    batch_nr++;

    // todo: optimize
    if (lstate.to_process > BATCH_SIZE) {
      lstate.to_process -= BATCH_SIZE;
    } else {
      // processing finalized
      lstate.to_process = 0;
      break;
    }

    if (lstate.to_process < BATCH_SIZE) {
      batch_size = lstate.to_process;
      lstate.batch_size_in_bytes = lstate.to_process * sizeof(T);
    }
  }

}

template <typename T>
void EncryptVectorized(const UnifiedVectorFormat &input_data_u, uint64_t size, ExpressionState &state, Vector &result, uint8_t vector_type) {

  // get the actual data and selection vector
  auto input_data = UnifiedVectorFormat::GetData<T>(input_data_u);
  auto input_data_sel = input_data_u.sel;

  // local state and key
  auto &lstate = VCryptFunctionLocalState::ResetAndGet(state);
  auto key = VCryptBasicFun::GetKey(state);
  auto &validity = FlatVector::Validity(result);

  Vector struct_vector(EncryptionTypes::GetEncryptionType(LogicalTypeId(vector_type)), size);
  result.ReferenceAndSetType(struct_vector);

  auto &children = StructVector::GetEntries(result);
  auto &nonce_hi = children[0];
  auto &nonce_lo = children[1];
  auto &counter_vec = children[2];
  auto &cipher_vec = children[3];

  nonce_hi->SetVectorType(VectorType::CONSTANT_VECTOR);
  nonce_lo->SetVectorType(VectorType::CONSTANT_VECTOR);
  counter_vec->SetVectorType(VectorType::FLAT_VECTOR);
  cipher_vec->SetVectorType(VectorType::FLAT_VECTOR);

  UnifiedVectorFormat nonce_hi_u;
  UnifiedVectorFormat nonce_lo_u;
  UnifiedVectorFormat counter_vec_u;
  UnifiedVectorFormat cipher_vec_u;

  nonce_hi->ToUnifiedFormat(size, nonce_hi_u);
  nonce_lo->ToUnifiedFormat(size, nonce_lo_u);
  counter_vec->ToUnifiedFormat(size, counter_vec_u);
  cipher_vec->ToUnifiedFormat(size, cipher_vec_u);

  auto nonce_hi_data = FlatVector::GetData<uint64_t>(*nonce_hi);
  auto nonce_lo_data = FlatVector::GetData<uint32_t>(*nonce_lo);
  auto counter_vec_data = FlatVector::GetData<uint32_t>(*counter_vec);
  auto cipher_vec_data = FlatVector::GetData<uint16_t>(*cipher_vec);

  // ----------Set Nonce ----------

  nonce_hi_data[0] = (static_cast<uint64_t>(lstate.iv[0]) << 32) | lstate.iv[1];
  nonce_lo_data[0] = lstate.iv[2];

  // ---------- Encrypt and store into a Dict Vector ----------

  auto &blob = children[4];
  SelectionVector sel(size);
  blob->Slice(*blob, sel, size);

  auto &blob_sel = DictionaryVector::SelVector(*blob);
  blob_sel.Initialize(size);

  auto &blob_child = DictionaryVector::Child(*blob);
  auto blob_child_data = FlatVector::GetData<string_t>(blob_child);

  if (lstate.batch_nr == 0) {
    lstate.encryption_state->InitializeEncryption(
        reinterpret_cast<const_data_ptr_t>(lstate.iv), 16, key);
  }

  uint32_t batch_size;
  lstate.to_process = size;
  auto rounded_size = size + (BATCH_SIZE - 1) & ~(BATCH_SIZE - 1);
  auto total_size = sizeof(T) * rounded_size;

  if (lstate.to_process > BATCH_SIZE) {
    batch_size = BATCH_SIZE;
  } else {
    batch_size = lstate.to_process;
  }

  lstate.batch_size_in_bytes = batch_size * sizeof(T);
  uint64_t plaintext_bytes;

  // We clear the buffer first to avoid leaking data
  memset(lstate.buffer_p, 0, total_size);

  uint64_t offset = 0;
  for (uint32_t i = 0; i < size; i++){
    if  (!validity.RowIsValid(input_data_sel->get_index(i))) {
      continue;
    }
    Store<T>(input_data[input_data_sel->get_index(i)], lstate.buffer_p + offset);
    offset += sizeof(T);
  }

  // this only works for flat vectors
  // memcpy(lstate.buffer_p, input_data, size * sizeof(T));
  lstate.encryption_state->Process(lstate.buffer_p, total_size, lstate.buffer_p, total_size);

  auto index = 0;
  uint64_t dict_index;
  auto batch_nr = 0;
  uint64_t buffer_offset;

  while (lstate.to_process) {
    buffer_offset = batch_nr * lstate.batch_size_in_bytes;

    // copy the first 8 bytes of plaintext of each batch
    // TODO: fix for edge case; resulting bytes are less then 64 bits (=8 bytes)
    // this is not trivial for dict vectors
    auto processed = batch_nr * BATCH_SIZE;
    memcpy(&plaintext_bytes, &input_data[input_data_sel->get_index(processed)], sizeof(uint64_t));

    blob_child_data[batch_nr] =
        StringVector::EmptyString(blob_child, lstate.batch_size_in_bytes);
    blob_child_data[batch_nr].SetPointer(
        reinterpret_cast<char *>(lstate.buffer_p + buffer_offset));
    blob_child_data[batch_nr].Finalize();

    // set index in selection vector
    for (uint32_t j = 0; j < batch_size; j++) {
//      if (!validity.RowIsValid(index)) {
// fix validity later
//        continue;
//      }
      // set index of selection vector
      blob_sel.set_index(index, batch_nr);
      // cipher contains the (masked) position in the block
      // to calculate the offset: plain_cipher * sizeof(T)
      // todo; fix the is_null
      cipher_vec_data[index] = MaskCipher(j, &plaintext_bytes, false);
      // counter is used to identify the delta of the nonce
      counter_vec_data[index] = batch_nr + lstate.batch_nr;
      index++;
    }

    batch_nr++;

    // todo: optimize this chunk of code
    if (lstate.to_process > BATCH_SIZE) {
      lstate.to_process -= BATCH_SIZE;
    } else {
      // processing finalized
      lstate.to_process = 0;
      break;
    }
    if (lstate.to_process < BATCH_SIZE) {
      batch_size = lstate.to_process;
    }
  }

  lstate.batch_nr += batch_nr;
}

uint32_t RoundUpToBlockSize(uint32_t num) {
  return (num + 15) & ~15;
}

template <typename T>
void EncryptVectorizedVariable(const UnifiedVectorFormat &input_data_u, uint64_t size, ExpressionState &state,
                               Vector &result, uint8_t vector_type) {

  // Storage Layout
  // ----------------------------------------------------------------------------
  // 8 bytes VCrypt version
  // BATCH_SIZE * 64 bytes is byte offset (could be truncated to 16 bits for small strings)
  // resulting bytes are total length of the encrypted data

  // get the actual data and selection vector
  auto input_data = UnifiedVectorFormat::GetData<T>(input_data_u);
  auto input_data_sel = input_data_u.sel;

  // local and global vcrypt state
  auto &lstate = VCryptFunctionLocalState::ResetAndGet(state);
  auto vcrypt_state = VCryptBasicFun::GetVCryptState(state);

  auto key = VCryptBasicFun::GetKey(state);
  auto &validity = FlatVector::Validity(result);

  Vector struct_vector(EncryptionTypes::GetEncryptionType(LogicalTypeId(vector_type)), size);
  result.ReferenceAndSetType(struct_vector);

  auto &children = StructVector::GetEntries(result);
  auto &nonce_hi = children[0];
  auto &nonce_lo = children[1];
  auto &counter_vec = children[2];
  auto &cipher_vec = children[3];

  nonce_hi->SetVectorType(VectorType::CONSTANT_VECTOR);
  nonce_lo->SetVectorType(VectorType::CONSTANT_VECTOR);
  counter_vec->SetVectorType(VectorType::FLAT_VECTOR);
  cipher_vec->SetVectorType(VectorType::FLAT_VECTOR);

  UnifiedVectorFormat nonce_hi_u;
  UnifiedVectorFormat nonce_lo_u;
  UnifiedVectorFormat counter_vec_u;
  UnifiedVectorFormat cipher_vec_u;
  UnifiedVectorFormat type_vec_u;

  nonce_hi->ToUnifiedFormat(size, nonce_hi_u);
  nonce_lo->ToUnifiedFormat(size, nonce_lo_u);
  counter_vec->ToUnifiedFormat(size, counter_vec_u);
  cipher_vec->ToUnifiedFormat(size, cipher_vec_u);

  auto nonce_hi_data = FlatVector::GetData<uint64_t>(*nonce_hi);
  auto nonce_lo_data = FlatVector::GetData<uint32_t>(*nonce_lo);
  auto counter_vec_data = FlatVector::GetData<uint32_t>(*counter_vec);
  auto cipher_vec_data = FlatVector::GetData<uint16_t>(*cipher_vec);

  // set nonce
  nonce_hi_data[0] = (static_cast<uint64_t>(lstate.iv[0]) << 32) | lstate.iv[1];
  nonce_lo_data[0] = lstate.iv[2];

  // result vector is a dict vector containing encrypted data
  auto &blob = children[4];
  SelectionVector sel(size);
  blob->Slice(*blob, sel, size);

  auto &blob_sel = DictionaryVector::SelVector(*blob);
  blob_sel.Initialize(size);

  auto &blob_child = DictionaryVector::Child(*blob);
  auto blob_child_data = FlatVector::GetData<string_t>(blob_child);

  auto counter_init = 0;

  auto index = 0;
  uint16_t batches = (size + BATCH_SIZE - 1) / BATCH_SIZE;
  auto const metadata_len = BATCH_SIZE * sizeof(uint64_t) + 1;

  uint32_t batch_size;
  lstate.to_process = size;

  if (size > BATCH_SIZE) {
    batch_size = BATCH_SIZE;
  } else {
    batch_size = size;
  }

  uint64_t dict_index;
  for (uint32_t i = 0; i < batches; i++) {
    lstate.ResetIV<T>(counter_init);

    // Initialize Encryption
    lstate.encryption_state->InitializeEncryption(
        reinterpret_cast<const_data_ptr_t>(lstate.iv), 16, key);

    // for now, allocate this on the stack
    // but put this later into the local state
    uint8_t offset_buffer[metadata_len];
    data_ptr_t offset_buf_ptr = offset_buffer;

    // first byte of a batch is the VCrypt version
    Store<uint8_t>(0, offset_buf_ptr);
    offset_buf_ptr++;
    auto current_offset = metadata_len;
    uint64_t val_size;

    // loop through the batch to see if we have to reallocate the buffer
    for (uint32_t j = 0; j < batch_size; j++) {
//      if  (!validity.RowIsValid(input_data_sel->get_index(i))) {
//        // Fix this later
//        continue;
//      }
      dict_index = input_data_sel->get_index(index);
      val_size = input_data[dict_index].GetSize();
      current_offset += val_size;
      Store<uint64_t>(current_offset, offset_buf_ptr);
      offset_buf_ptr += sizeof(uint64_t);
      index++;
    }

    index -= batch_size;

    blob_child_data[i] = StringVector::EmptyString(blob_child, current_offset);
    auto batch_ptr = blob_child_data[i].GetDataWriteable();
    // copy the metadata
    memcpy(batch_ptr, offset_buffer, metadata_len);
    batch_ptr += metadata_len;

    // loop again to store the actual values
    for (uint32_t j = 0; j < batch_size; j++) {
      dict_index = input_data_sel->get_index(index);
      val_size = input_data[dict_index].GetSize();
      memcpy(batch_ptr, input_data[dict_index].GetDataWriteable(), val_size);
      batch_ptr += val_size;
      blob_sel.set_index(index, i);
      cipher_vec_data[dict_index] = j;
      counter_vec_data[dict_index] = counter_init;
      index++;
    }

    // we encrypt data in-place
    lstate.encryption_state->Process(
        reinterpret_cast<data_ptr_t>(blob_child_data[i].GetDataWriteable()), current_offset,
        reinterpret_cast<data_ptr_t>(blob_child_data[i].GetDataWriteable()),
        current_offset);
    blob_child_data[i].Finalize();

    // round off to the nearest block of 16 bytes
    counter_init += ceil((current_offset  + 1) / 16);

    // todo: optimize this chunk of code
    if (lstate.to_process > BATCH_SIZE) {
      lstate.to_process -= BATCH_SIZE;
    } else {
      // processing finalized
      lstate.to_process = 0;
      break;
    }
    if (lstate.to_process < BATCH_SIZE) {
      batch_size = lstate.to_process;
    }
  }
}

static void EncryptDataVectorized(DataChunk &args, ExpressionState &state,
                               Vector &result) {

  auto result_vec_type = result.GetType();
  D_ASSERT(result_vec_type.HasExtensionInfo());
  auto &mods = result_vec_type.GetExtensionInfo()->modifiers;
  auto vector_type = LogicalTypeId(mods[0].value.GetValue<int8_t>());
  auto size = args.size();

  auto &input_vector = args.data[0];
  UnifiedVectorFormat input_data_u;
  input_vector.ToUnifiedFormat(args.size(), input_data_u);

  switch (vector_type) {
    case LogicalTypeId::TINYINT:
    case LogicalTypeId::UTINYINT:
      return EncryptVectorized<int8_t>(input_data_u, size, state, result, uint8_t(vector_type));
    case LogicalTypeId::SMALLINT:
    case LogicalTypeId::USMALLINT:
      return EncryptVectorized<int16_t>(input_data_u, size, state, result, uint8_t(vector_type));
    case LogicalTypeId::INTEGER:
    case LogicalTypeId::DATE:
      return EncryptVectorized<int32_t>(input_data_u,
                                     size, state, result, uint8_t(vector_type));
    case LogicalTypeId::UINTEGER:
      return EncryptVectorized<uint32_t>(input_data_u, size, state, result, uint8_t(vector_type));
    case LogicalTypeId::BIGINT:
    case LogicalTypeId::TIMESTAMP:
      return EncryptVectorized<int64_t>(input_data_u, size, state, result, uint8_t(vector_type));
    case LogicalTypeId::UBIGINT:
      return EncryptVectorized<uint64_t>(input_data_u, size, state, result, uint8_t(vector_type));
    case LogicalTypeId::FLOAT:
      return EncryptVectorized<float>(input_data_u, size, state, result, uint8_t(vector_type));
    case LogicalTypeId::DOUBLE:
      return EncryptVectorized<double>(input_data_u, size, state, result, uint8_t(vector_type));
    case LogicalTypeId::VARCHAR:
    case LogicalTypeId::VARINT:
    case LogicalTypeId::CHAR:
    case LogicalTypeId::BLOB:
    case LogicalTypeId::MAP:
    case LogicalTypeId::LIST:
    return EncryptVectorizedVariable<string_t>(input_data_u, size, state, result, uint8_t(vector_type));
    default:
      throw NotImplementedException("Unsupported type for Encryption");
}
}

ScalarFunctionSet GetEncryptionVectorizedFunction() {
  ScalarFunctionSet set("encrypt");

  for (auto &type : EncryptionTypes::IsAvailable()) {
    set.AddFunction(
        ScalarFunction({type, LogicalType::VARCHAR},
                       EncryptionTypes::GetEncryptionType(type.id()),
                       EncryptDataVectorized, EncryptFunctionData::EncryptBind, nullptr, nullptr,
                       VCryptFunctionLocalState::Init));
  }
  return set;
}

//------------------------------------------------------------------------------
// Register functions
//------------------------------------------------------------------------------

void CoreScalarFunctions::RegisterEncryptVectorizedScalarFunction(
    DatabaseInstance &db) {
  ExtensionUtil::RegisterFunction(db, GetEncryptionVectorizedFunction());
}
} // namespace core
} // namespace vcrypt
