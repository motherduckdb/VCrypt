#define DUCKDB_EXTENSION_MAIN

#include "duckdb.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/extension_util.hpp"
#include "duckdb/main/connection_manager.hpp"
#include "duckdb/main/secret/secret_manager.hpp"
#include "duckdb/function/scalar_function.hpp"
#include "duckdb/common/types.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/types/blob.hpp"
#include "duckdb/common/encryption_state.hpp"
#include "duckdb/common/vector_operations/generic_executor.hpp"
#include "duckdb/planner/expression/bound_function_expression.hpp"
#include "mbedtls_wrapper.hpp"

#include <duckdb/parser/parsed_data/create_scalar_function_info.hpp>

#include "simple_encryption_state.hpp"
#include "simple_encryption/core/functions/common.hpp"
#include "simple_encryption/core/functions/scalar.hpp"
#include "simple_encryption/core/functions/secrets.hpp"
#include "simple_encryption/core/functions/scalar/encrypt.hpp"
#include "simple_encryption/core/functions/function_data/encrypt_function_data.hpp"

namespace simple_encryption {

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

LogicalType CreateEncryptionStruct() {
  return LogicalType::STRUCT({{"nonce_hi", LogicalType::UBIGINT},
                              {"nonce_lo", LogicalType::UBIGINT},
                              {"counter", LogicalType::UINTEGER},
                              {"cipher", LogicalType::SMALLINT},
                              {"value", LogicalType::BLOB},
                              {"type", LogicalType::TINYINT}});
}

template <typename T>
void EncryptVectorizedFlat(T *input_vector, uint64_t size, ExpressionState &state, Vector &result, uint8_t vector_type) {

  // local, global and encryption state
  auto &lstate = VCryptFunctionLocalState::ResetAndGet(state);
  auto vcrypt_state =
      VCryptBasicFun::GetVCryptState(state);

  auto key = VCryptBasicFun::GetKey(state);
  auto &validity = FlatVector::Validity(result);

  Vector struct_vector(CreateEncryptionStruct(), size);
  result.ReferenceAndSetType(struct_vector);

  auto &children = StructVector::GetEntries(result);
  auto &nonce_hi = children[0];
  auto &nonce_lo = children[1];
  auto &counter_vec = children[2];
  auto &cipher_vec = children[3];
  auto &blob_vec = children[4];
  auto &type_vec = children[5];

  nonce_hi->SetVectorType(VectorType::CONSTANT_VECTOR);
  nonce_lo->SetVectorType(VectorType::CONSTANT_VECTOR);
  counter_vec->SetVectorType(VectorType::FLAT_VECTOR);
  cipher_vec->SetVectorType(VectorType::FLAT_VECTOR);
  blob_vec->SetVectorType(VectorType::FLAT_VECTOR);
  type_vec->SetVectorType(VectorType::CONSTANT_VECTOR);

  UnifiedVectorFormat nonce_hi_u;
  UnifiedVectorFormat nonce_lo_u;
  UnifiedVectorFormat counter_vec_u;
  UnifiedVectorFormat cipher_vec_u;
  UnifiedVectorFormat blob_vec_u;
  UnifiedVectorFormat type_vec_u;

  nonce_hi->ToUnifiedFormat(size, nonce_hi_u);
  nonce_lo->ToUnifiedFormat(size, nonce_lo_u);
  counter_vec->ToUnifiedFormat(size, counter_vec_u);
  cipher_vec->ToUnifiedFormat(size, cipher_vec_u);
  blob_vec->ToUnifiedFormat(size, blob_vec_u);
  type_vec->ToUnifiedFormat(size, type_vec_u);

  auto nonce_hi_data = FlatVector::GetData<uint64_t>(*nonce_hi);
  auto nonce_lo_data = FlatVector::GetData<uint32_t>(*nonce_lo);
  auto counter_vec_data = FlatVector::GetData<uint32_t>(*counter_vec);
  auto cipher_vec_data = FlatVector::GetData<uint16_t>(*cipher_vec);
  auto type_vec_data = FlatVector::GetData<int8_t>(*type_vec);
  auto blob_vec_data = FlatVector::GetData<string_t>(*blob_vec);

  // set type
  type_vec_data[0] = vector_type;

  // set nonce
  nonce_hi_data[0] = (static_cast<uint64_t>(lstate.iv[0]) << 32) | lstate.iv[1];
  nonce_lo_data[0] = lstate.iv[2];

  // if lstate.

  lstate.encryption_state->InitializeEncryption(
      reinterpret_cast<const_data_ptr_t>(lstate.iv), 16, key);

  auto batch_size = BATCH_SIZE;

  // todo; create separate function for strings
  lstate.to_process_batch = size;
  auto total_size = sizeof(T) * size;

  if (lstate.to_process_batch > batch_size) {
    batch_size = BATCH_SIZE;
  } else {
    batch_size = lstate.to_process_batch;
  }

  lstate.batch_size_in_bytes = batch_size * sizeof(T);
  uint64_t plaintext_bytes;

  auto base_ptr = StringVector::EmptyString(*blob_vec, total_size).GetDataWriteable();

  auto batch_nr = 0;
  auto buffer_offset = 0;

  // TODO: for strings this works different because the string size is variable
  while (lstate.to_process_batch) {

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

#ifdef DEBUG
    // todo implement hash to check the encrypted data
#endif

    batch_nr++;

    // todo: optimize
    if (lstate.to_process_batch > BATCH_SIZE) {
      lstate.to_process_batch -= BATCH_SIZE;
    } else {
      // processing finalized
      lstate.to_process_batch = 0;
      break;
    }

    if (lstate.to_process_batch < BATCH_SIZE) {
      batch_size = lstate.to_process_batch;
      lstate.batch_size_in_bytes = lstate.to_process_batch * sizeof(T);
    }
  }

}

template <typename T>
void EncryptVectorized(T *input_vector, uint64_t size, ExpressionState &state, Vector &result, uint8_t vector_type) {

  // local and global vcrypt state
  auto &lstate = VCryptFunctionLocalState::ResetAndGet(state);
  auto vcrypt_state =
      VCryptBasicFun::GetVCryptState(state);

  // auto encryption_state = VCryptBasicFun::GetEncryptionState(state);
  // todo; fix key
  auto key = VCryptBasicFun::GetKey(state);
  auto &validity = FlatVector::Validity(result);

  Vector struct_vector(CreateEncryptionStruct(), size);
  result.ReferenceAndSetType(struct_vector);

  auto &children = StructVector::GetEntries(result);
  auto &nonce_hi = children[0];
  auto &nonce_lo = children[1];
  auto &counter_vec = children[2];
  auto &cipher_vec = children[3];
  auto &type_vec = children[5];

  nonce_hi->SetVectorType(VectorType::CONSTANT_VECTOR);
  nonce_lo->SetVectorType(VectorType::CONSTANT_VECTOR);
  counter_vec->SetVectorType(VectorType::FLAT_VECTOR);
  cipher_vec->SetVectorType(VectorType::FLAT_VECTOR);
  type_vec->SetVectorType(VectorType::CONSTANT_VECTOR);

  UnifiedVectorFormat nonce_hi_u;
  UnifiedVectorFormat nonce_lo_u;
  UnifiedVectorFormat counter_vec_u;
  UnifiedVectorFormat cipher_vec_u;
  UnifiedVectorFormat type_vec_u;

  nonce_hi->ToUnifiedFormat(size, nonce_hi_u);
  nonce_lo->ToUnifiedFormat(size, nonce_lo_u);
  counter_vec->ToUnifiedFormat(size, counter_vec_u);
  cipher_vec->ToUnifiedFormat(size, cipher_vec_u);
  type_vec->ToUnifiedFormat(size, type_vec_u);

  auto nonce_hi_data = FlatVector::GetData<uint64_t>(*nonce_hi);
  auto nonce_lo_data = FlatVector::GetData<uint32_t>(*nonce_lo);
  auto counter_vec_data = FlatVector::GetData<uint32_t>(*counter_vec);
  auto cipher_vec_data = FlatVector::GetData<uint16_t>(*cipher_vec);
  auto type_vec_data = FlatVector::GetData<int8_t>(*type_vec);

  // set type
  type_vec_data[0] = vector_type;

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

  // todo: FIX! check if aligned with 16 bytes
  if (lstate.batch_nr == 0) {
    lstate.encryption_state->InitializeEncryption(
        reinterpret_cast<const_data_ptr_t>(lstate.iv), 16, key);
  }

  auto batch_size = BATCH_SIZE;

  // todo; create separate function for strings
  lstate.to_process_batch = size;
  auto total_size = sizeof(T) * size;

  if (lstate.to_process_batch > BATCH_SIZE) {
    batch_size = BATCH_SIZE;
  } else {
    batch_size = lstate.to_process_batch;
  }

  lstate.batch_size_in_bytes = batch_size * sizeof(T);
  uint64_t plaintext_bytes;

  lstate.encryption_state->Process(
      reinterpret_cast<const unsigned char *>(input_vector), total_size,
      lstate.buffer_p, total_size);

  auto index = 0;
  auto batch_nr = 0;
  uint64_t buffer_offset;

  while (lstate.to_process_batch) {
    buffer_offset = batch_nr * lstate.batch_size_in_bytes;

    // copy the first 64 bits of plaintext of each batch
    // TODO: fix for edge case; resulting bytes are less then 64 bits (=8 bytes)
    auto processed = batch_nr * BATCH_SIZE;
    memcpy(&plaintext_bytes, &input_vector[processed], sizeof(uint64_t));

    blob_child_data[batch_nr] =
        StringVector::EmptyString(blob_child, lstate.batch_size_in_bytes);
    blob_child_data[batch_nr].SetPointer(
        reinterpret_cast<char *>(lstate.buffer_p + buffer_offset));
    blob_child_data[batch_nr].Finalize();

    // set index in selection vector
    for (uint32_t j = 0; j < batch_size; j++) {
      if (!validity.RowIsValid(index)) {
        continue;
      }

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

    // todo: optimize
    if (lstate.to_process_batch > BATCH_SIZE) {
      lstate.to_process_batch -= BATCH_SIZE;
    } else {
      // processing finalized
      lstate.to_process_batch = 0;
      break;
    }

    if (lstate.to_process_batch < BATCH_SIZE) {
      batch_size = lstate.to_process_batch;
      lstate.batch_size_in_bytes = lstate.to_process_batch * sizeof(T);
    }
  }

  lstate.batch_nr += batch_nr;
}

static void EncryptDataVectorized(DataChunk &args, ExpressionState &state,
                               Vector &result) {

  auto &input_vector = args.data[0];
  auto vector_type = input_vector.GetType();

  auto vector_type_id = PhysicalType(input_vector.GetType().id());
  auto size = args.size();

  UnifiedVectorFormat vdata_input;
  input_vector.ToUnifiedFormat(args.size(), vdata_input);

  switch (vector_type.id()) {
    case LogicalTypeId::TINYINT:
    case LogicalTypeId::UTINYINT:
      return EncryptVectorized<int8_t>((int8_t *)vdata_input.data,
                                    size, state, result, uint8_t(vector_type_id));
    case LogicalTypeId::SMALLINT:
    case LogicalTypeId::USMALLINT:
      return EncryptVectorized<int16_t>((int16_t *)vdata_input.data,
                                     size, state, result, uint8_t(vector_type_id));
    case LogicalTypeId::INTEGER:
      return EncryptVectorized<int32_t>((int32_t *)vdata_input.data,
                                     size, state, result, uint8_t(vector_type_id));
    case LogicalTypeId::UINTEGER:
      return EncryptVectorized<uint32_t>((uint32_t *)vdata_input.data,
                                      size, state, result, uint8_t(vector_type_id));
    case LogicalTypeId::BIGINT:
      return EncryptVectorized<int64_t>((int64_t *)vdata_input.data,
                                     size, state, result, uint8_t(vector_type_id));
    case LogicalTypeId::UBIGINT:
      return EncryptVectorized<uint64_t>((uint64_t *)vdata_input.data,
                                      size, state, result, uint8_t(vector_type_id));
    case LogicalTypeId::FLOAT:
      return EncryptVectorized<float>((float *)vdata_input.data,
                                   size, state, result, uint8_t(vector_type_id));
    case LogicalTypeId::DOUBLE:
      return EncryptVectorized<double>((double *)vdata_input.data,
                                    size, state, result, uint8_t(vector_type_id));
    case LogicalTypeId::VARCHAR:
    return EncryptVectorized<string_t>((string_t *)vdata_input.data,
                                    size, state, result, uint8_t(vector_type_id));
    default:
      throw NotImplementedException("Unsupported numeric type for encryption");
}
}


ScalarFunctionSet GetEncryptionVectorizedFunction() {
  ScalarFunctionSet set("encrypt_vectorized");

  for (auto &type : LogicalType::AllTypes()) {
    set.AddFunction(
        ScalarFunction({type, LogicalType::VARCHAR},
                       LogicalType::STRUCT({{"nonce_hi", LogicalType::UBIGINT},
                                            {"nonce_lo", LogicalType::UBIGINT},
                                            {"counter", LogicalType::UINTEGER},
                                            {"cipher", LogicalType::SMALLINT},
                                            {"value", LogicalType::BLOB},
                                            {"type", LogicalType::TINYINT}}),
                       EncryptDataVectorized, EncryptFunctionData::EncryptBind, nullptr, nullptr, VCryptFunctionLocalState::Init));
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
} // namespace simple_encryption
