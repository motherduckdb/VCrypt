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

#define BATCH_SIZE 128

namespace simple_encryption {

namespace core {

uint8_t MaskCipher(uint8_t cipher, uint64_t *plaintext_bytes, bool is_null){
    const uint64_t prime = 10251357202697351;
    auto random_val = *plaintext_bytes * prime;

    // mask the first 8 bits by shifting and cast to uint8_t
    uint8_t masked_cipher = static_cast<uint8_t>((random_val) >> 56);

    if (is_null) {
      cipher |= 0x80;  // set first bit to 1
    } else {
      cipher &= 0x7F;  // Clear the first bit
    }

    return cipher ^ masked_cipher;
}

LogicalType CreateEncryptionStruct() {
  return LogicalType::STRUCT({{"nonce_hi", LogicalType::UBIGINT},
                              {"nonce_lo", LogicalType::UBIGINT},
                              {"counter", LogicalType::UINTEGER},
                              {"cipher", LogicalType::TINYINT},
                              {"value", LogicalType::BLOB}});
}

template <typename T>
void EncryptVectorized(T *input_vector, uint64_t size, ExpressionState &state, Vector &result) {

  // local, global and encryption state
  auto &lstate = SimpleEncryptionFunctionLocalState::ResetAndGet(state);
  auto vcrypt_state =
      VCryptBasicFun::GetSimpleEncryptionState(state);

  auto encryption_state = VCryptBasicFun::GetEncryptionState(state);
  auto key = VCryptBasicFun::GetKey(state);

  Vector struct_vector(CreateEncryptionStruct(), size);
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
  auto cipher_vec_data = FlatVector::GetData<uint8_t>(*cipher_vec);

  // set nonce
  nonce_hi_data[0] = vcrypt_state->iv[0];
  nonce_lo_data[0] = vcrypt_state->iv[1];

  // result vector is a dict vector containing encrypted data
  auto &blob = children[4];
  SelectionVector sel(size);
  blob->Slice(*blob, sel, size);

  auto &blob_sel = DictionaryVector::SelVector(*blob);
  blob_sel.Initialize(size);

  auto &blob_child = DictionaryVector::Child(*blob);
  auto blob_child_data = FlatVector::GetData<string_t>(blob_child);

  // also: fix IV in vcrypt_state
  encryption_state->InitializeEncryption(
      reinterpret_cast<const_data_ptr_t>(vcrypt_state->iv), 16, key);

  // todo; create separate function for strings
  auto to_process = size;
  auto total_size = sizeof(T) * size;
  uint32_t batch_size;

  if (to_process > BATCH_SIZE) {
    batch_size = BATCH_SIZE;
  } else {
    batch_size = to_process;
  }

  auto batch_size_in_bytes = batch_size * sizeof(T);
  uint64_t plaintext_bytes;

  encryption_state->Process(
      reinterpret_cast<const unsigned char *>(input_vector), total_size,
      lstate.buffer_p, total_size);

  auto index = 0;
  auto batch_nr = 0;
  uint64_t buffer_offset;

  // TODO: for strings this works different because the string size is variable
  while (to_process) {
    buffer_offset = batch_nr * batch_size_in_bytes;

    // copy the first 64 bits of plaintext of each batch
    // TODO: fix for edge case; resulting bytes are less then 64 bits (=8 bytes)
    auto processed = batch_nr * BATCH_SIZE;
    memcpy(&plaintext_bytes, &input_vector[processed], sizeof(uint64_t));

    blob_child_data[batch_nr] =
        StringVector::EmptyString(blob_child, batch_size_in_bytes);
    *(uint32_t *)blob_child_data[batch_nr].GetPrefixWriteable() =
        *(uint32_t *)lstate.buffer_p + buffer_offset;

    D_ASSERT(blob_child_data[batch_nr].GetDataWriteable() != nullptr);
    D_ASSERT(lstate.buffer_p != nullptr);
    D_ASSERT(reinterpret_cast<uintptr_t>(blob_child_data[batch_nr].GetDataWriteable()) % alignof(uint64_t) == 0);
    D_ASSERT(reinterpret_cast<uintptr_t>(lstate.buffer_p + buffer_offset) % alignof(uint64_t) == 0);
    D_ASSERT(batch_size <= blob_child_data[batch_nr].GetSize());

    memcpy(blob_child_data[batch_nr].GetDataWriteable(), lstate.buffer_p + buffer_offset,
           batch_size);

    blob_child_data[batch_nr].Finalize();

    // set index in selection vector
    for (uint32_t j = 0; j < batch_size; j++) {
      // set index of selection vector
      blob_sel.set_index(index, batch_nr);
      // cipher contains the (masked) position in the block
      // to calculate the offset: plain_cipher * sizeof(T)
      // todo; fix the is_null
      cipher_vec_data[index] = MaskCipher(j, &plaintext_bytes, false);
      // counter is used to identify the delta of the nonce
      counter_vec_data[index] = batch_nr;

      index++;
    }

    batch_nr++;

    // todo: optimize
    if (to_process > BATCH_SIZE) {
      to_process -= BATCH_SIZE;
    } else {
      // processing finalized
      to_process = 0;
      break;
    }

    if (to_process < BATCH_SIZE) {
      batch_size = to_process;
      batch_size_in_bytes = to_process * sizeof(T);
    }
  }
}

template <typename T>
void DecryptFromEtype(Vector &input_vector, uint64_t size,
                      ExpressionState &state, Vector &result) {

  // local state (contains key, buffer, iv etc.)
  auto &lstate = SimpleEncryptionFunctionLocalState::ResetAndGet(state);
  // global state
  auto simple_encryption_state = VCryptBasicFun::GetSimpleEncryptionState(state);
  auto encryption_state = VCryptBasicFun::GetEncryptionState(state);

  // Get Key from Bind
  auto key = VCryptBasicFun::GetKey(state);

//  using ENCRYPTED_TYPE = StructTypeTernary<uint64_t, uint64_t, T>;
//  using PLAINTEXT_TYPE = PrimitiveType<T>;
//
//  GenericExecutor::ExecuteUnary<ENCRYPTED_TYPE, PLAINTEXT_TYPE>(
//      input_vector, result, size, [&](ENCRYPTED_TYPE input) {
//        simple_encryption_state->iv[0] = input.a_val;
//        simple_encryption_state->iv[1] = input.b_val;
//
//        encryption_state->InitializeDecryption(
//            reinterpret_cast<const_data_ptr_t>(simple_encryption_state->iv), 12,
//            reinterpret_cast<const string *>(key));
//
//        T decrypted_data =
//            ProcessVectorizedDecrypt(encryption_state, result, input.c_val,
//                                  lstate.buffer_p);
//        return decrypted_data;
//      });
}


static void EncryptDataVectorized(DataChunk &args, ExpressionState &state,
                               Vector &result) {

  auto &input_vector = args.data[0];
  auto vector_type = input_vector.GetType();
  auto size = args.size();

  UnifiedVectorFormat vdata_input;
  input_vector.ToUnifiedFormat(args.size(), vdata_input);

  // TODO; fix and check validity
  ValidityMask &result_validity = FlatVector::Validity(result);
  auto vd = vdata_input.data;

  if (vector_type.IsNumeric()) {
    switch (vector_type.id()) {
    case LogicalTypeId::TINYINT:
    case LogicalTypeId::UTINYINT:
      return EncryptVectorized<int8_t>((int8_t *)vdata_input.data,
                                    size, state, result);
    case LogicalTypeId::SMALLINT:
    case LogicalTypeId::USMALLINT:
      return EncryptVectorized<int16_t>((int16_t *)vdata_input.data,
                                     size, state, result);
    case LogicalTypeId::INTEGER:
      return EncryptVectorized<int32_t>((int32_t *)vdata_input.data,
                                     size, state, result);
    case LogicalTypeId::UINTEGER:
      return EncryptVectorized<uint32_t>((uint32_t *)vdata_input.data,
                                      size, state, result);
    case LogicalTypeId::BIGINT:
      return EncryptVectorized<int64_t>((int64_t *)vdata_input.data,
                                     size, state, result);
    case LogicalTypeId::UBIGINT:
      return EncryptVectorized<uint64_t>((uint64_t *)vdata_input.data,
                                      size, state, result);
    case LogicalTypeId::FLOAT:
      return EncryptVectorized<float>((float *)vdata_input.data,
                                   size, state, result);
    case LogicalTypeId::DOUBLE:
      return EncryptVectorized<double>((double *)vdata_input.data,
                                    size, state, result);
    default:
      throw NotImplementedException("Unsupported numeric type for encryption");
    }
  } else if (vector_type.id() == LogicalTypeId::VARCHAR) {
    return EncryptVectorized<string_t>((string_t *)vdata_input.data,
                                    size, state, result);
  } else if (vector_type.IsNested()) {
    throw NotImplementedException(
        "Nested types are not supported for encryption");
  } else if (vector_type.IsTemporal()) {
    throw NotImplementedException(
        "Temporal types are not supported for encryption");
  }
}


static void DecryptDataVectorized(DataChunk &args, ExpressionState &state,
                                 Vector &result) {

  auto size = args.size();
  auto &input_vector = args.data[0];

  auto &children = StructVector::GetEntries(input_vector);
  // get type of vector containing encrypted values
  auto vector_type = children[2]->GetType();

  if (vector_type.IsNumeric()) {
    switch (vector_type.id()) {
    case LogicalTypeId::TINYINT:
    case LogicalTypeId::UTINYINT:
      return DecryptFromEtype<int8_t>(input_vector, size, state, result);
    case LogicalTypeId::SMALLINT:
    case LogicalTypeId::USMALLINT:
      return DecryptFromEtype<int16_t>(input_vector, size, state,
                                       result);
    case LogicalTypeId::INTEGER:
      return DecryptFromEtype<int32_t>(input_vector, size, state,
                                       result);
    case LogicalTypeId::UINTEGER:
      return DecryptFromEtype<uint32_t>(input_vector, size, state,
                                        result);
    case LogicalTypeId::BIGINT:
      return DecryptFromEtype<int64_t>(input_vector, size, state,
                                       result);
    case LogicalTypeId::UBIGINT:
      return DecryptFromEtype<uint64_t>(input_vector, size, state,
                                        result);
    case LogicalTypeId::FLOAT:
      return DecryptFromEtype<float>(input_vector, size, state, result);
    case LogicalTypeId::DOUBLE:
      return DecryptFromEtype<double>(input_vector, size, state, result);
    default:
      throw NotImplementedException("Unsupported numeric type for decryption");
    }
  } else if (vector_type.id() == LogicalTypeId::VARCHAR) {
    return DecryptFromEtype<string_t>(input_vector, size, state, result);
  } else if (vector_type.IsNested()) {
    throw NotImplementedException(
        "Nested types are not supported for decryption");
  } else if (vector_type.IsTemporal()) {
    throw NotImplementedException(
        "Temporal types are not supported for decryption");
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
                                            {"cipher", LogicalType::TINYINT},
                                            {"value", LogicalType::BLOB}}),
                       EncryptDataVectorized, EncryptFunctionData::EncryptBind, nullptr, nullptr, SimpleEncryptionFunctionLocalState::Init));
  }

  return set;
}

ScalarFunctionSet GetDecryptionVectorizedFunction() {
  ScalarFunctionSet set("decrypt_vectorized");

  for (auto &type : LogicalType::AllTypes()) {
    for (auto &nonce_type_a : LogicalType::Numeric()) {
      for (auto &nonce_type_b : LogicalType::Numeric()) {
        set.AddFunction(ScalarFunction(
            {LogicalType::STRUCT({{"nonce_hi", nonce_type_a},
                                  {"nonce_lo", nonce_type_b},
                                  {"value", type}}),
             LogicalType::VARCHAR},
            type, DecryptDataVectorized, EncryptFunctionData::EncryptBind, nullptr, nullptr, SimpleEncryptionFunctionLocalState::Init));
      }
    }

    // TODO: Fix EINT encryption
    //      set.AddFunction(ScalarFunction({EncryptionTypes::E_INTEGER(),
    //      LogicalType::VARCHAR}, LogicalTypeId::INTEGER, DecryptDataFromEtype,
    //                                     EncryptFunctionData::EncryptBind));

  }

  return set;
}

//------------------------------------------------------------------------------
// Register functions
//------------------------------------------------------------------------------

void CoreScalarFunctions::RegisterEncryptVectorizedScalarFunction(
    DatabaseInstance &db) {
  ExtensionUtil::RegisterFunction(db, GetEncryptionVectorizedFunction());
  ExtensionUtil::RegisterFunction(db, GetDecryptionVectorizedFunction());
}
} // namespace core
} // namespace simple_encryption
