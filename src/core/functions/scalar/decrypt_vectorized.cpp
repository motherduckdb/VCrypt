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

uint16_t UnMaskCipher(uint16_t cipher, uint64_t *plaintext_bytes){
  const uint64_t prime = 10251357202697351;
  auto random_val = *plaintext_bytes * prime;

  // mask the first 8 bits by shifting and cast to uint16_t
  uint16_t mask = static_cast<uint16_t>((random_val) >> 56);
  uint16_t unmasked_cipher = cipher ^ mask;

  bool is_null = (unmasked_cipher & 1) != 0;

  if (is_null) {
    return NULL;
  }

  // remove lsb
  cipher = static_cast<uint16_t>(unmasked_cipher >> 1);

  return cipher;
}

LogicalType CreateDecryptionStruct() {
  return LogicalType::STRUCT({{"nonce_hi", LogicalType::UBIGINT},
                              {"nonce_lo", LogicalType::UBIGINT},
                              {"counter", LogicalType::UINTEGER},
                              {"cipher", LogicalType::SMALLINT},
                              {"value", LogicalType::BLOB}});
}

template <typename T>
void DecryptFromEtype(Vector &input_vector, uint64_t size,
                      ExpressionState &state, Vector &result) {

  // todo; keep track with is_decrypted (bit)map
  ValidityMask &result_validity = FlatVector::Validity(result);
  result.SetVectorType(VectorType::FLAT_VECTOR);
  auto result_data = FlatVector::GetData<T>(result);

  // local, global and encryption state
  auto &lstate = VCryptFunctionLocalState::ResetAndGet(state);
  auto vcrypt_state = VCryptBasicFun::GetVCryptState(state);
  auto encryption_state = VCryptBasicFun::GetEncryptionState(state);
  auto key = VCryptBasicFun::GetKey(state);

  // do we need to check the validity?
  D_ASSERT(input_vector.GetType() == LogicalTypeId::STRUCT);

  auto &children = StructVector::GetEntries(input_vector);
  auto &nonce_hi = children[0];
  auto &nonce_lo = children[1];
  auto &counter_vec = children[2];
  auto &cipher_vec = children[3];

  UnifiedVectorFormat nonce_hi_u;
  UnifiedVectorFormat nonce_lo_u;
  UnifiedVectorFormat counter_vec_u;
  UnifiedVectorFormat cipher_vec_u;

  nonce_hi->ToUnifiedFormat(size, nonce_hi_u);
  nonce_lo->ToUnifiedFormat(size, nonce_lo_u);
  counter_vec->ToUnifiedFormat(size, counter_vec_u);
  cipher_vec->ToUnifiedFormat(size, cipher_vec_u);

  auto &value_vec = children[4];
  D_ASSERT(value_vec->GetType() == LogicalTypeId::BLOB);
  D_ASSERT(value_vec->GetVectorType() == VectorType::DICTIONARY_VECTOR);

  // maybe we should avoid materializing...
  UnifiedVectorFormat value_vec_u;
  value_vec->ToUnifiedFormat(size, value_vec_u);
  auto value_vec_data = FlatVector::GetData<string_t>(*value_vec);

  if ((nonce_hi->GetVectorType() == VectorType::CONSTANT_VECTOR) && (nonce_lo->GetVectorType() == VectorType::CONSTANT_VECTOR)) {
    // Set IV
    lstate.iv[0] = FlatVector::GetData<uint64_t>(*nonce_hi)[0];
    lstate.iv[1] = FlatVector::GetData<uint64_t>(*nonce_lo)[0];
  }

  auto counter_vec_data = FlatVector::GetData<uint32_t>(*counter_vec);
  auto cipher_vec_data = FlatVector::GetData<uint16_t>(*cipher_vec);
  uint32_t delta;

  lstate.to_process = size;

  if (lstate.to_process > BATCH_SIZE) {
    lstate.batch_size = BATCH_SIZE;
  } else {
    lstate.batch_size = lstate.to_process;
  }

  // the encryption granularity is always 128 * sizeof(T)
  // or is it always 512 bytes??
  // we need to align this in the encryption
  lstate.batch_size_in_bytes = sizeof(T) * BATCH_SIZE;
  uint64_t plaintext_bytes;

  // iterate through the whole vector
  for(uint32_t j = 0; j < size; j++){

    // todo; optimize with vectorizing?
    if (lstate.counter != counter_vec_data[j]) {
      // recalculate counter and reset iv
      lstate.counter = counter_vec_data[j];

      // calculate and copy delta to last 4 bytes of iv
      delta = lstate.counter * (BATCH_SIZE * sizeof(T) / 16);
      memcpy(lstate.iv + 12, &delta, 4);

      // (re)initialize encryption state
      encryption_state->InitializeDecryption(
          reinterpret_cast<const_data_ptr_t>(lstate.iv), 16,
          reinterpret_cast<const string *>(key));

      // decrypt the whole batch
      // todo; cache the decrypted plaintext
      encryption_state->Process(
          reinterpret_cast<const_data_ptr_t>(value_vec_data[j].GetData()), lstate.batch_size_in_bytes,
          reinterpret_cast<unsigned char *>(lstate.buffer_p),
          lstate.batch_size_in_bytes);

      // copy first 64 bits for the cipher
      memcpy(&plaintext_bytes, lstate.buffer_p, sizeof(uint64_t));

      // count all similar counter values (optimize?)
      auto seq_size = 0;
      while(lstate.counter == counter_vec_data[j]){
        seq_size++;
      }

      // todo; optimize vectorize
      uint32_t offset = 0;
      if ((seq_size + 1) * sizeof(T) == lstate.batch_size_in_bytes){
        // all values are in the same batch
        // copy the decrypted data to the result vector
        for (uint32_t i = 0; i < (seq_size); i++) {
          result_data[j] = Load<T>(lstate.buffer_p + offset);
          offset += sizeof(T);
        }
        j += seq_size;
      } else {
        // case: part of values are in the same batch
        // or values are in different batches
        uint16_t position = UnMaskCipher(cipher_vec_data[j], &plaintext_bytes);
        result_data[j] = Load<T>(lstate.buffer_p + position * sizeof(T));
      }

      j += seq_size;
    }
  }
}


static void DecryptDataVectorized(DataChunk &args, ExpressionState &state,
                                  Vector &result) {

  auto size = args.size();
  auto &input_vector = args.data[0];
  auto &children = StructVector::GetEntries(input_vector);

  // get type of vector containing encrypted values
  // todo; we need to derive the type from E_type value...
  auto vector_type = children[4]->GetType();

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

ScalarFunctionSet GetDecryptionVectorizedFunction() {
  ScalarFunctionSet set("decrypt_vectorized");

  for (auto &type : LogicalType::AllTypes()) {
        set.AddFunction(ScalarFunction(
            {LogicalType::STRUCT({{"nonce_hi", LogicalType::UBIGINT},
                                  {"nonce_lo", LogicalType::UBIGINT},
                                  {"counter", LogicalType::UINTEGER},
                                  {"cipher", LogicalType::SMALLINT},
                                  {"value", LogicalType::BLOB}}),
             type},
            type, DecryptDataVectorized, EncryptFunctionData::EncryptBind, nullptr, nullptr, VCryptFunctionLocalState::Init));
  }

  return set;
}

//------------------------------------------------------------------------------
// Register functions
//------------------------------------------------------------------------------

void CoreScalarFunctions::RegisterEncryptVectorizedScalarFunction(
    DatabaseInstance &db) {
  ExtensionUtil::RegisterFunction(db, GetDecryptionVectorizedFunction());
}
} // namespace core
} // namespace simple_encryption

