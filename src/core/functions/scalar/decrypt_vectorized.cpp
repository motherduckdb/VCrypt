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
//  const uint64_t prime = 10251357202697351;
//  auto const a_plaintext = plaintext_bytes + 1;
//  auto random_val = *plaintext_bytes * prime;

  // mask the first 8 bits by shifting and cast to uint16_t
//  uint16_t mask = static_cast<uint16_t>((random_val) >> 56);
//  uint16_t unmasked_cipher = cipher ^ mask;
//
//  bool is_null = (unmasked_cipher & 1) != 0;
//
//  if (is_null) {
//    return NULL;
//  }
//
//  // remove lsb
//  cipher = static_cast<uint16_t>(unmasked_cipher >> 1);
//
//  return cipher;
  return cipher;
}

LogicalType CreateDecryptionStruct() {
  return LogicalType::STRUCT({{"nonce_hi", LogicalType::UBIGINT},
                              {"nonce_lo", LogicalType::UBIGINT},
                              {"counter", LogicalType::UINTEGER},
                              {"cipher", LogicalType::SMALLINT},
                              {"value", LogicalType::BLOB}});
}

bool CheckNonce(Vector &nonce_hi, Vector &nonce_lo, uint64_t size) {

  // case: if data fetched from storage, and constant vectors
  if ((nonce_hi.GetVectorType() == VectorType::CONSTANT_VECTOR) &&
      (nonce_lo.GetVectorType() == VectorType::CONSTANT_VECTOR)) {
    return true;
  }

  auto nonce_hi_data = FlatVector::GetData<uint64_t>(nonce_hi);
  auto nonce_lo_data = FlatVector::GetData<uint64_t>(nonce_lo);

  auto nonce_hi_val = nonce_hi_data[0];
  auto nonce_lo_val = nonce_lo_data[0];
  auto nonce_hi_tmp = nonce_hi_data[0];
  auto nonce_lo_tmp = nonce_lo_data[0];

  idx_t index = 0;
  while (index < size) {
    nonce_hi_tmp = nonce_hi_data[index];
    nonce_lo_tmp = nonce_lo_data[index];
    if (nonce_hi_val == nonce_hi_data[index] && nonce_lo_val == nonce_lo_data[index]) {
      index++;
      continue;
    }
    break;
  }

  if (index < size) {
    return false;
  }

  return true;
}


template <typename T>
void DecryptPerValue(uint64_t nonce_hi_data, uint32_t *nonce_lo_data, uint32_t *counter_vec_data,
                     uint16_t *cipher_vec_data, string_t *value_vec_data, uint64_t size, Vector &result,
                     VCryptFunctionLocalState &lstate, EncryptionState &encryption_state, const string &key) {

  ValidityMask &result_validity = FlatVector::Validity(result);
  result.SetVectorType(VectorType::FLAT_VECTOR);
  auto result_data = FlatVector::GetData<T>(result);

  uint32_t i = 0;

  // todo; fix
  while (nonce_lo_data[i] == lstate.iv[2]) {
    i++;
  }

  lstate.to_process_batch = i;

  for (uint32_t j = 0; j < size; j++) {
    if (lstate.counter != counter_vec_data[j]) {
      if (lstate.counter + 1 != counter_vec_data[j]) {
        // case: if counter is not sequential
        // copy delta to last 4 bytes of iv
        lstate.iv[3] = counter_vec_data[j] * (BATCH_SIZE * sizeof(T) / 16);
        // (re)initialize encryption state
        encryption_state.InitializeDecryption(
            reinterpret_cast<const_data_ptr_t>(lstate.iv), 16,
            reinterpret_cast<const string *>(&key));
      }

      lstate.counter = counter_vec_data[j];

      // todo; cache the decrypted plaintext
      encryption_state.Process(
          reinterpret_cast<const_data_ptr_t>(value_vec_data[j].GetData()),
          lstate.batch_size_in_bytes,
          reinterpret_cast<unsigned char *>(lstate.buffer_p),
          lstate.batch_size_in_bytes);

      // copy first 64 bits of plaintext to uncipher the cipher
      uint64_t plaintext_bytes;

      // if cipher != seq then it's not in order and values need to be scattered
      memcpy(&plaintext_bytes, lstate.buffer_p, sizeof(uint64_t));
      // do already multiplication here

      // count all similar counter values (optimize?)
      auto seq_size = 0;
      while (lstate.counter == counter_vec_data[j]) {
        seq_size++;
        j++;
      }

      uint32_t offset = 0;
      if (seq_size == lstate.batch_size) {
        // all values are in the same batch
        // copy the decrypted data to the result vector
        for (uint32_t i = 0; i < seq_size; i++) {
          // is this internally stored as 32 bits?
          result_data[lstate.index] = Load<T>(lstate.buffer_p + offset);
          // memcpy(result_data + offset_result, lstate.buffer_p + offset_buffer + result_type_size, result_type_size);

#ifdef DEBUG
          T temp = Load<T>(lstate.buffer_p + offset);
          auto check = result_data[lstate.index];
          D_ASSERT(temp == check);
#endif
          offset += sizeof(T);
          lstate.index++;
        }
      } else {
        // case: values are in same batch but not in original order... (how to check?) case: part of values are in the same batch or values are in different batches
        uint16_t position = UnMaskCipher(cipher_vec_data[j], &plaintext_bytes);
        result_data[lstate.index] =
            Load<T>(lstate.buffer_p + position * sizeof(T));
        lstate.index++;
      }
      return;
    }
  }
}

template <typename T>
void DecryptFromEtype(Vector &input_vector, uint64_t size,
                      ExpressionState &state, Vector &result) {

  // todo; cache decrypted texts

  // TODO: check validity when storing decrypted values
  ValidityMask &result_validity = FlatVector::Validity(result);
  result.SetVectorType(VectorType::FLAT_VECTOR);
  auto result_data = FlatVector::GetData<T>(result);

  // local, vcrypt (global) and encryption state
  auto &lstate = VCryptFunctionLocalState::ResetAndGet(state);
  auto vcrypt_state = VCryptBasicFun::GetVCryptState(state);
  auto encryption_state = VCryptBasicFun::GetEncryptionState(state);
  auto key = VCryptBasicFun::GetKey(state);

  D_ASSERT(input_vector.GetType().id() == LogicalTypeId::STRUCT);

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

  UnifiedVectorFormat value_vec_u;
  value_vec->ToUnifiedFormat(size, value_vec_u);
  auto value_vec_data = FlatVector::GetData<string_t>(*value_vec);

  auto nonce_hi_data = FlatVector::GetData<uint64_t>(*nonce_hi);
  auto nonce_lo_data = FlatVector::GetData<uint32_t>(*nonce_lo);

  lstate.to_process_total = size;

  if (!CheckNonce(*nonce_hi, *nonce_lo, size)) {
    // nonce is not sequential, go to per value implementation
    throw NotImplementedException("Non-sequential nonce not yet supported");
  }

  auto counter_vec_data = FlatVector::GetData<uint32_t>(*counter_vec);

  // assign the right parts of the nonce and counter to iv
  lstate.iv[0] = static_cast<uint32_t>(nonce_hi_data[0] >> 32);
  ;
  lstate.iv[1] = static_cast<uint32_t>(nonce_hi_data[0] & 0xFFFFFFFF);
  lstate.iv[2] = nonce_lo_data[0];
  lstate.iv[3] = counter_vec_data[0];

  idx_t current_batch = 0;
  uint32_t total_batches = floor(size / lstate.batch_size);
  idx_t current_index = 0;

  while (current_batch < total_batches) {
    for (idx_t j = 0; j < lstate.batch_size; j++) {
      // check if the counter is sequential
      if (counter_vec_data[current_index] ==
          counter_vec_data[current_index + j]) {
        continue;
      }
      // if not sequential go to other implementation
      // to do: go to per-value implementation
      throw NotImplementedException("Non-sequential nonce not yet supported");
      break;
    }
    current_index += lstate.batch_size;
    current_batch++;
  }

  // case; if values in vector < standard batch size
  if (lstate.to_process_total < BATCH_SIZE) {
    lstate.batch_size = lstate.to_process_total;
  }

  // vectorized implementation for sequential counter
  lstate.batch_size_in_bytes = sizeof(T) * BATCH_SIZE;
  auto total_size = sizeof(T) * size;

  // initialize encryption
  encryption_state->InitializeDecryption(
      reinterpret_cast<const_data_ptr_t>(lstate.iv), 16,
      reinterpret_cast<const string *>(key));

  // decrypt the whole vector at once
  // does not work because strings are not aligned
#if 0
  encryption_state->Process(
        reinterpret_cast<const_data_ptr_t>(value_vec_data[0].GetData()),
        total_size,
        reinterpret_cast<unsigned char *>(lstate.buffer_p),
        total_size);
#endif

#ifdef DEBUG
  // check data pointer
  const char *data_ptr;
  uint32_t k = 0;
  while (k < size) {
    data_ptr = value_vec_data[k].GetData();
    k += 128;
  }
#endif

  // decrypt vectors per batch and store per batch
  for (idx_t index = 0; index < total_batches; index++) {
    auto data_size = value_vec_data[index].GetSize();

    // decrypt each batch
    encryption_state->Process(
        reinterpret_cast<const_data_ptr_t>(
            value_vec_data[index].GetDataWriteable()),
        data_size, reinterpret_cast<unsigned char *>(lstate.buffer_p),
        data_size);

    // todo; check validity of records before storing
    uint32_t offset = 0;
    for (uint32_t i = 0; i < lstate.batch_size; i++) {
      // read and store all values in vector
      result_data[lstate.index] = Load<T>(lstate.buffer_p + offset);

#ifdef DEBUG
      T temp = Load<T>(lstate.buffer_p + offset);
      auto check = result_data[lstate.index];
      D_ASSERT(temp == check);
#endif

#if 0
    if (i % 128 == 0){
      //break
      auto x = 1;
    }
#endif

      offset += sizeof(T);
      lstate.index++;
    }

    lstate.to_process_total -= lstate.batch_size;

    if (lstate.to_process_total < BATCH_SIZE) {
      lstate.batch_size = lstate.to_process_total;
    }

  }
}


static void DecryptDataVectorized(DataChunk &args, ExpressionState &state,
                                  Vector &result) {

  auto size = args.size();
  auto &input_vector = args.data[0];

  // derive TypeID from the input vector
  auto &children = StructVector::GetEntries(input_vector);
  auto &type_vec = children[5];
  UnifiedVectorFormat type_vec_u;
  type_vec->ToUnifiedFormat(size, type_vec_u);
  auto type_vec_data = FlatVector::GetData<uint8_t>(*type_vec);
  uint8_t type_id = static_cast<uint8_t>(type_vec_data[0]);
  auto vector_type = LogicalTypeId(type_id);

    switch (vector_type) {
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
    case LogicalTypeId::VARCHAR:
    return DecryptFromEtype<string_t>(input_vector, size, state, result);

    default:
      throw NotImplementedException("Unsupported type for decryption");
    }
}

ScalarFunctionSet GetDecryptionVectorizedFunction() {
  ScalarFunctionSet set("decrypt_vectorized");

  // todo fix the right return type
  set.AddFunction(ScalarFunction(
      {LogicalType::STRUCT({{"nonce_hi", LogicalType::UBIGINT},
                            {"nonce_lo", LogicalType::UBIGINT},
                            {"counter", LogicalType::UINTEGER},
                            {"cipher", LogicalType::UINTEGER},
                            {"value", LogicalType::BLOB},
                            {"type", LogicalType::TINYINT}}),
       LogicalType::VARCHAR}, LogicalType::BIGINT,
      DecryptDataVectorized, EncryptFunctionData::EncryptBind, nullptr, nullptr, VCryptFunctionLocalState::Init));

  return set;
}

//------------------------------------------------------------------------------
// Register functions
//------------------------------------------------------------------------------

void CoreScalarFunctions::RegisterDecryptVectorizedScalarFunction(
    DatabaseInstance &db) {
  ExtensionUtil::RegisterFunction(db, GetDecryptionVectorizedFunction());
}
} // namespace core
} // namespace simple_encryption

