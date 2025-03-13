#define DUCKDB_EXTENSION_MAIN

#include "simple_encryption/core/functions/common.hpp"
#include "duckdb/main/extension_util.hpp"
#include "duckdb/main/connection_manager.hpp"
#include "duckdb/main/secret/secret_manager.hpp"
#include "duckdb/function/scalar_function.hpp"
#include "duckdb/common/types.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/encryption_state.hpp"
#include "duckdb/common/vector_operations/generic_executor.hpp"
#include "duckdb/planner/expression/bound_function_expression.hpp"
#include "../etype/encrypted_type.hpp"
#include "simple_encryption/core/types.hpp"

#include <duckdb/parser/parsed_data/create_scalar_function_info.hpp>

#include "simple_encryption_state.hpp"
#include "simple_encryption/core/functions/common.hpp"
#include "simple_encryption/core/functions/scalar.hpp"
#include "simple_encryption/core/functions/secrets.hpp"
#include "simple_encryption/core/functions/scalar/encrypt.hpp"
#include "simple_encryption/core/functions/function_data/encrypt_function_data.hpp"

namespace simple_encryption {

namespace core {

uint16_t UnMaskCipher(uint16_t cipher, uint64_t *plaintext_bytes) {
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

  idx_t index = 0;
  while (index < size) {
    if (nonce_hi_val == nonce_hi_data[index] &&
        nonce_lo_val == nonce_lo_data[index]) {
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

bool CheckSequenceInDict(SelectionVector &dict_sel_value, uint64_t size) {
  idx_t child_idx;
  idx_t prev_idx = dict_sel_value.get_index(0);
  uint16_t count = 0;

  for (idx_t i = 0; i < size; i++) {
    if (!count) {
      prev_idx = dict_sel_value.get_index(i);
    }
    child_idx = dict_sel_value.get_index(i);

    if (child_idx != prev_idx) {
      // not all values are in the same batch
      return false;
    }
    count++;

    if (count == BATCH_SIZE) {
      count = 0;
    }
  }
  return true;
}

template <typename T>
void DecryptSingleValue(uint32_t counter_value, uint16_t cipher_value,
                        string_t value, T *result_data,
                        VCryptFunctionLocalState &lstate, const string &key,
                        uint32_t index) {

  // TODO; create caching mechanism in the local state so that you not have to reencrypt all data reset IV and initialize encryption state
  lstate.ResetIV<T>(counter_value);
  lstate.encryption_state->InitializeDecryption(
      reinterpret_cast<const_data_ptr_t>(lstate.iv), 16,
      reinterpret_cast<const string *>(&key));

  // decrypt the value into buffer_p
  lstate.encryption_state->Process(
      reinterpret_cast<const_data_ptr_t>(value.GetData()),
      BATCH_SIZE * sizeof(T),
      reinterpret_cast<unsigned char *>(lstate.buffer_p),
      BATCH_SIZE * sizeof(T));

  auto *base_ptr = lstate.buffer_p;
  auto first_val = Load<T>(lstate.buffer_p);

#if 0
    // copy first 64 bits of plaintext to uncipher the cipher
    uint64_t plaintext_bytes;

    // if cipher != seq then it's not in order and values need to be scattered
    memcpy(&plaintext_bytes, lstate.buffer_p, sizeof(uint64_t));

    // Get position from cipher
    uint16_t position = UnMaskCipher(cipher_value, &plaintext_bytes);
#endif

  //    memcpy(&result_data[index], base_ptr + (cipher_value * sizeof(T)), sizeof(T));
  // Load data into result vector
  auto offset = cipher_value * sizeof(T);
  result_data[index] = Load<T>(base_ptr + (cipher_value * sizeof(T)));
}

template <typename T>
void DecryptPerValue(uint64_t *nonce_hi_data, uint32_t *nonce_lo_data,
                     uint32_t *counter_vec_data, uint16_t *cipher_vec_data,
                     string_t *value_vec_data, uint64_t size, T *result_data,
                     VCryptFunctionLocalState &lstate,
                     shared_ptr<EncryptionState> &encryption_state,
                     const string &key, bool same_nonce) {

  // create cache here if counter is similar
  // decrypt every value in the vector separately
  for (uint32_t i = 0; i < size; i++) {
    if (!same_nonce) {
      // assign the right parts of the nonce and counter to iv
      lstate.iv[0] = static_cast<uint32_t>(nonce_hi_data[i] >> 32);
      lstate.iv[1] = static_cast<uint32_t>(nonce_hi_data[i] & 0xFFFFFFFF);
      lstate.iv[2] = nonce_lo_data[i];
    }

    DecryptSingleValue<T>(counter_vec_data[i], cipher_vec_data[i],
                          value_vec_data[i], result_data, lstate, key, i);
  }
}

template <typename T>
void DecryptPerValueVariable(uint64_t *nonce_hi_data, uint32_t *nonce_lo_data,
                             uint32_t *counter_vec_data,
                             uint16_t *cipher_vec_data,
                             string_t *value_vec_data, uint64_t size,
                             T *result_data, VCryptFunctionLocalState &lstate,
                             shared_ptr<EncryptionState> &encryption_state,
                             const string &key, bool same_nonce,
                             Vector &result) {

  for (uint32_t i = 0; i < size; i++) {
    if (!same_nonce) {
      // assign the right parts of the nonce and counter to iv
      lstate.iv[0] = static_cast<uint32_t>(nonce_hi_data[i] >> 32);
      lstate.iv[1] = static_cast<uint32_t>(nonce_hi_data[i] & 0xFFFFFFFF);
      lstate.iv[2] = nonce_lo_data[i];
    }

    // reset IV and initialize encryption state
    lstate.ResetIV<T>(counter_vec_data[i]);
    lstate.encryption_state->InitializeDecryption(
        reinterpret_cast<const_data_ptr_t>(lstate.iv), 16,
        reinterpret_cast<const string *>(&key));

    auto batch_size_stored = value_vec_data[i].GetSize();
    // reset buffer is size is exceeded
    if (batch_size_stored > lstate.max_buffer_size) {
      lstate.arena.Reset();
      lstate.buffer_p = (data_ptr_t)lstate.arena.Allocate(batch_size_stored);
      lstate.max_buffer_size = batch_size_stored;
    }

    // we encrypt into a buffer
    lstate.encryption_state->Process(
        reinterpret_cast<const_data_ptr_t>(value_vec_data[i].GetData()),
        batch_size_stored, reinterpret_cast<unsigned char *>(lstate.buffer_p),
        batch_size_stored);

    auto base_ptr = lstate.buffer_p;
    auto vcrypt_version = Load<uint8_t>(lstate.buffer_p);
    auto cipher = cipher_vec_data[i];

    // VCrypt type byte + 8 bytes * cipher_value
    auto metadata_len = 1025;
    auto current_offset =
        (cipher == 0)
            ? metadata_len
            : Load<uint64_t>(base_ptr + 1 + ((cipher - 1) * sizeof(uint64_t)));
    auto next_offset =
        Load<uint64_t>(base_ptr + 1 + (cipher * sizeof(uint64_t)));
    auto length = next_offset - current_offset;

    result_data[i] = StringVector::EmptyString(result, length);
    memcpy(result_data[i].GetDataWriteable(), base_ptr + current_offset,
           length);
    result_data[i].Finalize();
  }
}

template <typename T>
void DecryptCompressedExecution(Vector &input_vector, uint64_t size,
                                ExpressionState &state, Vector &result) {

  // todo; cache first decrypted text
  // TODO: check validity when storing decrypted values
  ValidityMask &result_validity = FlatVector::Validity(result);
  result.SetVectorType(VectorType::FLAT_VECTOR);
  auto result_data = FlatVector::GetData<T>(result);

  // local, vcrypt (global) and encryption state
  auto &lstate = VCryptFunctionLocalState::ResetAndGet(state);
  ;
  auto vcrypt_state = VCryptBasicFun::GetVCryptState(state);
  auto key = VCryptBasicFun::GetKey(state);
  lstate.index = 0;

  D_ASSERT(input_vector.GetType().id() == LogicalTypeId::STRUCT);

  auto &children = StructVector::GetEntries(input_vector);
  auto &nonce_hi = children[0];
  auto &nonce_lo = children[1];
  auto &counter_vec = children[2];
  auto &cipher_vec = children[3];
  auto &value_vec = children[4];

  D_ASSERT(value_vec->GetType() == LogicalTypeId::BLOB);

  UnifiedVectorFormat counter_vec_u;
  UnifiedVectorFormat cipher_vec_u;
  counter_vec->ToUnifiedFormat(size, counter_vec_u);
  cipher_vec->ToUnifiedFormat(size, cipher_vec_u);
  auto counter_vec_data = FlatVector::GetData<uint32_t>(*counter_vec);
  auto cipher_vec_data = FlatVector::GetData<uint16_t>(*cipher_vec);

  uint32_t batch_size = BATCH_SIZE;

  if (size < BATCH_SIZE) {
    batch_size = size;
  }

  uint32_t batch_size_in_bytes = sizeof(T) * batch_size;
  uint64_t current_batch = 0;
  uint64_t total_batches = (size + batch_size - 1) / batch_size;
  idx_t current_index = 0;

  // ---------- Vectorized Decryption using Compressed Execution --------------

  // TODO; create new function here
  auto nonce_hi_value = FlatVector::GetData<uint64_t>(*nonce_hi)[0];
  auto nonce_lo_value = FlatVector::GetData<uint64_t>(*nonce_lo)[0];

  lstate.iv[0] = static_cast<uint32_t>(nonce_hi_value >> 32);
  lstate.iv[1] = static_cast<uint32_t>(nonce_hi_value & 0xFFFFFFFF);
  lstate.iv[2] = nonce_lo_value;

  // flatten the dictionary vector
  auto &value_vec_dict = DictionaryVector::Child(*value_vec);
  auto &dict_sel_value = DictionaryVector::SelVector(*value_vec);
  UnifiedVectorFormat value_vec_dict_u;
  value_vec_dict.ToUnifiedFormat(size, value_vec_dict_u);
  auto value_vec_dict_data = FlatVector::GetData<string_t>(value_vec_dict);

  // check if the selection vector is sequential
  if (!CheckSequenceInDict(dict_sel_value, size)) {
    // does this even occur?
    // go to caching last decrypted ciphertext implementation?
    // also, we ideally need to check if the cipher is correct...
    throw NotImplementedException("Nonce is constant, compressed execution, but no Sequential Dictionary");
  }

  // Create a separate function and inline
  auto to_process_total = size;
  to_process_total = size;

  // case; if values in vector < standard batch size
  if (to_process_total < BATCH_SIZE) {
    batch_size = to_process_total;
  }

  uint32_t base_idx = 0;
  auto to_process_batch = size;

  if (lstate.batch_nr == 0) {
    lstate.ResetIV<T>(counter_vec_data[0]);
    // initialize encryption state
    lstate.encryption_state->InitializeDecryption(
        reinterpret_cast<const_data_ptr_t>(lstate.iv), 16,
        reinterpret_cast<const string *>(key));
  }

  // we decrypt each batch independently
  for (uint32_t batch = 0; batch < total_batches; batch++) {
    const idx_t dict_idx = dict_sel_value.get_index(base_idx);

    lstate.encryption_state->Process(
        reinterpret_cast<const_data_ptr_t>(value_vec_dict_data[dict_idx].GetData()),
        batch_size_in_bytes,
        reinterpret_cast<unsigned char *>(result_data + base_idx),
        batch_size_in_bytes);

#ifdef DEBUG
    // TODO; cache last decrypted ciphertext
    uint64_t output_buf[sizeof(T) * BATCH_SIZE / 8];
    memcpy(&output_buf, result_data + base_idx, batch_size_in_bytes);
#endif

    base_idx += batch_size;

    // todo: create a separate inlined function
    if (to_process_batch > batch_size) {
      to_process_batch -= batch_size;
    } else {
      to_process_batch = 0;
      break;
    }

    if (to_process_batch < batch_size) {
      batch_size = to_process_batch;
      batch_size_in_bytes = to_process_batch * sizeof(T);
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
  lstate.index = 0;
  auto vcrypt_state = VCryptBasicFun::GetVCryptState(state);
  // auto encryption_state = VCryptBasicFun::GetEncryptionState(state);
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

  if (value_vec->GetVectorType() == VectorType::DICTIONARY_VECTOR) {
    if (nonce_hi->GetVectorType() == VectorType::CONSTANT_VECTOR &&
        nonce_lo->GetVectorType() == VectorType::CONSTANT_VECTOR) {
      DecryptCompressedExecution<T>(input_vector, size, state, result);
      return;
    }
    // go to a dict implementation?
  }

// ---------- flattened in memory decryption -----------

    UnifiedVectorFormat value_vec_u;
    value_vec->ToUnifiedFormat(size, value_vec_u);
    auto value_vec_data = FlatVector::GetData<string_t>(*value_vec);

    auto nonce_hi_data = FlatVector::GetData<uint64_t>(*nonce_hi);
    auto nonce_lo_data = FlatVector::GetData<uint32_t>(*nonce_lo);

    auto to_process_total = size;

    auto counter_vec_data = FlatVector::GetData<uint32_t>(*counter_vec);
    auto cipher_vec_data = FlatVector::GetData<uint16_t>(*cipher_vec);

    bool same_nonce = true;
    if (!CheckNonce(*nonce_hi, *nonce_lo, size)) {
      // nonce is not sequential, go to per value implementation (for now)
      same_nonce = false;
      DecryptPerValue<T>(nonce_hi_data, nonce_lo_data, counter_vec_data,
                         cipher_vec_data, value_vec_data, size, result_data,
                         lstate, lstate.encryption_state, *key, same_nonce);
      return;
    }

    // assign the right parts of the nonce and counter to iv
    lstate.iv[0] = static_cast<uint32_t>(nonce_hi_data[0] >> 32);
    lstate.iv[1] = static_cast<uint32_t>(nonce_hi_data[0] & 0xFFFFFFFF);
    lstate.iv[2] = nonce_lo_data[0];

    uint32_t batch_size = BATCH_SIZE;
    uint32_t batch_size_in_bytes = sizeof(T) * batch_size;
    uint64_t current_batch = 0;
    uint64_t total_batches = (size + batch_size - 1) / batch_size;
    idx_t current_index = 0;

    while (current_batch < total_batches) {
      for (idx_t j = 0; j < batch_size; j++) {
        if (counter_vec_data[current_index] ==
            counter_vec_data[current_index + j]) {
          continue;
        }

        DecryptPerValue<T>(nonce_hi_data, nonce_lo_data, counter_vec_data,
                           cipher_vec_data, value_vec_data, size, result_data,
                           lstate, lstate.encryption_state, *key, same_nonce);
        return;
        // TODO: implement partly-per-batch implementation
      }

      current_index += batch_size;
      current_batch++;
    }

    to_process_total = size;
    if (to_process_total < BATCH_SIZE) {
      batch_size = to_process_total;
    }

    if (lstate.batch_nr == 0) {
      lstate.ResetIV<T>(counter_vec_data[0]);
      // initialize encryption state
      lstate.encryption_state->InitializeDecryption(
          reinterpret_cast<const_data_ptr_t>(lstate.iv), 16,
          reinterpret_cast<const string *>(key));
    }

    // decrypt each block independently (pointers are not always aligned)
    uint32_t base_idx = 0;
    auto to_process_batch = size;

    for (uint32_t batch = 0; batch < total_batches; batch++) {

      lstate.encryption_state->Process(
          reinterpret_cast<const_data_ptr_t>(
              value_vec_data[base_idx].GetData()),
          batch_size_in_bytes,
          reinterpret_cast<unsigned char *>(result_data + base_idx),
          batch_size_in_bytes);

      base_idx += batch_size;

      // todo: optimize
      if (to_process_batch > batch_size) {
        to_process_batch -= batch_size;
      } else {
        to_process_batch = 0;
        break;
      }

      if (to_process_batch < batch_size) {
        batch_size = to_process_batch;
        batch_size_in_bytes = to_process_batch * sizeof(T);
      }
    }
    lstate.batch_nr += total_batches;
}


template <typename T>
void DecryptDataVariable(Vector &input_vector, uint64_t size,
                      ExpressionState &state, Vector &result) {
  // TODO: check validity when storing decrypted values
  ValidityMask &result_validity = FlatVector::Validity(result);
  result.SetVectorType(VectorType::FLAT_VECTOR);
  auto result_data = FlatVector::GetData<T>(result);

  // local, vcrypt (global) and encryption state
  auto &lstate = VCryptFunctionLocalState::ResetAndGet(state);
  lstate.index = 0;
  auto vcrypt_state = VCryptBasicFun::GetVCryptState(state);
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
  auto counter_vec_data = FlatVector::GetData<uint32_t>(*counter_vec);
  auto cipher_vec_data = FlatVector::GetData<uint16_t>(*cipher_vec);

  bool same_nonce = true;
  if (!CheckNonce(*nonce_hi, *nonce_lo, size)) {
    same_nonce = false;
    DecryptPerValueVariable<T>(nonce_hi_data, nonce_lo_data, counter_vec_data,
                       cipher_vec_data, value_vec_data, size, result_data,
                       lstate, lstate.encryption_state, *key, same_nonce, result);
    return;
  }

  // assign the right parts of the nonce and counter to iv
  lstate.iv[0] = static_cast<uint32_t>(nonce_hi_data[0] >> 32);
  lstate.iv[1] = static_cast<uint32_t>(nonce_hi_data[0] & 0xFFFFFFFF);
  lstate.iv[2] = nonce_lo_data[0];

  uint64_t current_batch = 0;
  uint16_t total_batches = (size + BATCH_SIZE - 1) / BATCH_SIZE;
  lstate.to_process = size;
  idx_t index = 0;
  uint32_t batch_size = BATCH_SIZE;

  if (lstate.to_process < BATCH_SIZE){
    batch_size = lstate.to_process;
  }

  index = 0;
  while (current_batch < total_batches) {
    for (idx_t j = 0; j < batch_size; j++) {
      // check if the counter is sequential
      if (counter_vec_data[index] == counter_vec_data[index + j]) {
        continue;
      }

      DecryptPerValueVariable<T>(nonce_hi_data, nonce_lo_data, counter_vec_data,
                                 cipher_vec_data, value_vec_data, size,
                                 result_data, lstate, lstate.encryption_state,
                                 *key, same_nonce, result);
      return;
    }

    // for every batch, the IV is reset due to rounding to the nearest 16-byte block
    lstate.ResetIV<T>(counter_vec_data[index]);
    // for every batch, reset the encryption state
    lstate.encryption_state->InitializeDecryption(
        reinterpret_cast<const_data_ptr_t>(lstate.iv), 16,
        reinterpret_cast<const string *>(key));

    // index 150 is too high
    auto batch_size_stored = value_vec_data[index].GetSize();
    auto metadata_ptr = value_vec_data[index].GetDataWriteable();
    data_ptr_t buffer_ptr = reinterpret_cast<data_ptr_t const>(
        value_vec_data[index].GetDataWriteable());

    // we decrypt in place
    lstate.encryption_state->Process(
        reinterpret_cast<const_data_ptr_t>(value_vec_data[index].GetData()),
        batch_size_stored, (data_ptr_t)value_vec_data[index].GetData(),
        batch_size_stored);

    uint8_t vcrypt_version =
        Load<uint8_t>(reinterpret_cast<const_data_ptr_t>(metadata_ptr));
    metadata_ptr++;

    // previous offset is metadata length (hardcoded for now)
    uint64_t prev_offset = 1025;
    uint64_t current_offset, length;
    buffer_ptr += prev_offset;

    for (uint8_t j = 0; j < batch_size; j++) {
      current_offset =
          Load<uint64_t>(reinterpret_cast<const_data_ptr_t>(metadata_ptr));
      D_ASSERT(current_offset > prev_offset);
      length = current_offset - prev_offset;

      result_data[index] = StringVector::EmptyString(result, length);
      memcpy(result_data[index].GetDataWriteable(), buffer_ptr, length);
      result_data[index].Finalize();

      buffer_ptr += length;
      prev_offset = current_offset;
      metadata_ptr += sizeof(uint64_t);
      index++;
    }

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

    current_batch++;
  }
}


static void DecryptDataVectorized(DataChunk &args, ExpressionState &state,
                                  Vector &result) {
  auto size = args.size();
  auto &input_vector = args.data[0];

  // TODO; put this in the lstate; which gets initialized upon calling a scalar function
  auto input_type = input_vector.GetType();
  auto &mods = input_type.GetExtensionInfo()->modifiers;
  auto vector_type = LogicalTypeId(mods[0].value.GetValue<int8_t>());

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
    return DecryptDataVariable<string_t>(input_vector, size, state, result);

    default:
      throw NotImplementedException("Unsupported type for decryption");
    }
}

ScalarFunctionSet GetDecryptionVectorizedFunction() {
  ScalarFunctionSet set("decrypt");

  for (auto &type : EncryptionTypes::IsAvailable()) {
    set.AddFunction(ScalarFunction(
        {EncryptionTypes::GetEncryptionType(type.id()), LogicalType::VARCHAR},
        type, DecryptDataVectorized, EncryptFunctionData::EncryptBind, nullptr,
        nullptr, VCryptFunctionLocalState::Init));
  }

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

