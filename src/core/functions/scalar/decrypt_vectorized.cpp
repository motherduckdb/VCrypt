#define DUCKDB_EXTENSION_MAIN

#include "vcrypt/core/functions/common.hpp"
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
#include "vcrypt/core/types.hpp"

#include <duckdb/parser/parsed_data/create_scalar_function_info.hpp>

#include "vcrypt_state.hpp"
#include "vcrypt/core/functions/common.hpp"
#include "vcrypt/core/functions/scalar.hpp"
#include "vcrypt/core/functions/secrets.hpp"
#include "vcrypt/core/functions/scalar/encrypt.hpp"
#include "vcrypt/core/functions/function_data/encrypt_function_data.hpp"

namespace vcrypt {

namespace core {

uint16_t UnMaskCipher(uint16_t cipher, uint64_t *plaintext_bytes) {

#if 0
    const uint64_t prime = 10251357202697351;
    auto const a_plaintext = plaintext_bytes + 1;
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
#endif
  return cipher;
}

inline void CacheAndSetNonce(VCryptFunctionLocalState &lstate, uint64_t nonce_hi, uint64_t nonce_lo) {
  if (lstate.nonce_hi == nonce_hi && lstate.nonce_lo == nonce_lo) {
    return;
  }

  lstate.nonce_hi = nonce_hi;
  lstate.nonce_lo = nonce_lo;

  lstate.iv[0] = static_cast<uint32_t>(nonce_hi >> 32);
  lstate.iv[1] = static_cast<uint32_t>(nonce_hi & 0xFFFFFFFF);
  lstate.iv[2] = static_cast<uint32_t>(nonce_lo);
}

inline bool CheckNonceSimilarity(const SelectionVector *nonce_hi_u, const SelectionVector *nonce_lo_u, const ValidityMask &result_validity,
                     const uint64_t *nonce_hi_data, const uint64_t *nonce_lo_data, size_t size) {

    auto hi_idx = nonce_hi_u->get_index(0);
    auto lo_idx = nonce_lo_u->get_index(0);
    uint64_t nonce_hi_val = nonce_hi_data[hi_idx];
    uint64_t nonce_lo_val = nonce_lo_data[lo_idx];

    for (idx_t i = 1; i < size; i++) {
      if (!result_validity.RowIsValid(i)) {
        continue;
      }
      hi_idx = nonce_hi_u->get_index(i);
      lo_idx = nonce_lo_u->get_index(i);

      if (nonce_hi_data[hi_idx] != nonce_hi_val ||
          nonce_lo_data[lo_idx] != nonce_lo_val) {
        return false;
      }
    }
    return true;
}


template <typename T>
inline void DecryptSingleValue(uint32_t ctr, uint16_t cpr,
                        string_t value, T *result_data,
                        VCryptFunctionLocalState &lstate, const string &key,
                        uint32_t index) {

  lstate.ResetIV<T>(ctr);

  lstate.encryption_state->InitializeDecryption(
      reinterpret_cast<const_data_ptr_t>(lstate.iv), 16,
      reinterpret_cast<const string *>(&key));

  lstate.encryption_state->Process(
      reinterpret_cast<const_data_ptr_t>(value.GetData()),
      BATCH_SIZE * sizeof(T),
      reinterpret_cast<unsigned char *>(lstate.buffer_p),
      BATCH_SIZE * sizeof(T));

#if 0
    // copy first 64 bits of plaintext to uncipher the cipher
    uint64_t plaintext_bytes;

    // if cipher != seq then it's not in order and values need to be scattered
    memcpy(&plaintext_bytes, lstate.buffer_p, sizeof(uint64_t));

    // Get position from cipher
    uint16_t position = UnMaskCipher(cipher_value, &plaintext_bytes);
#endif

  // Load data into result vector
  result_data[index] = Load<T>(lstate.buffer_p + (cpr * sizeof(T)));
}

template <typename T>
inline void DecryptSingleValueVariable(uint32_t ctr, uint16_t cpr,
                               string_t value, Vector &result, T *result_data,
                               VCryptFunctionLocalState &lstate, const string &key,
                               uint32_t index) {

  auto batch_size_stored = value.GetSize();

  if (batch_size_stored > lstate.max_buffer_size) {
    // reset buffer is size is exceeded
    lstate.arena.Reset();
    lstate.buffer_p = (data_ptr_t)lstate.arena.Allocate(batch_size_stored);
    lstate.max_buffer_size = batch_size_stored;
  }

  lstate.ResetIV<T>(ctr);

  lstate.encryption_state->InitializeDecryption(
      reinterpret_cast<const_data_ptr_t>(lstate.iv), 16,
      reinterpret_cast<const string *>(&key));

  lstate.encryption_state->Process(
      reinterpret_cast<const_data_ptr_t>(value.GetData()),
      batch_size_stored, reinterpret_cast<unsigned char *>(lstate.buffer_p),
      batch_size_stored);

  auto base_ptr = lstate.buffer_p;
  auto vcrypt_version = Load<uint8_t>(lstate.buffer_p);

  // VCrypt type byte + 8 bytes * BATCH_SIZE cpr
  auto metadata_len = 1 + 8 * BATCH_SIZE;
  auto current_offset = (cpr == 0) ? metadata_len : Load<uint64_t>(base_ptr + 1 + ((cpr - 1) * sizeof(uint64_t)));
  auto next_offset = Load<uint64_t>(base_ptr + 1 + (cpr * sizeof(uint64_t)));
  auto length = next_offset - current_offset;

  result_data[index] = StringVector::EmptyString(result, length);
  memcpy(result_data[index].GetDataWriteable(), base_ptr + current_offset, length);
  result_data[index].Finalize();

#ifdef DEBUG
  auto res = result_data[index];
#endif
}


template <typename T>
inline void DecryptDataFixedSize(const SelectionVector *nonce_hi_u, const SelectionVector *nonce_lo_u,
                                  const uint64_t *nonce_hi_data, const uint64_t *nonce_lo_data,
                                  const ValidityMask &result_validity, const UnifiedVectorFormat &counter_vec_u,
                                  const UnifiedVectorFormat &cipher_vec_u, const UnifiedVectorFormat &value_vec_u,
                                  Vector &result, VCryptFunctionLocalState &lstate, const string &key,
                                  bool same_nonce, size_t size) {

  auto result_data = FlatVector::GetData<T>(result);

  uint32_t ctr;
  uint16_t cpr;
  string_t val;
  auto ctr_data = UnifiedVectorFormat::GetData<uint32_t>(counter_vec_u);
  auto cpr_data = UnifiedVectorFormat::GetData<uint16_t>(cipher_vec_u);
  auto val_data = UnifiedVectorFormat::GetData<string_t>(value_vec_u);

  for (uint32_t i = 0; i < size; i++) {
    if (!result_validity.RowIsValid(i)) {
      continue;
    }

    ctr = ctr_data[counter_vec_u.sel->get_index(i)];
    cpr = cpr_data[cipher_vec_u.sel->get_index(i)];
    val = val_data[value_vec_u.sel->get_index(i)];

#ifdef DEBUG
    T res;
#endif

    if (same_nonce && ctr == lstate.counter && (memcmp(lstate.prefix, val.GetPrefix(), 4) == 0)) {
      result_data[i] = Load<T>(lstate.buffer_p + (cpr * sizeof(T)));
#ifdef DEBUG
      res = result_data[i];

#endif
      continue;
    }

    if (!same_nonce) {
      CacheAndSetNonce(lstate, nonce_hi_data[nonce_hi_u->get_index(i)], nonce_lo_data[nonce_lo_u->get_index(i)]);
    }

    memcpy(lstate.prefix, val.GetPrefix(), 4);
    lstate.counter = ctr;
    DecryptSingleValue<T>(ctr, cpr, val, result_data, lstate, key, i);
  }
}

template <typename T>
inline void DecryptDataVariableSize(const SelectionVector *nonce_hi_u, const SelectionVector *nonce_lo_u,
                             const uint64_t *nonce_hi_data, const uint64_t *nonce_lo_data,
                             const ValidityMask &result_validity, const UnifiedVectorFormat &counter_vec_u,
                             const UnifiedVectorFormat &cipher_vec_u, const UnifiedVectorFormat &value_vec_u,
                             Vector &result, VCryptFunctionLocalState &lstate, const string &key,
                             bool same_nonce, size_t size) {

  auto result_data = FlatVector::GetData<T>(result);

  uint32_t ctr;
  uint16_t cpr;
  string_t val;

  auto ctr_data = UnifiedVectorFormat::GetData<uint32_t>(counter_vec_u);
  auto cpr_data = UnifiedVectorFormat::GetData<uint16_t>(cipher_vec_u);
  auto val_data = UnifiedVectorFormat::GetData<string_t>(value_vec_u);

  for (uint32_t i = 0; i < size; i++) {
    if (!result_validity.RowIsValid(i)) {
      continue;
    }

    ctr = ctr_data[counter_vec_u.sel->get_index(i)];
    cpr = cpr_data[cipher_vec_u.sel->get_index(i)];
    val = val_data[value_vec_u.sel->get_index(i)];

    if (same_nonce && ctr == lstate.counter && (memcmp(lstate.prefix, val.GetPrefix(), 4) == 0)) {
      auto metadata_len = 1 + 8 * BATCH_SIZE;
      auto current_offset = (cpr == 0) ? metadata_len : Load<uint64_t>(lstate.buffer_p + 1 + ((cpr - 1) * sizeof(uint64_t)));
      auto next_offset = Load<uint64_t>(lstate.buffer_p + 1 + (cpr * sizeof(uint64_t)));
      auto length = next_offset - current_offset;

      result_data[i] = StringVector::EmptyString(result, length);
      memcpy(result_data[i].GetDataWriteable(), lstate.buffer_p + current_offset, length);
      result_data[i].Finalize();

#ifdef DEBUG
      auto res = result_data[i];
#endif
      continue;
    }

    if (!same_nonce) {
      CacheAndSetNonce(lstate, nonce_hi_data[nonce_hi_u->get_index(i)], nonce_lo_data[nonce_lo_u->get_index(i)]);
    }

    memcpy(lstate.prefix, val.GetPrefix(), 4);
    lstate.counter = ctr;

    DecryptSingleValueVariable<T>(ctr, cpr, val, result, result_data, lstate, key, i);
  }
}


template <typename T>
void DecryptPerValueVariable(uint64_t *nonce_hi_data, uint64_t *nonce_lo_data,
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
    if (batch_size_stored > lstate.max_buffer_size) {
      // we might need to resize the buffer
      lstate.arena.Reset();
      lstate.buffer_p = (data_ptr_t)lstate.arena.Allocate(batch_size_stored);
      lstate.max_buffer_size = batch_size_stored;
    }

    lstate.encryption_state->Process(
        reinterpret_cast<const_data_ptr_t>(value_vec_data[i].GetData()),
        batch_size_stored, reinterpret_cast<unsigned char *>(lstate.buffer_p),
        batch_size_stored);

    auto base_ptr = lstate.buffer_p;
    auto vcrypt_version = Load<uint8_t>(lstate.buffer_p);
    auto cipher = cipher_vec_data[i];

    // VCrypt type byte + 8 bytes * cipher_value
    auto metadata_len = 1025;
    auto current_offset = (cipher == 0) ? metadata_len : Load<uint64_t>(base_ptr + 1 + ((cipher - 1) * sizeof(uint64_t)));
    auto next_offset =
        Load<uint64_t>(base_ptr + 1 + (cipher * sizeof(uint64_t)));
    auto length = next_offset - current_offset;

    result_data[i] = StringVector::EmptyString(result, length);
    memcpy(result_data[i].GetDataWriteable(), base_ptr + current_offset, length);
    result_data[i].Finalize();
  }
}

static void DecryptData(DataChunk &args, ExpressionState &state,
                                  Vector &result) {
  auto size = args.size();
  auto &input_vector = args.data[0];

  auto input_type = input_vector.GetType();
  auto &mods = input_type.GetExtensionInfo()->modifiers;
  auto vector_type = LogicalTypeId(mods[0].value.GetValue<int8_t>());

  // local, vcrypt (global) and encryption state
  auto &lstate = VCryptFunctionLocalState::ResetAndGet(state);
  auto key = VCryptBasicFun::GetKey(state);

  auto &children = StructVector::GetEntries(input_vector);
  auto &nonce_hi = children[0];
  auto &nonce_lo = children[1];
  auto &counter_vec = children[2];
  auto &cipher_vec = children[3];
  auto &value_vec = children[4];

  UnifiedVectorFormat nonce_hi_u;
  UnifiedVectorFormat nonce_lo_u;
  UnifiedVectorFormat counter_vec_u;
  UnifiedVectorFormat cipher_vec_u;
  UnifiedVectorFormat value_vec_u;

  nonce_hi->ToUnifiedFormat(size, nonce_hi_u);
  nonce_lo->ToUnifiedFormat(size, nonce_lo_u);
  counter_vec->ToUnifiedFormat(size, counter_vec_u);
  cipher_vec->ToUnifiedFormat(size, cipher_vec_u);
  value_vec->ToUnifiedFormat(size, value_vec_u);

  // -------- Set and Check Nonce Similarity --------

  auto nonce_hi_data = UnifiedVectorFormat::GetData<uint64_t>(nonce_hi_u);
  auto nonce_lo_data = UnifiedVectorFormat::GetData<uint64_t>(nonce_lo_u);

  bool same_nonce = true;
  if (!(nonce_lo->GetVectorType() == VectorType::CONSTANT_VECTOR &&
        nonce_hi->GetVectorType() == VectorType::CONSTANT_VECTOR)){

    same_nonce = CheckNonceSimilarity(nonce_hi_u.sel, nonce_lo_u.sel, FlatVector::Validity(result),
                                      nonce_hi_data, nonce_lo_data, size);
  }

  CacheAndSetNonce(lstate, nonce_hi_data[nonce_hi_u.sel->get_index(0)],
                   nonce_lo_data[nonce_lo_u.sel->get_index(0)]);

  // -------- Decrypt Functions --------

  switch (vector_type) {
  case LogicalTypeId::TINYINT:
  case LogicalTypeId::UTINYINT:
    return DecryptDataFixedSize<int8_t>(nonce_hi_u.sel, nonce_lo_u.sel, nonce_hi_data, nonce_lo_data, FlatVector::Validity(result),
                                counter_vec_u, cipher_vec_u, value_vec_u, result,
                                lstate, *key, same_nonce, size);
  case LogicalTypeId::SMALLINT:
  case LogicalTypeId::USMALLINT:
    return DecryptDataFixedSize<int16_t>(nonce_hi_u.sel, nonce_lo_u.sel, nonce_hi_data, nonce_lo_data, FlatVector::Validity(result),
                                         counter_vec_u, cipher_vec_u, value_vec_u, result,
                                         lstate, *key, same_nonce, size);
  case LogicalTypeId::INTEGER:
    return DecryptDataFixedSize<int32_t>(nonce_hi_u.sel, nonce_lo_u.sel, nonce_hi_data, nonce_lo_data, FlatVector::Validity(result),
                                         counter_vec_u, cipher_vec_u, value_vec_u, result,
                                         lstate, *key, same_nonce, size);
  case LogicalTypeId::UINTEGER:
    return DecryptDataFixedSize<uint32_t>(nonce_hi_u.sel, nonce_lo_u.sel, nonce_hi_data, nonce_lo_data, FlatVector::Validity(result),
                                          counter_vec_u, cipher_vec_u, value_vec_u, result,
                                          lstate, *key, same_nonce, size);
  case LogicalTypeId::BIGINT:
    return DecryptDataFixedSize<int64_t>(nonce_hi_u.sel, nonce_lo_u.sel, nonce_hi_data, nonce_lo_data, FlatVector::Validity(result),
                                         counter_vec_u, cipher_vec_u, value_vec_u, result,
                                         lstate, *key, same_nonce, size);
  case LogicalTypeId::UBIGINT:
    return DecryptDataFixedSize<uint64_t>(nonce_hi_u.sel, nonce_lo_u.sel, nonce_hi_data, nonce_lo_data, FlatVector::Validity(result),
                                          counter_vec_u, cipher_vec_u, value_vec_u, result,
                                          lstate, *key, same_nonce, size);
  case LogicalTypeId::FLOAT:
    return DecryptDataFixedSize<float>(nonce_hi_u.sel, nonce_lo_u.sel, nonce_hi_data, nonce_lo_data, FlatVector::Validity(result),
                                       counter_vec_u, cipher_vec_u, value_vec_u, result,
                                       lstate, *key, same_nonce, size);
  case LogicalTypeId::DOUBLE:
    return DecryptDataFixedSize<double>(nonce_hi_u.sel, nonce_lo_u.sel, nonce_hi_data, nonce_lo_data, FlatVector::Validity(result),
                                        counter_vec_u, cipher_vec_u, value_vec_u, result,
                                        lstate, *key, same_nonce, size);
  case LogicalTypeId::VARCHAR:
  case LogicalTypeId::CHAR:
  case LogicalTypeId::BLOB:
  case LogicalTypeId::BIT:
  case LogicalTypeId::VARINT:
    return DecryptDataVariableSize<string_t>(nonce_hi_u.sel, nonce_lo_u.sel, nonce_hi_data, nonce_lo_data, FlatVector::Validity(result),
                                             counter_vec_u, cipher_vec_u, value_vec_u, result,
                                             lstate, *key, same_nonce, size);
  default:
    throw NotImplementedException("Unsupported type for decryption");
  }
}


ScalarFunctionSet GetDecryptionVectorizedFunction() {
  ScalarFunctionSet set("decrypt");

  for (auto &type : EncryptionTypes::IsAvailable()) {
    set.AddFunction(ScalarFunction(
        {EncryptionTypes::GetEncryptionType(type.id()), LogicalType::VARCHAR},
        type, DecryptData, EncryptFunctionData::EncryptBind, nullptr,
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
} // namespace vcrypt

