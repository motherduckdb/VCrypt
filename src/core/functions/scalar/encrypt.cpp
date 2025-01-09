#define DUCKDB_EXTENSION_MAIN

#define TEST_KEY "0123456789112345"

// what is the maximum size of biggest type in duckdb
#define MAX_BUFFER_SIZE 1024

#include "duckdb.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/types.hpp"
#include "duckdb/common/encryption_state.hpp"
#include "duckdb/function/scalar_function.hpp"
#include "duckdb/main/extension_util.hpp"
#include "mbedtls_wrapper.hpp"
#include <duckdb/parser/parsed_data/create_scalar_function_info.hpp>
#include "duckdb/common/types/blob.hpp"
#include "duckdb/main/connection_manager.hpp"
#include "duckdb/common/encryption_state.hpp"
#include "duckdb/main/client_context.hpp"

#include "simple_encryption_state.hpp"
#include "simple_encryption/core/functions/scalar.hpp"
#include "simple_encryption/core/functions/scalar/encrypt.hpp"
#include "duckdb/planner/expression/bound_function_expression.hpp"

namespace simple_encryption {
namespace core {

EncryptFunctionData& VCryptBasicFun::GetEncryptionBindInfo(ExpressionState &state) {
  auto &func_expr = (BoundFunctionExpression &)state.expr;
  return (EncryptFunctionData &)*func_expr.bind_info;
}

shared_ptr<VCryptState>
VCryptBasicFun::GetVCryptState(ExpressionState &state) {
  auto &info = VCryptBasicFun::GetEncryptionBindInfo(state);
  return info.context.registered_state->Get<VCryptState>(
      "simple_encryption");
}
// TODO; maybe pass by reference or so
string* VCryptBasicFun::GetKey(ExpressionState &state) {
  auto &info = VCryptBasicFun::GetEncryptionBindInfo(state);
  return &info.key;
}

shared_ptr<EncryptionState> VCryptBasicFun::GetEncryptionState(ExpressionState &state) {
  return VCryptBasicFun::GetVCryptState(state)->encryption_state;
}

shared_ptr<EncryptionUtil> GetEncryptionUtil(ExpressionState &state) {
  auto &func_expr = (BoundFunctionExpression &)state.expr;
  auto &info = (EncryptFunctionData &)*func_expr.bind_info;
  // get Database config
  auto &config = DBConfig::GetConfig(*info.context.db);
  return config.encryption_util;
}

shared_ptr<EncryptionState> InitializeCryptoState(ExpressionState &state) {
  auto encryption_state = GetEncryptionUtil(state);

  if (!encryption_state) {
    return duckdb_mbedtls::MbedTlsWrapper::AESGCMStateMBEDTLSFactory()
        .CreateEncryptionState();
  }

  return encryption_state->CreateEncryptionState();
}

template <typename T>
typename std::enable_if<
    std::is_integral<T>::value || std::is_floating_point<T>::value, T>::type
EncryptValue(EncryptionState *encryption_state, Vector &result,
             T plaintext_data, uint8_t *buffer_p) {
  // actually, you can just for process already give the pointer to the result,
  // thus skip buffer
  T encrypted_data;
  encryption_state->Process(
      reinterpret_cast<unsigned char *>(&plaintext_data), sizeof(T),
      reinterpret_cast<unsigned char *>(&encrypted_data), sizeof(T));
  return encrypted_data;
}

template <typename T>
typename std::enable_if<
    std::is_integral<T>::value || std::is_floating_point<T>::value, T>::type
DecryptValue(EncryptionState *encryption_state, Vector &result,
             T encrypted_data, uint8_t *buffer_p) {
  // actually, you can just for process already give the pointer to the result,
  // thus skip buffer
  T decrypted_data;
  encryption_state->Process(
      reinterpret_cast<unsigned char *>(&encrypted_data), sizeof(T),
      reinterpret_cast<unsigned char *>(&decrypted_data), sizeof(T));
  return decrypted_data;
}

// Handle string_t type and convert to Base64
template <typename T>
typename std::enable_if<std::is_same<T, string_t>::value, T>::type
EncryptValue(EncryptionState *encryption_state, Vector &result, T value,
             uint8_t *buffer_p) {

  // first encrypt the bytes of the string into a temp buffer_p
  auto input_data = data_ptr_t(value.GetData());
  auto value_size = value.GetSize();
  encryption_state->Process(input_data, value_size, buffer_p, value_size);

  // Convert the encrypted data to Base64
  auto encrypted_data =
      string_t(reinterpret_cast<const char *>(buffer_p), value_size);
  size_t base64_size = Blob::ToBase64Size(encrypted_data);

  // convert to Base64 into a newly allocated string in the result vector
  string_t base64_data = StringVector::EmptyString(result, base64_size);
  Blob::ToBase64(encrypted_data, base64_data.GetDataWriteable());

  return base64_data;
}

template <typename T>
typename std::enable_if<std::is_same<T, string_t>::value, T>::type
DecryptValue(EncryptionState *encryption_state, Vector &result, T base64_data,
             uint8_t *buffer_p) {

  // first encrypt the bytes of the string into a temp buffer_p
  size_t encrypted_size = Blob::FromBase64Size(base64_data);
  size_t decrypted_size = encrypted_size;
  Blob::FromBase64(base64_data, reinterpret_cast<data_ptr_t>(buffer_p),
                   encrypted_size);
  D_ASSERT(encrypted_size <= base64_data.GetSize());

  string_t decrypted_data = StringVector::EmptyString(result, decrypted_size);
  encryption_state->Process(
      buffer_p, encrypted_size,
      reinterpret_cast<unsigned char *>(decrypted_data.GetDataWriteable()),
      decrypted_size);

  return decrypted_data;
}

template <typename T>
void ExecuteEncryptExecutor(Vector &vector, Vector &result, idx_t size,
                            ExpressionState &state, const string &key_t) {

  // TODO: put this in the state of the extension
  uint8_t encryption_buffer[MAX_BUFFER_SIZE];
  uint8_t *buffer_p = encryption_buffer;

  unsigned char iv[16];
  auto encryption_state = InitializeCryptoState(state);

  // TODO: construct nonce based on immutable ROW_ID + hash(col_name)
  memcpy(iv, "12345678901", 12);
  iv[12] = iv[13] = iv[14] = iv[15] = 0x00;

  UnaryExecutor::Execute<T, T>(vector, result, size, [&](T input) -> T {
    encryption_state->InitializeEncryption(iv, 16, &key_t);
    return EncryptValue<T>(encryption_state.get(), result, input, buffer_p);
    ;
  });
}

// Generated code
//---------------------------------------------------------------------------------------------

// Helper function that dispatches the runtime type to the appropriate templated
// function
void ExecuteEncrypt(Vector &vector, Vector &result, idx_t size,
                    ExpressionState &state, const string &key_t) {
  // Check the vector type and call the correct templated version
  switch (vector.GetType().id()) {
  case LogicalTypeId::INTEGER:
    ExecuteEncryptExecutor<int32_t>(vector, result, size, state, key_t);
    break;
  case LogicalTypeId::BIGINT:
    ExecuteEncryptExecutor<int64_t>(vector, result, size, state, key_t);
    break;
  case LogicalTypeId::VARCHAR:
    ExecuteEncryptExecutor<string_t>(vector, result, size, state, key_t);
    break;
  default:
    throw NotImplementedException("Unsupported type for Encryption");
  }
}
//---------------------------------------------------------------------------------------------

template <typename T>
void ExecuteDecryptExecutor(Vector &vector, Vector &result, idx_t size,
                            ExpressionState &state, const string &key_t) {

  // TODO: put this in the state of the extension
  uint8_t encryption_buffer[MAX_BUFFER_SIZE];
  uint8_t *buffer_p = encryption_buffer;

  unsigned char iv[16];
  auto encryption_state = InitializeCryptoState(state);

  // TODO: construct nonce based on immutable ROW_ID + hash(col_name)
  memcpy(iv, "12345678901", 12);
  iv[12] = iv[13] = iv[14] = iv[15] = 0x00;

  UnaryExecutor::Execute<T, T>(vector, result, size, [&](T input) -> T {
    encryption_state->InitializeDecryption(iv, 16, &key_t);
    return DecryptValue<T>(encryption_state.get(), result, input, buffer_p);
    ;
  });
}

// Generated code
//---------------------------------------------------------------------------------------------

// Helper function that dispatches the runtime type to the appropriate templated
// function
void ExecuteDecrypt(Vector &vector, Vector &result, idx_t size,
                    ExpressionState &state, const string &key_t) {
  // Check the vector type and call the correct templated version
  switch (vector.GetType().id()) {
  case LogicalTypeId::INTEGER:
    ExecuteDecryptExecutor<int32_t>(vector, result, size, state, key_t);
    break;
  case LogicalTypeId::BIGINT:
    ExecuteDecryptExecutor<int64_t>(vector, result, size, state, key_t);
    break;
  case LogicalTypeId::VARCHAR:
    ExecuteDecryptExecutor<string_t>(vector, result, size, state, key_t);
    break;
  default:
    throw NotImplementedException("Unsupported type for Encryption");
  }
}
//---------------------------------------------------------------------------------------------

static void EncryptData(DataChunk &args, ExpressionState &state,
                        Vector &result) {

  auto &value_vector = args.data[0];

  // Get the encryption key
  auto &key_vector = args.data[1];
  D_ASSERT(key_vector.GetVectorType() == VectorType::CONSTANT_VECTOR);

  // Fetch the encryption key as a constant string
  const string key_t =
      ConstantVector::GetData<string_t>(key_vector)[0].GetString();

  // can we not pass by reference?
  ExecuteEncrypt(value_vector, result, args.size(), state, key_t);
}

static void DecryptData(DataChunk &args, ExpressionState &state,
                        Vector &result) {

  auto &value_vector = args.data[0];

  // Get the encryption key
  auto &key_vector = args.data[1];
  D_ASSERT(key_vector.GetVectorType() == VectorType::CONSTANT_VECTOR);

  // Fetch the encryption key as a constant string
  const string key_t =
      ConstantVector::GetData<string_t>(key_vector)[0].GetString();

  // can we not pass by reference?
  ExecuteDecrypt(value_vector, result, args.size(), state, key_t);
}

ScalarFunctionSet GetEncryptionFunction() {
  ScalarFunctionSet set("encrypt_simple");

  set.AddFunction(ScalarFunction({LogicalTypeId::INTEGER, LogicalType::VARCHAR},
                                 LogicalTypeId::INTEGER, EncryptData,
                                 EncryptFunctionData::EncryptBind));

  set.AddFunction(ScalarFunction({LogicalTypeId::BIGINT, LogicalType::VARCHAR},
                                 LogicalTypeId::BIGINT, EncryptData,
                                 EncryptFunctionData::EncryptBind));

  set.AddFunction(ScalarFunction({LogicalType::VARCHAR, LogicalType::VARCHAR},
                                 LogicalType::VARCHAR, EncryptData,
                                 EncryptFunctionData::EncryptBind));

  return set;
}

ScalarFunctionSet GetDecryptionFunction() {
  ScalarFunctionSet set("decrypt_simple");

  // input is column of any type, key is of type VARCHAR, output is of same type
  set.AddFunction(ScalarFunction({LogicalTypeId::INTEGER, LogicalType::VARCHAR},
                                 LogicalTypeId::INTEGER, DecryptData,
                                 EncryptFunctionData::EncryptBind));

  set.AddFunction(ScalarFunction({LogicalTypeId::BIGINT, LogicalType::VARCHAR},
                                 LogicalTypeId::BIGINT, DecryptData,
                                 EncryptFunctionData::EncryptBind));

  set.AddFunction(ScalarFunction({LogicalType::VARCHAR, LogicalType::VARCHAR},
                                 LogicalType::VARCHAR, DecryptData,
                                 EncryptFunctionData::EncryptBind));

  return set;
}

//------------------------------------------------------------------------------
// Register functions
//------------------------------------------------------------------------------

void CoreScalarFunctions::RegisterEncryptDataScalarFunction(
    DatabaseInstance &db) {
  ExtensionUtil::RegisterFunction(db, GetEncryptionFunction());
  ExtensionUtil::RegisterFunction(db, GetDecryptionFunction());
}
} // namespace core
} // namespace simple_encryption