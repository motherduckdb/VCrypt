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
#include "simple_encryption/core/types.hpp"
#include "simple_encryption/core/crypto/crypto_primitives.hpp"
#include "simple_encryption/core/functions/common.hpp"
#include "simple_encryption/core/functions/scalar.hpp"
#include "simple_encryption/core/functions/secrets.hpp"
#include "simple_encryption/core/functions/scalar/encrypt.hpp"
#include "simple_encryption/core/functions/function_data/encrypt_function_data.hpp"

namespace simple_encryption {

namespace core {

template <typename T>
typename std::enable_if<
    std::is_integral<T>::value || std::is_floating_point<T>::value, T>::type
ProcessAndCastEncrypt(shared_ptr<EncryptionState> encryption_state,
                      Vector &result, T plaintext_data, uint8_t *buffer_p) {
  T encrypted_data;
  encryption_state->Process(
      reinterpret_cast<unsigned char *>(&plaintext_data), sizeof(int32_t),
      reinterpret_cast<unsigned char *>(&encrypted_data), sizeof(int32_t));
  return encrypted_data;
}

template <typename T>
typename std::enable_if<std::is_same<T, string_t>::value, T>::type
ProcessAndCastEncrypt(shared_ptr<EncryptionState> encryption_state,
                      Vector &result, T plaintext_data, uint8_t *buffer_p) {

  auto &children = StructVector::GetEntries(result);
  // take the third vector of the struct
  auto &result_vector = children[2];

  // first encrypt the bytes of the string into a temp buffer_p
  auto input_data = data_ptr_t(plaintext_data.GetData());
  auto value_size = plaintext_data.GetSize();
  encryption_state->Process(input_data, value_size, buffer_p, value_size);

  // Convert the encrypted data to Base64
  auto encrypted_data =
      string_t(reinterpret_cast<const char *>(buffer_p), value_size);
  size_t base64_size = Blob::ToBase64Size(encrypted_data);

  // convert to Base64 into a newly allocated string in the result vector
  T base64_data = StringVector::EmptyString(*result_vector, base64_size);
  Blob::ToBase64(encrypted_data, base64_data.GetDataWriteable());
  base64_data.Finalize();

  return base64_data;
}

template <typename T>
typename std::enable_if<std::is_same<T, string_t>::value, T>::type
ProcessEncrypt(shared_ptr<EncryptionState> encryption_state,
                      Vector &result, T plaintext_data, uint8_t *buffer_p) {

  auto &children = StructVector::GetEntries(result);
  auto &result_vector = children[2];

  // first encrypt the bytes of the string into a temp buffer_p
  auto input_data = data_ptr_t(plaintext_data.GetData());
  auto value_size = plaintext_data.GetSize();

  encryption_state->Process(input_data, value_size, buffer_p, value_size);

  // Convert the encrypted data to a BLOB
  auto encrypted_data =
      string_t(reinterpret_cast<const char *>(buffer_p), value_size);
  size_t base64_size = Blob::ToBase64Size(encrypted_data);

  // convert to Base64 into a newly allocated string in the result vector
  T base64_data = StringVector::EmptyString(*result_vector, base64_size);
  base64_data.Finalize();
  Blob::ToBase64(encrypted_data, base64_data.GetDataWriteable());

  return base64_data;
}


template <typename T>
typename std::enable_if<std::is_same<T, string_t>::value, T>::type
ProcessDecrypt(shared_ptr<EncryptionState> encryption_state,
                      Vector &result, T base64_data, uint8_t *buffer_p) {

  // first encrypt the bytes of the string into a temp buffer_p
  size_t encrypted_size = Blob::FromBase64Size(base64_data);
  size_t decrypted_size = encrypted_size;
  Blob::FromBase64(base64_data, reinterpret_cast<data_ptr_t>(buffer_p),
                   encrypted_size);

  D_ASSERT(encrypted_size <= base64_data.GetSize());

  string_t decrypted_data =
      StringVector::EmptyString(result, decrypted_size);
  encryption_state->Process(
      buffer_p, encrypted_size,
      reinterpret_cast<unsigned char *>(decrypted_data.GetDataWriteable()),
      decrypted_size);

  return decrypted_data;
}

template <typename T>
typename std::enable_if<std::is_same<T, string_t>::value, T>::type
ProcessAndCastDecrypt(shared_ptr<EncryptionState> encryption_state,
                      Vector &result, T base64_data, uint8_t *buffer_p) {

  // first encrypt the bytes of the string into a temp buffer_p
  size_t encrypted_size = Blob::FromBase64Size(base64_data);
  size_t decrypted_size = encrypted_size;
  Blob::FromBase64(base64_data, reinterpret_cast<data_ptr_t>(buffer_p),
                   encrypted_size);

  D_ASSERT(encrypted_size <= base64_data.GetSize());

  string_t decrypted_data =
      StringVector::EmptyString(result, decrypted_size);
  encryption_state->Process(
      buffer_p, encrypted_size,
      reinterpret_cast<unsigned char *>(decrypted_data.GetDataWriteable()),
      decrypted_size);

  return decrypted_data;
}

template <typename T>
typename std::enable_if<
    std::is_integral<T>::value || std::is_floating_point<T>::value, T>::type
ProcessAndCastDecrypt(shared_ptr<EncryptionState> encryption_state,
                      Vector &result, T encrypted_data, uint8_t *buffer_p) {
  T decrypted_data;
  encryption_state->Process(
      reinterpret_cast<unsigned char *>(&encrypted_data), sizeof(T),
      reinterpret_cast<unsigned char *>(&decrypted_data), sizeof(T));
  return decrypted_data;
}

EncryptFunctionData &GetEncryptionBindInfo(ExpressionState &state) {
  auto &func_expr = (BoundFunctionExpression &)state.expr;
  return (EncryptFunctionData &)*func_expr.bind_info;
}

shared_ptr<VCryptState>
GetSimpleEncryptionState(ExpressionState &state) {

  auto &info = GetEncryptionBindInfo(state);
  return info.context.registered_state->Get<VCryptState>(
      "simple_encryption");
}

bool HasSpace(shared_ptr<VCryptState> vcrypt_state,
              uint64_t size) {
  uint32_t max_value = ~0u;
  if ((max_value - vcrypt_state->counter) > size) {
    return true;
  }
  return false;
}

bool CheckGeneratedKeySize(const uint32_t size){

  switch(size){
  case 16:
  case 24:
  case 32:
    return true;
  default:
    return false;
  }
}

// todo; template
LogicalType CreateEINTtypeStruct() {
  return LogicalType::STRUCT({{"nonce_hi", LogicalType::UBIGINT},
                              {"nonce_lo", LogicalType::UBIGINT},
                              {"value", LogicalType::INTEGER}});
}

LogicalType CreateEVARtypeStruct() {
  return LogicalType::STRUCT({{"nonce_hi", LogicalType::UBIGINT},
                              {"nonce_lo", LogicalType::UBIGINT},
                              {"value", LogicalType::VARCHAR}});
}

template <typename T>
void EncryptToEtype(LogicalType result_struct, Vector &input_vector,
                    uint64_t size, ExpressionState &state,
                    Vector &result) {

  // global, local and encryption state
  auto &lstate = VCryptFunctionLocalState::ResetAndGet(state);
  auto vcrypt_state = GetSimpleEncryptionState(state);
  auto encryption_state = VCryptBasicFun::GetEncryptionState(state);

  // Get Key from Bind
  auto key = VCryptBasicFun::GetKey(state);

  // Reset the reference of the result vector
  Vector struct_vector(result_struct, size);
  result.ReferenceAndSetType(struct_vector);

  auto &children = StructVector::GetEntries(result);
  auto &nonce_hi = children[0];
  nonce_hi->SetVectorType(VectorType::CONSTANT_VECTOR);

  using ENCRYPTED_TYPE = StructTypeTernary<uint64_t, uint64_t, T>;
  using PLAINTEXT_TYPE = PrimitiveType<T>;

  encryption_state->InitializeEncryption(
      reinterpret_cast<const_data_ptr_t>(lstate.iv), 16,
      reinterpret_cast<const string *>(key));

  GenericExecutor::ExecuteUnary<PLAINTEXT_TYPE, ENCRYPTED_TYPE>(
      input_vector, result, size, [&](PLAINTEXT_TYPE input) {

        lstate.iv[1]++;
        lstate.counter++;

        encryption_state->InitializeEncryption(
            reinterpret_cast<const_data_ptr_t>(lstate.iv), 16,
            reinterpret_cast<const string *>(key));

        T encrypted_data =
            ProcessAndCastEncrypt(encryption_state, result, input.val,
                                  lstate.buffer_p);

        return ENCRYPTED_TYPE{lstate.iv[0],
                              lstate.iv[1], encrypted_data};
      });

}


template <typename T>
void DecryptFromEtype(Vector &input_vector, uint64_t size,
                      ExpressionState &state, Vector &result) {

  // local state (contains key, buffer, iv etc.)
  auto &lstate = VCryptFunctionLocalState::ResetAndGet(state);
  // global state
  auto vcrypt_state = GetSimpleEncryptionState(state);
  auto encryption_state = VCryptBasicFun::GetEncryptionState(state);

  // Get Key from Bind
  auto key = VCryptBasicFun::GetKey(state);

  using ENCRYPTED_TYPE = StructTypeTernary<uint64_t, uint64_t, T>;
  using PLAINTEXT_TYPE = PrimitiveType<T>;

  GenericExecutor::ExecuteUnary<ENCRYPTED_TYPE, PLAINTEXT_TYPE>(
      input_vector, result, size, [&](ENCRYPTED_TYPE input) {
        lstate.iv[0] = input.a_val;
        lstate.iv[1] = input.b_val;

        encryption_state->InitializeDecryption(
            reinterpret_cast<const_data_ptr_t>(lstate.iv), 12,
            reinterpret_cast<const string *>(key));

        T decrypted_data =
            ProcessAndCastDecrypt(encryption_state, result, input.c_val,
                                  lstate.buffer_p);
        return decrypted_data;
      });
}


static void EncryptDataToEtype(DataChunk &args, ExpressionState &state,
                               Vector &result) {

  auto &input_vector = args.data[0];
  auto vector_type = input_vector.GetType();
  auto size = args.size();

  if (vector_type.IsNumeric()) {
    switch (vector_type.id()) {
    case LogicalTypeId::TINYINT:
    case LogicalTypeId::UTINYINT:
      return EncryptToEtype<int8_t>(CreateEINTtypeStruct(), input_vector,
                                    size, state, result);
    case LogicalTypeId::SMALLINT:
    case LogicalTypeId::USMALLINT:
      return EncryptToEtype<int16_t>(CreateEINTtypeStruct(), input_vector,
                                     size, state, result);
    case LogicalTypeId::INTEGER:
      return EncryptToEtype<int32_t>(CreateEINTtypeStruct(), input_vector,
                                     size, state, result);
    case LogicalTypeId::UINTEGER:
      return EncryptToEtype<uint32_t>(CreateEINTtypeStruct(), input_vector,
                                      size, state, result);
    case LogicalTypeId::BIGINT:
      return EncryptToEtype<int64_t>(CreateEINTtypeStruct(), input_vector,
                                     size, state, result);
    case LogicalTypeId::UBIGINT:
      return EncryptToEtype<uint64_t>(CreateEINTtypeStruct(), input_vector,
                                      size, state, result);
    case LogicalTypeId::FLOAT:
      return EncryptToEtype<float>(CreateEINTtypeStruct(), input_vector,
                                   size, state, result);
    case LogicalTypeId::DOUBLE:
      return EncryptToEtype<double>(CreateEINTtypeStruct(), input_vector,
                                    size, state, result);
    default:
      throw NotImplementedException("Unsupported numeric type for encryption");
    }
  } else if (vector_type.id() == LogicalTypeId::VARCHAR) {
    return EncryptToEtype<string_t>(CreateEVARtypeStruct(), input_vector,
                                    size, state, result);
  } else if (vector_type.IsNested()) {
    throw NotImplementedException(
        "Nested types are not supported for encryption");
  } else if (vector_type.IsTemporal()) {
    throw NotImplementedException(
        "Temporal types are not supported for encryption");
  }
}


static void DecryptDataFromEtype(DataChunk &args, ExpressionState &state,
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

ScalarFunctionSet GetEncryptionStructFunction() {
  ScalarFunctionSet set("encrypt");

  for (auto &type : LogicalType::AllTypes()) {
    set.AddFunction(
        ScalarFunction({type, LogicalType::VARCHAR},
                       LogicalType::STRUCT({{"nonce_hi", LogicalType::UBIGINT},
                                            {"nonce_lo", LogicalType::UBIGINT},
                                            {"value", type}}),
                       EncryptDataToEtype, EncryptFunctionData::EncryptBind, nullptr, nullptr, VCryptFunctionLocalState::Init));
  }

  return set;
}

ScalarFunctionSet GetDecryptionStructFunction() {
  ScalarFunctionSet set("decrypt");

  for (auto &type : LogicalType::AllTypes()) {
    for (auto &nonce_type_a : LogicalType::Numeric()) {
      for (auto &nonce_type_b : LogicalType::Numeric()) {
        set.AddFunction(ScalarFunction(
            {LogicalType::STRUCT({{"nonce_hi", nonce_type_a},
                                  {"nonce_lo", nonce_type_b},
                                  {"value", type}}),
             LogicalType::VARCHAR},
            type, DecryptDataFromEtype, EncryptFunctionData::EncryptBind, nullptr, nullptr, VCryptFunctionLocalState::Init));
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

void CoreScalarFunctions::RegisterEncryptDataStructScalarFunction(
    DatabaseInstance &db) {
  ExtensionUtil::RegisterFunction(db, GetEncryptionStructFunction());
  ExtensionUtil::RegisterFunction(db, GetDecryptionStructFunction());
}
} // namespace core
} // namespace simple_encryption
