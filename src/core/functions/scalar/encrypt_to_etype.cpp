#define DUCKDB_EXTENSION_MAIN

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
#include "simple_encryption/core/functions/scalar/encrypt.hpp"
#include "simple_encryption/core/functions/scalar.hpp"
#include "simple_encryption_state.hpp"
#include "duckdb/main/client_context.hpp"
#include "simple_encryption/core/functions/function_data/encrypt_function_data.hpp"
#include "duckdb/planner/expression/bound_function_expression.hpp"
#include "simple_encryption/core/types.hpp"
#include "duckdb/common/vector_operations/generic_executor.hpp"

// temporary

namespace simple_encryption {

namespace core {


template <typename T>
typename std::enable_if<std::is_integral<T>::value || std::is_floating_point<T>::value, T>::type
ProcessAndCast(shared_ptr<EncryptionState> encryption_state, Vector &result, T plaintext_data, uint8_t *buffer_p) {
  // actually, you can just for process already give the pointer to the result, thus skip buffer
  T encrypted_data;
  encryption_state->Process(reinterpret_cast<unsigned char*>(&plaintext_data), sizeof(int32_t), reinterpret_cast<unsigned char*>(&encrypted_data), sizeof(int32_t));
  return encrypted_data;
}

template <typename T>
typename std::enable_if<std::is_same<T, string_t>::value, T>::type
ProcessAndCast(shared_ptr<EncryptionState> encryption_state, Vector &result, T plaintext_data, uint8_t *buffer_p) {

  auto &children = StructVector::GetEntries(result);
  // take the second vector of the struct
  auto &result_vector = children[1];

  // first encrypt the bytes of the string into a temp buffer_p
  auto input_data = data_ptr_t(plaintext_data.GetData());
  auto value_size = plaintext_data.GetSize();
  encryption_state->Process(input_data, value_size, buffer_p, value_size);

  // Convert the encrypted data to Base64
  auto encrypted_data = string_t(reinterpret_cast<const char*>(buffer_p), value_size);
  size_t base64_size = Blob::ToBase64Size(encrypted_data);

  // convert to Base64 into a newly allocated string in the result vector
  T base64_data = StringVector::EmptyString(*result_vector, base64_size);
  Blob::ToBase64(encrypted_data, base64_data.GetDataWriteable());

  return base64_data;
}

string_t DecryptValueToString(shared_ptr<EncryptionState> encryption_state, Vector &result, string_t base64_data, uint8_t *buffer_p) {

  // first encrypt the bytes of the string into a temp buffer_p
  size_t encrypted_size = Blob::FromBase64Size(base64_data);
  size_t decrypted_size = encrypted_size;
  Blob::FromBase64(base64_data, reinterpret_cast<data_ptr_t>(buffer_p), encrypted_size);
  D_ASSERT(encrypted_size <= base64_data.GetSize());

  string_t decrypted_data = StringVector::EmptyString(result, decrypted_size);
  encryption_state->Process(buffer_p, encrypted_size, reinterpret_cast<unsigned char*>(decrypted_data.GetDataWriteable()), decrypted_size);

  return decrypted_data;
}


shared_ptr<EncryptionState> GetEncryptionState(ExpressionState &state){

  auto &func_expr = (BoundFunctionExpression &)state.expr;
  auto &info = (EncryptFunctionData &)*func_expr.bind_info;

  // refactor this into GetSimpleEncryptionState(info.context);
  auto simple_encryption_state =
      info.context.registered_state->Get<SimpleEncryptionState>(
          "simple_encryption");

  return simple_encryption_state->encryption_state;

}

string_t GetKey(Vector &key_vector){
        D_ASSERT(key_vector.GetVectorType() == VectorType::CONSTANT_VECTOR);
        return ConstantVector::GetData<string_t>(key_vector)[0];
}

LogicalType CreateEINTtypeStruct() {
  return LogicalType::STRUCT({{"prefix", LogicalType::VARCHAR},
                              {"id", LogicalType::INTEGER},
                              {"value", LogicalType::INTEGER}});
}

LogicalType CreateEVARtypeStruct() {
  return LogicalType::STRUCT({{"prefix", LogicalType::VARCHAR},
                              {"id", LogicalType::INTEGER},
                              {"value", LogicalType::VARCHAR}});
}

template <typename T>
void EncryptToEtype(LogicalType result_struct, Vector &input_vector, const string key_t, uint64_t size, ExpressionState &state, Vector &result){

  // Reset the reference of the result vector
  Vector struct_vector(result_struct, size);
  result.ReferenceAndSetType(struct_vector);

  // For every bulk insert we generate a new initialization vector
  unsigned char iv[16];
  auto encryption_state = GetEncryptionState(state);
  encryption_state->GenerateRandomData(iv, 12);
  auto nonce_prefix = string_t(reinterpret_cast<const char*>(iv), 12);
  int32_t nonce_count = 0;

  // Initialize encryption state
  encryption_state->InitializeEncryption(iv, 16, reinterpret_cast<const string *>(&key_t));

  using ENCRYPTED_TYPE = StructTypeTernary<string_t, int32_t, T>;
  using PLAINTEXT_TYPE = PrimitiveType<T>;

  // TODO: put this in the state of the extension
  uint8_t encryption_buffer[MAX_BUFFER_SIZE];
  uint8_t *buffer_p = encryption_buffer;

  GenericExecutor::ExecuteUnary<PLAINTEXT_TYPE, ENCRYPTED_TYPE>(input_vector, result, size, [&](PLAINTEXT_TYPE input) {

    // set the nonce_id for the nonce
    nonce_count++;
    memcpy(iv + 12, &nonce_count, sizeof(int32_t));

    // Encrypt input data
    T encrypted_data = ProcessAndCast(encryption_state, result, input.val, buffer_p);

    return ENCRYPTED_TYPE {nonce_prefix, nonce_count, encrypted_data};
  });
}

static void EncryptDataChunkStruct(DataChunk &args, ExpressionState &state, Vector &result) {

  auto &input_vector = args.data[0];
  auto vector_type = input_vector.GetType();
  auto size = args.size();

  // Get the encryption key from client input
  auto &key_vector = args.data[1];
  D_ASSERT(key_vector.GetVectorType() == VectorType::CONSTANT_VECTOR);
  const string key_t =
      ConstantVector::GetData<string_t>(key_vector)[0].GetString();

  if (vector_type.IsNumeric()) {
    return EncryptToEtype<int32_t>(CreateEINTtypeStruct(), input_vector, key_t, size, state, result);

  } else if (vector_type.id() == LogicalTypeId::VARCHAR) {
    return EncryptToEtype<string_t>(CreateEVARtypeStruct(), input_vector, key_t, size, state, result);

  } else if (vector_type.IsNested()) {
    throw NotImplementedException(
        "Nested types are not supported for encryption");

  } else if (vector_type.IsTemporal()) {
    throw NotImplementedException(
        "Temporal types are not supported for encryption");
  }

}

//static void EncryptDataChunkStructString(DataChunk &args, ExpressionState &state, Vector &result) {
//
//  auto &func_expr = (BoundFunctionExpression &)state.expr;
//  auto &info = (EncryptFunctionData &)*func_expr.bind_info;
//
//  // refactor this into GetSimpleEncryptionState(info.context);
//  auto simple_encryption_state =
//      info.context.registered_state->Get<SimpleEncryptionState>(
//          "simple_encryption");
//
//  auto &input_vector = args.data[0];
//  auto &key_vector = args.data[1];
//
//  D_ASSERT(key_vector.GetVectorType() == VectorType::CONSTANT_VECTOR);
//
//  // Fetch the encryption key as a constant string
//  const string key_t =
//      ConstantVector::GetData<string_t>(key_vector)[0].GetString();
//
//  // create struct_type
//  LogicalType result_struct = LogicalType::STRUCT(
//      {{"prefix", LogicalType::VARCHAR}, {"id", LogicalType::INTEGER}, {"value", LogicalType::INTEGER}});
//
//  Vector struct_vector(result_struct, args.size());
//  // reset the reference of the result vector
//  result.ReferenceAndSetType(struct_vector);
//
//  // TODO: put this in the state of the extension
//  uint8_t encryption_buffer[MAX_BUFFER_SIZE];
//  uint8_t *buffer_p = encryption_buffer;
//  auto encryption_state = simple_encryption_state->encryption_state;
//
//  // For every bulk insert we generate a new nonce
//  auto iv = GenerateIV(16);
//  auto nonce_prefix = string_t(reinterpret_cast<const char*>(iv), 12);
//  int32_t nonce_count = 0;
//
//  encryption_state->InitializeEncryption(iv, 16, &key_t);
//  using ENCRYPTED_TYPE = StructTypeTernary<string_t, int32_t, string_t>;
//  using PLAINTEXT_TYPE = PrimitiveType<string_t>;
//
//  GenericExecutor::ExecuteUnary<PLAINTEXT_TYPE, ENCRYPTED_TYPE>(input_vector, result, args.size(), [&](PLAINTEXT_TYPE input) {
//
//    // set the nonce
//    nonce_count++;
//    memcpy(iv + 12, &nonce_count, sizeof(int32_t));
//
//    // Encrypt string_t data
//    string_t encrypted_data = EncryptValueToString(encryption_state, result, input.val, buffer_p);
//
//    return ENCRYPTED_TYPE {nonce_prefix, nonce_count, encrypted_data};
//  });
//}

static void DecryptDataChunkStruct(DataChunk &args, ExpressionState &state, Vector &result) {

  auto &func_expr = (BoundFunctionExpression &)state.expr;
  auto &info = (EncryptFunctionData &)*func_expr.bind_info;

  // refactor this into GetSimpleEncryptionState(info.context);
  auto simple_encryption_state =
      info.context.registered_state->Get<SimpleEncryptionState>(
          "simple_encryption");

  auto &input_vector = args.data[0];
  auto &key_vector = args.data[1];
  D_ASSERT(key_vector.GetVectorType() == VectorType::CONSTANT_VECTOR);

  // Fetch the encryption key as a constant string
  const string key_t =
      ConstantVector::GetData<string_t>(key_vector)[0].GetString();

  // maybe convert vector to unified format? Like they do in other scalar fucntions

  // TODO: put this in the state of the extension
  uint8_t encryption_buffer[MAX_BUFFER_SIZE];
  uint8_t *buffer_p = encryption_buffer;

  unsigned char iv[16];
  auto encryption_state = simple_encryption_state->encryption_state;
  encryption_state->InitializeDecryption(iv, 16, &key_t);
  int32_t decrypted_data;

  using ENCRYPTED_TYPE = StructTypeTernary<string_t, int32_t, int32_t>;
  using PLAINTEXT_TYPE = PrimitiveType<int32_t>;

  GenericExecutor::ExecuteUnary<ENCRYPTED_TYPE, PLAINTEXT_TYPE>(
      input_vector, result, args.size(), [&](ENCRYPTED_TYPE input) {

        auto nonce_prefix = input.a_val;
        auto nonce_id = input.b_val;
        auto value = input.c_val;

        // Set the nonce
        memcpy(iv, &nonce_prefix, 12);
        // Set the nonce id
        memcpy(iv + 12, &nonce_id, sizeof(int32_t));

        encryption_state->Process(
            reinterpret_cast<unsigned char *>(&value), sizeof(int32_t),
            reinterpret_cast<unsigned char *>(&decrypted_data),
            sizeof(int32_t));

        return decrypted_data;
      });
}

  static void DecryptDataChunkStructString(DataChunk &args, ExpressionState &state, Vector &result) {

    auto &func_expr = (BoundFunctionExpression &)state.expr;
    auto &info = (EncryptFunctionData &)*func_expr.bind_info;

    // refactor this into GetSimpleEncryptionState(info.context);
    auto simple_encryption_state =
        info.context.registered_state->Get<SimpleEncryptionState>(
            "simple_encryption");

    auto &input_vector = args.data[0];
    auto &key_vector = args.data[1];
    D_ASSERT(key_vector.GetVectorType() == VectorType::CONSTANT_VECTOR);

    // Fetch the encryption key as a constant string
    const string key_t =
        ConstantVector::GetData<string_t>(key_vector)[0].GetString();

    // maybe convert vector to unified format? Like they do in other scalar fucntions

    // TODO: put this in the state of the extension
    uint8_t encryption_buffer[MAX_BUFFER_SIZE];
    uint8_t *buffer_p = encryption_buffer;

    unsigned char iv[16];
    auto encryption_state = simple_encryption_state->encryption_state;

    // TODO: construct nonce based on immutable ROW_ID + hash(col_name)
    memcpy(iv, "12345678901", 12);
    iv[12] = iv[13] = iv[14] = iv[15] = 0x00;

    encryption_state->InitializeDecryption(iv, 16, &key_t);
    // Decrypt data
    int32_t decrypted_data;

    using ENCRYPTED_TYPE = StructTypeBinary<int32_t, string_t>;
    using PLAINTEXT_TYPE = PrimitiveType<string_t>;

    GenericExecutor::ExecuteUnary<ENCRYPTED_TYPE, PLAINTEXT_TYPE>(
        input_vector, result, args.size(), [&](ENCRYPTED_TYPE input) {
          auto nonce = input.a_val;
          auto value = input.b_val;

          // Set the nonce
          memcpy(iv, &nonce, sizeof(int32_t));

          // Decrypt data
          string_t decrypted_data =
              DecryptValueToString(encryption_state, result, value, buffer_p);
          return decrypted_data;
        });
}


ScalarFunctionSet GetEncryptionStructFunction() {
  ScalarFunctionSet set("encrypt_etypes");

//  set.AddFunction(ScalarFunction({LogicalTypeId::INTEGER, LogicalType::VARCHAR}, EncryptionTypes::E_INT(), EncryptDataChunkStruct,
//                                 EncryptFunctionData::EncryptBind));

  // Function to Encrypt INTEGERS
  set.AddFunction(ScalarFunction({LogicalTypeId::INTEGER, LogicalType::VARCHAR}, LogicalType::STRUCT(
                                                                                     {{"prefix", LogicalType::VARCHAR}, {"id", LogicalType::INTEGER}, {"value", LogicalType::INTEGER}}), EncryptDataChunkStruct,
                                 EncryptFunctionData::EncryptBind));

  // Function to encrypt VARCHAR
  set.AddFunction(ScalarFunction({LogicalTypeId::VARCHAR, LogicalType::VARCHAR}, LogicalType::STRUCT(
                                                                                     {{"prefix", LogicalType::VARCHAR}, {"id", LogicalType::INTEGER}, {"value", LogicalType::VARCHAR}}), EncryptDataChunkStruct,
                                 EncryptFunctionData::EncryptBind));

  return set;
}

ScalarFunctionSet GetDecryptionStructFunction() {
  ScalarFunctionSet set("decrypt_etypes");

  // Why is E_INT not working?
//  set.AddFunction(ScalarFunction({EncryptionTypes::E_INT(), LogicalType::VARCHAR}, LogicalTypeId::INTEGER, DecryptDataChunkStruct,
//                                 EncryptFunctionData::EncryptBind));

  // try with input struct?
  set.AddFunction(ScalarFunction({LogicalType::STRUCT(
{{"prefix", LogicalType::VARCHAR}, {"id", LogicalType::INTEGER}, {"value", LogicalType::INTEGER}}), LogicalType::VARCHAR}, LogicalTypeId::INTEGER, DecryptDataChunkStruct,
                                 EncryptFunctionData::EncryptBind));

  set.AddFunction(ScalarFunction({LogicalType::STRUCT(
                                    {{"prefix", LogicalType::VARCHAR}, {"id", LogicalType::INTEGER}, {"value", LogicalType::VARCHAR}}), LogicalType::VARCHAR}, LogicalTypeId::VARCHAR, DecryptDataChunkStructString,
                               EncryptFunctionData::EncryptBind));

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
}
}
