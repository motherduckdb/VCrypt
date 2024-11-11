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

int32_t EncryptValueInt32(EncryptionState *encryption_state, Vector &result, int plaintext_data, uint8_t *buffer_p) {
  // actually, you can just for process already give the pointer to the result, thus skip buffer
  int32_t encrypted_data;
  encryption_state->Process(reinterpret_cast<unsigned char*>(&plaintext_data), sizeof(int32_t), reinterpret_cast<unsigned char*>(&encrypted_data), sizeof(int32_t));
  return encrypted_data;
}

string_t EncryptValueToString(shared_ptr<EncryptionState> encryption_state, Vector &result, string_t value, uint8_t *buffer_p) {

  // first encrypt the bytes of the string into a temp buffer_p
  auto input_data = data_ptr_t(value.GetData());
  auto value_size = value.GetSize();
  encryption_state->Process(input_data, value_size, buffer_p, value_size);

  // Convert the encrypted data to Base64
  auto encrypted_data = string_t(reinterpret_cast<const char*>(buffer_p), value_size);
  size_t base64_size = Blob::ToBase64Size(encrypted_data);

  // convert to Base64 into a newly allocated string in the result vector
  string_t base64_data = StringVector::EmptyString(result, base64_size);
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

static void EncryptDataChunkStruct(DataChunk &args, ExpressionState &state, Vector &result) {

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

  // create struct_type
  LogicalType result_struct = LogicalType::STRUCT(
      {{"nonce", LogicalType::INTEGER}, {"value", LogicalType::INTEGER}});

  Vector struct_vector(result_struct, args.size());
  // reset the reference of the result vector
  result.ReferenceAndSetType(struct_vector);

  // TODO: put this in the state of the extension
  uint8_t encryption_buffer[MAX_BUFFER_SIZE];
  uint8_t *buffer_p = encryption_buffer;

  unsigned char iv[16];
  auto encryption_state = simple_encryption_state->encryption_state;

  // this can be an int64_t, we have 12 bytes available...
  // this needs to be in the state btw, because it needs to keep increasing PER vector
  int32_t nonce_count = 0;

  // TODO: construct nonce based on immutable ROW_ID + hash(col_name)
  memcpy(iv, "12345678901", 12);
  iv[12] = iv[13] = iv[14] = iv[15] = 0x00;

  encryption_state->InitializeEncryption(iv, 16, &key_t);

  // this can be templated: StructTypeBinary<int32_t, T>;
  // PLAINTEXT_TYPE = PrimitiveType<T>;
  using ENCRYPTED_TYPE = StructTypeBinary<int32_t, int32_t>;
  using PLAINTEXT_TYPE = PrimitiveType<int32_t>;

  GenericExecutor::ExecuteUnary<PLAINTEXT_TYPE, ENCRYPTED_TYPE>(input_vector, result, args.size(), [&](PLAINTEXT_TYPE input) {

    // set the nonce
    nonce_count++;
    memcpy(iv, &nonce_count, sizeof(int32_t));

    // Encrypt data
    int32_t encrypted_data;
    encryption_state->Process(reinterpret_cast<unsigned char*>(&input), sizeof(int32_t), reinterpret_cast<unsigned char*>(&encrypted_data), sizeof(int32_t));

    return ENCRYPTED_TYPE {nonce_count, encrypted_data};
  });
}

static void EncryptDataChunkStructString(DataChunk &args, ExpressionState &state, Vector &result) {

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

  // create struct_type
  LogicalType result_struct = LogicalType::STRUCT(
      {{"nonce", LogicalType::INTEGER}, {"value", LogicalType::VARCHAR}});

  Vector struct_vector(result_struct, args.size());
  // reset the reference of the result vector
  result.ReferenceAndSetType(struct_vector);

  // TODO: put this in the state of the extension
  uint8_t encryption_buffer[MAX_BUFFER_SIZE];
  uint8_t *buffer_p = encryption_buffer;

  unsigned char iv[16];
  auto encryption_state = simple_encryption_state->encryption_state;

  // this can be an int64_t, we have 12 bytes available...
  // this needs to be in the state btw, because it needs to keep increasing PER vector
  int32_t nonce_count = 0;

  // TODO: construct nonce based on immutable ROW_ID + hash(col_name)
  memcpy(iv, "12345678901", 12);
  iv[12] = iv[13] = iv[14] = iv[15] = 0x00;

  encryption_state->InitializeEncryption(iv, 16, &key_t);
  using ENCRYPTED_TYPE = StructTypeBinary<int32_t, string_t>;
  using PLAINTEXT_TYPE = PrimitiveType<string_t>;

  GenericExecutor::ExecuteUnary<PLAINTEXT_TYPE, ENCRYPTED_TYPE>(input_vector, result, args.size(), [&](PLAINTEXT_TYPE input) {

    // set the nonce
    nonce_count++;
    memcpy(iv, &nonce_count, sizeof(int32_t));

    // Encrypt data
    string_t encrypted_data = EncryptValueToString(encryption_state, result, input.val, buffer_p);

    return ENCRYPTED_TYPE {nonce_count, encrypted_data};
  });
}

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

  // TODO: construct nonce based on immutable ROW_ID + hash(col_name)
  memcpy(iv, "12345678901", 12);
  iv[12] = iv[13] = iv[14] = iv[15] = 0x00;

  encryption_state->InitializeDecryption(iv, 16, &key_t);
  // Decrypt data
  int32_t decrypted_data;

  using ENCRYPTED_TYPE = StructTypeBinary<int32_t, int32_t>;
  using PLAINTEXT_TYPE = PrimitiveType<int32_t>;

  GenericExecutor::ExecuteUnary<ENCRYPTED_TYPE, PLAINTEXT_TYPE>(
      input_vector, result, args.size(), [&](ENCRYPTED_TYPE input) {
        auto nonce = input.a_val;
        auto value = input.b_val;

        // Set the nonce
        memcpy(iv, &nonce, sizeof(int32_t));

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
                                                                                     {{"nonce", LogicalType::INTEGER}, {"value", LogicalType::INTEGER}}), EncryptDataChunkStruct,
                                 EncryptFunctionData::EncryptBind));

  // Function to encrypt VARCHAR
  set.AddFunction(ScalarFunction({LogicalTypeId::VARCHAR, LogicalType::VARCHAR}, LogicalType::STRUCT(
                                                                                     {{"nonce", LogicalType::INTEGER}, {"value", LogicalType::VARCHAR}}), EncryptDataChunkStructString,
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
{{"nonce", LogicalType::INTEGER}, {"value", LogicalType::INTEGER}}), LogicalType::VARCHAR}, LogicalTypeId::INTEGER, DecryptDataChunkStruct,
                                 EncryptFunctionData::EncryptBind));

  set.AddFunction(ScalarFunction({LogicalType::STRUCT(
                                    {{"nonce", LogicalType::INTEGER}, {"value", LogicalType::VARCHAR}}), LogicalType::VARCHAR}, LogicalTypeId::VARCHAR, DecryptDataChunkStructString,
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
