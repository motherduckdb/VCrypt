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

//  // Get the child vectors from the struct vector
//  auto &children = StructVector::GetEntries(result);
//  children[0] = make_uniq<Vector>(LogicalType::INTEGER);
//  children[1] = make_uniq<Vector>(LogicalType::INTEGER);

  // TODO: put this in the state of the extension
  uint8_t encryption_buffer[MAX_BUFFER_SIZE];
  uint8_t *buffer_p = encryption_buffer;

  unsigned char iv[16];
  auto encryption_state = simple_encryption_state->encryption_state;

  // this can be an int64_t, we have 12 bytes available...
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

static void DecryptDataChunkStruct(DataChunk &args, ExpressionState &state, Vector &result) {

  auto &func_expr = (BoundFunctionExpression &)state.expr;
  auto &info = (EncryptFunctionData &)*func_expr.bind_info;

  // refactor this into GetSimpleEncryptionState(info.context);
  auto simple_encryption_state =
      info.context.registered_state->Get<SimpleEncryptionState>(
          "simple_encryption");

  auto &input_vector = args.data[0];
  // D_assert to check whether it is a struct?
//  D_ASSERT(input_vector.GetType() == LogicalType::STRUCT);
  // get children of input data
  auto &children = StructVector::GetEntries(input_vector);
  auto &nonce_vector = children[0];
  auto &value_vector = children[1];

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

  // also, template this function
  BinaryExecutor::Execute<int32_t, int32_t, int32_t>(
      reinterpret_cast<Vector &>(nonce_vector),
      reinterpret_cast<Vector &>(value_vector), result, args.size(),
                                                                          [&](int32_t nonce, int32_t input) {
    // Set the nonce
    memcpy(iv, &nonce, sizeof(int32_t));

    // Decrypt data
    encryption_state->Process(reinterpret_cast<unsigned char*>(&input), sizeof(int32_t), reinterpret_cast<unsigned char*>(&decrypted_data), sizeof(int32_t));

    return decrypted_data;
  });
}


ScalarFunctionSet GetEncryptionStructFunction() {
  ScalarFunctionSet set("encrypt_etypes");

  set.AddFunction(ScalarFunction({LogicalTypeId::INTEGER, LogicalType::VARCHAR}, EncryptionTypes::E_INT(), EncryptDataChunkStruct,
                                 EncryptFunctionData::EncryptBind));

  return set;
}

ScalarFunctionSet GetDecryptionStructFunction() {
  ScalarFunctionSet set("decrypt_etypes");

  set.AddFunction(ScalarFunction({EncryptionTypes::E_INT(), LogicalType::VARCHAR}, LogicalTypeId::INTEGER, DecryptDataChunkStruct,
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
