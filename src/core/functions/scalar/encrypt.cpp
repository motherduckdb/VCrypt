#define DUCKDB_EXTENSION_MAIN

#define TEST_KEY "0123456789112345"
#define MAX_BUFFER_SIZE 1024
#define MAX_BUFFER_SIZE_2 8096

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

namespace simple_encryption {

namespace core {

SimpleEncryptKeys &SimpleEncryptKeys::Get(ClientContext &context) {
  auto &cache = ObjectCache::GetObjectCache(context);
  if (!cache.Get<SimpleEncryptKeys>(SimpleEncryptKeys::ObjectType())) {
    cache.Put(SimpleEncryptKeys::ObjectType(), make_shared_ptr<SimpleEncryptKeys>());
  }
  return *cache.Get<SimpleEncryptKeys>(SimpleEncryptKeys::ObjectType());
}

void SimpleEncryptKeys::AddKey(const string &key_name, const string &key) {
  keys[key_name] = key;
}

bool SimpleEncryptKeys::HasKey(const string &key_name) const {
  return keys.find(key_name) != keys.end();
}

const string &SimpleEncryptKeys::GetKey(const string &key_name) const {
  D_ASSERT(HasKey(key_name));
  return keys.at(key_name);
}

string SimpleEncryptKeys::ObjectType() {
  return "simple_encrypt_keys";
}

string SimpleEncryptKeys::GetObjectType() {
  return ObjectType();
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

shared_ptr<EncryptionState> InitializeEncryption(ExpressionState &state) {

  // For now, hardcode everything
  // for some reason, this is 12
  const string key = TEST_KEY;
  unsigned char iv[16];
//  memcpy((void *)iv, "12345678901", 16);
//
//  // TODO; construct nonce based on immutable ROW_ID + hash(col_name)
//  iv[12] = 0x00;
//  iv[13] = 0x00;
//  iv[14] = 0x00;
//  iv[15] = 0x00;

  auto encryption_state = InitializeCryptoState(state);
//  encryption_state->GenerateRandomData(iv, 16);
//  encryption_state->InitializeEncryption(iv, 16, &key);

  return encryption_state;
}

shared_ptr<EncryptionState> InitializeDecryption(ExpressionState &state) {

  // For now, hardcode everything
  const string key = TEST_KEY;
  unsigned char iv[16];
  memcpy((void *)iv, "12345678901", 16);
  //
  //  // TODO; construct nonce based on immutable ROW_ID + hash(col_name)
  iv[12] = 0x00;
  iv[13] = 0x00;
  iv[14] = 0x00;
  iv[15] = 0x00;

  auto decryption_state = InitializeCryptoState(state);
  decryption_state->InitializeDecryption(iv, 16, &key);

  return decryption_state;
}

inline const uint8_t *DecryptValue(uint8_t *buffer, size_t size, ExpressionState &state) {

  // Initialize Encryption
  auto encryption_state = InitializeDecryption(state);
  uint8_t decryption_buffer[MAX_BUFFER_SIZE];
  uint8_t *temp_buf = decryption_buffer;

  encryption_state->Process(buffer, size, temp_buf, size);

  return temp_buf;
}

bool CheckEncryption(string_t printable_encrypted_data, uint8_t *buffer,
                            size_t size, const uint8_t *value, ExpressionState &state){

  // cast encrypted data to blob back and forth
  // to check whether data will be lost with casting
  auto unblobbed_data = Blob::ToBlob(printable_encrypted_data);
  auto encrypted_unblobbed_data =
      reinterpret_cast<const uint8_t *>(unblobbed_data.data());

  if (memcmp(encrypted_unblobbed_data, buffer, size) != 0) {
    throw InvalidInputException(
        "Original Encrypted Data differs from Unblobbed Encrypted Data");
  }

  auto decrypted_data = DecryptValue(buffer, size, state);
  if (memcmp(decrypted_data, value, size) != 0) {
    throw InvalidInputException(
        "Original Data differs from Decrypted Data");
  }

  return true;
}

static void DecryptData(DataChunk &args, ExpressionState &state,
                        Vector &result) {

  auto &name_vector = args.data[0];
  //  auto encryption_state = InitializeEncryption(state);

  auto const size = sizeof(string_t);

  // TODO; handle all different input types
  UnaryExecutor::Execute<string_t, string_t>(
      name_vector, result, args.size(), [&](string_t name) {

        // renew for each value
        uint8_t decryption_buffer[MAX_BUFFER_SIZE];
        uint8_t *buffer_p = decryption_buffer;
        // For now; new encryption state for every new value
        // does this has to do with multithreading or something?
        // the size is suddenly 1, but we should just get the size of the input type...
        auto name_size = name.GetSize();

        // round the size to multiple of 16 for encryption efficiency
        //        size = (size + 15) & ~15;

        unsigned char iv[16];
        const string key = TEST_KEY;
        auto encryption_state = InitializeCryptoState(state);

        // fix IV for now
        memcpy((void *)iv, "12345678901", 16);
        //
        //  // TODO; construct nonce based on immutable ROW_ID + hash(col_name)
        iv[12] = 0x00;
        iv[13] = 0x00;
        iv[14] = 0x00;
        iv[15] = 0x00;

//        encryption_state->GenerateRandomData(iv, 16);
        encryption_state->InitializeDecryption(iv, 16, &key);

        // at some point, input gets invalid
        auto input = reinterpret_cast<const_data_ptr_t>(name.GetData());
        encryption_state->Process(input, name_size, buffer_p, name_size);

#if 0
        D_ASSERT(MAX_BUFFER_SIZE ==
                 sizeof(encryption_buffer) / sizeof(encryption_buffer[0]));
#endif

        string_t decrypted_data(reinterpret_cast<const char *>(buffer_p), name_size);
        auto printable_decrypted_data = Blob::ToString(decrypted_data);

#if 0
        D_ASSERT(CheckEncryption(printable_encrypted_data, buffer_p, size, reinterpret_cast<const_data_ptr_t>(name.GetData()), state) == 1);
#endif

        // attach the tag at the end of the encrypted data
        unsigned char tag[16];
        // this does not do anything for CTR
        encryption_state->Finalize(buffer_p, 0, tag, 16);

        return printable_decrypted_data;
      });
}

static void EncryptData(DataChunk &args, ExpressionState &state,
                        Vector &result) {

  auto &name_vector = args.data[0];

  // Get the encryption key
  auto &key_vector = args.data[1];
  D_ASSERT(key_vector.GetVectorType() == VectorType::CONSTANT_VECTOR);

  // Fetch the encryption key as a constant string
  const string key_t = ConstantVector::GetData<string_t>(key_vector)[0].GetString();

  // how to check the data type of the vector?

  // TODO; handle all different input types
  UnaryExecutor::Execute<string_t, string_t>(
      name_vector, result, args.size(), [&](string_t name) {

        // renew for each value
        // maybe put this in the state of the extension? But how about parallelism?
        uint8_t encryption_buffer[MAX_BUFFER_SIZE];
        uint8_t *buffer_p = encryption_buffer;
        auto name_size = name.GetSize();

        // round the size to multiple of 16 for encryption efficiency
//        size = (size + 15) & ~15;

        unsigned char iv[16];
        // const string key = TEST_KEY;
        auto encryption_state = InitializeCryptoState(state);

        // fix IV for now
        memcpy((void *)iv, "12345678901", 12);
        //
        //  // TODO; construct nonce based on immutable ROW_ID + hash(col_name)
        iv[12] = 0x00;
        iv[13] = 0x00;
        iv[14] = 0x00;
        iv[15] = 0x00;

        //        encryption_state->GenerateRandomData(iv, 16);
        encryption_state->InitializeEncryption(iv, 16, &key_t);

        // at some point, input gets invalid
        auto input = reinterpret_cast<const_data_ptr_t>(name.GetData());
        encryption_state->Process(input, name_size, buffer_p, name_size);

#if 0
        D_ASSERT(MAX_BUFFER_SIZE ==
                 sizeof(encryption_buffer) / sizeof(encryption_buffer[0]));
#endif

        string_t encrypted_data(reinterpret_cast<const char *>(buffer_p), name_size);

#if 0
        D_ASSERT(CheckEncryption(printable_encrypted_data, buffer_p, size, reinterpret_cast<const_data_ptr_t>(name.GetData()), state) == 1);
#endif

        // attach the tag at the end of the encrypted data
        unsigned char tag[16];
        // this does not do anything for CTR
        encryption_state->Finalize(buffer_p, 0, tag, 16);

        return encrypted_data;
      });
}

ScalarFunctionSet GetEncryptionFunction() {
  ScalarFunctionSet set("encrypt");
  // TODO; support all available types for encryption
  for (auto &type : LogicalType::AllTypes()) {
    set.AddFunction(ScalarFunction({type, LogicalType::VARCHAR}, LogicalType::BLOB, EncryptData,
                                  EncryptFunctionData::EncryptBind));
  }
  return set;
}

ScalarFunctionSet GetDecryptionFunction() {
  ScalarFunctionSet set("decrypt");
  // TODO; support all available types for encryption
  for (auto &type : LogicalType::AllTypes()) {
    set.AddFunction(ScalarFunction({type, LogicalType::VARCHAR}, LogicalType::BLOB, DecryptData,
                                   EncryptFunctionData::EncryptBind));
  }
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
}
}