#define DUCKDB_EXTENSION_MAIN

#define TEST_KEY "0123456789112345"
#define MAX_BUFFER_SIZE 1024

#include "simple_encryption_extension.hpp"
#include "duckdb.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/encryption_state.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/function/scalar_function.hpp"
#include "duckdb/main/extension_util.hpp"
#include "mbedtls_wrapper.hpp"
#include <duckdb/parser/parsed_data/create_scalar_function_info.hpp>
#include "duckdb/common/types/blob.hpp"
#include "simple_encryption_state.hpp"
#include "duckdb/main/connection_manager.hpp"

// OpenSSL linked through vcpkg
#include <openssl/opensslv.h>

// somewhere initialize the simpleencryptionstate here


namespace duckdb {

inline void SimpleEncryptionScalarFun(DataChunk &args, ExpressionState &state, Vector &result) {

    auto &name_vector = args.data[0];
    UnaryExecutor::Execute<string_t, string_t>(
	    name_vector, result, args.size(),
	    [&](string_t name) {
			return StringVector::AddString(result, "Test function " + name.GetString() + " 🐥");;
        });
}

inline void SimpleEncryptionOpenSSLVersionScalarFun(DataChunk &args, ExpressionState &state, Vector &result) {
    auto &name_vector = args.data[0];
    UnaryExecutor::Execute<string_t, string_t>(
	    name_vector, result, args.size(),
	    [&](string_t name) {
			return StringVector::AddString(result, "SimpleEncryption " + name.GetString() +
                                                     ", my linked OpenSSL version is " +
                                                     OPENSSL_VERSION_TEXT );;
        });
}

shared_ptr<EncryptionState> InitializeCryptoState(){

  // for now just do MBEDTLS here
  shared_ptr<EncryptionState> encryption_state = duckdb_mbedtls::MbedTlsWrapper::AESGCMStateMBEDTLSFactory().CreateEncryptionState();

  return encryption_state;
}

shared_ptr<EncryptionState> InitializeEncryption(){

  // For now, hardcode everything
  const string key = TEST_KEY;
  unsigned char tag[16];
  unsigned char iv[16];
  memcpy((void*)iv, "12345678901", 12);
  //
  //  // TODO; construct nonce based on immutable ROW_ID + hash(col_name)
  iv[12] = 0x00;
  iv[13] = 0x00;
  iv[14] = 0x00;
  iv[15] = 0x00;

  auto encryption_state = InitializeCryptoState();

  encryption_state->InitializeEncryption(iv, 16, &key);

  return encryption_state;
}

shared_ptr<EncryptionState> InitializeDecryption(){

  // For now, hardcode everything
  const string key = TEST_KEY;
  unsigned char tag[16];
  unsigned char iv[16];
  memcpy((void*)iv, "12345678901", 12);
  //
  //  // TODO; construct nonce based on immutable ROW_ID + hash(col_name)
  iv[12] = 0x00;
  iv[13] = 0x00;
  iv[14] = 0x00;
  iv[15] = 0x00;

  auto decryption_state = InitializeCryptoState();

  decryption_state->InitializeDecryption(iv, 16, &key);

  return decryption_state;

}

inline const uint8_t* DecryptValue(uint8_t *buffer, size_t size){

  // Initialize Encryption
  auto encryption_state = InitializeDecryption();

  // Change this to MAX_BUFFER_SIZE for better performance
  uint8_t decryption_buffer[MAX_BUFFER_SIZE];
  uint8_t* temp_buf = decryption_buffer;

  encryption_state->Process(buffer, size, temp_buf, size);

  return temp_buf;
}


inline void EncryptValue(DataChunk &args, ExpressionState &state, Vector &result) {

  auto encryption_state = InitializeEncryption();

  uint8_t encryption_buffer[MAX_BUFFER_SIZE];
  uint8_t* buffer = encryption_buffer;

  auto &name_vector = args.data[0];

  UnaryExecutor::Execute<string_t, string_t>(
      name_vector, result, args.size(),
      [&](string_t name) {

        auto size = name.GetSize();
        auto value = reinterpret_cast<const uint8_t*>(name.GetData());

        encryption_state->Process(value, size, buffer, size);

        D_ASSERT(MAX_BUFFER_SIZE == sizeof(encryption_buffer) / sizeof(encryption_buffer[0]));

        string_t encrypted_data = reinterpret_cast<const char*>(buffer);
        auto printable_encrypted_data = Blob::ToString(encrypted_data);

#ifdef DEBUG
        // cast encrypted data to blob back and forth to check whether data will be lost
        auto unblobbed_data = Blob::ToBlob(printable_encrypted_data);
        auto encrypted_unblobbed_data = reinterpret_cast<const uint8_t*>(unblobbed_data.data());

        if (memcmp(encrypted_unblobbed_data, buffer, size) != 0){
          throw InvalidInputException("Original Encrypted Data differs from Unblobbed Encrypted Data");
        }

        auto decrypted_data = DecryptValue(buffer, size);
        if (memcmp(decrypted_data, value, size) != 0){
          throw InvalidInputException("Original Data differs from Decrypted Data");
        }
#endif

        return StringVector::AddString(result, name.GetString() + " is encrypted as: " + printable_encrypted_data);

      });
}

inline void EncryptColumn(DataChunk &args, ExpressionState &state, Vector &result) {


  // Make as input a column name
  // For now, hardcode the nonce
  auto &name_vector = args.data[0];
  UnaryExecutor::Execute<string_t, string_t>(
      name_vector, result, args.size(),
      [&](string_t name) {
        return StringVector::AddString(result, "Test function " + name.GetString() + " 🐥");;
      });
}

static void LoadInternal(DatabaseInstance &instance) {

    auto &config = DBConfig::GetConfig(instance);

//    for (auto &connection : ConnectionManager::Get(instance).GetConnectionList()) {
//      connection->registered_state->Insert(
//          "simple_encryption",
//          make_shared_ptr<SimpleEncryptionState>(connection));
//    }

    // Register a scalar function
    // move this to somewhere else
    auto simple_encryption_scalar_function = ScalarFunction("simple_encryption", {LogicalType::VARCHAR}, LogicalType::VARCHAR, SimpleEncryptionScalarFun);
    ExtensionUtil::RegisterFunction(instance, simple_encryption_scalar_function);

    // Register another scalar function
    auto simple_encryption_openssl_version_scalar_function = ScalarFunction("simple_encryption_openssl_version", {LogicalType::VARCHAR},
                                                LogicalType::VARCHAR, SimpleEncryptionOpenSSLVersionScalarFun);

    ExtensionUtil::RegisterFunction(instance, simple_encryption_openssl_version_scalar_function);

    // Register a scalar function

    // what if scalar functions can have multiple types?
    auto encrypt_value = ScalarFunction("encrypt", {LogicalType::VARCHAR}, LogicalType::VARCHAR, EncryptValue);
    // also todo: er wordt niks geprint

    ExtensionUtil::RegisterFunction(instance, encrypt_value);
}

void SimpleEncryptionExtension::Load(DuckDB &db) {
	LoadInternal(*db.instance);
}
std::string SimpleEncryptionExtension::Name() {
	return "simple_encryption";
}

std::string SimpleEncryptionExtension::Version() const {
#ifdef EXT_VERSION_SIMPLE_ENCRYPTION
	return EXT_VERSION_SIMPLE_ENCRYPTION;
#else
	return "V0.0.1";
#endif
}

} // namespace duckdb

extern "C" {

  DUCKDB_EXTENSION_API void simple_encryption_init(duckdb::DatabaseInstance &db) {
      duckdb::DuckDB db_wrapper(db);
      db_wrapper.LoadExtension<duckdb::SimpleEncryptionExtension>();
  }

  DUCKDB_EXTENSION_API const char *simple_encryption_version() {
          return duckdb::DuckDB::LibraryVersion();
  }
}

#ifndef DUCKDB_EXTENSION_MAIN
#error DUCKDB_EXTENSION_MAIN not defined
#endif
