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

// OpenSSL linked through vcpkg
#include <openssl/opensslv.h>

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

//unsigned char* SetIV(){
//
//  unsigned char iv[16];
//  memcpy((void*)iv, "12345678901", 12);
//
//  // TODO; construct nonce based on immutable ROW_ID + hash(col_name)
//  iv[12] = 0x00;
//  iv[13] = 0x00;
//  iv[14] = 0x00;
//  iv[15] = 0x00;
//
//  return iv;
//};

shared_ptr<EncryptionState> InitializeEncryption(){
  duckdb_mbedtls::MbedTlsWrapper::AESGCMStateMBEDTLSFactory mbedtls_factory;
  shared_ptr<EncryptionState> encryption_state;
  encryption_state = mbedtls_factory.CreateEncryptionState();

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

  encryption_state->InitializeEncryption(iv, 16, &key);

  return encryption_state;
}

inline void EncryptValue(DataChunk &args, ExpressionState &state, Vector &result) {

  // Initialize Encryption
  auto encryption_state = InitializeEncryption();

  uint8_t encryption_buffer[MAX_BUFFER_SIZE];
  uint8_t* buffer = encryption_buffer;

  auto &name_vector = args.data[0];

  UnaryExecutor::Execute<string_t, string_t>(
      name_vector, result, args.size(),
      [&](string_t name) {

        auto const size = sizeof(name.GetData()) / sizeof(name.GetData()[0]);
        auto value = name.GetData();

        encryption_state->Process(reinterpret_cast<const_data_ptr_t>(value), size, buffer, size);
        D_ASSERT(MAX_BUFFER_SIZE == sizeof(encryption_buffer) / sizeof(encryption_buffer[0]));

        string_t str(reinterpret_cast<const char*>(buffer), size);

        // convert data to blob
        auto encrypted_data = Blob::ToString(str);

        // this works!
        // auto unblobbed_data = Blob::ToBlob(encrypted_data);

        return StringVector::AddString(result, "Test function " + encrypted_data);
        //return StringVector::AddString(result, "Test function " + encrypted_value.GetString() + " 🐥");
        // create a test now to properly debug :D
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

    // Register a scalar function
    auto simple_encryption_scalar_function = ScalarFunction("simple_encryption", {LogicalType::VARCHAR}, LogicalType::VARCHAR, SimpleEncryptionScalarFun);
    ExtensionUtil::RegisterFunction(instance, simple_encryption_scalar_function);

    // Register another scalar function
    auto simple_encryption_openssl_version_scalar_function = ScalarFunction("simple_encryption_openssl_version", {LogicalType::VARCHAR},
                                                LogicalType::VARCHAR, SimpleEncryptionOpenSSLVersionScalarFun);
    ExtensionUtil::RegisterFunction(instance, simple_encryption_openssl_version_scalar_function);

    // Register a scalar function
    auto encrypt_value = ScalarFunction("encrypt", {LogicalType::VARCHAR}, LogicalType::VARCHAR, EncryptValue);
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
	return "";
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
