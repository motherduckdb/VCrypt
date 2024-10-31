#define DUCKDB_EXTENSION_MAIN

#include "simple_encryption_extension.hpp"
#include "duckdb.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/function/scalar_function.hpp"
#include "duckdb/main/extension_util.hpp"
#include <duckdb/parser/parsed_data/create_scalar_function_info.hpp>

// OpenSSL linked through vcpkg
#include <openssl/opensslv.h>

namespace duckdb {

inline void SimpleEncryptionScalarFun(DataChunk &args, ExpressionState &state, Vector &result) {
    auto &name_vector = args.data[0];
    UnaryExecutor::Execute<string_t, string_t>(
	    name_vector, result, args.size(),
	    [&](string_t name) {
			return StringVector::AddString(result, "SimpleEncryption "+name.GetString()+" 🐥");;
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

static void LoadInternal(DatabaseInstance &instance) {
    // Register a scalar function
    auto simple_encryption_scalar_function = ScalarFunction("simple_encryption", {LogicalType::VARCHAR}, LogicalType::VARCHAR, SimpleEncryptionScalarFun);
    ExtensionUtil::RegisterFunction(instance, simple_encryption_scalar_function);

    // Register another scalar function
    auto simple_encryption_openssl_version_scalar_function = ScalarFunction("simple_encryption_openssl_version", {LogicalType::VARCHAR},
                                                LogicalType::VARCHAR, SimpleEncryptionOpenSSLVersionScalarFun);
    ExtensionUtil::RegisterFunction(instance, simple_encryption_openssl_version_scalar_function);
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
