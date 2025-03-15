#define DUCKDB_EXTENSION_MAIN
#define MAX_BUFFER_SIZE 1024

#include "vcrypt_extension.hpp"
#include "duckdb.hpp"
#include "duckdb/common/exception.hpp"
#include <duckdb/parser/parsed_data/create_scalar_function_info.hpp>
#include "duckdb/common/types/blob.hpp"
#include "vcrypt_state.hpp"
#include "duckdb/main/connection_manager.hpp"
#include <vcrypt_extension_callback.hpp>
#include "vcrypt/core/module.hpp"
#include "vcrypt/core/crypto/crypto_primitives.hpp"
#include "etype/encrypted_type.hpp"

namespace duckdb {

static void LoadInternal(DatabaseInstance &instance) {
  // register functions in the core module
  vcrypt::core::CoreModule::Register(instance);
  vcrypt::core::CoreModule::RegisterType(instance);

  // Register the VCryptState for all connections
  auto &config = DBConfig::GetConfig(instance);

  // set pointer to OpenSSL encryption state
  config.encryption_util = make_shared_ptr<AESStateSSLFactory>();

  // Add extension callback
  config.extension_callbacks.push_back(
      make_uniq<VCryptExtensionCallback>());

  // Register the VCryptState for all connections
  for (auto &connection :
       ConnectionManager::Get(instance).GetConnectionList()) {
    connection->registered_state->Insert(
        "vcrypt",
        make_shared_ptr<VCryptState>(connection));
  }
}

void VcryptExtension::Load(DuckDB &db) {
  LoadInternal(*db.instance); }
std::string VcryptExtension::Name() { return "vcrypt"; }

std::string VcryptExtension::Version() const {
#ifdef EXT_VERSION_SIMPLE_ENCRYPTION
  return EXT_VERSION_SIMPLE_ENCRYPTION;
#else
  return "V0.0.1";
#endif
}

} // namespace duckdb

extern "C" {

DUCKDB_EXTENSION_API void vcrypt_init(duckdb::DatabaseInstance &db) {
  duckdb::DuckDB db_wrapper(db);
  db_wrapper.LoadExtension<duckdb::VcryptExtension>();
}

DUCKDB_EXTENSION_API const char *vcrypt_version() {
  return duckdb::DuckDB::LibraryVersion();
}
}

#ifndef DUCKDB_EXTENSION_MAIN
#error DUCKDB_EXTENSION_MAIN not defined
#endif
