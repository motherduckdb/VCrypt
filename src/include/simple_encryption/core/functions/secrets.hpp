#pragma once

#include <string>
#include "duckdb/main/database.hpp"

namespace simple_encryption {

namespace core {

std::string read_token_from_file(const std::string &file_path);
duckdb::string_t GenerateDataEncryptionKey();

struct CoreSecretFunctions {
public:
  //! Register all CreateSecretFunctions
  static void Register(duckdb::DatabaseInstance &db){
    RegisterStoreEncryptSecretFunction(db);
//    RegisterGetEncryptSecretStructFunction(db);
//    RegisterDeleteEncryptSecretStructFunction(db);
  }

private:
  static void RegisterStoreEncryptSecretFunction(duckdb::DatabaseInstance &db);
//  static void RegisterGetEncryptSecretStructFunction(duckdb::DatabaseInstance &db);
//  static void RegisterDeleteEncryptSecretStructFunction(duckdb::DatabaseInstance &db);
};

}
}
