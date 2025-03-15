#pragma once
#include "duckdb.hpp"
#include "vcrypt/common.hpp"

namespace vcrypt {

namespace core {

struct CoreScalarFunctions {
  static void Register(duckdb::DatabaseInstance &db) {
    RegisterEncryptDataScalarFunction(db);
    RegisterEncryptDataStructScalarFunction(db);
    RegisterEncryptVectorizedScalarFunction(db);
    RegisterDecryptVectorizedScalarFunction(db);
    RegisterGenerateKeyFunction(db);
  }

private:
  static void RegisterEncryptDataScalarFunction(duckdb::DatabaseInstance &db);
  static void RegisterEncryptDataStructScalarFunction(duckdb::DatabaseInstance &db);
  static void RegisterEncryptVectorizedScalarFunction(duckdb::DatabaseInstance &db);
  static void RegisterDecryptVectorizedScalarFunction(duckdb::DatabaseInstance &db);
  static void RegisterGenerateKeyFunction(duckdb::DatabaseInstance &db);
};

} // namespace core

} // namespace vcrypt
