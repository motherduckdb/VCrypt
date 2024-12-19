#pragma once
#include "duckdb.hpp"
#include "simple_encryption/common.hpp"

namespace simple_encryption {

namespace core {

struct CoreScalarFunctions {
  static void Register(duckdb::DatabaseInstance &db) {
    RegisterEncryptDataScalarFunction(db);
    RegisterEncryptDataStructScalarFunction(db);
    RegisterEncryptVectorizedScalarFunction(db);
  }

private:
  static void RegisterEncryptDataScalarFunction(duckdb::DatabaseInstance &db);
  static void RegisterEncryptDataStructScalarFunction(duckdb::DatabaseInstance &db);
  static void RegisterEncryptVectorizedScalarFunction(duckdb::DatabaseInstance &db);
};

} // namespace core

} // namespace simple_encryption
