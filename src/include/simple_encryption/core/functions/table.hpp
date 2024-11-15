#pragma once
#include "duckdb.hpp"
#include "simple_encryption/common.hpp"

namespace simple_encryption {

namespace core {

struct CoreTableFunctions {
  static void Register(duckdb::DatabaseInstance &db) {
    RegisterEncryptColumnTableFunction(db);
  }

private:
  static void RegisterEncryptColumnTableFunction(duckdb::DatabaseInstance &db);
};

} // namespace core

} // namespace simple_encryption