#pragma once
#include "duckdb.hpp"
#include "vcrypt/common.hpp"

namespace vcrypt {

namespace core {

struct CoreTableFunctions {
  static void Register(duckdb::DatabaseInstance &db) {
    RegisterEncryptColumnTableFunction(db);
  }

private:
  static void RegisterEncryptColumnTableFunction(duckdb::DatabaseInstance &db);
};

} // namespace core

} // namespace vcrypt