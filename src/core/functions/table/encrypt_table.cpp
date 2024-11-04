#include "simple_encryption/core/functions/table/encrypt_table.hpp"
#include "duckdb/catalog/catalog_entry/table_catalog_entry.hpp"
#include "duckdb/parser/constraints/foreign_key_constraint.hpp"
#include "duckdb/parser/statement/create_statement.hpp"
#include "simple_encryption/common.hpp"
#include <simple_encryption/core/functions/table.hpp>
#include <simple_encryption/core/utils/simple_encryption_utils.hpp>
#include <simple_encryption_extension.hpp>

namespace simple_encryption {

namespace core {

void CreateEncryptColumnFunction::CreateEncryptColumnFunc(
    ClientContext &context, TableFunctionInput &data_p, DataChunk &output) {
}

//------------------------------------------------------------------------------
// Register functions
//------------------------------------------------------------------------------

void CoreTableFunctions::RegisterEncryptColumnTableFunction(
    DatabaseInstance &db) {
  ExtensionUtil::RegisterFunction(db, CreateEncryptColumnFunction());
}

}
}