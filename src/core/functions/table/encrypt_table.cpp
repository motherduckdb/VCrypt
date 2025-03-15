#include "vcrypt/core/functions/table/encrypt_table.hpp"
#include "duckdb/catalog/catalog_entry/table_catalog_entry.hpp"
#include "duckdb/parser/constraints/foreign_key_constraint.hpp"
#include "duckdb/parser/statement/create_statement.hpp"
#include "vcrypt/common.hpp"
#include <vcrypt/core/functions/table.hpp>
#include <vcrypt/core/utils/vcrypt_utils.hpp>
#include <vcrypt_extension.hpp>

namespace vcrypt {

namespace core {

void CreateEncryptColumnFunction::CreateEncryptColumnFunc(
    ClientContext &context, TableFunctionInput &data_p, DataChunk &output) {}

//------------------------------------------------------------------------------
// Register functions
//------------------------------------------------------------------------------

void CoreTableFunctions::RegisterEncryptColumnTableFunction(
    DatabaseInstance &db) {
  ExtensionUtil::RegisterFunction(db, CreateEncryptColumnFunction());
}

} // namespace core
} // namespace vcrypt