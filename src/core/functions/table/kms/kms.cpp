#include "simple_encryption/core/functions/table/kms/kms.hpp"
#include "duckdb/parser/constraints/foreign_key_constraint.hpp"
#include "duckdb/parser/statement/create_statement.hpp"
#include "simple_encryption/common.hpp"
#include <simple_encryption/core/functions/table.hpp>
#include <simple_encryption/core/utils/simple_encryption_utils.hpp>
#include <simple_encryption_extension.hpp>

namespace simple_encryption {

namespace core {

void CreateKMS::CreateKMSFunc(duckdb::ClientContext &context, duckdb::TableFunctionInput &data_p, duckdb::DataChunk &output) {
  throw NotImplementedException("KMS not implemented yet");
}

//------------------------------------------------------------------------------
// Register functions
//------------------------------------------------------------------------------

void CoreTableFunctions::RegisterEncryptColumnTableFunction(
    DatabaseInstance &db) {
  ExtensionUtil::RegisterFunction(db, CreateKMS());
}

} // namespace core
} // namespace simple_encryption
