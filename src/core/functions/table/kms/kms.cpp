#include "vcrypt/core/functions/table/kms/kms.hpp"
#include "duckdb/parser/constraints/foreign_key_constraint.hpp"
#include "duckdb/parser/statement/create_statement.hpp"
#include "vcrypt/common.hpp"
#include <vcrypt/core/functions/table.hpp>
#include <vcrypt/core/utils/vcrypt_utils.hpp>
#include <vcrypt_extension.hpp>

namespace vcrypt {

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
} // namespace vcrypt
