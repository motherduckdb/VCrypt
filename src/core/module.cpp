#include "simple_encryption/core/module.hpp"
#include "simple_encryption/common.hpp"
#include "simple_encryption/core/functions/table.hpp"
#include "simple_encryption/core/functions/scalar.hpp"
#include "simple_encryption/core/parser/duckpgq_parser.hpp"
#include "simple_encryption/core/operator/duckpgq_operator.hpp"

namespace duckpgq {

namespace core {

void CoreModule::Register(DatabaseInstance &db) {
  CoreTableFunctions::Register(db);
  CoreScalarFunctions::Register(db);
  CorePGQParser::Register(db);
  CorePGQOperator::Register(db);
}


} // namespace core

} // namespace duckpgq