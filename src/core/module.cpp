#include "simple_encryption/core/module.hpp"
#include "simple_encryption/common.hpp"
#include "simple_encryption/core/functions/scalar.hpp"

namespace simple_encryption {
namespace core {

void CoreModule::Register(DatabaseInstance &db) {
  CoreScalarFunctions::Register(db);
}
} // namespace core
} // namespace simple_encryption