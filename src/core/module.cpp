#include "simple_encryption/core/module.hpp"
#include "simple_encryption/common.hpp"
#include "simple_encryption/core/functions/scalar.hpp"
#include "simple_encryption/core/functions/secrets.hpp"

namespace simple_encryption {
namespace core {

void CoreModule::Register(DatabaseInstance &db) {
  CoreScalarFunctions::Register(db);
  CoreSecretFunctions::Register(db);
}
} // namespace core
} // namespace simple_encryption