#include "vcrypt/core/module.hpp"
#include "vcrypt/common.hpp"
#include "vcrypt/core/functions/scalar.hpp"
#include "vcrypt/core/functions/secrets.hpp"
#include "vcrypt/core/types.hpp"

namespace vcrypt {
namespace core {

void CoreModule::Register(DatabaseInstance &db) {
  CoreScalarFunctions::Register(db);
  CoreSecretFunctions::Register(db);
}

void CoreModule::RegisterType(DatabaseInstance &db) {
  EncryptionTypes::Register(db);
}
} // namespace core
} // namespace vcrypt