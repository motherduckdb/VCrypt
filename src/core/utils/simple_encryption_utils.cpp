#include "simple_encryption/core/utils/simple_encryption_utils.hpp"
#include "simple_encryption/common.hpp"
#include "duckdb/parser/statement/copy_statement.hpp"

namespace simple_encryption {

namespace core {

// Get SimpleEncryptionState from ClientContext
shared_ptr<SimpleEncryptionState>
GetSimpleEncryptionState(ClientContext &context) {
  auto lookup =
      context.registered_state->Get<SimpleEncryptionState>("simple_encryption");
  if (!lookup) {
    throw Exception(ExceptionType::INVALID,
                    "Registered simple encryption state not found");
  }
  return lookup;
}

} // namespace core
} // namespace simple_encryption
