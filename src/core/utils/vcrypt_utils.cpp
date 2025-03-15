#include "vcrypt/core/utils/vcrypt_utils.hpp"
#include "vcrypt/common.hpp"
#include "duckdb/parser/statement/copy_statement.hpp"

namespace vcrypt {

namespace core {

// Get VCryptState from ClientContext
shared_ptr<VCryptState>
GetVCryptState(ClientContext &context) {
  auto lookup =
      context.registered_state->Get<VCryptState>("vcrypt");
  if (!lookup) {
    throw Exception(ExceptionType::INVALID,
                    "Registered simple encryption state not found");
  }
  return lookup;
}

} // namespace core
} // namespace vcrypt
