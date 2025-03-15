#pragma once
#include "vcrypt/common.hpp"
#include "vcrypt_state.hpp"
#include "duckdb/main/client_context.hpp"

namespace vcrypt {

namespace core {

// Get VCryptState from ClientContext
shared_ptr<VCryptState>
GetVCryptState(ClientContext &context);
} // namespace core

} // namespace vcrypt
