#pragma once

#include "duckdb.hpp"
#include "duckdb/common/encryption_state.hpp"

namespace duckdb {

class SimpleEncryptionState : public ClientContextState {

public:
  explicit SimpleEncryptionState(shared_ptr<ClientContext> context);

public:
  shared_ptr<EncryptionState> encryption_state;
};

} // namespace duckdb

