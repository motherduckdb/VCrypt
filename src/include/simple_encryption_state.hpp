#pragma once

#include "duckdb.hpp"
#include "duckdb/common/encryption_state.hpp"

namespace duckdb {

class SimpleEncryptionState : public ClientContextState {

public:
  explicit SimpleEncryptionState(shared_ptr<ClientContext> context);
  void QueryEnd() override;

public:
  shared_ptr<ClientContext> context_p;
  shared_ptr<EncryptionState> encryption_state;
  uint8_t *buffer_p;
};

} // namespace duckdb

