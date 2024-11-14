#pragma once

#include "duckdb.hpp"
#include "duckdb/common/encryption_state.hpp"

namespace duckdb {

class SimpleEncryptionState : public ClientContextState {

public:
  explicit SimpleEncryptionState(shared_ptr<ClientContext> context);
  void QueryEnd() override;

  // should we make this private?
public:
  shared_ptr<ClientContext> context_p;
  shared_ptr<EncryptionState> encryption_state;

  // nonce metadata
  uint64_t iv[2];
  uint32_t counter = 0;

  // encryption buffer
  uint8_t *buffer_p;

};

} // namespace duckdb

