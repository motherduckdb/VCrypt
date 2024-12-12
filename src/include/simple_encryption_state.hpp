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
  shared_ptr<EncryptionUtil> encryption_util;

  // nonce metadata
  uint32_t counter = 0;
  bool is_initialized = false;
  uint64_t iv[2];

  // todo; key can also be 24 or 32 (resize or always allocate 32)
  std::string key;
  bool key_flag = false;

  // encryption buffer
  uint8_t *buffer_p;
};

} // namespace duckdb
