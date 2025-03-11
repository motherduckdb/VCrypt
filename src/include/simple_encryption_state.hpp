#pragma once

#include "duckdb.hpp"
#include "duckdb/common/encryption_state.hpp"
#include "duckdb/common/random_engine.hpp"

namespace duckdb {

class VCryptState : public ClientContextState {

public:
  explicit VCryptState(shared_ptr<ClientContext> context);
  void QueryEnd() override;

  // should we make this private?
public:
  shared_ptr<ClientContext> context_p;
  shared_ptr<EncryptionUtil> encryption_util;

  // nonce metadata
  uint32_t counter = 0;

  // bitmap for decrypted batches
  uint8_t* is_decrypted;
};

} // namespace duckdb
