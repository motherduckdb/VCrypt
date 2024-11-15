#pragma once

#include "simple_encryption/common.hpp"
#include "duckdb/planner/extension_callback.hpp"
#include "simple_encryption_state.hpp"

namespace duckdb {

class SimpleEncryptionExtensionCallback : public ExtensionCallback {
  void OnConnectionOpened(ClientContext &context) override {
    context.registered_state->Insert(
        "simple_encryption",
        make_shared_ptr<SimpleEncryptionState>(context.shared_from_this()));
  }
};
} // namespace duckdb