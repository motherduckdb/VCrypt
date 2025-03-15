#pragma once

#include "vcrypt/common.hpp"
#include "duckdb/planner/extension_callback.hpp"
#include "vcrypt_state.hpp"

namespace duckdb {

class VCryptExtensionCallback : public ExtensionCallback {
  void OnConnectionOpened(ClientContext &context) override {
    context.registered_state->Insert(
        "vcrypt",
        make_shared_ptr<VCryptState>(context.shared_from_this()));
  }
};
} // namespace duckdb