#pragma once

#include "simple_encryption/common.hpp"
#include "duckdb/common/encryption_state.hpp"
#include "simple_encryption/core/functions/function_data/encrypt_function_data.hpp"

#ifndef DUCKDB_AMALGAMATION
#include "duckdb/storage/object_cache.hpp"
#endif

namespace simple_encryption {

namespace core {

class VCryptBasicFun {

public:
  // Fix this later
  static VCryptBasicFun &Get(ClientContext &context);

public:
  static string* GetKey(ExpressionState &state);
  static EncryptFunctionData &GetEncryptionBindInfo(ExpressionState &state);
  static shared_ptr<SimpleEncryptionState> GetSimpleEncryptionState(ExpressionState &state);
  static shared_ptr<EncryptionState> GetEncryptionState(ExpressionState &state);

private:
  unordered_map<string, string> keys;
};

} // namespace core
} // namespace simple_encryption