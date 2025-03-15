#pragma once

#include "vcrypt/common.hpp"
#include "duckdb/common/encryption_state.hpp"
#include "vcrypt/core/functions/function_data/encrypt_function_data.hpp"

#ifndef DUCKDB_AMALGAMATION
#include "duckdb/storage/object_cache.hpp"
#endif

namespace vcrypt {

namespace core {

class VCryptBasicFun {

public:
  // Fix this later
  static VCryptBasicFun &Get(ClientContext &context);

public:
  static string* GetKey(ExpressionState &state);
  static EncryptFunctionData &GetEncryptionBindInfo(ExpressionState &state);
  static shared_ptr<VCryptState> GetVCryptState(ExpressionState &state);
  static shared_ptr<EncryptionState> GetEncryptionState(ExpressionState &state);

private:
  unordered_map<string, string> keys;
};

} // namespace core
} // namespace vcrypt