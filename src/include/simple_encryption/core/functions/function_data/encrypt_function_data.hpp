#pragma once

#include "simple_encryption/common.hpp"
#include "duckdb/main/client_context.hpp"

namespace simple_encryption {
namespace core {

struct EncryptFunctionData : FunctionData {

  // Save the ClientContext
  ClientContext &context;
  // Save the Key
  string key_name;
  string key;
  //  BoundStatement relation;

  EncryptFunctionData(ClientContext &context, string key_name) : context(context), key_name(key_name) {
    // generate encryption key and store
    key = GetKeyFromSecret(context, key_name);
  }

  static unique_ptr<FunctionData>
  EncryptBind(ClientContext &context, ScalarFunction &bound_function,
              vector<unique_ptr<Expression>> &arguments);

  unique_ptr<FunctionData> Copy() const override;
  bool Equals(const FunctionData &other_p) const override;
  string GetKeyFromSecret(ClientContext &context, string key_name);
};

} // namespace core

} // namespace simple_encryption