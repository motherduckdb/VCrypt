#pragma once

#include "simple_encryption/common.hpp"
#include "duckdb/main/client_context.hpp"

namespace simple_encryption {
namespace core {

struct EncryptFunctionData: FunctionData {

  // Save the ClientContext
  ClientContext &context;

  EncryptFunctionData(ClientContext &context)
      : context(context) {}

  static unique_ptr<FunctionData> EncryptBind(ClientContext &context, ScalarFunction &bound_function,
                      vector<unique_ptr<Expression>> &arguments);

  unique_ptr<FunctionData> Copy() const override;
  bool Equals(const FunctionData &other_p) const override;
};

} // namespace core

} // namespace simple_encryption