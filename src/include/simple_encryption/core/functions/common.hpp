#pragma once
#include "simple_encryption/common.hpp"

namespace simple_encryption {

namespace core {

struct SimpleEncryptionFunctionLocalState : FunctionLocalState {
public:

  ArenaAllocator arena;

public:
  explicit SimpleEncryptionFunctionLocalState(ClientContext &context);
  static unique_ptr<FunctionLocalState> Init(ExpressionState &state, const BoundFunctionExpression &expr,
                                             FunctionData *bind_data);
  static unique_ptr<FunctionLocalState> InitCast(CastLocalStateParameters &context);
  static SimpleEncryptionFunctionLocalState &ResetAndGet(ExpressionState &state);
  static SimpleEncryptionFunctionLocalState &ResetAndGet(CastParameters &parameters);
};

} // namespace core

} // namespace simple_encryption