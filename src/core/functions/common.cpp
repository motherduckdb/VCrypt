#include "simple_encryption/common.hpp"
#include "simple_encryption/core/functions/common.hpp"

// Code adapted from spatial extension

namespace simple_encryption {

namespace core {

SimpleEncryptionFunctionLocalState::SimpleEncryptionFunctionLocalState(ClientContext &context) : arena(BufferAllocator::Get(context)) {
}

unique_ptr<FunctionLocalState>
SimpleEncryptionFunctionLocalState::Init(ExpressionState &state, const BoundFunctionExpression &expr, FunctionData *bind_data) {
  return make_uniq<SimpleEncryptionFunctionLocalState>(state.GetContext());
}

unique_ptr<FunctionLocalState> SimpleEncryptionFunctionLocalState::InitCast(CastLocalStateParameters &parameters) {
  return make_uniq<SimpleEncryptionFunctionLocalState>(*parameters.context.get());
}

SimpleEncryptionFunctionLocalState &SimpleEncryptionFunctionLocalState::ResetAndGet(CastParameters &parameters) {
  auto &local_state = parameters.local_state->Cast<SimpleEncryptionFunctionLocalState>();
  local_state.arena.Reset();
  return local_state;
}

SimpleEncryptionFunctionLocalState &SimpleEncryptionFunctionLocalState::ResetAndGet(ExpressionState &state) {
  auto &local_state = ExecuteFunctionState::GetFunctionState(state)->Cast<SimpleEncryptionFunctionLocalState>();
  local_state.arena.Reset();
  return local_state;
}

} // namespace core

} // namespace simple_encryption