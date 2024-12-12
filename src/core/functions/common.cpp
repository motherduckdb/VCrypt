#include "simple_encryption/common.hpp"
#include "simple_encryption/core/functions/common.hpp"

// Code adapted from spatial extension

namespace simple_encryption {

namespace core {

SimpleEncryptionFunctionLocalState::SimpleEncryptionFunctionLocalState(ClientContext &context, EncryptFunctionData *bind_data) : arena(BufferAllocator::Get(context)) {
  // clear IV
  iv[0] = iv[1] = 0;

  buffer_length = 512;
  encryption_buffer = arena.Allocate(buffer_length);

}

unique_ptr<FunctionLocalState>
SimpleEncryptionFunctionLocalState::Init(ExpressionState &state, const BoundFunctionExpression &expr, FunctionData *bind_data) {
  return make_uniq<SimpleEncryptionFunctionLocalState>(state.GetContext(), static_cast<EncryptFunctionData *>(bind_data));
}

SimpleEncryptionFunctionLocalState &SimpleEncryptionFunctionLocalState::ResetAndGet(ExpressionState &state) {
  auto &local_state = ExecuteFunctionState::GetFunctionState(state)->Cast<SimpleEncryptionFunctionLocalState>();
  local_state.arena.Reset();
  return local_state;
}

SimpleEncryptionFunctionLocalState &SimpleEncryptionFunctionLocalState::ResetKeyAndGet(ExpressionState &state) {
  auto &local_state = ExecuteFunctionState::GetFunctionState(state)->Cast<SimpleEncryptionFunctionLocalState>();
  local_state.arena.Reset();
  return local_state;
}

} // namespace core

} // namespace simple_encryption