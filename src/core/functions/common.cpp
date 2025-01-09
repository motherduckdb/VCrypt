#include "simple_encryption/common.hpp"
#include "simple_encryption/core/functions/common.hpp"

// Code adapted from spatial extension

namespace simple_encryption {

namespace core {

VCryptFunctionLocalState::VCryptFunctionLocalState(ClientContext &context, EncryptFunctionData *bind_data) : arena(BufferAllocator::Get(context)) {
  // clear IV
  iv[0] = iv[1] = 0;

  // maybe generate iv_high also already in the bind
  // allocate depending in sizeof(T) * items_in_vector
  // maybe already in registering the function!
  size_t data_size;
  LogicalType type = bind_data->type;

  // todo; fix this for all other types
  // todo; now it allocates per vector size, but for var-sized data this is tricky
  if (type == LogicalType::VARCHAR) {
    // allocate buffer for encrypted data
    data_size = DEFAULT_STANDARD_VECTOR_SIZE;
  } else {
    // todo; maybe we can also just do per vector for certain types, so more then 128
    data_size = GetTypeIdSize(type.InternalType()) * DEFAULT_STANDARD_VECTOR_SIZE;
  }

  buffer_p = (data_ptr_t)arena.Allocate(data_size);

  if (bind_data->type.id() == LogicalTypeId::VARCHAR) {
    // allocate buffer for encrypted data
    buffer_p = (data_ptr_t)arena.Allocate(128);
  }
}

unique_ptr<FunctionLocalState>
VCryptFunctionLocalState::Init(ExpressionState &state, const BoundFunctionExpression &expr, FunctionData *bind_data) {
  return make_uniq<VCryptFunctionLocalState>(state.GetContext(), static_cast<EncryptFunctionData *>(bind_data));
}

VCryptFunctionLocalState &VCryptFunctionLocalState::Get(ExpressionState &state) {
  auto &local_state = ExecuteFunctionState::GetFunctionState(state)->Cast<VCryptFunctionLocalState>();
  return local_state;
}

VCryptFunctionLocalState &VCryptFunctionLocalState::ResetAndGet(ExpressionState &state) {
  auto &local_state = ExecuteFunctionState::GetFunctionState(state)->Cast<VCryptFunctionLocalState>();
  local_state.arena.Reset();
  return local_state;
}

VCryptFunctionLocalState &VCryptFunctionLocalState::AllocateAndGet(ExpressionState &state, idx_t buffer_size) {
  auto &local_state = ExecuteFunctionState::GetFunctionState(state)->Cast<VCryptFunctionLocalState>();
  local_state.arena.Allocate(buffer_size);
  return local_state;
}

VCryptFunctionLocalState &VCryptFunctionLocalState::ResetKeyAndGet(ExpressionState &state) {
  auto &local_state = ExecuteFunctionState::GetFunctionState(state)->Cast<VCryptFunctionLocalState>();
  local_state.arena.Reset();
  return local_state;
}

} // namespace core

} // namespace simple_encryption