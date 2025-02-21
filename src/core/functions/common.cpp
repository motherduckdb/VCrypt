#include "simple_encryption/common.hpp"
#include "simple_encryption/core/functions/common.hpp"

// Code adapted from spatial extension

namespace simple_encryption {

namespace core {

uint32_t GenerateRandom(RandomEngine *engine) {
  return engine->NextRandomInteger();
}

VCryptFunctionLocalState::VCryptFunctionLocalState(ClientContext &context, EncryptFunctionData *bind_data) : arena(BufferAllocator::Get(context)) {

  // currently for reproducability
  auto seed = 1;
  RandomEngine random_engine(seed);

  iv[0] = GenerateRandom(&random_engine);
  iv[1] = GenerateRandom(&random_engine);
  iv[2] = GenerateRandom(&random_engine);
  iv[3] = 0;

  size_t data_size;
  LogicalType type = bind_data->type;

  // set pointer to encryption primitives (mbedtls or openssl)
  encryption_state = bind_data->encryption_util->CreateEncryptionState();

  // For variable-sized data we need to be able to resize the buffer
  if (type == LogicalType::VARCHAR) {
    // version byte + offsets (BATCH_SIZE * sizeof(uint32_t) + BATCH_SIZE * 16 bytes (initial string length)
    data_size = 1 + BATCH_SIZE * sizeof(uint64_t) + sizeof(string_t) * BATCH_SIZE;
  } else {
    data_size = GetTypeIdSize(type.InternalType()) * DEFAULT_STANDARD_VECTOR_SIZE;
  }

  max_buffer_size = data_size;
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
  // fix this to return a new buffer?
  // AllocateAligned?
  auto &local_state = ExecuteFunctionState::GetFunctionState(state)->Cast<VCryptFunctionLocalState>();
  local_state.arena.Allocate(buffer_size);
  return local_state;
}

VCryptFunctionLocalState &VCryptFunctionLocalState::ResetKeyAndGet(ExpressionState &state) {
  auto &local_state = ExecuteFunctionState::GetFunctionState(state)->Cast<VCryptFunctionLocalState>();
  local_state.arena.Reset();
  return local_state;
}

const void VCryptFunctionLocalState::IncrementIV(uint32_t increment){
  // based on openssl ctr increment function
  // https://github.com/openssl/openssl/blob/master/crypto/modes/ctr128.c
  uint32_t n = 16;

  do {
    --n;
    increment += iv[n];
    iv[n] = (uint8_t)increment;
    increment >>= 8;
  } while (n && increment);

}

// Specialization for std::string
template <typename T>
typename std::enable_if<std::is_same<T, std::string>::value>::type
VCryptFunctionLocalState::CalculateOffset(uint32_t counter_val, uint32_t& increment) {
  IncrementIV(counter_val);
}

// Overload for non-std::string types (integral & floating-point)
template <typename T>
typename std::enable_if<std::is_integral<T>::value || std::is_floating_point<T>::value>::type
VCryptFunctionLocalState::CalculateOffset(uint32_t counter_val, uint32_t& increment) {
  increment = counter_val * (BATCH_SIZE * sizeof(T) / 16);
  IncrementIV(increment);
}

template <typename T>
void VCryptFunctionLocalState::ResetIV(uint32_t counter_val) {
  // counter needs to start from 0 before updating it
  iv[3] = 0;

  if (counter_val == 0) {
    return;
  }

  uint32_t increment;

  CalculateOffset<T>(counter_val);
  IncrementIV(increment);
}

} // namespace core

} // namespace simple_encryption