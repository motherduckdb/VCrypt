#include "vcrypt/common.hpp"
#include "vcrypt/core/functions/common.hpp"

// Code adapted from spatial extension

namespace vcrypt {

namespace core {

uint32_t GenerateRandom(RandomEngine *engine) {
  return engine->NextRandomInteger();
}

VCryptFunctionLocalState::VCryptFunctionLocalState(ClientContext &context, EncryptFunctionData *bind_data) : arena(BufferAllocator::Get(context)) {

#ifdef DEBUG
  auto seed = 1;
  RandomEngine random_engine(seed);
#else
  RandomEngine random_engine;
#endif

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
    // version byte + offsets (BATCH_SIZE * sizeof(uint64_t) + BATCH_SIZE * 16 bytes (initial string length)
    data_size = 1 + BATCH_SIZE * (sizeof(uint64_t) + sizeof(string_t));
  } else {
    data_size = 1 + GetTypeIdSize(type.InternalType()) * DEFAULT_STANDARD_VECTOR_SIZE * 2;
  }

  max_buffer_size = data_size;
  buffer_p = (data_ptr_t)arena.Allocate(data_size);
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

const void VCryptFunctionLocalState::IncrementIV(uint32_t increment) {
  // Based on OpenSSL CTR increment function
  uint32_t n = 16;

  // Cast iv (uint32_t*) to uint8_t* for byte-wise access
  uint8_t* iv_bytes = reinterpret_cast<uint8_t*>(&iv);

  do {
    --n;
    increment += iv_bytes[n];  // Access as uint8_t
    iv_bytes[n] = static_cast<uint8_t>(increment);
    increment >>= 8;
  } while (n && increment);
}


} // namespace core

} // namespace vcrypt