#pragma once
#include "simple_encryption/common.hpp"
#include "simple_encryption/core/functions/function_data/encrypt_function_data.hpp"

#define BATCH_SIZE 128

namespace simple_encryption {

namespace core {

struct VCryptFunctionLocalState : FunctionLocalState {
public:

  ArenaAllocator arena;
  uint32_t iv[4];

  uint32_t counter = -1;
  uint32_t index = 0;
  uint32_t batch_nr = 0;
  uint32_t to_process;
  uint64_t batch_size_in_bytes;
  uint32_t max_buffer_size;
  shared_ptr<EncryptionState> encryption_state;

  data_ptr_t buffer_p;
  uint64_t nonce_hi;
  uint64_t nonce_lo;

  // local state cache
  char prefix[4];

public:
  explicit VCryptFunctionLocalState(ClientContext &context, EncryptFunctionData *bind_data);
  static unique_ptr<FunctionLocalState> Init(ExpressionState &state, const BoundFunctionExpression &expr,
                                             FunctionData *bind_data);
  static VCryptFunctionLocalState &Get(ExpressionState &state);
  static VCryptFunctionLocalState &ResetAndGet(ExpressionState &state);
  static VCryptFunctionLocalState &AllocateAndGet(ExpressionState &state, idx_t buffer_size);
  static VCryptFunctionLocalState &ResetKeyAndGet(ExpressionState &state);
  const void IncrementIV(uint32_t increment);

public:
  template <typename T>
  inline void ResetIV(uint32_t counter_val) {
    iv[3] = 0;

    if (counter_val == 0) {
      return;
    }

    if (std::is_integral<T>::value || std::is_floating_point<T>::value) {
      auto increment = counter_val * (BATCH_SIZE * sizeof(T) / 16);
      IncrementIV(increment);
    } else {
      // For non-numeric types (e.g., std::string)
      IncrementIV(counter_val);
    }
  }

  ~VCryptFunctionLocalState() {
    // Reset state
    counter = -2;
    index = 0;
  }
};

} // namespace core

} // namespace simple_encryption