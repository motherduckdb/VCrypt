#pragma once
#include "simple_encryption/common.hpp"
#include "simple_encryption/core/functions/function_data/encrypt_function_data.hpp"

namespace simple_encryption {

namespace core {

struct VCryptFunctionLocalState : FunctionLocalState {
public:

  ArenaAllocator arena;
  uint32_t iv[4];

  uint32_t counter = -1;
  uint32_t internal_counter = 0;
  uint32_t to_process_total;
  uint32_t to_process_batch;
  uint32_t batch_size = BATCH_SIZE;
  uint64_t batch_size_in_bytes;

  data_ptr_t buffer_p;
public:
  explicit VCryptFunctionLocalState(ClientContext &context, EncryptFunctionData *bind_data);
  static unique_ptr<FunctionLocalState> Init(ExpressionState &state, const BoundFunctionExpression &expr,
                                             FunctionData *bind_data);
  static VCryptFunctionLocalState &Get(ExpressionState &state);
  static VCryptFunctionLocalState &ResetAndGet(ExpressionState &state);
  static VCryptFunctionLocalState &AllocateAndGet(ExpressionState &state, idx_t buffer_size);
  static VCryptFunctionLocalState &ResetKeyAndGet(ExpressionState &state);

  ~VCryptFunctionLocalState() {
    // Reset state
    counter = -1;
    internal_counter = 0;
  }
};

} // namespace core

} // namespace simple_encryption