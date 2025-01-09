#pragma once
#include "simple_encryption/common.hpp"
#include "simple_encryption/core/functions/function_data/encrypt_function_data.hpp"

namespace simple_encryption {

namespace core {

struct VCryptFunctionLocalState : FunctionLocalState {
public:

  ArenaAllocator arena;
  uint64_t iv[2];

  uint32_t counter = NULL;
  uint32_t to_process;
  uint32_t batch_size;
  uint64_t batch_size_in_bytes;

  // todo: key can be 16, 24 or 32
  unsigned char key[16];
  data_ptr_t buffer_p;

  bool initialized = false;

public:
  explicit VCryptFunctionLocalState(ClientContext &context, EncryptFunctionData *bind_data);
  static unique_ptr<FunctionLocalState> Init(ExpressionState &state, const BoundFunctionExpression &expr,
                                             FunctionData *bind_data);
  static VCryptFunctionLocalState &Get(ExpressionState &state);
  static VCryptFunctionLocalState &ResetAndGet(ExpressionState &state);
  static VCryptFunctionLocalState &AllocateAndGet(ExpressionState &state, idx_t buffer_size);
  static VCryptFunctionLocalState &ResetKeyAndGet(ExpressionState &state);
};

} // namespace core

} // namespace simple_encryption