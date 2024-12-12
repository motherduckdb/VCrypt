#pragma once
#include "simple_encryption/common.hpp"
#include "simple_encryption/core/functions/function_data/encrypt_function_data.hpp"

namespace simple_encryption {

namespace core {

struct SimpleEncryptionFunctionLocalState : FunctionLocalState {
public:

  ArenaAllocator arena;

  idx_t buffer_length;
  uint64_t iv[2];

  // todo: key can be 16, 24 or 32
  unsigned char key[16];
  data_ptr_t buffer_p;

  void *encryption_buffer;
  bool initialized = false;

public:
  explicit SimpleEncryptionFunctionLocalState(ClientContext &context, EncryptFunctionData *bind_data);
  static unique_ptr<FunctionLocalState> Init(ExpressionState &state, const BoundFunctionExpression &expr,
                                             FunctionData *bind_data);
  static SimpleEncryptionFunctionLocalState &ResetAndGet(ExpressionState &state);
  static SimpleEncryptionFunctionLocalState &ResetKeyAndGet(ExpressionState &state);
};

} // namespace core

} // namespace simple_encryption