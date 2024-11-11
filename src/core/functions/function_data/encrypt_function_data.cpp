#include "simple_encryption/core/functions/function_data/encrypt_function_data.hpp"
#include "simple_encryption/common.hpp"
#include <duckdb/function/function.hpp>
#include "duckdb/common/helper.hpp"

namespace simple_encryption {

namespace core {

unique_ptr<FunctionData> EncryptFunctionData::Copy() const {
  return make_uniq<EncryptFunctionData>(context);
}

bool EncryptFunctionData::Equals(const FunctionData &other_p) const {
  auto &other = (const EncryptFunctionData &)other_p;
  // fix this to return the right id
  return true;
}

unique_ptr<FunctionData> EncryptFunctionData::EncryptBind(ClientContext &context, ScalarFunction &bound_function,
                                         vector<unique_ptr<Expression>> &arguments) {
  // here, implement bound statements?

  // do something
  return make_uniq<EncryptFunctionData>(context);
}
}
}


