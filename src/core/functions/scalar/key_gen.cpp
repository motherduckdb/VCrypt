#define DUCKDB_EXTENSION_MAIN

#include "duckdb.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/extension_util.hpp"
#include "duckdb/main/connection_manager.hpp"
#include "duckdb/main/secret/secret_manager.hpp"
#include "duckdb/function/scalar_function.hpp"
#include "duckdb/common/types.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/types/blob.hpp"
#include "duckdb/common/encryption_state.hpp"
#include "duckdb/common/vector_operations/generic_executor.hpp"
#include "duckdb/planner/expression/bound_function_expression.hpp"
#include "mbedtls_wrapper.hpp"

#include <duckdb/parser/parsed_data/create_scalar_function_info.hpp>

#include "simple_encryption_state.hpp"
#include "simple_encryption/core/functions/common.hpp"
#include "simple_encryption/core/functions/scalar.hpp"
#include "simple_encryption/core/functions/secrets.hpp"
#include "simple_encryption/core/functions/scalar/encrypt.hpp"
#include "simple_encryption/core/functions/function_data/encrypt_function_data.hpp"

namespace simple_encryption {

namespace core {

bool ValidKeyLength(uint32_t length){

  switch(length){
    case 16:
    case 24:
    case 32:
      return true;
    default:
      return false;
  }
}

void GenerateRandomNumbers(uint32_t blocks, uint32_t *key_numeric) {

  RandomEngine random_engine;

  for (idx_t i = 0; i < blocks; i++) {
    key_numeric[i] = random_engine.NextRandomInteger();
  }

}

static void GenerateRandomKey(DataChunk &args, ExpressionState &state,
                                  Vector &result) {

  uint32_t length;
  auto &vector = args.data[0];

  // allocate maximum size on the stack for every vector
  uint32_t key_numeric[8];

  UnaryExecutor::Execute<uint32_t, string_t>(vector, result, args.size(), [&](uint32_t input) -> string_t {

    if (ValidKeyLength(input)) {
      length = input;
    } else {
      throw InvalidInputException("Invalid key length. Only 16, 24 or 32 bytes are supported.");
    }

    const uint32_t blocks = length / sizeof(uint32_t);
    GenerateRandomNumbers(blocks, key_numeric);

    auto key = string_t(reinterpret_cast<const char *>(key_numeric), length);
    size_t base64_size = Blob::ToBase64Size(key);

    // convert to Base64 into a newly allocated string in the result vector
    string_t base64_data = StringVector::EmptyString(result, base64_size);
    Blob::ToBase64(key, base64_data.GetDataWriteable());

    return base64_data;
});
}

ScalarFunctionSet GenerateKeyFunction() {
  ScalarFunctionSet set("generate_key");

    set.AddFunction(ScalarFunction({LogicalType::UINTEGER},
                       LogicalType::VARCHAR, GenerateRandomKey));

    return set;
}

//------------------------------------------------------------------------------
// Register functions
//------------------------------------------------------------------------------

void CoreScalarFunctions::RegisterGenerateKeyFunction(
    DatabaseInstance &db) {
  ExtensionUtil::RegisterFunction(db, GenerateKeyFunction());
}

} // namespace core
} // namespace simple_encryption
