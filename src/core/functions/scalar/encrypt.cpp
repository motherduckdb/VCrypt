#define DUCKDB_EXTENSION_MAIN

#define TEST_KEY "0123456789112345"
#define MAX_BUFFER_SIZE 1024

#include "simple_encryption_extension.hpp"
#include "simple_encryption_state.hpp"
#include "duckdb.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/types.hpp"
#include "duckdb/common/encryption_state.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/function/scalar_function.hpp"
#include "duckdb/main/extension_util.hpp"
#include "mbedtls_wrapper.hpp"
#include <duckdb/parser/parsed_data/create_scalar_function_info.hpp>
#include "duckdb/common/types/blob.hpp"
#include "duckdb/main/connection_manager.hpp"
#include "simple_encryption/core/functions/scalar/encrypt.hpp"

namespace duckdb {

static void EncryptData(DataChunk &args, ExpressionState &state,
                                  Vector &result) {
  // do here stuff
  }

ScalarFunctionSet GetEncryptionFunction() {
  ScalarFunctionSet set("encrypt");

  for (auto &type : LogicalType::AllTypes()) {
    set.AddFunction(ScalarFunction({type}, LogicalType::BLOB, EncryptData));
  }

  return set;
}

//------------------------------------------------------------------------------
// Register functions
//------------------------------------------------------------------------------

//void CoreScalarFunctions::RegisterCSRCreationScalarFunctions(DatabaseInstance &db) {
//  ExtensionUtil::RegisterFunction(db, GetEncryptionFunction());
//}

}