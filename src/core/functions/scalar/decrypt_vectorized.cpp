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

#define BATCH_SIZE 128

namespace simple_encryption {

namespace core {

LogicalType CreateDecryptionStruct() {
  return LogicalType::STRUCT({{"nonce_hi", LogicalType::UBIGINT},
                              {"nonce_lo", LogicalType::UBIGINT},
                              {"counter", LogicalType::UINTEGER},
                              {"cipher", LogicalType::TINYINT},
                              {"value", LogicalType::BLOB}});
}

template <typename T>
void DecryptFromEtype(Vector &input_vector, uint64_t size,
                      ExpressionState &state, Vector &result) {

  // local state (contains key, buffer, iv etc.)
  auto &lstate = VCryptFunctionLocalState::ResetAndGet(state);
  // global state
  auto simple_encryption_state = VCryptBasicFun::GetVCryptState(state);
  auto encryption_state = VCryptBasicFun::GetEncryptionState(state);

  // Get Key from Bind
  auto key = VCryptBasicFun::GetKey(state);

  //  using ENCRYPTED_TYPE = StructTypeTernary<uint64_t, uint64_t, T>;
  //  using PLAINTEXT_TYPE = PrimitiveType<T>;
  //
  //  GenericExecutor::ExecuteUnary<ENCRYPTED_TYPE, PLAINTEXT_TYPE>(
  //      input_vector, result, size, [&](ENCRYPTED_TYPE input) {
  //        simple_encryption_state->iv[0] = input.a_val;
  //        simple_encryption_state->iv[1] = input.b_val;
  //
  //        encryption_state->InitializeDecryption(
  //            reinterpret_cast<const_data_ptr_t>(simple_encryption_state->iv), 12,
  //            reinterpret_cast<const string *>(key));
  //
  //        T decrypted_data =
  //            ProcessVectorizedDecrypt(encryption_state, result, input.c_val,
  //                                  lstate.buffer_p);
  //        return decrypted_data;
  //      });
}


static void DecryptDataVectorized(DataChunk &args, ExpressionState &state,
                                  Vector &result) {

  auto size = args.size();
  auto &input_vector = args.data[0];

  auto &children = StructVector::GetEntries(input_vector);
  // get type of vector containing encrypted values
  auto vector_type = children[2]->GetType();

  if (vector_type.IsNumeric()) {
    switch (vector_type.id()) {
    case LogicalTypeId::TINYINT:
    case LogicalTypeId::UTINYINT:
      return DecryptFromEtype<int8_t>(input_vector, size, state, result);
    case LogicalTypeId::SMALLINT:
    case LogicalTypeId::USMALLINT:
      return DecryptFromEtype<int16_t>(input_vector, size, state,
                                       result);
    case LogicalTypeId::INTEGER:
      return DecryptFromEtype<int32_t>(input_vector, size, state,
                                       result);
    case LogicalTypeId::UINTEGER:
      return DecryptFromEtype<uint32_t>(input_vector, size, state,
                                        result);
    case LogicalTypeId::BIGINT:
      return DecryptFromEtype<int64_t>(input_vector, size, state,
                                       result);
    case LogicalTypeId::UBIGINT:
      return DecryptFromEtype<uint64_t>(input_vector, size, state,
                                        result);
    case LogicalTypeId::FLOAT:
      return DecryptFromEtype<float>(input_vector, size, state, result);
    case LogicalTypeId::DOUBLE:
      return DecryptFromEtype<double>(input_vector, size, state, result);
    default:
      throw NotImplementedException("Unsupported numeric type for decryption");
    }
  } else if (vector_type.id() == LogicalTypeId::VARCHAR) {
    return DecryptFromEtype<string_t>(input_vector, size, state, result);
  } else if (vector_type.IsNested()) {
    throw NotImplementedException(
        "Nested types are not supported for decryption");
  } else if (vector_type.IsTemporal()) {
    throw NotImplementedException(
        "Temporal types are not supported for decryption");
  }
}

ScalarFunctionSet GetDecryptionVectorizedFunction() {
  ScalarFunctionSet set("decrypt_vectorized");

  for (auto &type : LogicalType::AllTypes()) {
        set.AddFunction(ScalarFunction(
            {LogicalType::STRUCT({{"nonce_hi", LogicalType::UBIGINT},
                                  {"nonce_lo", LogicalType::UBIGINT},
                                  {"counter", LogicalType::UINTEGER},
                                  {"cipher", LogicalType::TINYINT},
                                  {"value", LogicalType::BLOB}}),
             type},
            type, DecryptDataVectorized, EncryptFunctionData::EncryptBind, nullptr, nullptr, VCryptFunctionLocalState::Init));
  }

  return set;
}

//------------------------------------------------------------------------------
// Register functions
//------------------------------------------------------------------------------

void CoreScalarFunctions::RegisterEncryptVectorizedScalarFunction(
    DatabaseInstance &db) {
  ExtensionUtil::RegisterFunction(db, GetDecryptionVectorizedFunction());
}
} // namespace core
} // namespace simple_encryption

