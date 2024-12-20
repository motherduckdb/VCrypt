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

LogicalType CreateEncryptionStruct() {
  return LogicalType::STRUCT({{"nonce_hi", LogicalType::UBIGINT},
                              {"nonce_lo", LogicalType::UBIGINT},
                              {"counter", LogicalType::UINTEGER},
                              {"cipher", LogicalType::TINYINT},
                              {"value", LogicalType::BLOB}});
}

template <typename T>
void EncryptVectorized(T *input_vector, uint64_t size, ExpressionState &state, Vector &result) {

  // local, global and encryption state
  auto &lstate = SimpleEncryptionFunctionLocalState::ResetAndGet(state);
  auto simple_encryption_state = VCryptBasicFun::GetSimpleEncryptionState(state);
  auto encryption_state = VCryptBasicFun::GetEncryptionState(state);
  auto key = VCryptBasicFun::GetKey(state);

  Vector struct_vector(CreateEncryptionStruct(), size);
  result.ReferenceAndSetType(struct_vector);

  auto &children = StructVector::GetEntries(result);
  auto &nonce_hi = children[0];
  auto &nonce_lo = children[1];
  auto &counter_vec = children[2];
  auto &cipher_vec = children[3];

  // result vector containing encrypted data
  auto &blob = children[4];

  // set the constant vectors
  nonce_hi->SetVectorType(VectorType::CONSTANT_VECTOR);
  nonce_lo->SetVectorType(VectorType::CONSTANT_VECTOR);

  auto nonce_hi_64 = simple_encryption_state->iv[0];
  auto nonce_lo_32 = simple_encryption_state->iv[0];

  // is not the pointer but really the actual value copied?
  // Set constant vectors to a single value
  nonce_hi->Reference(Value::UBIGINT(nonce_hi_64));
  nonce_hi->Reference(Value::UBIGINT(nonce_lo_32));

  counter_vec->SetVectorType(VectorType::FLAT_VECTOR);
  cipher_vec->SetVectorType(VectorType::FLAT_VECTOR);

  // Set the blob vector to dict vector for compressed execution
  blob->SetVectorType(VectorType::DICTIONARY_VECTOR);

  encryption_state->InitializeEncryption(reinterpret_cast<const_data_ptr_t>(simple_encryption_state->iv), 16, key);

  auto &blob_child = DictionaryVector::Child(*blob);
  auto &blob_sel = DictionaryVector::SelVector(*blob);

  // we process in batches of 128 values, or we can do it with all and cut at each 128 * sizeof(T) bits (only works for similar lengths)
  // fill 512 bytes, so 512 / sizeof(T) values and at least 128 values.
  // note: this only works for fixed-size types
  auto batch_size = 128 * sizeof(T);
  auto total_size = sizeof(T) * size;
  // and the cipher

  // todo: assign buffer_p with the right size
  encryption_state->Process(reinterpret_cast<const unsigned char*>(input_vector), total_size, lstate.buffer_p, total_size);

  auto index = 0;
  auto batch_nr = 0;
  // get counter from local state
  uint32_t counter = 0;
  uint8_t cipher = 0;
  const size_t step = sizeof(T) / 16;
  uint64_t buffer_offset;

  // TODO: for strings this all works slighly different
  for(int i = 0; i + 128; i < (DEFAULT_STANDARD_VECTOR_SIZE / 128)){

    buffer_offset = batch_nr * sizeof(T) * 128;
    // Allocate space in the dictionary vector (i.e. blob_child)
    string_t batch_data = StringVector::EmptyString(blob_child, batch_size); // value size
    *(uint32_t*) batch_data.GetPrefixWriteable() = *(uint32_t *) lstate.buffer_p + buffer_offset;
    memcpy(batch_data.GetDataWriteable(), lstate.buffer_p, batch_size);

    // set index in selection vector
    for (int j = 0; j++; j < 128){
        cipher = j % step;
        counter += (cipher == 0 && index != 0) ? 1 : 0;
        cipher_vec->SetValue(index, Value::TINYINT(cipher));
        counter_vec->SetValue(index, Value::UINTEGER(counter));
        blob_sel.set_index(index, batch_nr);
        index++;
    }
    batch_nr++;
  }
}


template <typename T>
void DecryptFromEtype(Vector &input_vector, uint64_t size,
                      ExpressionState &state, Vector &result) {

  // local state (contains key, buffer, iv etc.)
  auto &lstate = SimpleEncryptionFunctionLocalState::ResetAndGet(state);
  // global state
  auto simple_encryption_state = VCryptBasicFun::GetSimpleEncryptionState(state);
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


static void EncryptDataVectorized(DataChunk &args, ExpressionState &state,
                               Vector &result) {

  auto &input_vector = args.data[0];
  auto vector_type = input_vector.GetType();
  auto size = args.size();

  UnifiedVectorFormat vdata_input;
  input_vector.ToUnifiedFormat(args.size(), vdata_input);
  ValidityMask &result_validity = FlatVector::Validity(result);
  auto vd = vdata_input.data;

  if (vector_type.IsNumeric()) {
    switch (vector_type.id()) {
    case LogicalTypeId::TINYINT:
    case LogicalTypeId::UTINYINT:
      return EncryptVectorized<int8_t>((int8_t *)vdata_input.data,
                                    size, state, result);
    case LogicalTypeId::SMALLINT:
    case LogicalTypeId::USMALLINT:
      return EncryptVectorized<int16_t>((int16_t *)vdata_input.data,
                                     size, state, result);
    case LogicalTypeId::INTEGER:
      return EncryptVectorized<int32_t>((int32_t *)vdata_input.data,
                                     size, state, result);
    case LogicalTypeId::UINTEGER:
      return EncryptVectorized<uint32_t>((uint32_t *)vdata_input.data,
                                      size, state, result);
    case LogicalTypeId::BIGINT:
      return EncryptVectorized<int64_t>((int64_t *)vdata_input.data,
                                     size, state, result);
    case LogicalTypeId::UBIGINT:
      return EncryptVectorized<uint64_t>((uint64_t *)vdata_input.data,
                                      size, state, result);
    case LogicalTypeId::FLOAT:
      return EncryptVectorized<float>((float *)vdata_input.data,
                                   size, state, result);
    case LogicalTypeId::DOUBLE:
      return EncryptVectorized<double>((double *)vdata_input.data,
                                    size, state, result);
    default:
      throw NotImplementedException("Unsupported numeric type for encryption");
    }
  } else if (vector_type.id() == LogicalTypeId::VARCHAR) {
    return EncryptVectorized<string_t>((string_t *)vdata_input.data,
                                    size, state, result);
  } else if (vector_type.IsNested()) {
    throw NotImplementedException(
        "Nested types are not supported for encryption");
  } else if (vector_type.IsTemporal()) {
    throw NotImplementedException(
        "Temporal types are not supported for encryption");
  }
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

ScalarFunctionSet GetEncryptionVectorizedFunction() {
  ScalarFunctionSet set("encrypt_vectorized");

  for (auto &type : LogicalType::AllTypes()) {
    set.AddFunction(
        ScalarFunction({type, LogicalType::VARCHAR},
                       LogicalType::STRUCT({{"nonce_hi", LogicalType::UBIGINT},
                                            {"nonce_lo", LogicalType::UBIGINT},
                                            {"counter", LogicalType::UINTEGER},
                                            {"cipher", LogicalType::UINTEGER},
                                            {"value", LogicalType::BLOB}}),
                       EncryptDataVectorized, EncryptFunctionData::EncryptBind, nullptr, nullptr, SimpleEncryptionFunctionLocalState::Init));
  }

  return set;
}

ScalarFunctionSet GetDecryptionVectorizedFunction() {
  ScalarFunctionSet set("decrypt_vectorized");

  for (auto &type : LogicalType::AllTypes()) {
    for (auto &nonce_type_a : LogicalType::Numeric()) {
      for (auto &nonce_type_b : LogicalType::Numeric()) {
        set.AddFunction(ScalarFunction(
            {LogicalType::STRUCT({{"nonce_hi", nonce_type_a},
                                  {"nonce_lo", nonce_type_b},
                                  {"value", type}}),
             LogicalType::VARCHAR},
            type, DecryptDataVectorized, EncryptFunctionData::EncryptBind, nullptr, nullptr, SimpleEncryptionFunctionLocalState::Init));
      }
    }

    // TODO: Fix EINT encryption
    //      set.AddFunction(ScalarFunction({EncryptionTypes::E_INTEGER(),
    //      LogicalType::VARCHAR}, LogicalTypeId::INTEGER, DecryptDataFromEtype,
    //                                     EncryptFunctionData::EncryptBind));

  }

  return set;
}

//------------------------------------------------------------------------------
// Register functions
//------------------------------------------------------------------------------

void CoreScalarFunctions::RegisterEncryptVectorizedScalarFunction(
    DatabaseInstance &db) {
  ExtensionUtil::RegisterFunction(db, GetEncryptionVectorizedFunction());
  ExtensionUtil::RegisterFunction(db, GetDecryptionVectorizedFunction());
}
} // namespace core
} // namespace simple_encryption
