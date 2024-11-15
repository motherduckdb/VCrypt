#include "simple_encryption/core/types.hpp"

#include "duckdb/parser/parsed_data/create_scalar_function_info.hpp"
#include "duckdb/parser/parsed_data/create_type_info.hpp"
#include "simple_encryption/common.hpp"

namespace simple_encryption {

namespace core {

LogicalType EncryptionTypes::E_INTEGER() {
  auto type = LogicalType::STRUCT(
      {{"nonce_hi", LogicalType::BIGINT}, {"nonce_lo", LogicalType::BIGINT}, {"value", LogicalType::INTEGER}});
  type.SetAlias("E_INTEGER");
  return type;
}

LogicalType EncryptionTypes::EA_INTEGER() {
  auto type = LogicalType::STRUCT(
      {{"value", LogicalType::INTEGER}, {"nonce_hi", LogicalType::BIGINT}, {"nonce_lo", LogicalType::BIGINT},
       {"tag", LogicalType::VARCHAR}});
  type.SetAlias("EA_INTEGER");
  return type;
}

LogicalType EncryptionTypes::E_UINTEGER() {
  auto type = LogicalType::STRUCT(
      {{"nonce_hi", LogicalType::BIGINT}, {"nonce_lo", LogicalType::BIGINT}, {"value", LogicalType::UINTEGER}});
  type.SetAlias("E_UINTEGER");
  return type;
}

LogicalType EncryptionTypes::EA_UINTEGER() {
  auto type = LogicalType::STRUCT(
      {{"value", LogicalType::UINTEGER}, {"nonce_hi", LogicalType::BIGINT}, {"nonce_lo", LogicalType::BIGINT},
       {"tag", LogicalType::VARCHAR}});
  type.SetAlias("EA_UINTEGER");
  return type;
}

LogicalType EncryptionTypes::E_VARCHAR() {
  auto type = LogicalType::STRUCT(
      {{"nonce_hi", LogicalType::BIGINT}, {"nonce_lo", LogicalType::BIGINT}, {"value", LogicalType::VARCHAR}});
type.SetAlias("E_VARCHAR");
  return type;
}

void EncryptionTypes::Register(DatabaseInstance &db) {

  // Supported Numeric Values
  ExtensionUtil::RegisterType(db, "E_INTEGER", EncryptionTypes::E_INTEGER());
  ExtensionUtil::RegisterType(db, "E_UINTEGER", EncryptionTypes::E_UINTEGER());

  // Encrypted VARCHAR
  ExtensionUtil::RegisterType(db, "E_VARCHAR", EncryptionTypes::E_VARCHAR());
}

} // namespace core

} // namespace simple_encryption
