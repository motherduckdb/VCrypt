#include "simple_encryption/core/types.hpp"

#include "duckdb/parser/parsed_data/create_scalar_function_info.hpp"
#include "duckdb/parser/parsed_data/create_type_info.hpp"
#include "simple_encryption/common.hpp"

namespace simple_encryption {

namespace core {

LogicalType EncryptionTypes::E_INT() {
  auto type = LogicalType::STRUCT({{"nonce", LogicalType::INTEGER}, {"value", LogicalType::INTEGER}});
  type.SetAlias("E_INT");
  return type;
}

LogicalType EncryptionTypes::E_VARCHAR() {
  auto blob_type = LogicalType::STRUCT({{"nonce", LogicalType::INTEGER}, {"value", LogicalType::VARCHAR}});
  blob_type.SetAlias("E_VARCHAR");
  return blob_type;
}

void EncryptionTypes::Register(DatabaseInstance &db) {

  // Encrypted INT
  ExtensionUtil::RegisterType(db, "E_INT", EncryptionTypes::E_INT());

  // Encrypted VARCHAR
  ExtensionUtil::RegisterType(db, "E_VARCHAR", EncryptionTypes::E_VARCHAR());
}

} // namespace core

} // namespace spatial
