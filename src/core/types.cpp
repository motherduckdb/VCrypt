#include "simple_encryption/core/types.hpp"

#include "duckdb/parser/parsed_data/create_scalar_function_info.hpp"
#include "duckdb/parser/parsed_data/create_type_info.hpp"
#include "simple_encryption/common.hpp"
#include "duckdb/common/extension_type_info.hpp"
#include "../etype/encrypted_type.hpp"

namespace simple_encryption {

namespace core {

// for all types in an ENUM
LogicalType EncryptionTypes::GetBasicEncryptedType() {
  return LogicalType::STRUCT({{"nonce_hi", LogicalType::UBIGINT},
                                   {"nonce_lo", LogicalType::UBIGINT},
                                   {"counter", LogicalType::UINTEGER},
                                   {"cipher", LogicalType::USMALLINT},
                                   {"value", LogicalType::BLOB}});
}

static LogicalType GetOriginalType(EncryptedType etype) {
  // needs an integer type
  switch(etype){
    case EncryptedType::E_INTEGER:
      return LogicalType::INTEGER;
    case EncryptedType::E_UINTEGER:
      return LogicalType::UINTEGER;
    case EncryptedType::E_BIGINT:
      return LogicalType::BIGINT;
    case EncryptedType::E_UBIGINT:
      return LogicalType::UBIGINT;
    case EncryptedType::E_VARCHAR:
      return LogicalType::VARCHAR;
    default:
             throw InternalException("Encrypted Type not convertible to LogicalType");
  }
}

static EncryptedType GetEncryptedType(LogicalTypeId ltype) {
  switch (ltype) {
  case LogicalType::INTEGER:
    return EncryptedType::E_INTEGER;
  case LogicalType::UINTEGER:
    return EncryptedType::E_UINTEGER;
  case LogicalType::BIGINT:
    return EncryptedType::E_BIGINT;
  case LogicalType::UBIGINT:
    return EncryptedType::E_UBIGINT;
  case LogicalType::VARCHAR:
    return EncryptedType::E_VARCHAR;
  default:
    throw InternalException("LogicalType not convertible to Encrypted type");
  }
}

LogicalType EncryptionTypes::GetEncryptionType(LogicalTypeId ltype) {
  switch (ltype) {
  case LogicalType::INTEGER:
    return EncryptionTypes::E_INTEGER();
  case LogicalType::UINTEGER:
    return EncryptionTypes::E_UINTEGER();
  case LogicalType::BIGINT:
    return EncryptionTypes::E_BIGINT();
  case LogicalType::UBIGINT:
    return EncryptionTypes::E_UBIGINT();
  case LogicalType::VARCHAR:
    return EncryptionTypes::E_VARCHAR();
  default:
    throw InternalException("LogicalType not convertible to Encrypted type");
  }
}

// basic encrypted type
LogicalType EncryptionTypes::ENCRYPTED() {
  auto type = GetBasicEncryptedType();
  type.SetAlias("ENCRYPTED");
  return type;
}

LogicalType EncryptionTypes::E_INTEGER() {
  auto type = GetBasicEncryptedType();
  type.SetAlias("E_INTEGER");
  return type;
}

LogicalType EncryptionTypes::E_BIGINT() {
  auto type = GetBasicEncryptedType();
  type.SetAlias("E_BIGINT");
  return type;
}

LogicalType EncryptionTypes::E_UBIGINT() {
  auto type = GetBasicEncryptedType();
  type.SetAlias("E_UBIGINT");
  return type;
}

LogicalType EncryptionTypes::E_UINTEGER() {
  auto type = GetBasicEncryptedType();
  type.SetAlias("E_UINTEGER");
  return type;
}

LogicalType EncryptionTypes::E_VARCHAR() {
  auto type = GetBasicEncryptedType();
  type.SetAlias("E_VARCHAR");
  return type;
}

void EncryptionTypes::Register(DatabaseInstance &db) {

  // register encrypted type
  ExtensionUtil::RegisterType(db, "ENCRYPTED", EncryptionTypes::ENCRYPTED());

  // Supported Numeric Values
  ExtensionUtil::RegisterType(db, "E_INTEGER", EncryptionTypes::E_INTEGER());
  ExtensionUtil::RegisterType(db, "E_UINTEGER", EncryptionTypes::E_UINTEGER());
  ExtensionUtil::RegisterType(db, "E_BIGINT", EncryptionTypes::E_BIGINT());
  ExtensionUtil::RegisterType(db, "E_UBIGINT", EncryptionTypes::E_UBIGINT());

  // Encrypted VARCHAR
  ExtensionUtil::RegisterType(db, "E_VARCHAR", EncryptionTypes::E_VARCHAR());
}

} // namespace core

} // namespace simple_encryption
