#include "simple_encryption/core/types.hpp"
#include "simple_encryption/common.hpp"
#include "duckdb/common/extension_type_info.hpp"

namespace simple_encryption {

namespace core {

// available types for encryption
vector<LogicalType> EncryptionTypes::IsAvailable() {
  vector<LogicalType> types = {
      LogicalType::VARCHAR,      LogicalType::INTEGER,      LogicalType::UINTEGER,
      LogicalType::BIGINT,   LogicalType::UBIGINT, LogicalType::DATE,
      LogicalType::TIMESTAMP, LogicalType::FLOAT, LogicalType::DOUBLE
  };
  return types;
}

LogicalType EncryptionTypes::GetBasicEncryptedType() {
  return LogicalType::STRUCT({{"nonce_hi", LogicalType::UBIGINT},
                                   {"nonce_lo", LogicalType::UBIGINT},
                                   {"counter", LogicalType::UINTEGER},
                                   {"cipher", LogicalType::USMALLINT},
                                   {"value", LogicalType::BLOB}});
}

LogicalType EncryptionTypes::GetOriginalType(EncryptedType etype) {
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
    case EncryptedType::E_DATE:
      return LogicalType::DATE;
    case EncryptedType::E_TIMESTAMP:
      return LogicalType::TIMESTAMP;
    case EncryptedType::E_FLOAT:
      return LogicalType::FLOAT;
    case EncryptedType::E_DOUBLE:
      return LogicalType::DOUBLE;
    case EncryptedType::E_CHAR:
      return LogicalType::VARCHAR;
    default:
             throw InternalException("Encrypted Type not convertible to LogicalType");
  }
}

EncryptedType EncryptionTypes::GetEncryptedType(LogicalTypeId ltype) {
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
  case LogicalTypeId::DATE:
    return EncryptedType::E_DATE;
  case LogicalTypeId::TIMESTAMP:
    return EncryptedType::E_TIMESTAMP;
  case LogicalTypeId::CHAR:
    return EncryptedType::E_CHAR;
  case LogicalTypeId::FLOAT:
    return EncryptedType::E_FLOAT;
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
  case LogicalTypeId::DATE:
    return EncryptionTypes::E_DATE();
  case LogicalTypeId::TIMESTAMP:
    return EncryptionTypes::E_TIMESTAMP();
  case LogicalTypeId::CHAR:
    return EncryptionTypes::E_CHAR();
  case LogicalTypeId::FLOAT:
    return EncryptionTypes::E_FLOAT();
  case LogicalTypeId::DOUBLE:
    return EncryptionTypes::E_DOUBLE();
  default:
    throw InternalException("LogicalType not convertible to Encrypted type");
  }
}

// basic encrypted type
// todo; we can just use one encrypted type, and just emplace the original type in the type modifiers...
// the encrypted type just then needs an input (the original type)
// discuss this
LogicalType EncryptionTypes::ENCRYPTED() {
  auto type = GetBasicEncryptedType();
  type.SetAlias("ENCRYPTED");
  return type;
}

LogicalType EncryptionTypes::E_INTEGER() {
  auto type = GetBasicEncryptedType();
  type.SetAlias("E_INTEGER");
  auto info = make_uniq<ExtensionTypeInfo>();
  info->modifiers.emplace_back(Value::TINYINT((int8_t)LogicalType::INTEGER));
  type.SetExtensionInfo(std::move(info));
  return type;
}

LogicalType EncryptionTypes::E_BIGINT() {
  auto type = GetBasicEncryptedType();
  type.SetAlias("E_BIGINT");
  auto info = make_uniq<ExtensionTypeInfo>();
  info->modifiers.emplace_back(Value::TINYINT((int8_t)LogicalType::BIGINT));
  type.SetExtensionInfo(std::move(info));
  return type;
}

LogicalType EncryptionTypes::E_UBIGINT() {
  auto type = GetBasicEncryptedType();
  type.SetAlias("E_UBIGINT");
  auto info = make_uniq<ExtensionTypeInfo>();
  info->modifiers.emplace_back(Value::TINYINT((int8_t)LogicalType::UBIGINT));
  type.SetExtensionInfo(std::move(info));
  return type;
}

LogicalType EncryptionTypes::E_UINTEGER() {
  auto type = GetBasicEncryptedType();
  type.SetAlias("E_UINTEGER");
  auto info = make_uniq<ExtensionTypeInfo>();
  info->modifiers.emplace_back(Value::TINYINT((int8_t)LogicalType::UINTEGER));
  type.SetExtensionInfo(std::move(info));
  return type;
}

LogicalType EncryptionTypes::E_VARCHAR() {
  auto type = GetBasicEncryptedType();
  type.SetAlias("E_VARCHAR");
  auto info = make_uniq<ExtensionTypeInfo>();
  info->modifiers.emplace_back(Value::TINYINT((int8_t)LogicalType::VARCHAR));
  type.SetExtensionInfo(std::move(info));
  return type;
}

LogicalType EncryptionTypes::E_DATE() {
  auto type = GetBasicEncryptedType();
  type.SetAlias("E_DATE");
  auto info = make_uniq<ExtensionTypeInfo>();
  info->modifiers.emplace_back(Value::TINYINT((int8_t)LogicalType::DATE));
  type.SetExtensionInfo(std::move(info));
  return type;
}

LogicalType EncryptionTypes::E_TIMESTAMP() {
  auto type = GetBasicEncryptedType();
  type.SetAlias("E_TIMESTAMP");
  auto info = make_uniq<ExtensionTypeInfo>();
  info->modifiers.emplace_back(Value::TINYINT((int8_t)LogicalType::TIMESTAMP));
  type.SetExtensionInfo(std::move(info));
  return type;
}

LogicalType EncryptionTypes::E_DOUBLE() {
  auto type = GetBasicEncryptedType();
  type.SetAlias("E_DOUBLE");
  auto info = make_uniq<ExtensionTypeInfo>();
  info->modifiers.emplace_back(Value::TINYINT((int8_t)LogicalType::DOUBLE));
  type.SetExtensionInfo(std::move(info));
  return type;
}

LogicalType EncryptionTypes::E_CHAR() {
  auto type = GetBasicEncryptedType();
  type.SetAlias("E_CHAR");
  auto info = make_uniq<ExtensionTypeInfo>();
  info->modifiers.emplace_back(Value::TINYINT((int8_t)LogicalTypeId::CHAR));
  type.SetExtensionInfo(std::move(info));
  return type;
}

LogicalType EncryptionTypes::E_FLOAT() {
  auto type = GetBasicEncryptedType();
  type.SetAlias("E_FLOAT");
  auto info = make_uniq<ExtensionTypeInfo>();
  info->modifiers.emplace_back(Value::TINYINT((int8_t)LogicalType::FLOAT));
  type.SetExtensionInfo(std::move(info));
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
  ExtensionUtil::RegisterType(db, "E_DATE", EncryptionTypes::E_DATE());
  ExtensionUtil::RegisterType(db, "E_TIMESTAMP", EncryptionTypes::E_TIMESTAMP());
  ExtensionUtil::RegisterType(db, "E_DOUBLE", EncryptionTypes::E_DOUBLE());
  ExtensionUtil::RegisterType(db, "E_FLOAT", EncryptionTypes::E_FLOAT());

  // Encrypted VARCHAR
  ExtensionUtil::RegisterType(db, "E_VARCHAR", EncryptionTypes::E_VARCHAR());
  ExtensionUtil::RegisterType(db, "E_CHAR", EncryptionTypes::E_CHAR());
}

} // namespace core

} // namespace simple_encryption
