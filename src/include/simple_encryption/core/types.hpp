#pragma once
#include "simple_encryption/common.hpp"
#include "../etype/encrypted_type.hpp"

namespace simple_encryption {

namespace core {

struct EncryptionTypes {
  static LogicalType E_INTEGER();
  static LogicalType EA_INTEGER();
  static LogicalType E_UINTEGER();
  static LogicalType EA_UINTEGER();
  static LogicalType E_BIGINT();
  static LogicalType E_UBIGINT();
  static LogicalType E_VARCHAR();
  static LogicalType E_DATE();
  static LogicalType E_TIMESTAMP();
  static LogicalType E_DECIMAL();
  static LogicalType E_FLOAT();
  static LogicalType E_DOUBLE();
  static LogicalType E_CHAR();
  static LogicalType ENCRYPTED();

  static void Register(DatabaseInstance &db);
  static LogicalType GetBasicEncryptedType();
  static LogicalType GetEncryptionType(LogicalTypeId ltype);
  static vector<LogicalType> IsAvailable();
  static LogicalType GetOriginalType(EncryptedType etype);
  static EncryptedType GetEncryptedType(LogicalTypeId ltype);
};

} // namespace core
} // namespace simple_encryption
