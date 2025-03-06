#pragma once
#include "simple_encryption/common.hpp"

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

  static void Register(DatabaseInstance &db);
};

} // namespace core
} // namespace simple_encryption
