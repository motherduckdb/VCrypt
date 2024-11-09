#pragma once
#include "simple_encryption/common.hpp"

namespace simple_encryption {

namespace core {

struct EncryptionTypes {
  static LogicalType E_INT();
  static LogicalType E_VARCHAR();

  static void Register(DatabaseInstance &db);
};

} // namespace core

} // namespace simple_encryption
