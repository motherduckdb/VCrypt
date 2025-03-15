#pragma once
#include "vcrypt/common.hpp"

namespace simple_encrypt {

namespace core {

struct EncryptionFactory;

struct CoreVectorOperations {
public:
  static void EVarToVarchar(Vector &source, Vector &result, idx_t count);
};

struct CoreCastFunctions {
public:
  static void Register(DatabaseInstance &db) { RegisterVarcharCasts(db); }

private:
  static void RegisterVarcharCasts(DatabaseInstance &db);
};

} // namespace core

} // namespace simple_encrypt