#pragma once

#include "simple_encryption/common.hpp"

namespace simple_encryption {
namespace core {

struct CoreModule {

public:
  static void Register(DatabaseInstance &db);
};

} // namespace core
} // namespace simple_encryption