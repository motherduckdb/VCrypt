#pragma once

#include "vcrypt/common.hpp"

namespace vcrypt {
namespace core {

struct CoreModule {

public:
  static void Register(DatabaseInstance &db);
  static void RegisterType(DatabaseInstance &db);
};

} // namespace core
} // namespace vcrypt