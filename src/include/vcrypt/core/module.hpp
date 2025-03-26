#pragma once

#include "vcrypt/common.hpp"

namespace vcrypt {
namespace core {

struct CoreModule {

public:
  static void Register(DatabaseInstance &db);
  static void RegisterType(DatabaseInstance &db);
  static void SetBatchSize(uint32_t batch_size);
};

} // namespace core
} // namespace vcrypt