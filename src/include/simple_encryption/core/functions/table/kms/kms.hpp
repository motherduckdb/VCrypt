#pragma once

#include "simple_encryption/common.hpp"
#include "duckdb/function/table_function.hpp"
#include "duckdb/catalog/catalog_entry/table_catalog_entry.hpp"

namespace simple_encryption {
namespace core {

class CreateKMS : public TableFunction {
public:
  CreateKMS() { name = "create_kms"; }

  static void CreateKMSFunc(ClientContext &context,
                            TableFunctionInput &data_p,
                            DataChunk &output);
};
} // namespace core
} // namespace simple_encryption