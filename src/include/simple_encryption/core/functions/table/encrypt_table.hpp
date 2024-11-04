#pragma once

#include "simple_encryption/common.hpp"
#include "duckdb/function/table_function.hpp"
#include "duckdb/catalog/catalog_entry/table_catalog_entry.hpp"

namespace simple_encryption {
namespace core {

class CreateEncryptColumnFunction : public TableFunction {
public:
  CreateEncryptColumnFunction() { name = "encrypt_column"; }

  static void CreateEncryptColumnFunc(ClientContext &context,
                                      TableFunctionInput &data_p,
                                      DataChunk &output);

};
}
}