#include "etype_serialization.hpp"
#include "encrypted_type.hpp"
#include "duckdb/common/serializer/serializer.hpp"
#include "duckdb/common/serializer/deserializer.hpp"
//#include "duckdb/common/extension_type_info.hpp"
#include "duckdb/common/extra_type_info.hpp"

namespace duckdb {

void StructTypeInfo::Serialize(Serializer &serializer) const {
  ExtraTypeInfo::Serialize(serializer);
  serializer.WritePropertyWithDefault<child_list_t<LogicalType>>(
      200, "child_types", child_types);
}

shared_ptr<ExtraTypeInfo>
StructTypeInfo::Deserialize(Deserializer &deserializer) {
  auto result = duckdb::shared_ptr<StructTypeInfo>(new StructTypeInfo());
  deserializer.ReadPropertyWithDefault<child_list_t<LogicalType>>(
      200, "child_types", result->child_types);
  return std::move(result);
}
}
