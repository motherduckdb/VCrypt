#pragma once

#include "simple_encryption/util/cursor.hpp"
#include "etype_properties.hpp"

#include "duckdb/common/types/string_type.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/common/types/vector.hpp"
#include "duckdb/common/serializer/serializer.hpp"
#include "duckdb/common/serializer/deserializer.hpp"
#include "duckdb/common/extra_type_info.hpp"

namespace duckdb {

enum class EncryptedType : uint8_t {
  INVALID = 0,
  SQLNULL = 1, /* NULL type, used for constant NULL */
  UNKNOWN = 2, /* unknown type, used for parameter expressions */
  ANY = 3,     /* ANY type, used for functions that accept any type as parameter */
  USER = 4,    /* A User Defined Type (e.g., ENUMs before the binder) */
  BOOLEAN = 10,
  TINYINT = 11,
  SMALLINT = 12,
  INTEGER = 13,
  BIGINT = 14,
  DATE = 15,
  TIME = 16,
  TIMESTAMP_SEC = 17,
  TIMESTAMP_MS = 18,
  TIMESTAMP = 19, //! us
  TIMESTAMP_NS = 20,
  DECIMAL = 21,
  FLOAT = 22,
  DOUBLE = 23,
  CHAR = 24,
  VARCHAR = 25,
  BLOB = 26,
  INTERVAL = 27,
  UTINYINT = 28,
  USMALLINT = 29,
  UINTEGER = 30,
  UBIGINT = 31,
  TIMESTAMP_TZ = 32,
  TIME_TZ = 34,
  BIT = 36,
  STRING_LITERAL = 37, /* string literals, used for constant strings - only exists while binding */
  INTEGER_LITERAL = 38,/* integer literals, used for constant integers - only exists while binding */
  VARINT = 39,
  UHUGEINT = 49,
  HUGEINT = 50,
  POINTER = 51,
  VALIDITY = 53,
  UUID = 54,

  STRUCT = 100,
  LIST = 101,
  MAP = 102,
  TABLE = 103,
  ENUM = 104,
  AGGREGATE_STATE = 105,
  LAMBDA = 106,
  UNION = 107,
  ARRAY = 108
};

struct Etype {
  static bool IsNumeric(EncryptedType type) {
    return type == EncryptedType::INTEGER || type == EncryptedType::UINTEGER;
  }

  static bool IsVariable(EncryptedType type) {
    return type == EncryptedType::VARCHAR;
  }

  static string ToString(EncryptedType type) {
    switch (type) {
    case EncryptedType::INTEGER:
      return "E_INTEGER";
    case EncryptedType::UINTEGER:
      return "E_UINTEGER";
    case EncryptedType::VARCHAR:
      return "E_VARCHAR";
    default:
      return StringUtil::Format("UNKNOWN(%d)", static_cast<int>(type));
    }
  }
};

enum class SerializedEncryptedType : uint32_t {
  INVALID = 0,
  SQLNULL = 1, /* NULL type, used for constant NULL */
  UNKNOWN = 2, /* unknown type, used for parameter expressions */
  ANY = 3,     /* ANY type, used for functions that accept any type as parameter */
  USER = 4,    /* A User Defined Type (e.g., ENUMs before the binder) */
  BOOLEAN = 10,
  TINYINT = 11,
  SMALLINT = 12,
  INTEGER = 13,
  BIGINT = 14,
  DATE = 15,
  TIME = 16,
  TIMESTAMP_SEC = 17,
  TIMESTAMP_MS = 18,
  TIMESTAMP = 19, //! us
  TIMESTAMP_NS = 20,
  DECIMAL = 21,
  FLOAT = 22,
  DOUBLE = 23,
  CHAR = 24,
  VARCHAR = 25,
  BLOB = 26,
  INTERVAL = 27,
  UTINYINT = 28,
  USMALLINT = 29,
  UINTEGER = 30,
  UBIGINT = 31,
  TIMESTAMP_TZ = 32,
  TIME_TZ = 34,
  BIT = 36,
  STRING_LITERAL = 37, /* string literals, used for constant strings - only exists while binding */
  INTEGER_LITERAL = 38,/* integer literals, used for constant integers - only exists while binding */
  VARINT = 39,
  UHUGEINT = 49,
  HUGEINT = 50,
  POINTER = 51,
  VALIDITY = 53,
  UUID = 54,
  STRUCT = 100,
  LIST = 101,
  MAP = 102,
  TABLE = 103,
  ENUM = 104,
  AGGREGATE_STATE = 105,
  LAMBDA = 106,
  UNION = 107,
  ARRAY = 108
};


class encrypted_t {
private:
  EncryptedType etype;
  StructVector vector_data;

public:
  encrypted_t() = default;

  explicit encrypted_t(EncryptedType type, StructVector *vector_data)
      : etype(type), vector_data(*vector_data) {}

  EncryptedType GetEncryptionType() const { return etype; }
  StructVector &GetVectorData() { return vector_data; }

//  static void Serialize(Serializer &serializer) {
//    serializer.WritePropertyWithDefault<uint8_t>(200, "etype", static_cast<const uint8_t>(etype));
//    serialize.vector_data.Serialize(serializer);
//  }
//
//  shared_ptr<ExtraTypeInfo> Deserialize(Deserializer &deserializer) {
//    auto etype = static_cast<EncryptedType>(deserializer.Read<uint8_t>());
//    StructVector struct_data = StructVector::Deserialize(deserializer);
//    return encrypted_t(etype, struct_data.GetType());
  };

} // namespace duckdb