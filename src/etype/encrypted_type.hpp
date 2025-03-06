#pragma once

#include "simple_encryption/util/cursor.hpp"
#include "etype_properties.hpp"

#include "duckdb/common/types/string_type.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/common/types/vector.hpp"
#include "duckdb/common/serializer/serializer.hpp"
#include "duckdb/common/serializer/deserializer.hpp"
#include "duckdb/common/extension_type_info.hpp"
#include "duckdb/common/extra_type_info.hpp"
#include "duckdb.hpp"
#include "duckdb/parser/parser_extension.hpp"
#include "duckdb/parser/parsed_data/create_table_function_info.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/parser/parsed_data/create_scalar_function_info.hpp"
#include "duckdb/parser/parsed_data/create_type_info.hpp"
#include "duckdb/catalog/catalog_entry/type_catalog_entry.hpp"
#include "duckdb/planner/extension_callback.hpp"
#include "duckdb/function/cast/cast_function_set.hpp"
#include "duckdb/main/extension_util.hpp"
#include "duckdb/common/vector_operations/generic_executor.hpp"
#include "duckdb/common/exception/conversion_exception.hpp"
#include "duckdb/planner/expression/bound_constant_expression.hpp"
#include "duckdb/common/extension_type_info.hpp"
#include "duckdb/common/serializer/serializer.hpp"
#include "duckdb/common/serializer/deserializer.hpp"
#include "duckdb/common/extension_type_info.hpp"
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

    static LogicalType Bind(const BindLogicalTypeInput &input) {
      auto &modifiers = input.modifiers;

      if (modifiers.size() != 1) {
        throw BinderException("ENCRYPTED type must have one internal type");
      }
      if (modifiers[0].type() != LogicalType::TINYINT) {
        throw BinderException("ENCRYPTED type must be a TINYINT");
      }
      if (modifiers[0].IsNull()) {
        throw BinderException("ENCRYPTED type cannot be NULL");
      }

      auto etype = modifiers[0].GetValue<uint8_t>();
      return Get(etype);
    }

    static LogicalType Get(uint8_t type_id) {
      auto type = LogicalType::STRUCT({{"nonce_hi", LogicalType::UBIGINT},
          {"nonce_lo", LogicalType::UBIGINT},
          {"counter", LogicalType::UINTEGER},
          {"cipher", LogicalType::USMALLINT},
          {"value", LogicalType::BLOB}});
      
      type.SetAlias("ENCRYPTED");
      auto info = make_uniq<ExtensionTypeInfo>();
      info->modifiers.emplace_back(Value::TINYINT(type_id));
      type.SetExtensionInfo(std::move(info));
      return type;
    }

    static LogicalType GetDefault() {
      auto type = LogicalType(LogicalTypeId::STRUCT);
      type.SetAlias("ENCRYPTED");
      return type;
    }

    static int32_t GetEtype(const LogicalType &type) {
      if (!type.HasExtensionInfo()) {
        throw InvalidInputException("ENCRYPTED type must have a valid LogicalType");
      }
      auto &mods = type.GetExtensionInfo()->modifiers;
      if (mods[0].value.IsNull()) {
        throw InvalidInputException("ENCRYPTED type must have a valid LogicalType");
      }
      return mods[0].value.GetValue<uint8_t>();
    }
};

  enum class SerializedEncryptedType : uint32_t {
    INVALID = 0,
    SQLNULL = 1, /* NULL type, used for constant NULL */
    UNKNOWN = 2, /* unknown type, used for parameter expressions */
    ANY =
        3, /* ANY type, used for functions that accept any type as parameter */
    USER = 4, /* A User Defined Type (e.g., ENUMs before the binder) */
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
    STRING_LITERAL = 37,  /* string literals, used for constant strings - only
                             exists while binding */
    INTEGER_LITERAL = 38, /* integer literals, used for constant integers - only
                             exists while binding */
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

} // namespace duckdb