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
  E_INVALID = 0,
  E_SQLNULL = 1, /* NULL type, used for constant NULL */
  E_UNKNOWN = 2, /* unknown type, used for parameter expressions */
  E_ANY = 3,     /* ANY type, used for functions that accept any type as parameter */
  E_USER = 4,    /* A User Defined Type (e.g., ENUMs before the binder) */
  E_BOOLEAN = 10,
  E_TINYINT = 11,
  E_SMALLINT = 12,
  E_INTEGER = 13,
  E_BIGINT = 14,
  E_DATE = 15,
  E_TIME = 16,
  E_TIMESTAMP_SEC = 17,
  E_TIMESTAMP_MS = 18,
  E_TIMESTAMP = 19, //! us
  E_TIMESTAMP_NS = 20,
  E_DECIMAL = 21,
  E_FLOAT = 22,
  E_DOUBLE = 23,
  E_CHAR = 24,
  E_VARCHAR = 25,
  E_BLOB = 26,
  E_INTERVAL = 27,
  E_UTINYINT = 28,
  E_USMALLINT = 29,
  E_UINTEGER = 30,
  E_UBIGINT = 31,
  E_TIMESTAMP_TZ = 32,
  E_TIME_TZ = 34,
  E_BIT = 36,
  E_STRING_LITERAL = 37, /* string literals, used for constant strings - only exists while binding */
  E_INTEGER_LITERAL = 38,/* integer literals, used for constant integers - only exists while binding */
  E_VARINT = 39,
  E_UHUGEINT = 49,
  E_HUGEINT = 50,
  E_POINTER = 51,
  E_VALIDITY = 53,
  E_UUID = 54,

  E_STRUCT = 100,
  E_LIST = 101,
  E_MAP = 102,
  E_TABLE = 103,
  E_ENUM = 104,
  E_AGGREGATE_STATE = 105,
  E_LAMBDA = 106,
  E_UNION = 107,
  E_ARRAY = 108
};

struct EType {

  static bool IsNumeric(EncryptedType type) {
    return type == EncryptedType::E_INTEGER || type == EncryptedType::E_UINTEGER;
  }

  static bool IsVariable(EncryptedType type) {
    return type == EncryptedType::E_VARCHAR;
  }

  static string ToString(EncryptedType type) {
    switch (type) {
    case EncryptedType::E_INTEGER:
      return "E_INTEGER";
    case EncryptedType::E_UINTEGER:
      return "E_UINTEGER";
    case EncryptedType::E_VARCHAR:
      return "E_VARCHAR";
    default:
      return StringUtil::Format("UNKNOWN(%d)", static_cast<int>(type));
    }
  }

    static LogicalType Get() {
      auto type = LogicalType::STRUCT({{"nonce_hi", LogicalType::UBIGINT},
          {"nonce_lo", LogicalType::UBIGINT},
          {"counter", LogicalType::UINTEGER},
          {"cipher", LogicalType::USMALLINT},
          {"value", LogicalType::BLOB}});

      type.SetAlias("ENCRYPTED");
      return type;
    }

    static LogicalType GetDefault() {
      auto type = LogicalType::STRUCT({{"nonce_hi", LogicalType::UBIGINT},
                                       {"nonce_lo", LogicalType::UBIGINT},
                                       {"counter", LogicalType::UINTEGER},
                                       {"cipher", LogicalType::USMALLINT},
                                       {"value", LogicalType::BLOB}});
      type.SetAlias("ENCRYPTED");
      return type;
    }

    static LogicalType GetEType(LogicalType &ltype) {
      auto type = LogicalType::STRUCT({{"nonce_hi", LogicalType::UBIGINT},
                                       {"nonce_lo", LogicalType::UBIGINT},
                                       {"counter", LogicalType::UINTEGER},
                                       {"cipher", LogicalType::USMALLINT},
                                       {"value", LogicalType::BLOB}});
      type.SetAlias("ENCRYPTED");

      uint8_t type_id = static_cast<uint8_t>(ltype.InternalType());
      auto info = make_uniq<ExtensionTypeInfo>();
      info->modifiers.emplace_back(Value::TINYINT(type_id));
      type.SetExtensionInfo(std::move(info));
      return type;
    }

    static LogicalType GetEncryptedType(LogicalType &ltype) {
      auto type = LogicalType::STRUCT({{"nonce_hi", LogicalType::UBIGINT},
                                       {"nonce_lo", LogicalType::UBIGINT},
                                       {"counter", LogicalType::UINTEGER},
                                       {"cipher", LogicalType::USMALLINT},
                                       {"value", LogicalType::BLOB}});

      type.SetAlias("ENCRYPTED");
      uint8_t type_id = static_cast<uint8_t>(ltype.InternalType());
      auto info = make_uniq<ExtensionTypeInfo>();
      info->modifiers.emplace_back(Value::TINYINT(type_id));
      type.SetExtensionInfo(std::move(info));
      return type;
    }

    static LogicalType SetInternalType(uint8_t type_id) {
      auto type = Get();
      auto info = make_uniq<ExtensionTypeInfo>();
      info->modifiers.emplace_back(Value::TINYINT(type_id));
      type.SetExtensionInfo(std::move(info));
      return type;
    }

    static int32_t GetInternalType(const LogicalType &type) {
      if (!type.HasExtensionInfo()) {
        throw InvalidInputException("ENCRYPTED type does not have an internal LogicalType");
      }
      auto &mods = type.GetExtensionInfo()->modifiers;
      if (mods[0].value.IsNull()) {
        throw InvalidInputException("ENCRYPTED type must have a valid LogicalType (not NULL)");
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