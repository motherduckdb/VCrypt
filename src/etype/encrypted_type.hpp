#pragma once

#include "simple_encryption/util/cursor.hpp"

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

} // namespace duckdb