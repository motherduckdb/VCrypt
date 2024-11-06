#pragma once

#include "simple_encryption/common.hpp"
#include "duckdb/common/encryption_state.hpp"

#ifndef DUCKDB_AMALGAMATION
#include "duckdb/storage/object_cache.hpp"
#endif

namespace simple_encryption {

namespace core {

class SimpleEncryptKeys : public ObjectCacheEntry {

public:
  static SimpleEncryptKeys &Get(ClientContext &context);

public:
  void AddKey(const string &key_name, const string &key);
  bool HasKey(const string &key_name) const;
  const string &GetKey(const string &key_name) const;

public:
  static string ObjectType();
  string GetObjectType() override;

private:
  unordered_map<string, string> keys;
};

}
}