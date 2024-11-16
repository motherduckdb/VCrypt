#include "simple_encryption/core/functions/secrets.hpp"
#include "simple_encryption/common.hpp"
#include "simple_encryption/core/utils/simple_encryption_utils.hpp"
#include "simple_encryption/core/crypto/crypto_primitives.hpp"
#include "simple_encryption/core/functions/scalar.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/main/secret/secret.hpp"
#include "duckdb/main/extension_util.hpp"
#include "openssl/rand.h"
#include <fstream>
#include <cstdlib>

namespace simple_encryption {

namespace core {

 string_t GenerateDataEncryptionKey(const uint32_t size){

   unsigned char* key = new unsigned char[size];

   // generate random bytes with OpenSSL function
   RAND_bytes(key, size);

   // cast back to string ('normal' string, not duckdb string)
   std::string key_string(reinterpret_cast<char*>(key), size);

  return key_string;
}

string_t GetDataEncryptionKey(const uint32_t size){

  switch(size){
  case 16:
    return GenerateDataEncryptionKey(16);
  case 24:
    return GenerateDataEncryptionKey(24);
  case 32:
    return GenerateDataEncryptionKey(32);
  default:
    throw InvalidInputException("Invalid size for data encryption key: '%d', expected: 16, 24, or 32", size);
  }
}

// This code partly copied / inspired by the gsheets extension for duckdb
static void CopySecret(const std::string &key, const CreateSecretInput &input,
                       KeyValueSecret &result) {

  // this method checks whether a secret_param is present in the secret_map
  auto val = input.options.find(key);
  // does this also take a key, value or list struct?
  if (val != input.options.end()) {
    result.secret_map[key] = val->second;
  }
}

static void RegisterCommonSecretParameters(CreateSecretFunction &function) {
  // Register named parameters for encryption of columns
  // key encryption key (kek) (keks encrypt/decrypt data encryption keys (deks))
  function.named_parameters["kek"] = LogicalType::VARCHAR;
  function.named_parameters["column"] = LogicalType::VARCHAR;
  function.named_parameters["key_id"] = LogicalType::VARCHAR;
}

static void InsertColumnKeys(KeyValueSecret &result, string column_key_name) {
  result.redact_keys.insert(column_key_name);
}

static unique_ptr<BaseSecret>
CreateKeyEncryptionKey(ClientContext &context, CreateSecretInput &input) {

  auto scope = input.scope;

  auto result =
      make_uniq<KeyValueSecret>(scope, input.type, input.provider, input.name);

  // Manage specific secret option
  CopySecret("column", input, *result);
  CopySecret("key_id", input, *result);

  // Redact sensible keys
//  RedactCommonKeys(*result);

  result->redact_keys.insert("column");

  return std::move(result);
}

void CoreSecretFunctions::RegisterStoreEncryptSecretFunction(DatabaseInstance &db) {

  string type = "internal";

  // Register the new secret type
  SecretType secret_type;
  secret_type.name = type;
  secret_type.deserializer = KeyValueSecret::Deserialize<KeyValueSecret>;
  secret_type.default_provider = "client";
  ExtensionUtil::RegisterSecretType(db, secret_type);

  // Register the key_encryption_key secret provider
  CreateSecretFunction key_encryption_key = {type, "client", CreateKeyEncryptionKey};

  key_encryption_key.named_parameters["client"] = LogicalType::VARCHAR;
  RegisterCommonSecretParameters(key_encryption_key);
  ExtensionUtil::RegisterFunction(db, key_encryption_key);

}

}
}