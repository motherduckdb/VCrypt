#include "simple_encryption/core/functions/function_data/encrypt_function_data.hpp"
#include "simple_encryption/common.hpp"
#include "simple_encryption/core/crypto/crypto_primitives.hpp"
#include <duckdb/function/function.hpp>
#include "duckdb/common/helper.hpp"
#include "duckdb/main/secret/secret_manager.hpp"

namespace simple_encryption {

namespace core {

struct KeyData {
  string key;
  uint32_t length;
};

unique_ptr<FunctionData> EncryptFunctionData::Copy() const {
  return make_uniq<EncryptFunctionData>(context, key_name);
}

bool EncryptFunctionData::Equals(const FunctionData &other_p) const {
  auto &other = (const EncryptFunctionData &)other_p;
  // fix this to return the right id
  return true;
}

string EncryptFunctionData::GetKeyFromSecret(duckdb::ClientContext &context, std::string key_name) {

  // get key from secret
 auto &secret_manager = SecretManager::Get(context);
 auto transaction = CatalogTransaction::GetSystemCatalogTransaction(context);
 auto secret_entry = secret_manager.GetSecretByName(transaction, key_name);

 if (!secret_entry) {
   throw InvalidInputException("No secret found with name '%s'.", key_name);
 }

 // Safely access the secret
 if (!secret_entry->secret) {
   throw InvalidInputException("Secret found, but '%s' contains no actual secret.", key_name);
 }

 // Retrieve the (k,v) secret
 auto &secret = *secret_entry->secret;
 const auto *kv_secret = dynamic_cast<const KeyValueSecret *>(&secret);

 Value token;
 Value length;

 if (!kv_secret->TryGetValue("token", token)) {
   throw InvalidInputException("'token' not found in 'encryption' secret.");
 }

 if (!kv_secret->TryGetValue("length", length)) {
   throw InvalidInputException("'length' not found in 'encryption' secret.");
 }

 // Calculate key
 return CalculateHMAC(token.ToString(), "fixedrandom", length.GetValue<uint32_t>());
}

unique_ptr<FunctionData>
EncryptFunctionData::EncryptBind(ClientContext &context,
                                 ScalarFunction &bound_function,
                                 vector<unique_ptr<Expression>> &arguments) {

  auto &key_child = arguments[1];
  if (key_child->HasParameter()) {
    throw ParameterNotResolvedException();
  }

  if (key_child->return_type.id() != LogicalTypeId::VARCHAR || !key_child->IsFoldable()) {
    throw BinderException("Key name needs to be a constant string");
  }
  Value key_val = ExpressionExecutor::EvaluateScalar(context, *key_child);
  D_ASSERT(key_val.type().id() == LogicalTypeId::VARCHAR);
  auto &key_str = StringValue::Get(key_val);
  if (key_val.IsNull() || key_str.empty()) {
    throw BinderException("Key name needs to be neither NULL nor empty");
  }

  auto key_name = StringUtil::Lower(key_str);

  return make_uniq<EncryptFunctionData>(context, key_name);
}
} // namespace core
} // namespace simple_encryption
