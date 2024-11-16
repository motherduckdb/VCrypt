#pragma once

#include "duckdb/common/encryption_state.hpp"
#include "duckdb/common/helper.hpp"

#include <stddef.h>
#include <string>

typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;

namespace duckdb {

class DUCKDB_EXTENSION_API AESStateSSL : public duckdb::EncryptionState {

public:
  explicit AESStateSSL();
  ~AESStateSSL() override;

  // We can use GCM, CTR or OCB
  enum Algorithm { GCM, CTR, OCB };

public:
  bool IsOpenSSL() override;
  void InitializeEncryption(const_data_ptr_t iv, idx_t iv_len,
                            const std::string *key) override;
  void InitializeDecryption(const_data_ptr_t iv, idx_t iv_len,
                            const std::string *key) override;
  size_t Process(const_data_ptr_t in, idx_t in_len, data_ptr_t out,
                 idx_t out_len) override;
  size_t Finalize(data_ptr_t out, idx_t out_len, data_ptr_t tag,
                  idx_t tag_len) override;
  void GenerateRandomData(data_ptr_t data, idx_t len) override;

  // crypto-specific functions
  void SetEncryptionAlgorithm(string_t s_algorithm);

private:
  bool ssl = true;
  EVP_CIPHER_CTX *context;
  Mode mode;

  // default value is GCM
  Algorithm algorithm = CTR;
};

} // namespace duckdb

extern "C" {

class DUCKDB_EXTENSION_API AESStateSSLFactory : public duckdb::EncryptionUtil {
public:
  explicit AESStateSSLFactory() {}

  duckdb::shared_ptr<duckdb::EncryptionState>
  CreateEncryptionState() const override {
    return duckdb::make_shared_ptr<duckdb::AESStateSSL>();
  }

  ~AESStateSSLFactory() override {}
};
}