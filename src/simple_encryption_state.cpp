#include "include/simple_encryption_state.hpp"
#include "duckdb.hpp"
#include "mbedtls_wrapper.hpp"


namespace duckdb {

// Get Encryption Util
shared_ptr<EncryptionUtil> GetEncryptionUtil(ClientContext &context_p) {

  // set pointer to factory method for the encryption state
  auto &config = DBConfig::GetConfig(context_p);

  if (config.encryption_util) {
    return config.encryption_util;
  } else {
    return make_shared_ptr<duckdb_mbedtls::MbedTlsWrapper::AESGCMStateMBEDTLSFactory>();
  }
}

SimpleEncryptionState::SimpleEncryptionState(shared_ptr<ClientContext> context) {

  // initialize encryption state
  encryption_state = GetEncryptionUtil(*context)->CreateEncryptionState();
  auto new_conn = make_shared_ptr<ClientContext>(context->db);

  // Create a new table containing encryption metadata (nonce, tag)
  auto query = new_conn->Query("CREATE TABLE IF NOT EXISTS __simple_encryption_internal ("
                               "nonce varchar, "
                               "tag varchar, ",
                               false);

  if (query->HasError()) {
    throw TransactionException(query->GetError());
  }
}
}
