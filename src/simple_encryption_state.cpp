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

SimpleEncryptionState::SimpleEncryptionState(shared_ptr<ClientContext> context)
    : context_p(context) {

  // create a new connection with the db
  auto new_conn = make_shared_ptr<ClientContext>(context->db);

  // set pointer to encryption primitives (mbedtls or openssl)
  encryption_state = GetEncryptionUtil(*new_conn)->CreateEncryptionState();

  // Create a new table containing encryption metadata (nonce, tag)
  auto query = new_conn->Query("CREATE TABLE IF NOT EXISTS __simple_encryption_internal ("
                               "nonce VARCHAR, "
                               "tag VARCHAR)", false);

  if (query->HasError()) {
    throw TransactionException(query->GetError());
  }
}

void SimpleEncryptionState::QueryEnd() {
// clean up
  }
}
