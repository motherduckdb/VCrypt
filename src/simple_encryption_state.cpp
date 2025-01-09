#define MAX_BUFFER_SIZE 128
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
    return make_shared_ptr<
        duckdb_mbedtls::MbedTlsWrapper::AESGCMStateMBEDTLSFactory>();
  }
}

uint32_t GenerateRandom(RandomEngine *engine) {
  return engine->NextRandomInteger();
}

SimpleEncryptionState::SimpleEncryptionState(shared_ptr<ClientContext> context)
    : context_p(context) {

  // create a new connection with the db
  auto new_conn = make_shared_ptr<ClientContext>(context->db);

  // set pointer to encryption primitives (mbedtls or openssl)
  encryption_state = GetEncryptionUtil(*new_conn)->CreateEncryptionState();

  // initialize IV with random data
  // for now, fixed seed
  RandomEngine random_engine(1);

  iv[0] = (static_cast<uint64_t>(GenerateRandom(&random_engine)) << 32) | GenerateRandom(&random_engine);
  iv[1] = GenerateRandom(&random_engine);

  // Create a new table containing encryption metadata (nonce, tag)
  // this is used for later
  auto query = new_conn->Query(
      "CREATE TABLE IF NOT EXISTS __simple_encryption_internal ("
      "nonce VARCHAR, "
      "tag VARCHAR)",
      false);

  if (query->HasError()) {
    throw TransactionException(query->GetError());
  }
}

void SimpleEncryptionState::QueryEnd() {
  // clean up
}
} // namespace duckdb
