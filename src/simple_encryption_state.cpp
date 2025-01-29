#define MAX_BUFFER_SIZE 128
#include "include/simple_encryption_state.hpp"
#include "duckdb.hpp"
#include "mbedtls_wrapper.hpp"

namespace duckdb {

VCryptState::VCryptState(shared_ptr<ClientContext> context)
    : context_p(context) {

  // create a new connection with the db
  auto new_conn = make_shared_ptr<ClientContext>(context->db);

//  // set pointer to encryption primitives (mbedtls or openssl)
//  encryption_state = GetEncryptionUtil(*new_conn)->CreateEncryptionState();

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

void VCryptState::QueryEnd() {
  // clean up
}
} // namespace duckdb
