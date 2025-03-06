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

}

void VCryptState::QueryEnd() {
  // clean up
}
} // namespace duckdb
