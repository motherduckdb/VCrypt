#if 0

// ---------- We can check whether ctr and cpr are increasing ----------

//  TODO; we can decrypt en put everything in 1 go, IF;
// the counter is 128x the same for the whole vector
// the cipher is increasing
// the selection vector in the dict is sequential (128 x the same in the sel vec) the cipher is increasing from 0 to 127

bool CheckSequenceInDict(SelectionVector &dict_sel_value, uint64_t size) {
  idx_t child_idx;
  idx_t prev_idx = dict_sel_value.get_index(0);
  uint16_t count = 0;

  for (idx_t i = 0; i < size; i++) {
    if (!count) {
      prev_idx = dict_sel_value.get_index(i);
    }
    child_idx = dict_sel_value.get_index(i);

    if (child_idx != prev_idx) {
      // not all values are in the same batch
      return false;
    }
    count++;

    if (count == BATCH_SIZE) {
      count = 0;
    }
  }
  return true;
}

template <typename T>
void DecryptPerValue(uint64_t *nonce_hi_data, uint64_t *nonce_lo_data,
                     uint32_t *counter_vec_data, uint16_t *cipher_vec_data,
                     string_t *value_vec_data, uint64_t size, T *result_data,
                     VCryptFunctionLocalState &lstate,
                     shared_ptr<EncryptionState> &encryption_state,
                     const string &key, bool same_nonce) {

  // create cache here if counter is similar
  // decrypt every value in the vector separately

  for (uint32_t i = 0; i < size; i++) {
    // todo; optimize
    if (!same_nonce) {
      if (!(lstate.nonce_hi == nonce_hi_data[i] &&
            lstate.nonce_lo == nonce_lo_data[i])) {
        lstate.nonce_hi = nonce_hi_data[i];
        lstate.nonce_lo = nonce_lo_data[i];

        // assign the right parts of the nonce and counter to iv
        lstate.iv[0] = static_cast<uint32_t>(nonce_hi_data[i] >> 32);
        lstate.iv[1] = static_cast<uint32_t>(nonce_hi_data[i] & 0xFFFFFFFF);
        lstate.iv[2] = static_cast<uint32_t>(nonce_lo_data[i]);
      }
    }

    DecryptSingleValue<T>(counter_vec_data[i], cipher_vec_data[i],
                          value_vec_data[i], result_data, lstate, key, i);
  }
}

template <typename T>
void DecryptAllBatchesVectorized(VCryptFunctionLocalState &lstate, uint32_t *counter_vec_data,
                                 string_t *value_vec_data, T *result_data, uint64_t size,
                                 const string *key, SelectionVector *sel = nullptr) {

  uint32_t batch_size = BATCH_SIZE;

  if (size < BATCH_SIZE) {
    batch_size = size;
  }
  uint32_t batch_size_in_bytes = sizeof(T) * batch_size;
  uint64_t total_batches = (size + batch_size - 1) / batch_size;
  auto to_process_total = size;
  to_process_total = size;

  // case; if values in vector < standard batch size
  if (to_process_total < BATCH_SIZE) {
    batch_size = to_process_total;
  }

  // decrypt each block independently (pointers are not always aligned)
  idx_t base_idx = 0;
  idx_t dict_idx = 0;
  auto to_process_batch = size;

  for (uint32_t batch = 0; batch < total_batches; batch++) {
  lstate.ResetIV<T>(counter_vec_data[base_idx]);
  // initialize encryption state
  lstate.encryption_state->InitializeDecryption(
    reinterpret_cast<const_data_ptr_t>(lstate.iv), 16,
    reinterpret_cast<const string *>(key));

  if (sel){
    dict_idx = sel->get_index(base_idx);
  } else {
    dict_idx = base_idx;
  }

  lstate.encryption_state->Process(
    reinterpret_cast<const_data_ptr_t>(value_vec_data[dict_idx].GetData()),
    batch_size_in_bytes,
    reinterpret_cast<unsigned char *>(result_data + base_idx),
    batch_size_in_bytes);

  base_idx += batch_size;

  // todo: optimize
  if (to_process_batch > batch_size) {
    to_process_batch -= batch_size;
  } else {
    to_process_batch = 0;
  break;
  }

  if (to_process_batch < batch_size) {
    batch_size = to_process_batch;
    batch_size_in_bytes = to_process_batch * sizeof(T);
  }
  }
  lstate.batch_nr += total_batches;
}

template <typename T>
void DecryptCompressedExecution(Vector &input_vector, uint64_t size,
                                ExpressionState &state, Vector &result) {

  ValidityMask &result_validity = FlatVector::Validity(result);
  result.SetVectorType(VectorType::FLAT_VECTOR);
  T *result_data = FlatVector::GetData<T>(result);

  // local, vcrypt (global) and encryption state
  auto &lstate = VCryptFunctionLocalState::ResetAndGet(state);
  auto vcrypt_state = VCryptBasicFun::GetVCryptState(state);
  auto key = VCryptBasicFun::GetKey(state);

  D_ASSERT(input_vector.GetType().id() == LogicalTypeId::STRUCT);

  auto &children = StructVector::GetEntries(input_vector);
  auto &nonce_hi = children[0];
  auto &nonce_lo = children[1];
  auto &counter_vec = children[2];
  auto &cipher_vec = children[3];
  auto &value_vec = children[4];

  D_ASSERT(value_vec->GetType() == LogicalTypeId::BLOB);

  UnifiedVectorFormat counter_vec_u;
  UnifiedVectorFormat cipher_vec_u;
  counter_vec->ToUnifiedFormat(size, counter_vec_u);
  cipher_vec->ToUnifiedFormat(size, cipher_vec_u);
  auto counter_vec_data = FlatVector::GetData<uint32_t>(*counter_vec);
  auto cipher_vec_data = FlatVector::GetData<uint16_t>(*cipher_vec);

  auto nonce_hi_value = FlatVector::GetData<uint64_t>(*nonce_hi)[0];
  auto nonce_lo_value = FlatVector::GetData<uint64_t>(*nonce_lo)[0];

  lstate.iv[0] = static_cast<uint32_t>(nonce_hi_value >> 32);
  lstate.iv[1] = static_cast<uint32_t>(nonce_hi_value & 0xFFFFFFFF);
  lstate.iv[2] = nonce_lo_value;

  // flatten the dictionary vector
  Vector &value_vec_dict = DictionaryVector::Child(*value_vec);
  UnifiedVectorFormat value_vec_dict_u;
  value_vec_dict.ToUnifiedFormat(size, value_vec_dict_u);
  auto value_vec_dict_data = FlatVector::GetData<string_t>(value_vec_dict);

  // check if the selection vector is sequential
  SelectionVector &sel = DictionaryVector::SelVector(*value_vec);
  if (!CheckSequenceInDict(sel, size)) {
    // does this even occur?
    // go to caching last decrypted ciphertext implementation?
    // also, we ideally need to check if the cipher is correct...
    throw NotImplementedException("Nonce is constant, compressed execution, but no Sequential Dictionary");
  }

  DecryptAllBatchesVectorized<T>(lstate, counter_vec_data, value_vec_dict_data, result_data, size, key, &sel);

}

D_ASSERT(value_vec->GetType() == LogicalTypeId::BLOB);

// assign the right parts of the nonce and counter to iv
lstate.iv[0] = static_cast<uint32_t>(nonce_hi_data[0] >> 32);
lstate.iv[1] = static_cast<uint32_t>(nonce_hi_data[0] & 0xFFFFFFFF);
lstate.iv[2] = nonce_lo_data[0];

if (value_vec->GetVectorType() == VectorType::DICTIONARY_VECTOR && same_nonce) {
    // todo; maybe already set the nonce here?
    // to do, cleanup nonce code in understaande functie
    DecryptCompressedExecution<T>(input_vector, size, state, result);
    return;
  } else if (value_vec->GetVectorType() == VectorType::DICTIONARY_VECTOR) {
    // go to a dict implementation for selection vectors in a query
    // this is still to do
    throw NotImplementedException("Dictionary Vector in-query implementation is missing");
  } else if (same_nonce) {

    // ---------- flattened in memory decryption -----------

    UnifiedVectorFormat value_vec_u;
    value_vec->ToUnifiedFormat(size, value_vec_u);
    auto value_vec_data = FlatVector::GetData<string_t>(*value_vec);

    auto to_process_total = size;
    auto counter_vec_data = FlatVector::GetData<uint32_t>(*counter_vec);
    auto cipher_vec_data = FlatVector::GetData<uint16_t>(*cipher_vec);

    uint32_t batch_size = BATCH_SIZE;
    uint32_t batch_size_in_bytes = sizeof(T) * batch_size;
    uint64_t total_batches = (size + batch_size - 1) / batch_size;
    idx_t current_index = 0;

    for (uint32_t i = 0; i < total_batches; i++) {
      for (idx_t j = 0; j < batch_size; j++) {
        if (counter_vec_data[current_index] ==
            counter_vec_data[current_index + j]) {
          continue;
        }

        DecryptPerValue<T>(nonce_hi_data, nonce_lo_data, counter_vec_data,
                           cipher_vec_data, value_vec_data, size, result_data,
                           lstate, lstate.encryption_state, *key, same_nonce);
        return;
      }

      current_index += batch_size;
    }

    DecryptAllBatchesVectorized<T>(lstate, counter_vec_data, value_vec_data, result_data, size, key);
  } else {

    UnifiedVectorFormat value_vec_u;
    value_vec->ToUnifiedFormat(size, value_vec_u);
    auto value_vec_data = FlatVector::GetData<string_t>(*value_vec);

    auto to_process_total = size;
    auto counter_vec_data = FlatVector::GetData<uint32_t>(*counter_vec);
    auto cipher_vec_data = FlatVector::GetData<uint16_t>(*cipher_vec);

    if (nonce_hi->GetVectorType() == VectorType::CONSTANT_VECTOR) {
      same_nonce = CheckNonceIndividual(nonce_lo_data, size);
    } else if (nonce_lo->GetVectorType() == VectorType::CONSTANT_VECTOR) {
      same_nonce = CheckNonceIndividual(nonce_hi_data, size);
    } else {
      same_nonce = CheckNonce(nonce_hi_data, nonce_lo_data, size);
      DecryptPerValue<T>(nonce_hi_data, nonce_lo_data, counter_vec_data,
                         cipher_vec_data, value_vec_data, size, result_data,
                         lstate, lstate.encryption_state, *key, same_nonce);
      return;
    }

    uint32_t batch_size = BATCH_SIZE;
    uint32_t batch_size_in_bytes = sizeof(T) * batch_size;
    uint64_t total_batches = (size + batch_size - 1) / batch_size;
    idx_t current_index = 0;

    for (uint32_t i = 0; i < total_batches; i++) {
      for (idx_t j = 0; j < batch_size; j++) {
        if (counter_vec_data[current_index] ==
            counter_vec_data[current_index + j]) {
          continue;
        }

        DecryptPerValue<T>(nonce_hi_data, nonce_lo_data, counter_vec_data,
                           cipher_vec_data, value_vec_data, size, result_data,
                           lstate, lstate.encryption_state, *key, same_nonce);
        return;
      }

      current_index += batch_size;
    }

    DecryptAllBatchesVectorized<T>(lstate, counter_vec_data, value_vec_data, result_data, size, key);

    }

template <typename T>
void DecryptDataVariable(Vector &input_vector, uint64_t size,
                      ExpressionState &state, Vector &result) {

  D_ASSERT(input_vector.GetType().id() == LogicalTypeId::STRUCT);
  ValidityMask &result_validity = FlatVector::Validity(result);
  result.SetVectorType(VectorType::FLAT_VECTOR);
  auto result_data = FlatVector::GetData<T>(result);

  // local, vcrypt (global) and encryption state
  auto &lstate = VCryptFunctionLocalState::ResetAndGet(state);
  auto vcrypt_state = VCryptBasicFun::GetVCryptState(state);
  auto key = VCryptBasicFun::GetKey(state);

  auto &children = StructVector::GetEntries(input_vector);
  auto &nonce_hi = children[0];
  auto &nonce_lo = children[1];
  auto &counter_vec = children[2];
  auto &cipher_vec = children[3];
  auto &value_vec = children[4];
  D_ASSERT(value_vec->GetType() == LogicalTypeId::BLOB);

  UnifiedVectorFormat nonce_hi_u;
  UnifiedVectorFormat nonce_lo_u;
  UnifiedVectorFormat counter_vec_u;
  UnifiedVectorFormat cipher_vec_u;
  UnifiedVectorFormat value_vec_u;

  nonce_hi->ToUnifiedFormat(size, nonce_hi_u);
  nonce_lo->ToUnifiedFormat(size, nonce_lo_u);
  counter_vec->ToUnifiedFormat(size, counter_vec_u);
  cipher_vec->ToUnifiedFormat(size, cipher_vec_u);
  value_vec->ToUnifiedFormat(size,value_vec_u);

  // change to unified vector format to handle compressed vectors
  auto nonce_hi_data = FlatVector::GetData<uint64_t>(*nonce_hi);
  auto nonce_lo_data = FlatVector::GetData<uint64_t>(*nonce_lo);
  auto counter_vec_data = FlatVector::GetData<uint32_t>(*counter_vec);
  auto cipher_vec_data = FlatVector::GetData<uint16_t>(*cipher_vec);
  auto value_vec_data = FlatVector::GetData<string_t>(*value_vec);

  bool same_nonce = true;
  if (!CheckNonce(nonce_hi_data, nonce_lo_data, size)) {
    same_nonce = false;
    DecryptPerValueVariable<T>(nonce_hi_data, nonce_lo_data, counter_vec_data,
                       cipher_vec_data, value_vec_data, size, result_data,
                       lstate, lstate.encryption_state, *key, same_nonce, result);
    return;
  }

  // assign the right parts of the nonce and counter to iv
  lstate.iv[0] = static_cast<uint32_t>(nonce_hi_data[0] >> 32);
  lstate.iv[1] = static_cast<uint32_t>(nonce_hi_data[0] & 0xFFFFFFFF);
  lstate.iv[2] = nonce_lo_data[0];

  uint64_t current_batch = 0;
  uint16_t total_batches = (size + BATCH_SIZE - 1) / BATCH_SIZE;
  lstate.to_process = size;
  idx_t index = 0;
  uint32_t batch_size = BATCH_SIZE;

  if (lstate.to_process < BATCH_SIZE){
    batch_size = lstate.to_process;
  }

  index = 0;
  while (current_batch < total_batches) {
    for (idx_t j = 0; j < batch_size; j++) {
      // check if the counter is sequential
      if (counter_vec_data[index] == counter_vec_data[index + j]) {
        continue;
      }

      DecryptPerValueVariable<T>(nonce_hi_data, nonce_lo_data, counter_vec_data,
                                 cipher_vec_data, value_vec_data, size,
                                 result_data, lstate, lstate.encryption_state,
                                 *key, same_nonce, result);
      return;
    }

    // for every batch, the IV is reset due to rounding to the nearest 16-byte block
    lstate.ResetIV<T>(counter_vec_data[index]);
    // for every batch, reset the encryption state
    lstate.encryption_state->InitializeDecryption(
        reinterpret_cast<const_data_ptr_t>(lstate.iv), 16,
        reinterpret_cast<const string *>(key));

    // index 150 is too high
    auto batch_size_stored = value_vec_data[index].GetSize();
    auto metadata_ptr = value_vec_data[index].GetDataWriteable();
    data_ptr_t buffer_ptr = reinterpret_cast<data_ptr_t const>(
        value_vec_data[index].GetDataWriteable());

    // we decrypt in place
    lstate.encryption_state->Process(
        reinterpret_cast<const_data_ptr_t>(value_vec_data[index].GetData()),
        batch_size_stored, (data_ptr_t)value_vec_data[index].GetData(),
        batch_size_stored);

    uint8_t vcrypt_version =
        Load<uint8_t>(reinterpret_cast<const_data_ptr_t>(metadata_ptr));
    metadata_ptr++;

    // previous offset is metadata length (hardcoded for now)
    uint64_t prev_offset = 1025;
    uint64_t current_offset, length;
    buffer_ptr += prev_offset;

    for (uint8_t j = 0; j < batch_size; j++) {
      current_offset =
          Load<uint64_t>(reinterpret_cast<const_data_ptr_t>(metadata_ptr));
      D_ASSERT(current_offset > prev_offset);
      length = current_offset - prev_offset;

      result_data[index] = StringVector::EmptyString(result, length);
      memcpy(result_data[index].GetDataWriteable(), buffer_ptr, length);
      result_data[index].Finalize();

      buffer_ptr += length;
      prev_offset = current_offset;
      metadata_ptr += sizeof(uint64_t);
      index++;
    }

    // todo: optimize this chunk of code
    if (lstate.to_process > BATCH_SIZE) {
      lstate.to_process -= BATCH_SIZE;
    } else {
      // processing finalized
      lstate.to_process = 0;
      break;
    }
    if (lstate.to_process < BATCH_SIZE) {
      batch_size = lstate.to_process;
    }

    current_batch++;
  }
}
#endif