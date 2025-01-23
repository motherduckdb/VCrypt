CREATE SECRET key_1 (
	TYPE ENCRYPTION,
    TOKEN '0123456789112345',
    LENGTH 16
);
CREATE TABLE test_1  AS SELECT range AS value FROM range(2048);
ALTER TABLE test_1 ADD COLUMN encrypted_values STRUCT(nonce_hi UBIGINT, nonce_lo UBIGINT, counter UINTEGER, cipher UINTEGER, value BLOB, type TINYINT);
ALTER TABLE test_1 ADD COLUMN decrypted_values BIGINT;
UPDATE test_1 SET encrypted_values = encrypt_vectorized(value, 'key_1');
SELECT decrypt_vectorized(encrypted_values, 'key_1') FROM test_1;
