# VCrypt

This repository is based on https://github.com/duckdb/extension-template, check it out if you want to build and ship your own DuckDB extension.

---

VCrypt, short for _Vectorized Cryptography_, allows to efficiently encrypt and decrypt values within DuckDB. It is leveraging DuckDB compression methods to compress away metadata such as nonces, which are used to randomize the encryption. Because of its design, VCrypt often uses _vectorized processing_ to encrypt and decrypt values in batch.

NB: this extension is under development and not stable yet

## Usage

### Key management

Create a DuckDB secret;

```
CREATE SECRET key_name (
    TYPE ENCRYPTION,
    TOKEN 'secret_key'
    LENGTH 16);
```

Supported key lenghts are 16, 24 and 32 bytes.

### Encrypting and Decrypting

Then Encrypt or Decrypt with:

```
encrypt(value, 'key_name')
decrypt(value, 'key_name')
```

Message is (for now) used as a 'salt', to generate a new encryption key per value or per column that is encrypted. In future versions, we are implementing another mechanism to automatically generate columnar keys.

### Notes

We are now only supporting MBEDTLS/OPENSSL `AES-CTR`, but are working on supporting more encryption algorithms later.

## Building
### Managing dependencies
DuckDB extensions uses VCPKG for dependency management. Enabling VCPKG is very simple: follow the [installation instructions](https://vcpkg.io/en/getting-started) or just run the following:
```shell
git clone https://github.com/Microsoft/vcpkg.git
./vcpkg/bootstrap-vcpkg.sh
export VCPKG_TOOLCHAIN_PATH=`pwd`/vcpkg/scripts/buildsystems/vcpkg.cmake
```
Note: VCPKG is only required for extensions that want to rely on it for dependency management. If you want to develop an extension without dependencies, or want to do your own dependency management, just skip this step. Note that the example extension uses VCPKG to build with a dependency for instructive purposes, so when skipping this step the build may not work without removing the dependency.

### Build steps
Now to build the extension, run:
```sh
make
```
The main binaries that will be built are:
```sh
./build/release/duckdb
./build/release/test/unittest
./build/release/extension/simple_encryption/simple_encryption.duckdb_extension
```
- `duckdb` is the binary for the duckdb shell with the extension code automatically loaded.
- `unittest` is the test runner of duckdb. Again, the extension is already linked into the binary.
- `simple_encryption.duckdb_extension` is the loadable binary as it would be distributed.

## Running the extension
To run the extension code, simply start the shell with `./build/release/duckdb`.

Now we can use the features from the extension directly in DuckDB. The template contains a single scalar function `simple_encryption()` that takes a string arguments and returns a string:
```
D select simple_encryption('Jane') as result;
┌───────────────┐
│    result     │
│    varchar    │
├───────────────┤
│ Simple_encryption Jane 🐥 │
└───────────────┘
```

## Running the tests
Different tests can be created for DuckDB extensions. The primary way of testing DuckDB extensions should be the SQL tests in `./test/sql`. These SQL tests can be run using:
```sh
make test
```

### Installing the deployed binaries
To install your extension binaries from S3, you will need to do two things. Firstly, DuckDB should be launched with the
`allow_unsigned_extensions` option set to true. How to set this will depend on the client you're using. Some examples:

CLI:
```shell
duckdb -unsigned
```

Python:
```python
con = duckdb.connect(':memory:', config={'allow_unsigned_extensions' : 'true'})
```

NodeJS:
```js
db = new duckdb.Database(':memory:', {"allow_unsigned_extensions": "true"});
```

Secondly, you will need to set the repository endpoint in DuckDB to the HTTP url of your bucket + version of the extension
you want to install. To do this run the following SQL query in DuckDB:
```sql
SET custom_extension_repository='bucket.s3.eu-west-1.amazonaws.com/<your_extension_name>/latest';
```
Note that the `/latest` path will allow you to install the latest extension version available for your current version of
DuckDB. To specify a specific version, you can pass the version instead.

After running these steps, you can install and load your extension using the regular INSTALL/LOAD commands in DuckDB:
```sql
INSTALL simple_encryption
LOAD simple_encryption
```
