#pragma once

namespace duckdb {

static constexpr const uint8_t VCRYPT_VERSION = 0;

struct EtypeProperties {
private:
  static constexpr const uint8_t COMPRESSION = 0x01;
  static constexpr const uint8_t VERSION_1 = 0x40;
  static constexpr const uint8_t VERSION_0 = 0x80;
  uint8_t flags = 0;

public:
  explicit EtypeProperties(uint8_t flags = 0) : flags(flags) {
  }
  EtypeProperties(bool has_compression) {
    SetCompression(has_compression);
  }

  inline void CheckVersion() const {
    const auto v0 = (flags & VERSION_0);
    const auto v1 = (flags & VERSION_1);
    if ((v1 | v0) != VCRYPT_VERSION) {
      throw NotImplementedException(
          "This Etype seems to be written with a newer version of the DuckDB vcrypt library that is not "
          "compatible with this version. Please upgrade your DuckDB installation.");
    }
  }

  inline bool HasCompression() const {
    return (flags & COMPRESSION) != 0;
  }

  inline void SetCompression(bool value) {
    flags = value ? (flags | COMPRESSION) : (flags & ~COMPRESSION);
  }
};

} // namespace duckdb