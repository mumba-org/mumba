// Copyright 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// some code from crypto/secure_hash(.h/.cc)

// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "storage/hash.h"

#include <stddef.h>

#include "base/logging.h"
#include "base/memory/ptr_util.h"
#include "base/pickle.h"
#include "crypto/openssl_util.h"
#include "third_party/boringssl/src/include/openssl/mem.h"
#include "third_party/boringssl/src/include/openssl/sha.h"

namespace storage {

namespace {

class SecureHashSHA1 : public SecureHash {
 public:
  SecureHashSHA1() {
    SHA1_Init(&ctx_);
  }

  SecureHashSHA1(const SecureHashSHA1& other) {
    memcpy(&ctx_, &other.ctx_, sizeof(ctx_));
  }

  ~SecureHashSHA1() override {
    OPENSSL_cleanse(&ctx_, sizeof(ctx_));
  }

  void Update(const void* input, size_t len) override {
    SHA1_Update(&ctx_, static_cast<const unsigned char*>(input), len);
  }

  void Finish(void* output, size_t len) override {
    crypto::ScopedOpenSSLSafeSizeBuffer<SHA_DIGEST_LENGTH> result(
        static_cast<unsigned char*>(output), len);
    SHA1_Final(result.safe_buffer(), &ctx_);
  }

  void Finish(void* output) override {
    crypto::ScopedOpenSSLSafeSizeBuffer<SHA_DIGEST_LENGTH> result(
        static_cast<unsigned char*>(output), SHA_DIGEST_LENGTH);
    SHA1_Final(result.safe_buffer(), &ctx_);
  }

  std::unique_ptr<SecureHash> Clone() const override {
    return std::make_unique<SecureHashSHA1>(*this);
  }

  size_t GetHashLength() const override { return SHA_DIGEST_LENGTH; }

 private:
  SHA_CTX ctx_;
};

class SecureHashSHA256 : public SecureHash {
 public:
  SecureHashSHA256() {
    SHA256_Init(&ctx_);
  }

  SecureHashSHA256(const SecureHashSHA256& other) {
    memcpy(&ctx_, &other.ctx_, sizeof(ctx_));
  }

  ~SecureHashSHA256() override {
    OPENSSL_cleanse(&ctx_, sizeof(ctx_));
  }

  void Update(const void* input, size_t len) override {
    SHA256_Update(&ctx_, static_cast<const unsigned char*>(input), len);
  }

  void Finish(void* output, size_t len) override {
    crypto::ScopedOpenSSLSafeSizeBuffer<SHA256_DIGEST_LENGTH> result(
        static_cast<unsigned char*>(output), len);
    SHA256_Final(result.safe_buffer(), &ctx_);
  }

  void Finish(void* output) override {
    crypto::ScopedOpenSSLSafeSizeBuffer<SHA256_DIGEST_LENGTH> result(
        static_cast<unsigned char*>(output), SHA256_DIGEST_LENGTH);
    SHA256_Final(result.safe_buffer(), &ctx_);
  }

  std::unique_ptr<SecureHash> Clone() const override {
    return std::make_unique<SecureHashSHA256>(*this);
  }

  size_t GetHashLength() const override { return SHA256_DIGEST_LENGTH; }

 private:
  SHA256_CTX ctx_;
};

}  // namespace

std::unique_ptr<SecureHash> SecureHash::Create(Algorithm algorithm) {
  switch (algorithm) {
    case SHA1:
      return std::make_unique<SecureHashSHA1>();
    case SHA256:
      return std::make_unique<SecureHashSHA256>();
    default:
      NOTIMPLEMENTED();
      return nullptr;
  }
}

}
