// Copyright 2015 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <brillo/streams/openssl_stream_bio.h>

#include <openssl/bio.h>

#include <base/numerics/safe_conversions.h>
#include <brillo/streams/stream.h>

namespace brillo {

namespace {

// TODO(crbug.com/984789): Remove once support for OpenSSL <1.1 is dropped.
#if OPENSSL_VERSION_NUMBER < 0x10100000L
static void BIO_set_data(BIO* a, void* ptr) {
  a->ptr = ptr;
}

static void* BIO_get_data(BIO* a) {
  return a->ptr;
}

static void BIO_set_init(BIO* a, int init) {
  a->init = init;
}

static int BIO_get_init(BIO* a) {
  return a->init;
}

static void BIO_set_shutdown(BIO* a, int shut) {
  a->shutdown = shut;
}
#endif

// Internal functions for implementing OpenSSL BIO on brillo::Stream.
int stream_write(BIO* bio, const char* buf, int size) {
  brillo::Stream* stream = static_cast<brillo::Stream*>(BIO_get_data(bio));
  size_t written = 0;
  BIO_clear_retry_flags(bio);
  if (!stream->WriteNonBlocking(buf, size, &written, nullptr))
    return -1;

  if (written == 0) {
    // Socket's output buffer is full, try again later.
    BIO_set_retry_write(bio);
    return -1;
  }
  return base::checked_cast<int>(written);
}

int stream_read(BIO* bio, char* buf, int size) {
  brillo::Stream* stream = static_cast<brillo::Stream*>(BIO_get_data(bio));
  size_t read = 0;
  BIO_clear_retry_flags(bio);
  bool eos = false;
  if (!stream->ReadNonBlocking(buf, size, &read, &eos, nullptr))
    return -1;

  if (read == 0 && !eos) {
    // If no data is available on the socket and it is still not closed,
    // ask OpenSSL to try again later.
    BIO_set_retry_read(bio);
    return -1;
  }
  return base::checked_cast<int>(read);
}

// NOLINTNEXTLINE(runtime/int)
long stream_ctrl(BIO* bio, int cmd, long /* num */, void* /* ptr */) {
  if (cmd == BIO_CTRL_FLUSH) {
    brillo::Stream* stream = static_cast<brillo::Stream*>(BIO_get_data(bio));
    return stream->FlushBlocking(nullptr) ? 1 : 0;
  }
  return 0;
}

int stream_new(BIO* bio) {
  // By default do not close underlying stream on shutdown.
  BIO_set_shutdown(bio, 0);
  BIO_set_init(bio, 0);
  return 1;
}

int stream_free(BIO* bio) {
  if (!bio)
    return 0;

  if (BIO_get_init(bio)) {
    BIO_set_data(bio, nullptr);
    BIO_set_init(bio, 0);
  }
  return 1;
}

#if OPENSSL_VERSION_NUMBER < 0x10100000L
// TODO(crbug.com/984789): Remove #ifdef once support for OpenSSL <1.1 is
// dropped.

// BIO_METHOD structure describing the BIO built on top of brillo::Stream.
BIO_METHOD stream_method = {
    0x7F | BIO_TYPE_SOURCE_SINK,  // type: 0x7F is an arbitrary unused type ID.
    "stream",                     // name
    stream_write,                 // write function
    stream_read,                  // read function
    nullptr,                      // puts function, not implemented
    nullptr,                      // gets function, not implemented
    stream_ctrl,                  // control function
    stream_new,                   // creation
    stream_free,                  // free
    nullptr,                      // callback function, not used
};

BIO_METHOD* stream_get_method() {
  return &stream_method;
}

#else

BIO_METHOD* stream_get_method() {
  static BIO_METHOD* stream_method;

  if (!stream_method) {
    stream_method =
        BIO_meth_new(BIO_get_new_index() | BIO_TYPE_SOURCE_SINK, "stream");
    BIO_meth_set_write(stream_method, stream_write);
    BIO_meth_set_read(stream_method, stream_read);
    BIO_meth_set_ctrl(stream_method, stream_ctrl);
    BIO_meth_set_create(stream_method, stream_new);
    BIO_meth_set_destroy(stream_method, stream_free);
  }

  return stream_method;
}

#endif

}  // anonymous namespace

BIO* BIO_new_stream(brillo::Stream* stream) {
  BIO* bio = BIO_new(stream_get_method());
  if (bio) {
    BIO_set_data(bio, stream);
    BIO_set_init(bio, 1);
  }
  return bio;
}

}  // namespace brillo
