// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stddef.h>
#include <stdint.h>

#include "base/test/fuzzed_data_provider.h"
#include "net/third_party/http2/hpack/decoder/hpack_decoder.h"

// Entry point for LibFuzzer.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  // At least 4 bytes of fuzz data are needed to generate a max string size.
  if (size < 4)
    return 0;

  base::FuzzedDataProvider fuzzed_data_provider(data, size);
  size_t max_string_size =
      fuzzed_data_provider.ConsumeUint32InRange(1, 10 * size);
  net::HpackDecoder decoder(net::HpackDecoderNoOpListener::NoOpListener(),
                            max_string_size);
  decoder.StartDecodingBlock();
  while (fuzzed_data_provider.remaining_bytes() > 0) {
    size_t chunk_size = fuzzed_data_provider.ConsumeUint32InRange(1, 32);
    std::string chunk = fuzzed_data_provider.ConsumeBytes(chunk_size);
    net::DecodeBuffer fragment(chunk.data(), chunk.size());
    decoder.DecodeFragment(&fragment);
  }
  decoder.EndDecodingBlock();
  return 0;
}