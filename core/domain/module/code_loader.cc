// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/domain/module/code_loader.h"

#include "core/domain/module/local_file_loader.h"
#include "core/domain/module/memory_file_loader.h"
#include "core/domain/module/snapshot_file_loader.h"

namespace domain {

std::unique_ptr<CodeLoader> CodeLoader::CreateDefault(storage_proto::ExecutableArchitecture arch, bool load_from_memory) {
  if (arch == storage_proto::ANY_WASM || arch == storage_proto::ANY_LLVMIR || arch == storage_proto::ANY_SOURCE) {
  	return std::unique_ptr<CodeLoader>(new SnapshotFileLoader());
  } else if (load_from_memory) {
    return std::unique_ptr<CodeLoader>(new MemoryFileLoader());
  } else { // native (for .dll, .so and .dylib)
  	return std::unique_ptr<CodeLoader>(new LocalFileLoader());
  }
}

}