#include "gin/v8_initializer.h"

namespace {


void LoadV8SnapshotFile() {
 #if defined(USE_V8_CONTEXT_SNAPSHOT)
   static constexpr gin::V8Initializer::V8SnapshotFileType kSnapshotType =
       gin::V8Initializer::V8SnapshotFileType::kWithAdditionalContext;
//   static const char* snapshot_data_descriptor =
//       kV8ContextSnapshotDataDescriptor;
 #else
   static constexpr gin::V8Initializer::V8SnapshotFileType kSnapshotType =
       gin::V8Initializer::V8SnapshotFileType::kDefault;
//   static const char* snapshot_data_descriptor = kV8SnapshotDataDescriptor;
 #endif  // USE_V8_CONTEXT_SNAPSHOT
//   ALLOW_UNUSED_LOCAL(kSnapshotType);
//   ALLOW_UNUSED_LOCAL(snapshot_data_descriptor);

// #if defined(OS_POSIX) && !defined(OS_MACOSX)
//   base::FileDescriptorStore& file_descriptor_store =
//       base::FileDescriptorStore::GetInstance();
//   base::MemoryMappedFile::Region region;
//   base::ScopedFD fd =
//       file_descriptor_store.MaybeTakeFD(snapshot_data_descriptor, &region);
//   if (fd.is_valid()) {
//     base::File file(std::move(fd));
//     gin::V8Initializer::LoadV8SnapshotFromFile(std::move(file), &region,
//                                                kSnapshotType);
//     return;
//   }
// #endif  // OS_POSIX && !OS_MACOSX
  gin::V8Initializer::LoadV8Snapshot(kSnapshotType);
  gin::V8Initializer::LoadV8Natives();
}


}  // namespace

int main(int argc, char** argv) {
  LoadV8SnapshotFile();
  gin::V8Initializer::Initialize(gin::IsolateHolder::kNonStrictMode, gin::IsolateHolder::kStableV8Extras);
}