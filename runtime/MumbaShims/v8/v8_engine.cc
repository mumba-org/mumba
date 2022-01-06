// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "runtime/MumbaShims/v8/v8_engine.h"
#include "runtime/MumbaShims/v8/v8_context.h"
#include "v8/include/libplatform/libplatform.h"
#include "base/debug/alias.h"
#include "base/files/file.h"
#include "base/sys_info.h"
#include "base/files/file_path.h"
#include "base/task_scheduler/post_task.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/files/memory_mapped_file.h"
#include "base/logging.h"
#include "base/metrics/histogram.h"
#include "base/rand_util.h"
#include "base/strings/sys_string_conversions.h"
#include "base/threading/platform_thread.h"
#include "base/time/time.h"
#include "crypto/sha2.h"
#include "gin/public/isolate_holder.h"
#include "gin/public/v8_platform.h"
#include "gin/array_buffer.h"
#include "gin/v8_initializer.h"

namespace mumba {

// namespace {

// const char kFlags[] = "--harmony --es_staging --use-strict";

// // None of these globals are ever freed nor closed.
// //base::MemoryMappedFile* g_mapped_natives = nullptr;
// //base::MemoryMappedFile* g_mapped_snapshot = nullptr;

// #if defined(V8_USE_EXTERNAL_STARTUP_DATA)

// const base::PlatformFile kInvalidPlatformFile =
// #if defined(OS_WIN)
//     INVALID_HANDLE_VALUE;
// #else
//     -1;
// #endif

// // File handles intentionally never closed. Not using File here because its
// // Windows implementation guards against two instances owning the same
// // PlatformFile (which we allow since we know it is never freed).
// base::PlatformFile g_natives_pf = kInvalidPlatformFile;
// base::PlatformFile g_snapshot_pf = kInvalidPlatformFile;
// base::MemoryMappedFile::Region g_natives_region;
// base::MemoryMappedFile::Region g_snapshot_region;

// #if defined(OS_ANDROID)
// #ifdef __LP64__
// const char kNativesFileName[] = "natives_blob_64.bin";
// const char kSnapshotFileName[] = "snapshot_blob_64.bin";
// #else
// const char kNativesFileName[] = "natives_blob_32.bin";
// const char kSnapshotFileName[] = "snapshot_blob_32.bin";
// #endif // __LP64__

// #else  // defined(OS_ANDROID)
// const char kNativesFileName[] = "natives_blob.bin";
// const char kSnapshotFileName[] = "snapshot_blob.bin";
// #endif  // defined(OS_ANDROID)

// void GetV8FilePath(const char* file_name, base::FilePath* path_out) {
// #if !defined(OS_MACOSX)
//   base::FilePath data_path;
// #if defined(OS_ANDROID)
//   // This is the path within the .apk.
//   data_path = base::FilePath(FILE_PATH_LITERAL("assets"));
// #elif defined(OS_POSIX)
//   PathService::Get(base::DIR_EXE, &data_path);
// #elif defined(OS_WIN)
//   PathService::Get(base::DIR_MODULE, &data_path);
// #endif
//   DCHECK(!data_path.empty());

//   *path_out = data_path.AppendASCII(file_name);
// #else   // !defined(OS_MACOSX)
//   base::ScopedCFTypeRef<CFStringRef> natives_file_name(
//       base::SysUTF8ToCFStringRef(file_name));
//   *path_out = base::mac::PathForFrameworkBundleResource(natives_file_name);
// #endif  // !defined(OS_MACOSX)
//   DCHECK(!path_out->empty());
// }

// static bool MapV8File(base::PlatformFile platform_file,
//                       base::MemoryMappedFile::Region region,
//                       base::MemoryMappedFile** mmapped_file_out) {
//   DCHECK(*mmapped_file_out == NULL);
//   scoped_ptr<base::MemoryMappedFile> mmapped_file(new base::MemoryMappedFile());
//   if (mmapped_file->Initialize(base::File(platform_file), region)) {
//     *mmapped_file_out = mmapped_file.release();
//     return true;
//   }
//   return false;
// }

// base::PlatformFile OpenV8File(const char* file_name,
//                               base::MemoryMappedFile::Region* region_out) {
//   // Re-try logic here is motivated by http://crbug.com/479537
//   // for A/V on Windows (https://support.microsoft.com/en-us/kb/316609).

//   // These match tools/metrics/histograms.xml
//   enum OpenV8FileResult {
//     OPENED = 0,
//     OPENED_RETRY,
//     FAILED_IN_USE,
//     FAILED_OTHER,
//     MAX_VALUE
//   };
//   base::FilePath path;
//   GetV8FilePath(file_name, &path);

// #if defined(OS_ANDROID)
//   base::File file(base::android::OpenApkAsset(path.value(), region_out));
//   OpenV8FileResult result = file.IsValid() ? OpenV8FileResult::OPENED
//                                            : OpenV8FileResult::FAILED_OTHER;
// #else
//   // Re-try logic here is motivated by http://crbug.com/479537
//   // for A/V on Windows (https://support.microsoft.com/en-us/kb/316609).
//   const int kMaxOpenAttempts = 5;
//   const int kOpenRetryDelayMillis = 250;

//   OpenV8FileResult result = OpenV8FileResult::FAILED_IN_USE;
//   int flags = base::File::FLAG_OPEN | base::File::FLAG_READ;
//   base::File file;
//   for (int attempt = 0; attempt < kMaxOpenAttempts; attempt++) {
//     file.Initialize(path, flags);
//     if (file.IsValid()) {
//       *region_out = base::MemoryMappedFile::Region::kWholeFile;
//       if (attempt == 0) {
//         result = OpenV8FileResult::OPENED;
//         break;
//       } else {
//         result = OpenV8FileResult::OPENED_RETRY;
//         break;
//       }
//     } else if (file.error_details() != base::File::FILE_ERROR_IN_USE) {
//       result = OpenV8FileResult::FAILED_OTHER;
// #ifdef OS_WIN
//       // TODO(oth): temporary diagnostics for http://crbug.com/479537
//       std::string narrow(kNativesFileName);
//       base::FilePath::StringType nativesBlob(narrow.begin(), narrow.end());
//       if (path.BaseName().value() == nativesBlob) {
//         base::File::Error file_error = file.error_details();
//         base::debug::Alias(&file_error);
//         LOG(FATAL) << "Failed to open V8 file '" << path.value()
//                    << "' (reason: " << file.error_details() << ")";
//       }
// #endif  // OS_WIN
//       break;
//     } else if (kMaxOpenAttempts - 1 != attempt) {
//       base::PlatformThread::Sleep(
//           base::TimeDelta::FromMilliseconds(kOpenRetryDelayMillis));
//     }
//   }
// #endif  // defined(OS_ANDROID)

//   UMA_HISTOGRAM_ENUMERATION("V8.Initializer.OpenV8File.Result",
//                             result,
//                             OpenV8FileResult::MAX_VALUE);
//   return file.TakePlatformFile();
// }

// void OpenNativesFileIfNecessary() {
//   if (g_natives_pf == kInvalidPlatformFile) {
//     g_natives_pf = OpenV8File(kNativesFileName, &g_natives_region);
//   }
// }

// void OpenSnapshotFileIfNecessary() {
//   if (g_snapshot_pf == kInvalidPlatformFile) {
//     g_snapshot_pf = OpenV8File(kSnapshotFileName, &g_snapshot_region);
//   }
// }

// #if defined(V8_VERIFY_EXTERNAL_STARTUP_DATA)
// bool VerifyV8StartupFile(base::MemoryMappedFile** file,
//                          const unsigned char* fingerprint) {
//   unsigned char output[crypto::kSHA256Length];
//   crypto::SHA256HashString(
//       base::StringPiece(reinterpret_cast<const char*>((*file)->data()),
//                         (*file)->length()),
//       output, sizeof(output));
//   if (!memcmp(fingerprint, output, sizeof(output))) {
//     return true;
//   }

//   // TODO(oth): Remove this temporary diagnostics for http://crbug.com/501799
//   uint64_t input[sizeof(output)];
//   memcpy(input, fingerprint, sizeof(input));

//   base::debug::Alias(output);
//   base::debug::Alias(input);

//   const uint64_t* o64 = reinterpret_cast<const uint64_t*>(output);
//   const uint64_t* f64 = reinterpret_cast<const uint64_t*>(fingerprint);
//   LOG(FATAL) << "Natives length " << (*file)->length()
//              << " H(computed) " << o64[0] << o64[1] << o64[2] << o64[3]
//              << " H(expected) " << f64[0] << f64[1] << f64[2] << f64[3];

//   delete *file;
//   *file = NULL;
//   return false;
// }
// #endif  // V8_VERIFY_EXTERNAL_STARTUP_DATA
// #endif  // V8_USE_EXTERNAL_STARTUP_DATA

// }

// ArrayBufferAllocator::ArrayBufferAllocator() {}

// ArrayBufferAllocator::~ArrayBufferAllocator() {}

// void* ArrayBufferAllocator::Allocate(size_t length) {
//  void* data = AllocateUninitialized(length);
//  return data == NULL ? data : memset(data, 0, length);
// }

// void* ArrayBufferAllocator::AllocateUninitialized(size_t length) { return malloc(length); }

// void ArrayBufferAllocator::Free(void* data, size_t) { free(data); }


// static 
V8Engine* V8Engine::GetInstance() {
  return nullptr;//base::Singleton<V8Engine, base::DefaultSingletonTraits<V8Engine> >::get();
}

V8Engine::V8Engine(): vm_thread_("V8Thread"){//,
  //allocator_(nullptr) {
  DCHECK(vm_thread_.Start());
}

V8Engine::~V8Engine() {
  vm_thread_.Stop();
}

bool V8Engine::Init() {
  // delegate to another thread, but block on init
  // until its done
  base::WaitableEvent wait(
    base::WaitableEvent::ResetPolicy::AUTOMATIC,
    base::WaitableEvent::InitialState::NOT_SIGNALED);
  
  vm_thread_.task_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&V8Engine::InitVM, 
      base::Unretained(this),
      base::Unretained(&wait)));

  wait.Wait();
  
  return true;
} 

void V8Engine::Shutdown() {
  base::WaitableEvent wait(
    base::WaitableEvent::ResetPolicy::AUTOMATIC,
    base::WaitableEvent::InitialState::NOT_SIGNALED);

  vm_thread_.task_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&V8Engine::ShutdownVM, 
      base::Unretained(this),
      base::Unretained(&wait)));

  wait.Wait();
}

void V8Engine::InitVM(base::WaitableEvent* wait_event) {
  //DLOG(INFO) << "V8Engine::InitVM";
//#ifdef V8_USE_EXTERNAL_STARTUP_DATA
//  gin::V8Initializer::LoadV8Snapshot();
//  gin::V8Initializer::LoadV8Natives();
//#endif
 
  gin::IsolateHolder::Initialize(
    gin::IsolateHolder::kStrictMode,
    gin::IsolateHolder::kStableAndExperimentalV8Extras,
    gin::ArrayBufferAllocator::SharedInstance());

  isolate_holder_.reset(
    new gin::IsolateHolder(
      vm_thread_.task_runner(),
      gin::IsolateHolder::kSingleThread,
      gin::IsolateHolder::kAllowAtomicsWait));

  if (wait_event) {
    wait_event->Signal();
  }
}

void V8Engine::ShutdownVM(base::WaitableEvent* wait_event) {
  isolate_holder_.reset();
  if (wait_event) {
    wait_event->Signal();
  }
}

v8::Isolate* V8Engine::isolate() const {
  return isolate_holder_->isolate();
}

V8Context* V8Engine::CreateContext() {
  base::WaitableEvent wait(
    base::WaitableEvent::ResetPolicy::AUTOMATIC,
    base::WaitableEvent::InitialState::NOT_SIGNALED);

  V8Context* result = nullptr;
  vm_thread_.task_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&V8Engine::CreateContextImpl, 
      base::Unretained(this),
      base::Unretained(&wait),
      base::Unretained(&result)));
  wait.Wait();

  return result;
}

V8Context* V8Engine::CreateContext(v8::Local<v8::ObjectTemplate> global) {
  base::WaitableEvent wait(
    base::WaitableEvent::ResetPolicy::AUTOMATIC,
    base::WaitableEvent::InitialState::NOT_SIGNALED);

  V8Context* result = nullptr;

  vm_thread_.task_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&V8Engine::CreateContextWithGlobal, 
      base::Unretained(this),
      base::Passed(std::move(global)),
      base::Unretained(&wait),
      base::Unretained(&result)));

  wait.Wait();

  return result;
}

void V8Engine::CreateContextImpl(base::WaitableEvent* wait_event, V8Context** result) { 
  *result = new V8Context(isolate_holder_->isolate());
  if (wait_event) {
    wait_event->Signal();
  }
}

void V8Engine::CreateContextWithGlobal(v8::Local<v8::ObjectTemplate> global, base::WaitableEvent* wait_event, V8Context** result) {
  *result = new V8Context(isolate_holder_->isolate(), std::move(global));
  if (wait_event) {
    wait_event->Signal();
  }
}

}