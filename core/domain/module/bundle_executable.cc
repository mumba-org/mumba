// Copyright 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/domain/module/bundle_executable.h"

#include "build/build_config.h"
#include "base/path_service.h"
#include "base/base_paths.h"
#include "base/memory/ref_counted.h"
#include "base/files/file.h"
#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/strings/string_util.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/utf_string_conversions.h"
#include "base/strings/string_piece.h"
#include "base/hash.h"
#include "storage/db/sqliteInt.h"
#include "net/base/file_stream.h"
#include "net/base/io_buffer.h"
#include "crypto/secure_hash.h"
#include "crypto/sha2.h"
#include "core/domain/module/code.h"
#include "core/shared/domain/storage/storage_context.h"
#include "core/shared/domain/storage/data_storage.h"
#include "storage/storage_utils.h"
#include "storage/storage_constants.h"

namespace domain {

namespace {  

const char kHEADER_VERSION[] = "0.0.1";
//const size_t kHEADER_SIZE = arraysize(kHEADER_MAGIC) + arraysize(kHEADER_VERSION);
const int kReadBufSize = 16 * 1024;

const char kAPP_INIT_ENTRY[] = "ApplicationInit";
const char kAPP_DESTROY_ENTRY[] = "ApplicationDestroy";
const char kAPP_GET_CLIENT_ENTRY[] = "ApplicationGetClient";

//std::string GetSHA256Hash(base::StringPiece payload) {
//  std::string sha256_hash(crypto::kSHA256Length, 0);
//  std::unique_ptr<crypto::SecureHash> ctx = crypto::SecureHash::Create(crypto::SecureHash::SHA256);
//  ctx->Update(payload.data(), payload.size());
//  ctx->Finish(const_cast<char *>(sha256_hash.data()), sha256_hash.size());
//  return sha256_hash;
//}

void OnDataPut(int result) {
  //DLOG(INFO) << "OnDataPut: result = " << result;
}

}

BundleExecutable::BundleExecutable(
  base::UUID id,
  const std::string& identifier,
  scoped_refptr<StorageContext> context):
    host_arch_(storage::GetHostArchitecture()),
    id_(std::move(id)),
    identifier_(identifier),
    context_(context),
    initialized_(false),
#if defined (OS_WIN)
    path_(base::ASCIIToUTF16(identifier)),
#else
    path_(identifier),
#endif
    app_keyspace_("app"),
    loaded_archs_(0) {
  
}

BundleExecutable::~BundleExecutable() {
  context_ = nullptr;
}

storage_proto::ExecutableFormat BundleExecutable::executable_format() const {
  return application_proto_->format();
}

const base::UUID& BundleExecutable::id() const {
  return id_;
}

const std::string& BundleExecutable::identifier() const {
  return identifier_;
}

Code* BundleExecutable::host_code() const {
  // for now its like this, but we are suppose to have multiple
  // binaries for the supported target OS's and processor architectures

  // we should return only one executable here, but internally
  // we must have a map
  auto it = codes_.find(storage::GetHostArchitecture());
  
  // this architecture is not supported
  if (it == codes_.end()) {
    return nullptr;
  }

  return it->second.get();
}

const base::FilePath& BundleExecutable::path() const {
  return path_;
}

size_t BundleExecutable::size() {
  return 0;
}

storage_proto::ExecutableEntry BundleExecutable::GetStaticEntry(storage_proto::ExecutableEntryCode entry_code) {
  storage_proto::ExecutableEntry entry;
  entry.set_kind(storage_proto::ExecutableEntry::STATIC);
  entry.set_code(entry_code);
  return entry;
}

// for now this is fixed. But we may leave this to the disk dev
// and get this information from the application disk manifest/header
std::string BundleExecutable::GetEntryName(storage_proto::ExecutableEntry entry) {
  if (entry.kind() == storage_proto::ExecutableEntry::STATIC) {
    return GetStaticEntryName(entry.code());
  }
  // dynamic kind of entry
  return entry.name();
}

bool BundleExecutable::Init(InitParams params) {
   if (!params.creating) {
    LOG(INFO) << "opening app " << identifier();
    LoadHeader();
    LoadExecutableImages(true);
    //if (!LoadHeader()) {
    //  LOG(ERROR) << "loading header failed.";
    //  return false;
    //}
    //if (!LoadExecutableImages(params.check, params.eager_load)) {
    //  LOG(ERROR) << "loading executables failed.";
    //  return false;
    //}
  } else {
    LOG(INFO) << "creating app " << identifier();
    CreateHeader(params.format);
    //if (!CreateHeader(params.format)) {
    //  return false;
    //}
  }
  initialized_ = true;
  return initialized_;
}

bool BundleExecutable::SupportsArch(storage_proto::ExecutableArchitecture arch) const {
  bool supported = false;
  for (auto it = codes_.begin(); it != codes_.end(); ++it) {
    if (it->second->executable_architecture() == arch) {
      supported = true;
      break;
    }
  }
  return supported;
}

bool BundleExecutable::HostSupported() {
  return SupportsArch(storage::GetHostArchitecture());
}

bool BundleExecutable::AddExecutableFromPathForHostArch(const base::FilePath& path) {
  return AddExecutableFromPath(storage::GetHostArchitecture(), path); 
}

bool BundleExecutable::AddExecutableFromPath(storage_proto::ExecutableArchitecture arch, const base::FilePath& path) {
  if (base::PathExists(path)) {
    base::File file(path, base::File::FLAG_OPEN | base::File::FLAG_READ);
    if (file.IsValid()) {
      size_t file_len = file.GetLength();
      int readlen = file_len < kReadBufSize ? file_len : kReadBufSize;

      // formulate the proto
      storage_proto::Code executable_proto;
      executable_proto.set_format(executable_format());
      executable_proto.set_architecture(arch);
      executable_proto.mutable_resource()->set_size(file_len);
      
      std::string encoded_proto;
      if (!executable_proto.SerializeToString(&encoded_proto)) {
        LOG(ERROR) << "failed to serialize protobuf header for " << path;
        return false;
      }

      // file content is right after (file len + proto len) part of the header
      // the hash len is saved after the file content and the proto len after the
      // hash payload, and before the proto contents

      // saving everything upfront in the top, would make us lose
      // the bufferization of writing the file in chunks.

      // by using StringPiece we are not copying the contents (and thats why we need this silly 'Scope' from file)
      // loaded by the DB, while the contents of the db file are being mmaped
      // so that way we are avoinding to keep all the file contents in memory at once  

      size_t header_size = 
        csqliteVarintLen(static_cast<u64>(file_len)) + 
        csqliteVarintLen(static_cast<u64>(encoded_proto.size())) + 
        //crypto::kSHA256Length + 
        encoded_proto.size();
      
      //printf("header len = %zu proto len = %lu file len = %d\nproto: '%s'\n", header_size, encoded_proto.size(), total_len, encoded_proto.c_str());
      size_t total_size = file_len + header_size;
      //scoped_refptr<net::IOBufferWithSize> file_content = new net::IOBufferWithSize(header_size + total_len);
      mojo::ScopedSharedBufferHandle write_buffer = mojo::SharedBufferHandle::Create(total_size);  
      mojo::ScopedSharedBufferMapping mapping = write_buffer->Map(total_size);

      scoped_refptr<net::IOBufferWithSize> read_buffer = new net::IOBufferWithSize(readlen);
      
      // Theres no need for hash here anymore..

      //std::string sha256_hash(crypto::kSHA256Length, 0);
      //std::unique_ptr<crypto::SecureHash> ctx = crypto::SecureHash::Create(crypto::SecureHash::SHA256);
      
      char* write_ptr = static_cast<char *>(mapping.get());//file_content->data();
      // write the file len
      write_ptr += csqlitePutVarint(reinterpret_cast<uint8_t *>(write_ptr), static_cast<u64>(file_len));
      // write the protobuf len
      write_ptr += csqlitePutVarint(reinterpret_cast<uint8_t *>(write_ptr), static_cast<u64>(encoded_proto.size()));
      // TODO: support buffered write on DB so we dont need to 
      // allocate the whole file in memory as we are doing with file_content

      // If the allocated pages on DB use mmaped files everything is fine
      // and we dont have to worry about big files
      for (int offset = 0; offset < file_len; offset += readlen) {
        int rv = file.Read(offset, read_buffer->data(), readlen);
        if (rv < readlen && ((offset + rv) != file_len)) {
         //DLOG(ERROR) << "read error. r: " << rv << " readlen: " << readlen << " offset:" << offset << " file_len:" << file_len;
         file.Close();
         return false;
        }
        memcpy(write_ptr, read_buffer->data(), rv);
        //ctx->Update(read_buffer->data(), rv);
        write_ptr += rv;
      }

      //ctx->Finish(const_cast<char *>(sha256_hash.data()), sha256_hash.size());
      file.Close();

      // write the hash
      //memcpy(write_ptr, sha256_hash.data(), sha256_hash.size());

      //write_ptr += sha256_hash.size();

      // write the proto
      memcpy(write_ptr, encoded_proto.data(), encoded_proto.size());
        
      //std::string hex = base::ToLowerASCII(base::HexEncode(sha256_hash.data(), sha256_hash.size()));
      //printf("hash: %s\n", hex.c_str());
      
      std::string key = storage::GetIdentifierForArchitecture(arch);
      
      // add into the file
      
      WriteData(
        base::StringPiece(key), 
        std::move(write_buffer),
        total_size,
        base::Bind(&OnDataPut));

      //if (ok) {
        auto it = codes_.find(arch);
        if (it != codes_.end()) {
          it->second.reset();
          codes_.erase(it);
        }
        codes_.emplace(std::make_pair(arch, std::make_unique<Code>(std::move(executable_proto))));
      //}
    
      return true;//ok;
    }
  } else {
    LOG(ERROR) << "error: trying to push an unexistent executable at " << path;
  }
  return false;
}

void BundleExecutable::LoadHeader() {
  ReadHeaderData(base::Bind(&BundleExecutable::OnHeaderLoad, base::Unretained(this)));
}

void BundleExecutable::OnHeaderLoad(int status, mojo::ScopedSharedBufferHandle buffer, int readed) {
  if (readed > 0) {
    LOG(ERROR) << "OnHeaderLoad: parsing " << readed << " bytes from the shared buffer";
    mojo::ScopedSharedBufferMapping mapping = buffer->Map(readed);
    application_proto_.reset(new storage_proto::Application());
    if (!application_proto_->ParseFromArray(mapping.get(), readed)) {
      LOG(ERROR) << "OnHeaderLoad: failed while decoding protobuf header. readed " << readed << " data:\n'" << static_cast<const char *>(mapping.get()) << "'";
    }
  } else {
    LOG(ERROR) << "OnHeaderLoad: failed while reading header data from app file. readed = " << readed;
  } 
}

void BundleExecutable::CreateHeader(storage_proto::ExecutableFormat format) {
  storage_proto::Application header;
  header.mutable_resource()->set_kind(storage_proto::APPLICATION_RESOURCE);
  // we are creating now, so its the same size as the file creation
  size_t updated_size = size();
  header.mutable_resource()->set_size(updated_size);
  //header.mutable_resource()->set_sha256_hash(file_->sha256_hash());
  header.set_version(kHEADER_VERSION);
  header.set_format(format);
  //std::string header_data;
  
  size_t serial_size = header.ByteSizeLong();
  mojo::ScopedSharedBufferHandle data = mojo::SharedBufferHandle::Create(serial_size);
  mojo::ScopedSharedBufferMapping mapping = data->Map(serial_size);
  if (!header.SerializeToArray(mapping.get(), serial_size)) {
    //DLOG(ERROR) << "CreateHeader: failed to serialize header";
    return;
  }
  WriteHeaderData(std::move(data), serial_size, base::Bind(&OnDataPut));
}

void BundleExecutable::ExtractExecutable(const base::FilePath& exe_path) {
  std::string arch_identifier = storage::GetIdentifierForArchitecture(host_arch_);
  ReadDataForArch(host_arch_, base::Bind(&BundleExecutable::OnReadExecutableData, base::Unretained(this), arch_identifier));
}

void BundleExecutable::OnReadExecutableData(std::string arch_identifier, int status, mojo::ScopedSharedBufferHandle buffer, int readed) {
  if (readed > 0) {
    base::StringPiece file_data;
    mojo::ScopedSharedBufferMapping mapping = buffer->Map(readed);
    if (!GetExecutableContents(mapping.get(), readed, &file_data)) {
      return;
    }

    auto it = codes_.find(host_arch_);
    if (it == codes_.end()) {
      LOG(ERROR) << "error: couldnt find a (cached) executable for arch " << arch_identifier <<
        ". The current host arch is probably not supported";
      return;
    }
    Code* executable = it->second.get();
    if (!base::PathExists(executable->path())) {
      base::FilePath dir_path = executable->path().DirName();
      if (!base::DirectoryExists(dir_path)) {
        base::CreateDirectory(dir_path);
      }
      int wr = base::WriteFile(executable->path(), file_data.data(), file_data.size());
      if (wr == (int)file_data.size()) {
#if defined(OS_POSIX)
        int mode;
        if (base::GetPosixFilePermissions(executable->path(), &mode)) {
          mode = mode | 
            base::FILE_PERMISSION_EXECUTE_BY_OTHERS | 
            base::FILE_PERMISSION_EXECUTE_BY_GROUP | 
            base::FILE_PERMISSION_EXECUTE_BY_USER;
          
          base::SetPosixFilePermissions(executable->path(), mode);
        }
#endif      
      } else {
        LOG(ERROR) << "write of '" << executable->path().value() << "' for '" << arch_identifier << "' failed.";
        return;
      }
    }
  } else {
    printf("Failed to load executable for '%s'. No executable found for this architecture\n", arch_identifier.c_str());
    return;
  }
}

void BundleExecutable::LoadExecutableImages(bool eager_load) {
  for (int i = 0; i < storage_proto::MAX_ARCH; ++i) {
    LoadExecutableImage(static_cast<storage_proto::ExecutableArchitecture>(i), storage_proto::MAX_ARCH);
  }
}

void BundleExecutable::LoadExecutableImage(storage_proto::ExecutableArchitecture arch, int total_archs) {
  std::string arch_identifier = storage::GetIdentifierForArchitecture(arch);
  ReadDataForArch(arch, base::Bind(&BundleExecutable::OnReadExecutableImage, base::Unretained(this), arch, total_archs));
}

void BundleExecutable::OnReadExecutableImage(storage_proto::ExecutableArchitecture arch, int total_archs, int status, mojo::ScopedSharedBufferHandle buffer, int readed) {
  if (readed > 0) {
    std::string arch_identifier = storage::GetIdentifierForArchitecture(arch);
    mojo::ScopedSharedBufferMapping mapping = buffer->Map(readed);
    //DLOG(INFO) << "found executable image for arch " << arch_identifier;
    storage_proto::Code executable_proto;
    
    if (!DecodeExecutableHeader(mapping.get(), readed, &executable_proto)) {
      LOG(ERROR) << "failed to decode header for " << arch_identifier;
      return;
    }

    std::unique_ptr<Code> executable = std::make_unique<Code>(std::move(executable_proto));
    codes_.emplace(std::make_pair(arch, std::move(executable)));
    loaded_archs_++;
  }
  if (loaded_archs_ == total_archs) {
    LoadHostExecutable();
  }
}

void BundleExecutable::LoadHostExecutable() {
  Code* host_executable = host_code();
  if (host_executable) {
    base::FilePath exe_path = storage::GetPathForArchitecture(identifier(), host_arch_);
    if (!base::PathExists(exe_path)) {
      //DLOG(INFO) << "exe not there. extracting on " << exe_path;
      ExtractExecutable(exe_path);
    } else {
      //DLOG(INFO) << "exe already on " << exe_path << ". not extracting.";
    }

    // now we are sure that the executable should be there on path
    // we can safely load
    host_executable->Load();
  } else {
    //DLOG(ERROR) << "no host executable found";
  }
}

bool BundleExecutable::DecodeExecutableHeader(void* data, size_t size, storage_proto::Code* proto) {
  u64 file_len = 0;
  u64 proto_len = 0;

  const char* ptr = static_cast<const char *>(data);//data.data();
  ptr += csqliteGetVarint(reinterpret_cast<const uint8_t*>(ptr), &file_len);
  ptr += csqliteGetVarint(reinterpret_cast<const uint8_t*>(ptr), &proto_len);

  size_t header_size = 
    // size of the encoded int for the file/body len
    csqliteVarintLen(file_len) + 
    // size of the encoded int for the proto len
    csqliteVarintLen(proto_len) + 
    // size of the sha256 hash payload (always fixed)
 //   crypto::kSHA256Length + 
    // the size of the encoded protobuf header
    proto_len;

  if (file_len != (size - header_size)) {
    LOG(ERROR) << "decoding executable header failed." <<
     " sizes dont match. (" << file_len << "(decoded) vs " << header_size << " - " << size << "(header - readed size))";
    return false; 
  }

  // ptr should be pointing to file contents. move
  ptr += file_len;

  // ptr should be pointing to the sha256 hash payload
  //base::StringPiece decoded_hash(ptr, crypto::kSHA256Length);
  //std::string decoded_hex = base::ToLowerASCII(base::HexEncode(decoded_hash.data(), decoded_hash.size()));
  
  //printf("decoded hash: %s\n", decoded_hex.c_str());
  //printf("payload for '%s':\n%s\n", arch_key.c_str(), payload.as_string().c_str());

  // move to protobuf header
  //ptr += crypto::kSHA256Length;
  
  base::StringPiece protobuf_payload(ptr, proto_len);
 // printf("header len = %zu proto len = %llu file len = %llu\nproto: '%s'\n", header_size, proto_len, file_len, protobuf_payload.as_string().c_str());
  if (!proto->ParseFromString(protobuf_payload.as_string())) {
    LOG(ERROR) << "failed to parsed the body as Code protobuf data";
    return false;
  }

  if (proto->resource().size() != static_cast<int64_t>(file_len)) {
    LOG(ERROR) << "something wrong: the size of the file does not match with the size on the encoded header proto: " <<
      "file size on proto: " << proto->resource().size() << " file size : " << file_len;
    return false; 
  }
  
  base::FilePath exe_path = storage::GetPathForArchitecture(identifier(), host_arch_);

  // give the proto a little more information
#if defined (OS_WIN)
  proto->mutable_resource()->set_path(base::UTF16ToASCII(exe_path.value()));
#else        
  proto->mutable_resource()->set_path(exe_path.value());
#endif
  //proto->mutable_resource()->set_sha256_hash(decoded_hash.as_string());
  return true;
}

bool BundleExecutable::GetExecutableContents(void* data, size_t size, base::StringPiece* contents) {
  u64 file_len = 0;
  u64 proto_len = 0;

  const char* ptr = static_cast<const char*>(data);//data.data();
  ptr += csqliteGetVarint(reinterpret_cast<const uint8_t*>(ptr), &file_len);
  ptr += csqliteGetVarint(reinterpret_cast<const uint8_t*>(ptr), &proto_len);

  size_t header_size = 
    // size of the encoded int for the file/body len
    csqliteVarintLen(file_len) + 
    // size of the encoded int for the proto len
    csqliteVarintLen(proto_len) + 
    // size of the sha256 hash payload (always fixed)
    //crypto::kSHA256Length + 
    // the size of the encoded protobuf header
    proto_len;

  if (file_len != (size - header_size)) {
    LOG(ERROR) << "getting executable contents failed." <<
     " sizes dont match. (" << file_len << "(decoded) vs " << header_size << " - " << size << "(header - readed size))";
    return false; 
  }
  
  // file content is right after (file len + proto len) part of the header
  // the hash len is saved after the file content and the proto len after the
  // hash payload, and before the proto contents

  // saving everything upfront in the top, would make us lose
  // the bufferization of writing the file in chunks.

  // by using StringPiece we are not copying the contents
  // loaded by the DB, while the contents of the db file are being mmaped
  // so that way we are avoinding to keep all the file contents in memory at once  
  
  *contents = base::StringPiece(ptr, file_len);
  return true;
}

std::string BundleExecutable::GetStaticEntryName(storage_proto::ExecutableEntryCode entry_code) {
  switch (entry_code) {
    case storage_proto::APP_INIT:
      return std::string(kAPP_INIT_ENTRY, arraysize(kAPP_INIT_ENTRY));
      break;
    case storage_proto::APP_DESTROY:
      return std::string(kAPP_DESTROY_ENTRY, arraysize(kAPP_DESTROY_ENTRY));
      break;
    case storage_proto::APP_GET_CLIENT:
      return std::string(kAPP_GET_CLIENT_ENTRY, arraysize(kAPP_GET_CLIENT_ENTRY));
      break;
    default:
      NOTREACHED();
  }
  return std::string();
}

void BundleExecutable::Close() {
  context_->data().Close(identifier_, base::Callback<void(int)>());
}

void BundleExecutable::ReadHeaderData(base::Callback<void(int, mojo::ScopedSharedBufferHandle, int)> cb) {
  std::string key = storage::kApplicationFileHeaderKey;
  context_->data().GetOnce(identifier_, app_keyspace_, key, std::move(cb));
//  //DLOG(INFO) << "Scope::ReadHeaderData(" << data->size() << "): '" << *data << "'";
}

void BundleExecutable::ReadData(base::StringPiece key, base::Callback<void(int, mojo::ScopedSharedBufferHandle, int)> cb) {
  context_->data().GetOnce(identifier_, app_keyspace_, key.as_string(), std::move(cb));
}

void BundleExecutable::ReadDataForArch(storage_proto::ExecutableArchitecture arch, base::Callback<void(int, mojo::ScopedSharedBufferHandle, int)> cb) {
  std::string key = storage::GetIdentifierForArchitecture(arch);
  return ReadData(key, std::move(cb));
}

void BundleExecutable::WriteData(base::StringPiece key, mojo::ScopedSharedBufferHandle data, int64_t size, base::Callback<void(int)> cb) {
  context_->data().Put(identifier_, app_keyspace_, key.as_string(), size, std::move(data), std::move(cb));
}

void BundleExecutable::WriteHeaderData(mojo::ScopedSharedBufferHandle data, int64_t size, base::Callback<void(int)> cb) {
  std::string key = storage::kApplicationFileHeaderKey;
  context_->data().Put(identifier_, app_keyspace_, key, size, std::move(data), std::move(cb));
}


}
