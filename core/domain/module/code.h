// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_EXECUTION_CODE_H_
#define MUMBA_DOMAIN_EXECUTION_CODE_H_

#include "base/macros.h"
#include "base/files/file_path.h"
#include "base/files/file_path.h"
#include "storage/proto/storage.pb.h"
#include "core/domain/module/code_entry.h"
#include "mojo/public/cpp/system/buffer.h"
#include "third_party/protobuf/src/google/protobuf/descriptor.h"
#include "third_party/protobuf/src/google/protobuf/descriptor.pb.h"

namespace domain {
class CodeLoader;

// a executable portion of data.
// be it working as a library or as a program

// TODO: the disk layer is doing too much
//       having to Bind() the function
//       we cannot know or deal with the layout here
//       we need to leave this to the executor, on the shell layer
//       ...
//       Scrap the Function<> and Callable interface out of here
//
//       We (disk::) shoud ONLY pass a 'cursor' to the executable data
//       when the consumer asks for. The cursor being the begin() and end()
//       of the executable payload for a given symbol
//
//       Having to find the payload by symbol name
//       might be already be a lot in some cases
//
class Code {
public:
  Code(storage_proto::Code code_proto);
  Code(storage_proto::Code code_proto, mojo::ScopedSharedBufferHandle data, size_t size);

  ~Code();

  const base::FilePath& path() const;
  void set_path(const base::FilePath& path);

  storage_proto::ExecutableFormat executable_format() const {
    return code_proto_.format();
  }

  size_t size() const {
    return code_proto_.resource().size();
  }

  void set_size(size_t size) {
    code_proto_.mutable_resource()->set_size(size); 
  }

  const std::string& sha256_hash() const {
    return code_proto_.resource().sha256_hash();
  }

  void set_sha256_hash(const std::string& hash) {
    code_proto_.mutable_resource()->set_sha256_hash(hash);  
  }

  void set_executable_format(storage_proto::ExecutableFormat type) {
    code_proto_.set_format(type);
  }

  storage_proto::ExecutableArchitecture executable_architecture() const {
    return code_proto_.architecture();
  }

  // the protobuf service descriptor that describes the methods in this library
  const google::protobuf::ServiceDescriptor* service_descriptor() const {
    return service_descriptor_;
  }
  
  // only valid for executables of the library type
  bool Load();
  void Unload();

  CodeEntry* GetEntry(const std::string& name);

  // TODO We: need to create a more elaborated form of method description
  //      because we can have a .proto of a service and will try to find
  //      the method by its function signature here
  
  //      using the proto to find the bynary payload be it a
  //      wasm bytecode, or a native executable payload from 
  //      a DSO or from a snapshot

private:

  bool Init();

  CodeEntry* GetCachedEntry(const std::string& name);

  storage_proto::Code code_proto_;

  base::FilePath path_;

  std::vector<CodeEntry *> entries_;

  const google::protobuf::ServiceDescriptor* service_descriptor_;

  std::unique_ptr<CodeLoader> code_loader_;

  mojo::ScopedSharedBufferHandle data_;

  size_t data_size_;

  bool load_from_memory_;

  DISALLOW_COPY_AND_ASSIGN(Code); 
}; 

}

#endif
