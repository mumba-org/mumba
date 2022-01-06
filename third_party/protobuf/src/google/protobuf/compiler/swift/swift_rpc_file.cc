// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "swift_rpc_file.h"

#include <google/protobuf/compiler/code_generator.h>
#include <google/protobuf/io/printer.h>
#include <google/protobuf/io/zero_copy_stream.h>
#include <google/protobuf/descriptor.h>
#include <google/protobuf/descriptor.pb.h>
#include <google/protobuf/stubs/strutil.h>

#include <sstream>

#include "swift_enum.h"
#include "swift_oneof.h"
#include "swift_extension.h"
#include "swift_helpers.h"
#include "swift_message.h"
#include "swift_extra.h"

namespace google { namespace protobuf { namespace compiler {namespace swift {
    
    RpcFileGenerator::RpcFileGenerator(const FileDescriptor* file)
    : file_(file), classname_(PackageFileName(file)) {
        
    }
    
    
    RpcFileGenerator::~RpcFileGenerator() {
      
    }
    
    void RpcFileGenerator::GenerateSource(io::Printer* printer) {
      for (int i = 0 ; i < file_->service_count(); i++) {
        const ServiceDescriptor* descriptor = file_->service(i);
        RpcServiceGeneratorExtra service_gen(file_, descriptor);
        service_gen.GenerateSource(printer);
      }
    }
    
    
}  // namespace swift
}  // namespace compiler
}  // namespace protobuf
}  // namespace google
