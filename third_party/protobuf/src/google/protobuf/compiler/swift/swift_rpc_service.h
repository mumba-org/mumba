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

#ifndef swift_RPC_SERVICE_H
#define swift_RPC_SERVICE_H

#include <string>
#include <map>
#include <set>
#include <google/protobuf/stubs/common.h>

#include "swift_field.h"

namespace google {
    namespace protobuf {
        namespace io {
            class Printer;             // printer.h
        }
    }
    
    namespace protobuf {
        namespace compiler {
            namespace swift {
                
                class RpcServiceGenerator {
                public:
                    RpcServiceGenerator(const FileDescriptor* file, const ServiceDescriptor* service);
                    virtual ~RpcServiceGenerator();
                    
                    string access() const;
                    string ServiceClassName() const;
                    string ProviderName() const;
                    string CallName() const;
                    string MethodFunctionName() const;
                    string MethodSessionName() const;
                    string MethodInputName() const;
                    string MethodOutputName() const;
                    string ServicePath() const;
                    string MethodPath() const;
                    
                    virtual void GenerateSource(io::Printer* printer);
                    virtual void PrintServerProtocol(io::Printer* printer);

                protected:
                    void PrintServerMethodUnary(io::Printer* printer);
                    void PrintServerMethodClientStreaming(io::Printer* printer);
                    void PrintServerMethodServerStreaming(io::Printer* printer);
                    void PrintServerMethodBidirectional(io::Printer* printer);

                    void PrintServerMethodSendAndClose(io::Printer* printer, const string& sentType);
                    void PrintStreamReceiveMethods(io::Printer* printer, const std::string& receivedType);
                    void PrintStreamReceiveExtension(io::Printer* printer, const std::string& extendedType, const std::string& receivedType);
                    void PrintStreamSendMethods(io::Printer* printer, const std::string& sentType);
                    void PrintStreamSendExtension(io::Printer* printer, const std::string& extendedType, const std::string& sentType); 
                    void PrintServerMethodClose(io::Printer* printer);

                  const FileDescriptor* file_;
                  const ServiceDescriptor* service_;
                  const MethodDescriptor* method_;

                 private:   
                  
                    void GenerateServer(io::Printer* printer);
                    void GenerateClient(io::Printer* printer);


                    GOOGLE_DISALLOW_EVIL_CONSTRUCTORS(RpcServiceGenerator);
                };
            }  // namespace swift
        }  // namespace compiler
    }  // namespace protobuf
}  // namespace google

#endif // swift_MESSAGE_H
