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

#include "swift_rpc_service.h"

#include <algorithm>
#include <vector>
#include <google/protobuf/stubs/hash.h>
#include <google/protobuf/stubs/strutil.h>
#include <google/protobuf/io/printer.h>
#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/wire_format.h>
#include <google/protobuf/wire_format_lite_inl.h>
#include <google/protobuf/descriptor.pb.h>

#include "swift_enum.h"
#include "swift_extension.h"
#include "swift_helpers.h"
#include "swift_oneof.h"

namespace google { namespace protobuf { namespace compiler { namespace swift {
    
    using internal::WireFormat;
    using internal::WireFormatLite;
    using namespace std;

    enum class StreamingType {
      Unary = 0,
      ClientStreaming = 1,
      ServerStreaming = 2,
      BidirectionalStreaming = 3
    };

    namespace {

      StreamingType GetStreamingType(const MethodDescriptor* method) {
        if (method->client_streaming()) {
          if (method->server_streaming()) {
            return StreamingType::BidirectionalStreaming;
          } else {
            return StreamingType::ClientStreaming;
          }
        } else {
          if (method->server_streaming()) {
            return StreamingType::ServerStreaming;
          } else {
            return StreamingType::Unary;
          }
        }
      }

      string TypePrefix(const FileDescriptor* file) {
        // for now
        return file->package() + "_";
      }

      //string FullName(const FieldDescriptor* field) {
      //}

      string ProtoMessageName(const FileDescriptor* file, const Descriptor* descriptor) {
        // for now
        if (!file->package().empty()) {
          return UnderscoresToCapitalizedCamelCase(file->package()) + "." + descriptor->name();
        } else {
          return descriptor->name();;
        }
        //FullName(descriptor);
      }

      string NameForPackageService(const FileDescriptor* file,
                                   const ServiceDescriptor* service) {
        if (!file->package().empty()) {
          return TypePrefix(file) + service->name();
        } else {
          return service->name();
        }
      }

      string NameForPackageServiceMethod(const FileDescriptor* file,
                                         const ServiceDescriptor* service,
                                         const MethodDescriptor* method) {
        return NameForPackageService(file, service) + method->name();
      }

    }
    
    RpcServiceGenerator::RpcServiceGenerator(const FileDescriptor* file, const ServiceDescriptor* service) : 
        file_(file),
        service_(service),
        method_(nullptr) {
          
    }
    
    
    RpcServiceGenerator::~RpcServiceGenerator() {
      
    }

    string RpcServiceGenerator::access() const {
      // for now
      return "public";
    }

    string RpcServiceGenerator::ServiceClassName() const {
      return NameForPackageService(file_, service_) + "Service";
    }

    string RpcServiceGenerator::ProviderName() const {
      return NameForPackageService(file_, service_) + "Provider";
    }

    string RpcServiceGenerator::CallName() const {
      return NameForPackageServiceMethod(file_, service_, method_) + "Call";
    }

    string RpcServiceGenerator::MethodFunctionName() const {
      return UnderscoresToCamelCase(method_);
      //return method_->name();
    }

    string RpcServiceGenerator::MethodSessionName() const {
      return NameForPackageServiceMethod(file_, service_, method_) + "Session";
    }

    string RpcServiceGenerator::MethodInputName() const {
      return ProtoMessageName(file_, method_->input_type());
    }

    string RpcServiceGenerator::MethodOutputName() const {
      return ProtoMessageName(file_, method_->output_type());
    }
  
    string RpcServiceGenerator::ServicePath() const {
      if (!file_->package().empty()) {
        return file_->package() + "." + service_->name();
      } else {
        return service_->name();
      }
    }

    string RpcServiceGenerator::MethodPath() const {
      return "\"/" + ServicePath() + "/" + method_->name() + "\"";
    }
    
    void RpcServiceGenerator::GenerateSource(io::Printer* printer) {
      GenerateServer(printer);
      GenerateClient(printer);
    }

    void RpcServiceGenerator::GenerateServer(io::Printer* printer) {
      PrintServerProtocol(printer);
      for (int i = 0; i < service_->method_count(); i++) {
        const MethodDescriptor* method = service_->method(i);
        method_ = method;
        StreamingType streaming_type = GetStreamingType(method);
        switch (streaming_type) {
          case StreamingType::Unary:
            PrintServerMethodUnary(printer);
            break;
          case StreamingType::ClientStreaming:
            PrintServerMethodClientStreaming(printer);
            break;
          case StreamingType::ServerStreaming:
            PrintServerMethodServerStreaming(printer);
            break;
          case StreamingType::BidirectionalStreaming:
            PrintServerMethodBidirectional(printer);
            break;
        }
        //println();
      }
    }
    
    void RpcServiceGenerator::GenerateClient(io::Printer* printer) {

    }

    void RpcServiceGenerator::PrintServerProtocol(io::Printer* printer) {
      printer->Print("/// To build a server, implement a class that conforms to this protocol.\n");
      printer->Print("/// If one of the methods returning `ServerStatus?` returns nil,\n");
      printer->Print("/// it is expected that you have already returned a status to the client by means of `session.close`.\n");
      printer->Print("$access$ protocol $providerName$: ServiceProvider {\n", 
        "access", access(),
        "providerName", ProviderName());
      printer->Indent();
      for (int i = 0; i < service_->method_count(); i++) {
        const MethodDescriptor* method = service_->method(i);
        method_ = method;
        switch (GetStreamingType(method)) {
          //case StreamingType::Unary:
            // printer->Print("func $methodFunctionName$(request: $methodInputName$, session: $methodSessionName$) throws -> $methodOutputName$?\n",
            //   "methodFunctionName", MethodFunctionName(),
            //   "methodInputName", MethodInputName(),
            //   "methodSessionName", MethodSessionName(),
            //   "methodOutputName", MethodOutputName());
            // break;
          case StreamingType::Unary:
          case StreamingType::ServerStreaming:
            printer->Print("func $methodFunctionName$(callId: Int, request: $methodInputName$, session: $methodSessionName$) throws -> ServerStatus?\n",
              "methodFunctionName", MethodFunctionName(),
              "methodInputName", MethodInputName(),
              "methodSessionName", MethodSessionName());
            break;
          case StreamingType::ClientStreaming:
            printer->Print("func $methodFunctionName)(callId: Int, session: $methodSessionName$) throws -> $methodOutputName$?\n",
              "methodFunctionName", MethodFunctionName(),
              "methodSessionName", MethodSessionName(),
              "methodOutputName", MethodOutputName());
            break;
          case StreamingType::BidirectionalStreaming:
            printer->Print("func $methodFunctionName$(callId: Int, session: $methodSessionName$) throws -> ServerStatus?\n",
              "methodFunctionName", MethodFunctionName(),
              "methodSessionName", MethodSessionName());
            break;
        }
      }

      printer->Outdent();
      printer->Print("}\n\n");
      printer->Print("extension $providerName$ {\n", "providerName", ProviderName());
      printer->Indent();
      printer->Print("$access$ var serviceName: String { return \"$servicePath$\" }\n\n", 
        "access", access(), 
        "servicePath", ServicePath());
      printer->Print("/// Determines and calls the appropriate request handler, depending on the request's method.\n");
      printer->Print("/// Throws `HandleMethodError.unknownMethod` for methods not handled by this service.\n");
      printer->Print("$access$ func handleMethod(_ method: String, callId: Int, handler: RpcHandler) throws -> ServerStatus? {\n",
        "access", access());
      printer->Indent();
      printer->Print("switch method {\n");
      for (int i = 0; i < service_->method_count(); i++) {
        const MethodDescriptor* method = service_->method(i);
        method_ = method;
        printer->Print("case $methodPath$:\n", 
          "methodPath", MethodPath());
        printer->Indent();
        switch (GetStreamingType(method)) {
          case StreamingType::Unary:
          case StreamingType::ServerStreaming:
            printer->Print("return try $methodSessionName$Base(\n", 
              "methodSessionName", MethodSessionName());
            printer->Indent();
            //printer->Print("callId: callId,\n");
            printer->Print("handler: handler,\n");
            printer->Print("providerBlock: { try self.$methodFunctionName$(callId: $$0, request: $$1, session: $$2 as! $methodSessionName$Base) })\n",
              "methodFunctionName", MethodFunctionName(),
              "methodSessionName", MethodSessionName());
            printer->Indent();
            printer->Print(".run(callId: callId)\n");
            printer->Outdent();
            printer->Outdent();
            break; 
          default:
            printer->Print("return try $methodSessionName$Base(\n", 
              "methodSessionName", MethodSessionName());
            printer->Indent();
            //printer->Print("callId: callId,\n");
            printer->Print("handler: handler,\n");
            printer->Print(
              "providerBlock: { try self.$methodFunctionName$(callId: $$0, session: $$1 as! $methodSessionName$Base) })\n", 
              "methodFunctionName", MethodFunctionName(), 
              "methodSessionName", MethodSessionName());
            printer->Indent();
            printer->Print(".run(callId: callId)\n");
            printer->Outdent();
            printer->Outdent();
        }
        printer->Outdent();
      }


      printer->Print("default:\n");
      printer->Indent();
      printer->Print("throw HandleMethodError.unknownMethod\n");
      printer->Outdent();
      printer->Print("}\n");
      printer->Outdent();
      printer->Print("}\n");
      printer->Outdent();

      printer->Print("}\n\n");
    }

    void RpcServiceGenerator::PrintServerMethodUnary(io::Printer* printer) {
      //printer->Print("$access$ protocol $methodSessionName$: ServerSessionUnary {}\n\n",
      printer->Print("$access$ protocol $methodSessionName$: ServerSessionServerStreaming {\n",
       "access", access(),
       "methodSessionName", MethodSessionName());
      printer->Indent();
      PrintStreamSendMethods(printer, MethodOutputName());
      printer->Print("\n");
      PrintServerMethodClose(printer);
      printer->Outdent();
      printer->Print("}\n");
      PrintStreamSendExtension(printer, MethodSessionName(), MethodOutputName());
      //printer->Print("fileprivate final class $methodSessionName$Base: ServerSessionUnaryBase<$methodInputName$, $methodOutputName$>, $methodSessionName$ {}\n",
      printer->Print("fileprivate final class $methodSessionName$Base: ServerSessionServerStreamingBase<$methodInputName$, $methodOutputName$>, $methodSessionName$ {\n",
        "methodSessionName", MethodSessionName(),
        "methodInputName", MethodInputName(),
        "methodOutputName", MethodOutputName());
      printer->Indent();
      printer->Print("$access$ func close(callId: Int, withStatus status: ServerStatus, completion: (() -> Void)?) throws {\n",
       "access", access());
      printer->Indent();
      printer->Print("handler.sendStatus(callId: callId, status)");
      printer->Outdent();
      printer->Print("}\n");
      printer->Outdent();
      printer->Print("}\n");  
    }
    
    void RpcServiceGenerator::PrintServerMethodClientStreaming(io::Printer* printer) {
      printer->Print("$access$ protocol $methodSessionName$: ServerSessionClientStreaming {",
       "access", access(),
       "methodSessionName", MethodSessionName());
      printer->Indent();
      PrintStreamReceiveMethods(printer, MethodInputName());
      printer->Print("\n");
      PrintServerMethodSendAndClose(printer, MethodOutputName());
      printer->Outdent();
      printer->Print("}\n");
      PrintStreamReceiveExtension(printer, MethodSessionName(), MethodInputName());
      printer->Print("\nfileprivate final class $methodSessionName$Base: ServerSessionClientStreamingBase<$methodInputName$, $methodOutputName$>, $methodSessionName$ {}",
        "methodSessionName", MethodSessionName(),
        "methodInputName", MethodInputName(),
        "methodOutputName", MethodOutputName());
    }

    void RpcServiceGenerator::PrintServerMethodClose(io::Printer* printer) {
      printer->Print("/// Close the connection and send the status. Non-blocking.\n");
      printer->Print("/// This method should be called if and only if your request handler returns a nil value instead of a server status;\n");
      printer->Print("/// otherwise SwiftGRPC will take care of sending the status for you.\n");
      printer->Print("func close(callId: Int, withStatus status: ServerStatus, completion: (() -> Void)?) throws\n");
    }
    
    void RpcServiceGenerator::PrintServerMethodServerStreaming(io::Printer* printer) {
      printer->Print("$access$ protocol $methodSessionName$: ServerSessionServerStreaming {\n",
       "access", access(),
       "methodSessionName", MethodSessionName());
      printer->Indent();
      PrintStreamSendMethods(printer, MethodOutputName());
      printer->Print("\n");
      PrintServerMethodClose(printer);
      printer->Outdent();
      printer->Print("}\n");
      PrintStreamSendExtension(printer, MethodSessionName(), MethodOutputName());
      printer->Print("\nfileprivate final class $methodSessionName$Base: ServerSessionServerStreamingBase<$methodInputName$, $methodOutputName$>, $methodSessionName$ {\n",
       "methodSessionName", MethodSessionName(),
       "methodInputName", MethodInputName(),
       "methodOutputName", MethodOutputName());
      printer->Indent();
      printer->Print("$access$ func close(callId: Int, withStatus status: ServerStatus, completion: (() -> Void)?) throws {\n",
       "access", access());
      printer->Indent();
      printer->Print("handler.sendStatus(callId: callId, status)");
      printer->Outdent();
      printer->Print("}\n");
      printer->Outdent();
      printer->Print("}\n");
    }
    
    void RpcServiceGenerator::PrintServerMethodBidirectional(io::Printer* printer) {
      printer->Print("$access$ protocol $methodSessionName$: ServerSessionBidirectionalStreaming {\n",
       "access", access(),
       "methodSessionName", MethodSessionName());
      printer->Indent();
      PrintStreamReceiveMethods(printer, MethodInputName());
      printer->Print("\n");
      PrintStreamSendMethods(printer, MethodOutputName());
      printer->Print("\n");
      PrintServerMethodClose(printer);
      printer->Outdent();
      printer->Print("}\n");
      PrintStreamReceiveExtension(printer, MethodSessionName(), MethodInputName());
      printer->Print("\n");
      PrintStreamSendExtension(printer, MethodSessionName(), MethodOutputName());
      printer->Print("\nfileprivate final class $methodSessionName$Base: ServerSessionBidirectionalStreamingBase<$methodInputName$, $methodOutputName$>, $methodSessionName$ {}\n",
       "methodSessionName", MethodSessionName(),
       "methodInputName", MethodInputName(),
       "methodOutputName", MethodOutputName());
    }

    void RpcServiceGenerator::PrintServerMethodSendAndClose(io::Printer* printer, const string& sentType) {
      printer->Print("/// Exactly one of these two methods should be called if and only if your request handler returns nil;\n");
      printer->Print("/// otherwise SwiftGRPC will take care of sending the response and status for you.\n");
      printer->Print("/// Close the connection and send a single result. Non-blocking.\n");
      printer->Print("func sendAndClose(callId: Int, response: $sentType$, status: ServerStatus, completion: (() -> Void)?) throws\n",
       "sentType", sentType);
      printer->Print("/// Close the connection and send an error. Non-blocking.\n");
      printer->Print("/// Use this method if you encountered an error that makes it impossible to send a response.\n");
      printer->Print("/// Accordingly, it does not make sense to call this method with a status of `.ok`.\n");
      printer->Print("func sendErrorAndClose(callId: Int, status: ServerStatus, completion: (() -> Void)?) throws\n");
    }

    void RpcServiceGenerator::PrintStreamReceiveMethods(io::Printer* printer, const std::string& receivedType) {
      printer->Print("/// Do not call this directly, call `receive()` in the protocol extension below instead.\n");
      printer->Print("func _receive(callId: Int, timeout: TimeDelta) throws -> $receivedType$?\n",
        "receivedType", receivedType);
      printer->Print("/// Call this to wait for a result. Nonblocking.\n");
      printer->Print("func receive(callId: Int, completion: @escaping (ResultOrRpcError<$receivedType$?>) -> Void) throws\n",
        "receivedType", receivedType);
    }
    
    void RpcServiceGenerator::PrintStreamReceiveExtension(io::Printer* printer, const std::string& extendedType, const std::string& receivedType) {
      printer->Print("$access$ extension $extendedType$ {\n", 
        "access", access(), 
        "extendedType", extendedType);
      printer->Indent();
      printer->Print("/// Call this to wait for a result. Blocking.\n");
      printer->Print("func receive(callId: Int, timeout: TimeDelta = TimeDelta()) throws -> $receivedType$? { return try self._receive(callId: callId, timeout: timeout) }\n",
        "receivedType", receivedType);
      printer->Outdent();
      printer->Print("}\n");
    }
    
    void RpcServiceGenerator::PrintStreamSendMethods(io::Printer* printer, const std::string& sentType) {
      printer->Print("/// Send a message to the stream. Nonblocking.\n");
      printer->Print("func send(_ message: $sentType$, callId: Int, completion: ((Error?) -> Void)?) throws\n", "sentType", sentType);
      printer->Print("/// Do not call this directly, call `send()` in the protocol extension below instead.\n");
      printer->Print("func _send(_ message: $sentType$, callId: Int, timeout: TimeDelta) throws\n", "sentType", sentType);
    }
    
    void RpcServiceGenerator::PrintStreamSendExtension(io::Printer* printer, const std::string& extendedType, const std::string& sentType) {
      printer->Print("$access$ extension $extendedType$ {\n", 
        "access", access(), 
        "extendedType", extendedType);
      printer->Indent();
      printer->Print("/// Send a message to the stream and wait for the send operation to finish. Blocking.\n");
      printer->Print("func send(_ message: $sentType$, callId: Int, timeout: TimeDelta = TimeDelta()) throws { try self._send(message, callId: callId, timeout: timeout) }\n",
       "sentType", sentType);
      printer->Outdent();
      printer->Print("}\n");
    }
    
}  // namespace swift
}  // namespace compiler
}  // namespace protobuf
}  // namespace google
