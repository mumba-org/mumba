#ifndef swift_RPC_SERVICE_EXTRA_H__
#define swift_RPC_SERVICE_EXTRA_H__

#include <string>
#include <set>
#include <vector>
#include <google/protobuf/stubs/common.h>
#include "swift_rpc_service.h"
#include "swift_file.h"

namespace google {
namespace protobuf {
class FileDescriptor;        // descriptor.h
namespace io {
class Printer;             // printer.h
}
}
}

namespace google {
namespace protobuf {
namespace compiler {
namespace swift {

class FileGeneratorExtra : public FileGenerator {
public:
  FileGeneratorExtra(const FileDescriptor* file);
  ~FileGeneratorExtra() override;
  
  void GenerateSource(io::Printer* printer) override;
private:

  void GenerateMessage(const std::string& message_name, io::Printer* printer);
  void GenerateMessageIsEqualSource(const std::string& message_name, io::Printer* printer);
  void PrintInjectedMessages(io::Printer* printer);  
  void GenerateBuilderSource(const std::string& message_name, io::Printer* printer);
  void GenerateIsInitializedSource(io::Printer* printer);
  void GenerateBuilderMembersSource(const std::string& containing_class, const std::string& field, const std::string& field_type, const std::string& def, io::Printer* printer) const;
  void GenerateMessageSerializationMethodsSource(const std::string& message_name, io::Printer* printer);
  void GenerateCommonBuilderMethodsSource(const std::string& message_name, io::Printer* printer);
  void GenerateBuilderParsingMethodsSource(const std::string& message_name, io::Printer* printer);
  void GenerateParseFromMethodAndBuilderExtensions(io::Printer* printer);
  void GenerateParseFromMethodsSource(const std::string& message, io::Printer* printer);
  void GenerateBuilderExtensions(const std::string& message, io::Printer* printer);
  void GenerateSubscript(const std::string& message, io::Printer* printer) const;
  void GenerateSetSubscript(const std::string& message, io::Printer* printer) const;
};

class RpcServiceGeneratorExtra : public RpcServiceGenerator {
public:
  RpcServiceGeneratorExtra(const FileDescriptor* file, const ServiceDescriptor* service);
  ~RpcServiceGeneratorExtra() override;
  
  void PrintInjectedMethodEntries(io::Printer* printer);
  void PrintInjectedMethodsInterfaces(io::Printer* printer);
  void PrintInjectedMethods(io::Printer* printer);

  void GenerateSource(io::Printer* printer) override;
  void PrintServerProtocol(io::Printer* printer) override;

private:

};

}
}
}
}

#endif