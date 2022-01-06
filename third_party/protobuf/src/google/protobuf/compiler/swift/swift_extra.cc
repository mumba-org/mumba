#include "swift_extra.h"

#include <google/protobuf/compiler/code_generator.h>
#include <google/protobuf/io/printer.h>
#include <google/protobuf/io/zero_copy_stream.h>
#include <google/protobuf/descriptor.pb.h>
#include <google/protobuf/stubs/strutil.h>
#include <google/protobuf/wire_format.h>
#include <google/protobuf/wire_format_lite_inl.h>

#include <sstream>

#include "swift_enum.h"
#include "swift_oneof.h"
#include "swift_extension.h"
#include "swift_helpers.h"
#include "swift_message.h"

namespace google { 
namespace protobuf { 
namespace compiler {
namespace swift {

using internal::WireFormat;
using internal::WireFormatLite;

namespace {

enum class StreamingType {
  Unary = 0,
  ClientStreaming = 1,
  ServerStreaming = 2,
  BidirectionalStreaming = 3
};

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


std::string TypePrefix(const FileDescriptor* file) {
  // for now
  return file->package() + "_";
}

std::string NameForPackageService(const FileDescriptor* file,
                                  const ServiceDescriptor* service) {
  if (!file->package().empty()) {
    return TypePrefix(file) + service->name();
  } else {
    return service->name();
  }
}

std::string ServicePath(const FileDescriptor* file, const ServiceDescriptor* service) {
  if (!file->package().empty()) {
    return file->package() + "." + service->name();
  } else {
    return service->name();
  }
}

std::string FetchServicePath(const FileDescriptor* file) {
  if (!file->package().empty()) {
    return file->package() + ".FetchService";
  } else {
    return "FetchService";
  }
}

std::string ClassNameReturnedType(const FileDescriptor* file, const std::string& message) {
  //string name = UnderscoresToCapitalizedCamelCase(file->package());
  string className = FileClassPrefix(file);
  className += UnderscoresToCapitalizedCamelCase(message);
  return SafeName(className);//SafeName(name + SafeName(className));
}

}

FileGeneratorExtra::FileGeneratorExtra(const FileDescriptor* file): FileGenerator(file) {
  
}


FileGeneratorExtra::~FileGeneratorExtra() {
    
}

void FileGeneratorExtra::GenerateSource(io::Printer* printer) {
    FileGenerator file_generator(file_);

    std::vector<string> tokens = FullNameSplit(file_);

    //fields
    for (int i = 0; i < file_->extension_count(); i++) {
        ExtensionGenerator(ExtensionFileClassName(file_), file_->extension(i)).GenerateFieldsGetterSource(printer, FileClassName(file_));
    }
    
    for (int i = 0; i < file_->message_type_count(); i++) {
        MessageGenerator(file_->message_type(i)).GenerateGlobalStaticVariablesSource(printer, FileClassName(file_));
    }
    
    
    //Generate Messages with packages
    if (tokens.size() > 0) {
        printer->Print("public extension $package$ {\n",
                        "package", PackageExtensionName(tokens));
        XCodeStandartIndent(printer);
    }
    
    
    printer->Print("public struct $classname$ {\n",
                    "classname", classname_);
    
    XCodeStandartIndent(printer);
    printer->Print("public static let `default` = $classname$()\n",
                    "classname", classname_);
    
    for (int i = 0; i < file_->extension_count(); i++) {
        ExtensionGenerator(classname_, file_->extension(i)).GenerateFieldsSource(printer);
    }
    
    
    for (int i = 0; i < file_->message_type_count(); i++) {
        MessageGenerator(file_->message_type(i)).GenerateStaticVariablesSource(printer);
    }
    
    printer->Print("public var extensionRegistry:ExtensionRegistry\n");
    printer->Print(
                    "\n"
                    "init() {\n");
    
    XCodeStandartIndent(printer);
    
    
    for (int i = 0; i < file_->extension_count(); i++) {
        ExtensionGenerator(classname_, file_->extension(i)).GenerateInitializationSource(printer);
    }
    
    for (int i = 0; i < file_->message_type_count(); i++) {
        MessageGenerator(file_->message_type(i)).GenerateStaticVariablesInitialization(printer);
    }
    
    printer->Print("extensionRegistry = ExtensionRegistry()\n"
                    "registerAllExtensions(registry: extensionRegistry)\n");
    
    for (int i = 0; i < file_->dependency_count(); i++) {
        printer->Print("$dependency$.default.registerAllExtensions(registry: extensionRegistry)\n",
                        "dependency", FileClassName(file_->dependency(i)));
    }
    
    XCodeStandartOutdent(printer);
    printer->Print("}\n");
    
    
    printer->Print("public func registerAllExtensions(registry: ExtensionRegistry) {\n");
    
    XCodeStandartIndent(printer);
    for (int i = 0; i < file_->extension_count(); i++) {
        ExtensionGenerator(classname_, file_->extension(i)).GenerateRegistrationSource(printer);
    }
    
    for (int i = 0; i < file_->message_type_count(); i++) {
        MessageGenerator(file_->message_type(i)).GenerateExtensionRegistrationSource(printer);
    }
    XCodeStandartOutdent(printer);
    printer->Print("}\n");
    
    for (int i = 0; i < file_->extension_count(); i++) {
        ExtensionGenerator(classname_, file_->extension(i)).GenerateMembersSourceExtensions(printer,classname_);
    }
    
    XCodeStandartOutdent(printer);
    printer->Print("}\n\n");
    
    ///
    
    for (int i = 0; i < file_->enum_type_count(); i++) {
        EnumGenerator(file_->enum_type(i)).GenerateSource(printer);
    }
    
    
    for (int i = 0; i < file_->message_type_count(); i++) {
        MessageGenerator(file_->message_type(i)).GenerateSource(printer);
    }

    PrintInjectedMessages(printer);
    
    if (tokens.size() > 0) {
        XCodeStandartOutdent(printer);
        printer->Print("}\n");
    }
    
    for (int i = 0; i < file_->message_type_count(); i++) {
        MessageGenerator(file_->message_type(i)).GenerateParseFromMethodsSource(printer);
        MessageGenerator(file_->message_type(i)).GenerateBuilderExtensions(printer);
    }

    GenerateParseFromMethodAndBuilderExtensions(printer);

    printer->Print("\n""// @@protoc_insertion_point(global_scope)\n");
}

void FileGeneratorExtra::GenerateParseFromMethodAndBuilderExtensions(io::Printer* printer) {
  GenerateParseFromMethodsSource("FetchRequest", printer);
  GenerateParseFromMethodsSource("FetchReply", printer);
  GenerateBuilderExtensions("FetchRequest", printer);
  GenerateBuilderExtensions("FetchReply", printer);
}

void FileGeneratorExtra::GenerateParseFromMethodsSource(const std::string& message, io::Printer* printer) {
  std::string classNameReturnedType = UnderscoresToCapitalizedCamelCase(file_->package()) + "." + message;
  std::string fileName = FileClassName(file_);
  printer->Print("extension $classNameReturnedType$: GeneratedMessageProtocol {\n", "classNameReturnedType", classNameReturnedType);
  XCodeStandartIndent(printer);
  printer->Print( "public class func parseArrayDelimitedFrom(inputStream: InputStream) throws -> Array<$classNameReturnedType$> {\n"
                  "    var mergedArray = Array<$classNameReturnedType$>()\n"
                  "    while let value = try parseDelimitedFrom(inputStream: inputStream) {\n"
                  "      mergedArray.append(value)\n"
                  "    }\n"
                  "    return mergedArray\n"
                  "}\n"
                  "public class func parseDelimitedFrom(inputStream: InputStream) throws -> $classNameReturnedType$? {\n"
                  "    return try $classNameReturnedType$.Builder().mergeDelimitedFrom(inputStream: inputStream)?.build()\n"
                  "}\n"
                  "public class func parseFrom(data: Data) throws -> $classNameReturnedType$ {\n"
                  "    return try $classNameReturnedType$.Builder().mergeFrom(data: data, extensionRegistry:$fileName$.default.extensionRegistry).build()\n"
                  "}\n"
                  "public class func parseFrom(data: Data, extensionRegistry:ExtensionRegistry) throws -> $classNameReturnedType$ {\n"
                  "    return try $classNameReturnedType$.Builder().mergeFrom(data: data, extensionRegistry:extensionRegistry).build()\n"
                  "}\n"
                  "public class func parseFrom(inputStream: InputStream) throws -> $classNameReturnedType$ {\n"
                  "    return try $classNameReturnedType$.Builder().mergeFrom(inputStream: inputStream).build()\n"
                  "}\n"
                  "public class func parseFrom(inputStream: InputStream, extensionRegistry:ExtensionRegistry) throws -> $classNameReturnedType$ {\n"
                  "    return try $classNameReturnedType$.Builder().mergeFrom(inputStream: inputStream, extensionRegistry:extensionRegistry).build()\n"
                  "}\n"
                  "public class func parseFrom(codedInputStream: CodedInputStream) throws -> $classNameReturnedType$ {\n"
                  "    return try $classNameReturnedType$.Builder().mergeFrom(codedInputStream: codedInputStream).build()\n"
                  "}\n"
                  "public class func parseFrom(codedInputStream: CodedInputStream, extensionRegistry:ExtensionRegistry) throws -> $classNameReturnedType$ {\n"
                  "    return try $classNameReturnedType$.Builder().mergeFrom(codedInputStream: codedInputStream, extensionRegistry:extensionRegistry).build()\n"
                  "}\n", "fileName", fileName, "classNameReturnedType", classNameReturnedType);
  

  XCodeStandartOutdent(printer);
  
  GenerateSubscript(message, printer);
  
  printer->Print("}\n");
  //for (int i = 0; i < descriptor_->nested_type_count(); i++) {
  //    MessageGenerator(descriptor_->nested_type(i)).GenerateParseFromMethodsSource(printer);
  //}
}

void FileGeneratorExtra::GenerateSubscript(const std::string& message, io::Printer* printer) const {
  XCodeStandartIndent(printer);
  printer->Print("public subscript(key: String) -> Any? {\n");
  XCodeStandartIndent(printer);
  printer->Print("switch key {\n");
  if (message == "FetchRequest") {
    printer->Print("case \"startedTime\": return self.startedTime\n");
    printer->Print("case \"contentType\": return self.contentType\n");
    printer->Print("case \"url\": return self.url\n");  
  }
  printer->Print("case \"size\": return self.size\n");
  printer->Print("case \"data\": return self.data\n");
  printer->Print("default: return nil\n");
  printer->Print("}\n");
  XCodeStandartOutdent(printer);
  printer->Print("}\n");
  XCodeStandartOutdent(printer);
}

void FileGeneratorExtra::GenerateSetSubscript(const std::string& message, io::Printer* printer) const {
  printer->Print("public subscript(key: String) -> Any? {\n");
  XCodeStandartIndent(printer);
  printer->Print("get { \n");
  XCodeStandartIndent(printer);
  printer->Print("switch key {\n");
  if (message == "FetchRequest") {
    printer->Print("case \"startedTime\": return self.startedTime\n");
    printer->Print("case \"contentType\": return self.contentType\n");
    printer->Print("case \"url\": return self.url\n");  
  }
  printer->Print("case \"size\": return self.size\n");
  printer->Print("case \"data\": return self.data\n");
  printer->Print("default: return nil\n");
  printer->Print("}\n");
  XCodeStandartOutdent(printer);
  printer->Print("}\n");
  printer->Print("set (newSubscriptValue) { \n");
  XCodeStandartIndent(printer);
  printer->Print("switch key {\n");

  if (message == "FetchRequest") {
    printer->Print("case \"startedTime\":\n");
    XCodeStandartIndent(printer);
    printer->Print("guard let newSubscriptValue = newSubscriptValue as? Int64 else {\n");
    XCodeStandartIndent(printer);
    printer->Print("return\n");
    XCodeStandartOutdent(printer);
    printer->Print("}\n");
    printer->Print("self.startedTime = newSubscriptValue\n");

    printer->Print("case \"contentType\":\n");
    XCodeStandartIndent(printer);
    printer->Print("guard let newSubscriptValue = newSubscriptValue as? String else {\n");
    XCodeStandartIndent(printer);
    printer->Print("return\n");
    XCodeStandartOutdent(printer);
    printer->Print("}\n");
    printer->Print("self.contentType = newSubscriptValue\n");

    printer->Print("case \"url\":\n");
    XCodeStandartIndent(printer);
    printer->Print("guard let newSubscriptValue = newSubscriptValue as? String else {\n");
    XCodeStandartIndent(printer);
    printer->Print("return\n");
    XCodeStandartOutdent(printer);
    printer->Print("}\n");
    printer->Print("self.url = newSubscriptValue\n");
  }
  
  printer->Print("case \"size\":\n");
  XCodeStandartIndent(printer);
  printer->Print("guard let newSubscriptValue = newSubscriptValue as? Int64 else {\n");
  XCodeStandartIndent(printer);
  printer->Print("return\n");
  XCodeStandartOutdent(printer);
  printer->Print("}\n");
  printer->Print("self.size = newSubscriptValue\n");

  printer->Print("case \"data\":\n");
  XCodeStandartIndent(printer);
  printer->Print("guard let newSubscriptValue = newSubscriptValue as? Data else {\n");
  XCodeStandartIndent(printer);
  printer->Print("return\n");
  XCodeStandartOutdent(printer);
  printer->Print("}\n");
  printer->Print("self.data = newSubscriptValue\n");

  XCodeStandartOutdent(printer);
  
  printer->Print("default: return\n");
  printer->Print("}\n");
  XCodeStandartOutdent(printer);
  printer->Print("}\n");
  XCodeStandartOutdent(printer);
  printer->Print("}\n");
}

void FileGeneratorExtra::GenerateBuilderExtensions(const std::string& message, io::Printer* printer) {
  std::string classNameReturnedType = UnderscoresToCapitalizedCamelCase(file_->package()) + "." + message;
  printer->Print("extension $classNameReturnedType$.Builder: GeneratedMessageBuilderProtocol {\n", "classNameReturnedType", classNameReturnedType);
  XCodeStandartIndent(printer);
  printer->Print("public typealias GeneratedMessageType = $classNameReturnedType$\n", "classNameReturnedType", classNameReturnedType);
  GenerateSetSubscript(message, printer);
  
  XCodeStandartOutdent(printer);
  printer->Print("}\n");
  //for (int i = 0; i < descriptor_->nested_type_count(); i++) {
  //    MessageGenerator(descriptor_->nested_type(i)).GenerateBuilderExtensions(printer);
  //}
}

void FileGeneratorExtra::PrintInjectedMessages(io::Printer* printer) {
  GenerateMessage("FetchRequest", printer);
  GenerateMessage("FetchReply", printer);
}

void FileGeneratorExtra::GenerateMessage(const std::string& message_name, io::Printer* printer) {
  std::string classNameReturnedType = UnderscoresToCapitalizedCamelCase(file_->package()) + "." + message_name;
  printer->Print("final public class $className$ : GeneratedMessage {\n", "className", message_name);
  // public typealias BuilderType = Tweedy.EntryInfo.Builder
  printer->Print("public typealias BuilderType = $classNameReturnedType$.Builder\n", "classNameReturnedType", classNameReturnedType);
  printer->Print("\n");
  GenerateMessageIsEqualSource(message_name, printer);
  
  //for (int i = 0; i < descriptor_->field_count(); i++) {
  //    field_generators_.get(descriptor_->field(i)).GenerateVariablesSource(printer);
  //}

  if (message_name == "FetchRequest") {
    // started_time
    printer->Print("public fileprivate(set) var startedTime: Int64 = 0\n\n");
    printer->Print("public fileprivate(set) var hasStartedTime: Bool = false\n\n");
    // content_type
    printer->Print("public fileprivate(set) var contentType: String = String()\n\n");
    printer->Print("public fileprivate(set) var hasContentType: Bool = false\n\n");
    // url
    printer->Print("public fileprivate(set) var url: String = String()\n\n");
    printer->Print("public fileprivate(set) var hasUrl: Bool = false\n\n");
  }

  // size
  printer->Print("public fileprivate(set) var size: Int64 = 0\n\n");
  printer->Print("public fileprivate(set) var hasSize: Bool = false\n\n");
  // data
  printer->Print("public fileprivate(set) var data: Data = Data()\n\n");
  printer->Print("public fileprivate(set) var hasData: Bool = false\n");
  
  
  //for (int i = 0; i < descriptor_->extension_count(); i++) {
  //    ExtensionGenerator(ClassNameExtensions(descriptor_), descriptor_->extension(i)).GenerateMembersSource(printer);
 // }
  
  // for (int i = 0; i < descriptor_->field_count(); i++) {
  //     field_generators_.get(descriptor_->field(i)).GenerateMembersSource(printer);
  // }
  
  printer->Print("required public init() {\n");
  
  
  //for (int i = 0; i < descriptor_->field_count(); i++) {
    
  //    field_generators_.get(descriptor_->field(i)).GenerateInitializationSource(printer);
  //}
  
  printer->Print("    super.init()\n"
                  "}\n");
  
  GenerateIsInitializedSource(printer);
  GenerateMessageSerializationMethodsSource(message_name, printer);

  printer->Print( "public class func getBuilder() -> $classNameReturnedType$.Builder {\n"
                  "    return $classNameReturnedType$.classBuilder() as! $classNameReturnedType$.Builder\n"
                  "}\n"
                  "public func getBuilder() -> $classNameReturnedType$.Builder {\n"
                  "    return classBuilder() as! $classNameReturnedType$.Builder\n"
                  "}\n"
                  "override public class func classBuilder() -> ProtocolBuffersMessageBuilder {\n"
                  "    return $classNameReturnedType$.Builder()\n"
                  "}\n"
                  "override public func classBuilder() -> ProtocolBuffersMessageBuilder {\n"
                  "    return $classNameReturnedType$.Builder()\n"
                  "}\n"
                  "public func toBuilder() throws -> $classNameReturnedType$.Builder {\n"
                  "    return try $classNameReturnedType$.builderWithPrototype(prototype:self)\n"
                  "}\n"
                  "public class func builderWithPrototype(prototype:$classNameReturnedType$) throws -> $classNameReturnedType$.Builder {\n"
                  "    return try $classNameReturnedType$.Builder().mergeFrom(other:prototype)\n"
                  "}\n",
                  "classNameReturnedType", classNameReturnedType);

  //JSON
  //GenerateMessageJSONSource(printer);
  //GenerateMessageDescriptionSource(printer);
  //GenerateMessageHashSource(printer);
  
  printer->Print("\n\n//Meta information declaration start\n\n");
  
  printer->Print( "override public class func className() -> String {\n"
                  "    return \"$classNameReturnedType$\"\n"
                  "}\n"
                  "override public func className() -> String {\n"
                  "    return \"$classNameReturnedType$\"\n"
                  "}\n", "classNameReturnedType", classNameReturnedType);
  
  printer->Print("//Meta information declaration end\n\n");
  GenerateBuilderSource(message_name, printer);
  printer->Print("}\n\n");
}

void FileGeneratorExtra::GenerateMessageIsEqualSource(const std::string& message_name, io::Printer* printer) {
  std::string classNameReturnedType = UnderscoresToCapitalizedCamelCase(file_->package()) + "." + message_name;
  printer->Print("public static func == (lhs: $classNameReturnedType$, rhs: $classNameReturnedType$) -> Bool {\n", 
                  "classNameReturnedType", 
                  classNameReturnedType);  
  printer->Print("if lhs === rhs {\n"
                  "    return true\n"
                  "}\n"
                  );
  printer->Print("var fieldCheck:Bool = (lhs.hashValue == rhs.hashValue)\n");
 
  printer->Print("fieldCheck = fieldCheck && ");
  if (message_name == "FetchRequest") {
    printer->Print("(lhs.startedTime == rhs.startedTime) && (lhs.contentType == rhs.contentType) && (lhs.url == rhs.url) && ");
  }
  printer->Print("(lhs.size == rhs.size) && (lhs.data == rhs.data)");
  printer->Print("\n");
  
  printer->Print("fieldCheck = (fieldCheck && (lhs.unknownFields == rhs.unknownFields))\n");
  printer->Print("return fieldCheck\n");
  printer->Print("}\n\n");
}

void FileGeneratorExtra::GenerateBuilderSource(const std::string& message_name, io::Printer* printer) {
  std::string classNameReturnedType = UnderscoresToCapitalizedCamelCase(file_->package()) + "." + message_name;

  printer->Print("final public class Builder : GeneratedMessageBuilder {\n");
  
  printer->Print( "fileprivate var builderResult:$classNameReturnedType$ = $classNameReturnedType$()\n"
                  "public func getMessage() -> $classNameReturnedType$ {\n"
                  "    return builderResult\n"
                  "}\n\n"
                  "required override public init () {\n"
                  "    super.init()\n"
                  "}\n",
                  "classNameReturnedType",
                  classNameReturnedType);
  
  // const std::string& message_name,
  if (message_name == "FetchRequest") {
    GenerateBuilderMembersSource(message_name, "startedTime", "Int64", "0", printer);
    GenerateBuilderMembersSource(message_name, "contentType", "String", "String()", printer);
    GenerateBuilderMembersSource(message_name, "url", "String", "String()", printer);
  }
  GenerateBuilderMembersSource(message_name, "size", "Int64", "0",printer);
  GenerateBuilderMembersSource(message_name, "data", "Data", "Data()", printer);
  
  GenerateCommonBuilderMethodsSource(message_name, printer);
  GenerateBuilderParsingMethodsSource(message_name, printer);
  //GenerateMessageBuilderJSONSource(printer);

  printer->Print("}\n\n");
}

void FileGeneratorExtra::GenerateBuilderParsingMethodsSource(const std::string& message_name, io::Printer* printer) {
    std::string classNameReturnedType = ClassNameReturnedType(file_, message_name);
    printer->Print( "@discardableResult\n"
                    "override public func mergeFrom(codedInputStream: CodedInputStream) throws -> $classNameReturnedType$.Builder {\n"
                    "    return try mergeFrom(codedInputStream: codedInputStream, extensionRegistry:ExtensionRegistry())\n"
                    "}\n"
                    "@discardableResult\n"
                    "override public func mergeFrom(codedInputStream: CodedInputStream, extensionRegistry:ExtensionRegistry) throws -> $classNameReturnedType$.Builder {\n", 
                    "classNameReturnedType",
                    classNameReturnedType);
    XCodeStandartIndent(printer);
    
    printer->Print(
                    "let unknownFieldsBuilder:UnknownFieldSet.Builder = try UnknownFieldSet.builderWithUnknownFields(copyFrom:self.unknownFields)\n"
                    "while (true) {\n");
    XCodeStandartIndent(printer);
    printer->Print("let protobufTag = try codedInputStream.readTag()\n");
    printer->Print("switch protobufTag {\n");
    
    printer->Print("case 0: \n");
    XCodeStandartIndent(printer);
    printer->Print("self.unknownFields = try unknownFieldsBuilder.build()\n"
                    "return self\n"
                    "\n");
    XCodeStandartOutdent(printer);

    if (message_name == "FetchRequest") {

      uint32 sttag = WireFormatLite::MakeTag(1,
                                          WireFormat::WireTypeForFieldType(FieldDescriptor::Type::TYPE_INT64));        
      printer->Print("case $tag$:\n",
                    "tag", SimpleItoa(sttag));
      XCodeStandartIndent(printer);
      printer->Print("  startedTime = try codedInputStream.readInt64()");
      //field_generators_.get(field).GenerateParsingCodeSource(printer);
      XCodeStandartOutdent(printer);
      printer->Print("\n");

      uint32 ctag = WireFormatLite::MakeTag(2,
                                          WireFormat::WireTypeForFieldType(FieldDescriptor::Type::TYPE_STRING));        
      printer->Print("case $tag$:\n",
                    "tag", SimpleItoa(ctag));
      XCodeStandartIndent(printer);
      printer->Print("  contentType = try codedInputStream.readString()");
      //field_generators_.get(field).GenerateParsingCodeSource(printer);
      XCodeStandartOutdent(printer);
      printer->Print("\n");

      uint32 utag = WireFormatLite::MakeTag(3,
                                          WireFormat::WireTypeForFieldType(FieldDescriptor::Type::TYPE_STRING));        
      printer->Print("case $tag$:\n",
                    "tag", SimpleItoa(utag));
      XCodeStandartIndent(printer);
      printer->Print(" url = try codedInputStream.readString()");
      //field_generators_.get(field).GenerateParsingCodeSource(printer);
      XCodeStandartOutdent(printer);
      printer->Print("\n");

      uint32 stag = WireFormatLite::MakeTag(4,
                                          WireFormat::WireTypeForFieldType(FieldDescriptor::Type::TYPE_UINT64));        
      printer->Print("case $tag$:\n",
                    "tag", SimpleItoa(stag));
      XCodeStandartIndent(printer);
      printer->Print("  size = try codedInputStream.readInt64()");
      //field_generators_.get(field).GenerateParsingCodeSource(printer);
      XCodeStandartOutdent(printer);
      printer->Print("\n");

      uint32 dtag = WireFormatLite::MakeTag(5,
                                          WireFormat::WireTypeForFieldType(FieldDescriptor::Type::TYPE_BYTES));        
      printer->Print("case $tag$:\n",
                    "tag", SimpleItoa(dtag));
      
      //field_generators_.get(field).GenerateParsingCodeSource(printer);
      printer->Print("  data = try codedInputStream.readData()");
      printer->Print("\n");
    } else {
      uint32 stag = WireFormatLite::MakeTag(1,
                                          WireFormat::WireTypeForFieldType(FieldDescriptor::Type::TYPE_UINT64));        
      printer->Print("case $tag$:\n",
                    "tag", SimpleItoa(stag));
      XCodeStandartIndent(printer);
      printer->Print("  size = try codedInputStream.readInt64()");
      //field_generators_.get(field).GenerateParsingCodeSource(printer);
      XCodeStandartOutdent(printer);
      printer->Print("\n");

      uint32 dtag = WireFormatLite::MakeTag(2,
                                          WireFormat::WireTypeForFieldType(FieldDescriptor::Type::TYPE_BYTES));        
      printer->Print("case $tag$:\n",
                    "tag", SimpleItoa(dtag));
      
      //field_generators_.get(field).GenerateParsingCodeSource(printer);
      printer->Print("  data = try codedInputStream.readData()");
      printer->Print("\n");
    }
    
    
    printer->Print("default:\n"
                    "    if (!(try parse(codedInputStream:codedInputStream, unknownFields:unknownFieldsBuilder, extensionRegistry:extensionRegistry, tag:protobufTag))) {\n"
                    "        unknownFields = try unknownFieldsBuilder.build()\n"
                    "        return self\n"
                    "    }\n"
                    "}\n");
    XCodeStandartOutdent(printer);
    printer->Print("}\n");
    XCodeStandartOutdent(printer);
    printer->Print("}\n");
}

void FileGeneratorExtra::GenerateMessageSerializationMethodsSource(const std::string& message_name, io::Printer* printer) {
    
    printer->Print("override public func writeTo(codedOutputStream: CodedOutputStream) throws {\n");
    
    // for (int i = 0, j = 0;
    //       i < descriptor_->field_count() || j < sorted_extensions.size(); ) {
    //     if (i == descriptor_->field_count()) {
    //         GenerateSerializeOneExtensionRangeSource(printer, sorted_extensions[j++]);
    //     } else if (j == sorted_extensions.size()) {
    //         GenerateSerializeOneFieldSource(printer, sorted_fields[i++]);
    //     } else if (sorted_fields[i]->number() < sorted_extensions[j]->start) {
    //         GenerateSerializeOneFieldSource(printer, sorted_fields[i++]);
    //     } else {
    //         GenerateSerializeOneExtensionRangeSource(printer, sorted_extensions[j++]);
    //     }
    // }

    if (message_name == "FetchRequest") {
      printer->Print(" if hasStartedTime {\n"
                     "   try codedOutputStream.writeInt64(fieldNumber: 1, value: startedTime)\n"
                     " }\n");
      printer->Print(" if hasContentType {\n"
                     "   try codedOutputStream.writeString(fieldNumber: 2, value: contentType)\n"
                     " }\n");
      printer->Print(" if hasUrl {\n"
                     "   try codedOutputStream.writeString(fieldNumber: 3, value: url)\n"
                     " }\n");
      printer->Print(" if hasSize {\n"
                   "   try codedOutputStream.writeInt64(fieldNumber: 4, value: size)\n"
                   " }\n");
      printer->Print(" if hasData {\n"
                   "   try codedOutputStream.writeData(fieldNumber: 5, value: data)\n"
                   " }\n");
    } else {
      printer->Print(" if hasSize {\n"
                   "   try codedOutputStream.writeInt64(fieldNumber: 1, value: size)\n"
                   " }\n");
      printer->Print(" if hasData {\n"
                   "   try codedOutputStream.writeData(fieldNumber: 2, value: data)\n"
                   " }\n");
    }
    
    printer->Print(" try unknownFields.writeTo(codedOutputStream: codedOutputStream)\n");
    
    printer->Print("}\n");
    
    printer->Print("override public func serializedSize() -> Int32 {\n");
    
    printer->Print("var serializeSize: Int32 = memoizedSerializedSize\n"
                    "if serializeSize != -1 {\n"
                    " return serializeSize\n"
                    "}\n"
                    "\n"
                    "serializeSize = 0\n");

    //for (int i = 0; i < descriptor_->field_count(); i++) {
    //  field_generators_.get(sorted_fields[i]).GenerateSerializedSizeCodeSource(printer);
    //}
    if (message_name == "FetchRequest") {
      printer->Print("if hasStartedTime {\n"
                     " serializeSize += startedTime.computeInt64Size(fieldNumber: 1)\n"
                     "}\n");
      printer->Print("if hasContentType {\n"
                     " serializeSize += contentType.computeStringSize(fieldNumber: 2)\n"
                     "}\n");
      printer->Print("if hasUrl {\n"
                     " serializeSize += url.computeStringSize(fieldNumber: 3)\n"
                     "}\n");
      printer->Print("if hasSize {\n"
                     " serializeSize += size.computeInt64Size(fieldNumber: 4)\n"
                     "}\n");
      printer->Print("if hasData {\n"
                     " serializeSize += data.computeDataSize(fieldNumber: 5)\n"
                     "}\n");
    }
    else {
      printer->Print("if hasSize {\n"
                     " serializeSize += size.computeInt64Size(fieldNumber: 1)\n"
                     "}\n");
      printer->Print("if hasData {\n"
                     " serializeSize += data.computeDataSize(fieldNumber: 2)\n"
                     "}\n");
    }
    
    printer->Print(
      "serializeSize += unknownFields.serializedSize()\n");
    
    printer->Print(
                    "memoizedSerializedSize = serializeSize\n"
                    "return serializeSize\n");
    
    printer->Print("}\n");
}
    

void FileGeneratorExtra::GenerateBuilderMembersSource(const std::string& containing_class, const std::string& field, const std::string& field_type, const std::string& def, io::Printer* printer) const {
  std::string capitalized_name = UnderscoresToCapitalizedCamelCase(field);
  printer->Print( "public var has$capitalized_name$:Bool {\n"
                  "    get {\n"
                  "        return builderResult.has$capitalized_name$\n"
                  "    }\n"
                  "}\n"
                  "public var $name_reserved$:$type$ {\n"
                  "    get {\n"
                  "        return builderResult.$name_reserved$\n"
                  "    }\n"
                  "    set (value) {\n"
                  "        builderResult.has$capitalized_name$ = true\n"
                  "        builderResult.$name_reserved$ = value\n"
                  "    }\n"
                  "}\n"
                  "@discardableResult\n"
                  "public func set$capitalized_name$(_ value:$type$) -> $containing_class$.Builder {\n"
                  "    self.$name_reserved$ = value\n"
                  "    return self\n"
                  "}\n"
                  "@discardableResult\n"
                  "public func clear$capitalized_name$() -> $containing_class$.Builder{\n"
                  "    builderResult.has$capitalized_name$ = false\n"
                  "    builderResult.$name_reserved$ = $default$\n"
                  "    return self\n"
                  "}\n", 
                  "containing_class", containing_class, 
                  "capitalized_name", capitalized_name, 
                  "name_reserved", field, 
                  "type", field_type,
                  "default", def);   
}

void FileGeneratorExtra::GenerateIsInitializedSource(io::Printer* printer) {
    printer->Print("override public func isInitialized() throws {\n");
    // XCodeStandartIndent(printer);
  
    // for (int i = 0; i < descriptor_->field_count(); i++) {
    //     const FieldDescriptor* field = descriptor_->field(i);
        
    //     if (field->is_required()) {
    //         printer->Print("if !has$capitalized_name$ {\n"
    //                         "    throw ProtocolBuffersError.invalidProtocolBuffer(\"Uninitialized Message \\($classNameReturnedType$.self): field \\\"$fieldName$\\\" mark required\")\n"
    //                         "}\n",
    //                         "capitalized_name", UnderscoresToCapitalizedCamelCase(field),
    //                         "classNameReturnedType", ClassNameReturnedType(descriptor_),
    //                         "fieldName", UnderscoresToCamelCase(field));
    //     }
    // }
    
    // for (int i = 0; i < descriptor_->field_count(); i++) {
    //     const FieldDescriptor* field = descriptor_->field(i);
    //     if (field->cpp_type() == FieldDescriptor::CPPTYPE_MESSAGE &&
    //         HasRequiredFields(field->message_type())) {
            
    //         std::map<string,string> vars;
    //         vars["type"] = ClassName(field->message_type());
    //         vars["name"] = UnderscoresToCamelCase(field);
    //         vars["name_reserved"] = SafeName(UnderscoresToCamelCase(field));
    //         vars["capitalized_name"] = UnderscoresToCapitalizedCamelCase(field);
            
    //         switch (field->label()) {
    //             case FieldDescriptor::LABEL_REQUIRED:
    //                 printer->Print(vars,
    //                                 "try $name_reserved$.isInitialized()\n");
    //                 break;
    //             case FieldDescriptor::LABEL_OPTIONAL:
    //                 printer->Print(vars,
    //                                 "if has$capitalized_name$ {\n"
    //                                 "    try $name_reserved$.isInitialized()\n"
    //                                 "}\n");
    //                 break;
    //             case FieldDescriptor::LABEL_REPEATED:
    //                 if (field->is_map()) {
    //                     printer->Print(vars,
    //                                     "for (_, oneElement$capitalized_name$) in $name_reserved$ {\n"
    //                                     "    try oneElement$capitalized_name$.isInitialized()\n"
    //                                     "}\n"
    //                                     );
    //                 } else {
    //                     printer->Print(vars,
    //                                     "for oneElement$capitalized_name$ in $name_reserved$ {\n"
    //                                     "    try oneElement$capitalized_name$.isInitialized()\n"
    //                                     "}\n"
    //                                     //                                       "if !isInit$capitalized_name$ {\n"
    //                                     //                                       "    return isInit$capitalized_name$\n"
    //                                     //                                       "}\n"
    //                                     );
    //                 }
                    
    //                 break;
    //         }
    //     }
    // }
    
    // if (descriptor_->extension_range_count() > 0) {
    //     printer->Print(
    //                     "try extensionsAreInitialized()");
    // }
    
    // XCodeStandartOutdent(printer);
    printer->Print("}\n");
}

void FileGeneratorExtra::GenerateCommonBuilderMethodsSource(const std::string& message_name, io::Printer* printer) {
    std::string classNameReturnedType = ClassNameReturnedType(file_, message_name);
   
    printer->Print( "override public var internalGetResult:GeneratedMessage {\n"
                    "    get {\n"
                    "        return builderResult\n"
                    "    }\n"
                    "}\n");
    
    
    printer->Print( "@discardableResult\n"
                    "override public func clear() -> $classNameReturnedType$.Builder {\n"
                    "    builderResult = $classNameReturnedType$()\n"
                    "    return self\n"
                    "}\n"
                    "override public func clone() throws -> $classNameReturnedType$.Builder {\n"
                    "    return try $classNameReturnedType$.builderWithPrototype(prototype:builderResult)\n"
                    "}\n",
                    "classNameReturnedType", classNameReturnedType);
    
    printer->Print( "override public func build() throws -> $classNameReturnedType$ {\n"
                    "    try checkInitialized()\n"
                    "    return buildPartial()\n"
                    "}\n"
                    "public func buildPartial() -> $classNameReturnedType$ {\n",
                    "classNameReturnedType", classNameReturnedType);
    
    
    //for (int i = 0; i < descriptor_->field_count(); i++) {
    //    field_generators_.get(descriptor_->field(i)).GenerateBuildingCodeSource(printer);
   // }
    
    
    printer->Print( "    let returnMe:$classNameReturnedType$ = builderResult\n"
                    "    return returnMe\n"
                    "}\n",
                    "classNameReturnedType", classNameReturnedType);
    
    printer->Print(
                    "@discardableResult\n"
                    "public func mergeFrom(other:$classNameReturnedType$) throws -> $classNameReturnedType$.Builder {\n",
                    "classNameReturnedType", classNameReturnedType);

    printer->Print( "if other == $classNameReturnedType$() {\n"
                    "    return self\n"
                    "}\n",
                    "classNameReturnedType", classNameReturnedType);
    
    //for (int i = 0; i < descriptor_->field_count(); i++) {
    //    field_generators_.get(descriptor_->field(i)).GenerateMergingCodeSource(printer);
    //}
    
    //if (descriptor_->extension_range_count() > 0) {
    //    printer->Print("try mergeExtensionFields(other: other)\n");
    //}
    
    printer->Print("try merge(unknownField: other.unknownFields)\n"
                    "return self\n");
    
    printer->Print("}\n");
}

RpcServiceGeneratorExtra::RpcServiceGeneratorExtra(const FileDescriptor* file, const ServiceDescriptor* service):
 RpcServiceGenerator(file, service) {
    
}


RpcServiceGeneratorExtra::~RpcServiceGeneratorExtra() {
    
}

void RpcServiceGeneratorExtra::GenerateSource(io::Printer* printer) {
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
  PrintInjectedMethodsInterfaces(printer);
}

void RpcServiceGeneratorExtra::PrintServerProtocol(io::Printer* printer) {
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
      // case StreamingType::Unary:
      //   printer->Print("func $methodFunctionName$(request: $methodInputName$, session: $methodSessionName$) throws -> $methodOutputName$\n",
      //     "methodFunctionName", MethodFunctionName(),
      //     "methodInputName", MethodInputName(),
      //     "methodSessionName", MethodSessionName(),
      //     "methodOutputName", MethodOutputName());
      //   break;
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
  // FIXME: hack - we are forcing the addition of 'common methods' here
  // 

  PrintInjectedMethods(printer);

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
  printer->Indent();
  printer->Print("var callHandler: ServerSession?\n");
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
        printer->Print("callHandler = $methodSessionName$Base(\n", 
          "methodSessionName", MethodSessionName());
        printer->Indent();
        //printer->Print("callId: callId,\n");
        printer->Print("handler: handler,\n");
        printer->Print("providerBlock: { try self.$methodFunctionName$(callId: $$0, request: $$1, session: $$2 as! $methodSessionName$Base) })\n",
          "methodFunctionName", MethodFunctionName(),
          "methodSessionName", MethodSessionName());
        printer->Outdent();
        break; 
      default:
        printer->Print("callHandler = $methodSessionName$Base(\n", 
          "methodSessionName", MethodSessionName());
        printer->Indent();
        //printer->Print("callId: callId,\n");
        printer->Print("handler: handler,\n");
        printer->Print(
          "providerBlock: { try self.$methodFunctionName$(callId: $$0, session: $$2 as! $methodSessionName$Base) })\n", 
          "methodFunctionName", MethodFunctionName(), 
          "methodSessionName", MethodSessionName());
        printer->Outdent();
    }
    printer->Outdent();
  }

  PrintInjectedMethodEntries(printer);

  printer->Print("default:\n");
  printer->Indent();
  printer->Print("throw HandleMethodError.unknownMethod\n");
  printer->Outdent();
  printer->Print("}\n");
  printer->Outdent();
  printer->Print("if let chandler = callHandler {\n");
  printer->Indent();
  printer->Print("return chandler.run(callId: callId)\n");
  printer->Print("}\n");
  printer->Outdent();
  printer->Print("return nil\n");
  printer->Print("}\n\n");
  printer->Outdent();

  // common implementation
  printer->Indent();
  printer->Print("public func fetchUnary(callId: Int, request: $methodInputName$, session: $methodSessionName$) throws -> ServerStatus? {\n",
    "methodInputName", UnderscoresToCapitalizedCamelCase(file_->package()) + ".FetchRequest",
    "methodSessionName", NameForPackageService(file_, service_) + "FetchUnarySession");
  printer->Print("  let urlString = base64UrlDecode(string: request.url)\n");
  printer->Print("  let replyDataDecoded = base64UrlDecode(data: request.data)\n");
  //printer->Print("  let route = String(urlString[urlString.index(urlString.firstIndex(of: \"/\")!, offsetBy: 1)..<urlString.lastIndex(of: \"/\")!])\n");
  printer->Print("  var route = String(urlString[urlString.index(urlString.firstIndex(of: \"/\")!, offsetBy: 2)..<urlString.endIndex])\n");
  printer->Print("  route = \"/\" + String(route[route.startIndex..<route.firstIndex(of: \"/\")!])\n");
  printer->Print("  let routeRequest = RouteRequest(callId: callId, url: urlString, contentType: request.contentType, startedTime: request.startedTime, inputData: request.data)\n");
  printer->Print("\n");
  printer->Print("  guard var handler = routeHandler(for: route) else {\n");
  printer->Print("    let reply = $methodOutputName$.getBuilder()\n", "methodOutputName", UnderscoresToCapitalizedCamelCase(file_->package()) + ".FetchReply");
  printer->Print("    reply.size = Int64(replyDataDecoded.count)\n");
  printer->Print("    reply.data = Data(bytes: replyDataDecoded, count: replyDataDecoded.count)\n");
  printer->Print("    try session.send(reply.build(), callId: callId)\n");
  printer->Print("    try session.close(callId: callId, withStatus: .ok, completion: nil)\n");
  printer->Print("    return nil\n");
  printer->Print("  }\n");
  printer->Print("\n");
  printer->Print("  let bufferSize = handler.bufferSize\n");
  printer->Print("  handler.lastCallId = callId\n");
  printer->Print("  handler.writeCompletion = {\n");
  printer->Print("    let fullsize = $$2\n");
  printer->Print("    var bytesLeft = fullsize\n");
  printer->Print("    while bytesLeft > 0 {\n");
  printer->Print("      let toWrite = bytesLeft >= bufferSize ? bufferSize : bytesLeft\n");
  printer->Print("      let offset = fullsize - bytesLeft\n");
  printer->Print("      let wrote = sendEncodedBuffer(callId: $$0, session: session, data: $$1, offset: offset, size: toWrite, { _ in \n");
  printer->Print("          print(\"data offset:\\\(offset) sent\")\n");
  printer->Print("      })\n");
  printer->Print("      bytesLeft = bytesLeft - wrote\n");
  //printer->Print("      print(\"size: \\\(fullsize) wrote: \\\(wrote) bytesLeft: \\\(bytesLeft) offset: \\\(offset)\")\n");
  printer->Print("    }\n");
  printer->Print("  }\n");
  printer->Print("  handler.writeRawCompletion = {\n");
  printer->Print("    let fullsize = $$2\n");
  printer->Print("    var bytesLeft = fullsize\n");
  printer->Print("    while bytesLeft > 0 {\n");
  printer->Print("      let toWrite = bytesLeft >= bufferSize ? bufferSize : bytesLeft\n");
  printer->Print("      let offset = fullsize - bytesLeft\n");
  printer->Print("      let wrote = sendBuffer(callId: $$0, session: session, data: $$1, offset: offset, size: toWrite)\n");
  printer->Print("      bytesLeft = bytesLeft - wrote\n");
  //printer->Print("      print(\"size: \\\(fullsize) wrote: \\\(wrote) bytesLeft: \\\(bytesLeft) offset: \\\(offset)\")\n");
  printer->Print("    }\n");
  printer->Print("  }\n");
  printer->Print("  handler.closeCompletion = {\n");
  printer->Print("    try! session.close(callId: $$0, withStatus: $$1 == CloseStatus.ok ? .ok : .unknown, completion: nil)\n");
  printer->Print("  }\n");
  printer->Print("  handler.onResponseStarted(request: routeRequest, info: RouteResponseInfo(), completion: nil)\n");
  printer->Print("  handler.onReadCompleted(request: routeRequest, info: RouteResponseInfo(), buffer: RouteBuffer(string: replyDataDecoded), bytesRead: UInt64(replyDataDecoded.count))\n");
  printer->Print("  handler.onSucceeded(request: routeRequest, info: RouteResponseInfo())\n");
  printer->Print("\n");
  printer->Print("  return nil\n");
  printer->Print("}\n\n");
  printer->Outdent();

  printer->Indent();
  printer->Print("public func fetchServerStream(callId: Int, request: $methodInputName$, session: $methodSessionName$) throws -> ServerStatus? {\n",
   "methodInputName", UnderscoresToCapitalizedCamelCase(file_->package()) + ".FetchRequest",
   "methodSessionName", NameForPackageService(file_, service_) + "FetchServerStreamSession");
  printer->Print("  return .ok\n");
  printer->Print("}\n");
  printer->Outdent();
  
  printer->Indent();
  printer->Print("public func fetchClientStream(callId: Int, session: $methodSessionName$) throws -> $methodOutputName$? {\n",
  "methodSessionName", NameForPackageService(file_, service_) + "FetchClientStreamSession",
  "methodOutputName", UnderscoresToCapitalizedCamelCase(file_->package()) + ".FetchReply");
  printer->Print("  return nil\n");
  printer->Print("}\n");
  printer->Outdent();
  
  printer->Indent();
  printer->Print("public func fetchBidiStream(callId: Int, session: $methodSessionName$) throws -> ServerStatus? {\n",
   "methodSessionName", NameForPackageService(file_, service_) + "FetchBidiStreamSession");
  printer->Print("  return .ok\n");
  printer->Print("}\n");
  printer->Outdent();

  printer->Indent();
  printer->Print("internal func buildReply(data: UnsafeRawPointer?, size: Int) -> $methodOutputName$.Builder {\n",
    "methodOutputName", UnderscoresToCapitalizedCamelCase(file_->package()) + ".FetchReply");
  printer->Print("   let resultData = Data(bytesNoCopy: UnsafeMutableRawPointer(mutating: data!), count: size, deallocator: .none)\n");
  printer->Print("   let reply = $methodOutputName$.getBuilder()\n", "methodOutputName", UnderscoresToCapitalizedCamelCase(file_->package()) + ".FetchReply");
  printer->Print("   reply.size = Int64(size)\n");
  printer->Print("   reply.data = resultData\n");
  printer->Print("   return reply\n");
  printer->Print("}\n");
  printer->Outdent();

  printer->Indent();
  printer->Print("internal func sendEncodedBuffer(callId: Int, session: $methodSessionName$, data: UnsafeRawPointer?, offset: Int, size: Int, _ completion: ((Error?) -> Void)?) -> Int {\n",
    "methodSessionName", NameForPackageService(file_, service_) + "FetchUnarySession");
  printer->Print("   let view = offset > 0 ? data! + offset : data\n");
  printer->Print("   let replyBuilder = buildReply(data: view, size: size)\n");
  printer->Print("   let reply = try! replyBuilder.build()\n");
  //printer->Print("   print(\"encoded size: \\\(reply.serializedSize())\")\n");
  printer->Print("   try! session.send(reply, callId: callId, completion: completion)\n");
  printer->Print("   return size\n");
  printer->Print("}\n");
  printer->Outdent();
  
  printer->Indent();
  printer->Print("internal func sendBuffer(callId: Int, session: $methodSessionName$, data: UnsafeRawPointer?, offset: Int, size: Int) -> Int {\n",
    "methodSessionName", NameForPackageService(file_, service_) + "FetchUnarySession");
  printer->Print("   let view = offset > 0 ? data! + offset : data\n");
  printer->Print("   try! session.handler.sendMessage(callId: callId, bytes: view, size: size, method: RpcMethodType.serverStream, completion: nil)\n");
  printer->Print("   return size\n");
  printer->Print("}\n");
  printer->Outdent();

  printer->Print("}\n\n");
}

void RpcServiceGeneratorExtra::PrintInjectedMethodEntries(io::Printer* printer) {
  //case "/tweedy.Entries/ListEntries":
  //return try tweedy_EntriesListEntriesSessionBase(
  //  callId: callId,
  //  handler: handler,
  //  providerBlock: { try self.listEntries(request: $0, session: $1 as! tweedy_EntriesListEntriesSessionBase) })
  //    .run()

    // unary fetch
    printer->Print("case $methodPath$:\n", 
      "methodPath", "\"/" + ServicePath() + "/FetchUnary\"");
    printer->Indent();

    printer->Print("callHandler = $methodSessionName$Base(\n", 
      "methodSessionName", NameForPackageService(file_, service_) + "FetchUnary" + "Session");
    printer->Indent();
    //printer->Print("callId: callId,\n");
    printer->Print("handler: handler,\n");
    printer->Print("providerBlock: { try self.$methodFunctionName$(callId: $$0, request: $$1, session: $$2 as! $methodSessionName$Base) })\n",
      "methodFunctionName", "fetchUnary",
      "methodSessionName", NameForPackageService(file_, service_) + "FetchUnary" + "Session");
    printer->Outdent();

    printer->Outdent();
    
    // server streaming fetch
    printer->Print("case $methodPath$:\n", 
      "methodPath", "\"/" + ServicePath() + "/FetchServerStream\"");
    printer->Indent();
  
    printer->Print("callHandler = $methodSessionName$Base(\n", 
      "methodSessionName", NameForPackageService(file_, service_) + "FetchServerStream" + "Session");
    printer->Indent();
    //printer->Print("callId: callId,\n");
    printer->Print("handler: handler,\n");
    printer->Print("providerBlock: { try self.$methodFunctionName$(callId: $$0, request: $$1, session: $$2 as! $methodSessionName$Base) })\n",
      "methodFunctionName", "fetchServerStream",
      "methodSessionName", NameForPackageService(file_, service_) + "FetchServerStream" + "Session");
    printer->Outdent();

    printer->Outdent();
    
    // client streaming fetch 
    printer->Print("case $methodPath$:\n", 
      "methodPath", "\"/" + ServicePath() + "/FetchClientStream\"");
    printer->Indent();

    printer->Print("callHandler = $methodSessionName$Base(\n", 
      "methodSessionName", NameForPackageService(file_, service_) + "FetchClientStream" + "Session");
    printer->Indent();
    //printer->Print("callId: callId,\n");
    printer->Print("handler: handler,\n");
    printer->Print(
      "providerBlock: { try self.$methodFunctionName$(callId: $$0, session: $$1 as! $methodSessionName$Base) })\n", 
      "methodFunctionName", "fetchClientStream", 
      "methodSessionName", NameForPackageService(file_, service_) + "FetchClientStream" + "Session");
    printer->Indent();
    printer->Outdent();

    printer->Outdent();

    // bidi streaming fetch
    printer->Print("case $methodPath$:\n", 
      "methodPath", "\"/" + ServicePath() + "/FetchBidiStream\"");
    printer->Indent();

    printer->Print("callHandler = $methodSessionName$Base(\n", 
      "methodSessionName", NameForPackageService(file_, service_) + "FetchBidiStream" + "Session");
    printer->Indent();
    //printer->Print("callId: callId,\n");
    printer->Print("handler: handler,\n");
    printer->Print(
      "providerBlock: { try self.$methodFunctionName$(callId: $$0, session: $$1 as! $methodSessionName$Base) })\n", 
      "methodFunctionName", "fetchBidiStream", 
      "methodSessionName", NameForPackageService(file_, service_) + "FetchBidiStream" + "Session");
    printer->Indent();
    printer->Outdent();

    printer->Outdent();


    /////
    /////

    // unary fetch
    printer->Print("case $methodPath$:\n", 
      "methodPath", "\"/" + FetchServicePath(file_) + "/FetchUnary\"");
    printer->Indent();

    printer->Print("callHandler = $methodSessionName$Base(\n", 
      "methodSessionName", NameForPackageService(file_, service_) + "FetchUnary" + "Session");
    printer->Indent();
    //printer->Print("callId: callId,\n");
    printer->Print("handler: handler,\n");
    printer->Print("providerBlock: { try self.$methodFunctionName$(callId: $$0, request: $$1, session: $$2 as! $methodSessionName$Base) })\n",
      "methodFunctionName", "fetchUnary",
      "methodSessionName", NameForPackageService(file_, service_) + "FetchUnary" + "Session");
    printer->Indent();
    printer->Outdent();

    printer->Outdent();
    
    // server streaming fetch
    printer->Print("case $methodPath$:\n", 
      "methodPath", "\"/" + FetchServicePath(file_) + "/FetchServerStream\"");
    printer->Indent();
  
    printer->Print("callHandler = $methodSessionName$Base(\n", 
      "methodSessionName", NameForPackageService(file_, service_) + "FetchServerStream" + "Session");
    printer->Indent();
    //printer->Print("callId: callId,\n");
    printer->Print("handler: handler,\n");
    printer->Print("providerBlock: { try self.$methodFunctionName$(callId: $$0, request: $$1, session: $$2 as! $methodSessionName$Base) })\n",
      "methodFunctionName", "fetchServerStream",
      "methodSessionName", NameForPackageService(file_, service_) + "FetchServerStream" + "Session");
    printer->Outdent();

    printer->Outdent();
    
    // client streaming fetch 
    printer->Print("case $methodPath$:\n", 
      "methodPath", "\"/" + FetchServicePath(file_) + "/FetchClientStream\"");
    printer->Indent();

    printer->Print("callHandler = $methodSessionName$Base(\n", 
      "methodSessionName", NameForPackageService(file_, service_) + "FetchClientStream" + "Session");
    printer->Indent();
    //printer->Print("callId: callId,\n");
    printer->Print("handler: handler,\n");
    printer->Print(
      "providerBlock: { try self.$methodFunctionName$(callId: $$0, session: $$1 as! $methodSessionName$Base) })\n", 
      "methodFunctionName", "fetchClientStream", 
      "methodSessionName", NameForPackageService(file_, service_) + "FetchClientStream" + "Session");
    //printer->Indent();
    printer->Outdent();

    printer->Outdent();

    // bidi streaming fetch
    printer->Print("case $methodPath$:\n", 
      "methodPath", "\"/" + FetchServicePath(file_) + "/FetchBidiStream\"");
    printer->Indent();

    printer->Print("callHandler = $methodSessionName$Base(\n", 
      "methodSessionName", NameForPackageService(file_, service_) + "FetchBidiStream" + "Session");
    printer->Indent();
    //printer->Print("callId: callId,\n");
    printer->Print("handler: handler,\n");
    printer->Print(
      "providerBlock: { try self.$methodFunctionName$(callId: $$0, session: $$1 as! $methodSessionName$Base) })\n", 
      "methodFunctionName", "fetchBidiStream", 
      "methodSessionName", NameForPackageService(file_, service_) + "FetchBidiStream" + "Session");
    printer->Outdent();

    printer->Outdent();
}

void RpcServiceGeneratorExtra::PrintInjectedMethods(io::Printer* printer) {
  // message FetchRequest {
  //  uint64 size=1; 
  //  bytes data = 2;
  // }
  // message FetchReply {
  //  uint64 size=1;
  //  bytes data = 2;
  // }
  // service FetchService {
  //  rpc FetchUnary(FetchRequest) returns (FetchReply);
  //  rpc FetchClientStream(stream FetchRequest) returns (FetchReply);
  //  rpc FetchServerStream(FetchRequest) returns (stream FetchReply);
  //  rpc FetchBidiStream(stream FetchRequest) returns (stream FetchReply);
  // }

  // unary fetch
  printer->Print("func fetchUnary(callId: Int, request: $methodInputName$, session: $methodSessionName$) throws -> ServerStatus?\n",
    "methodInputName", UnderscoresToCapitalizedCamelCase(file_->package()) + ".FetchRequest",
    "methodSessionName", NameForPackageService(file_, service_) + "FetchUnary" + "Session",
    "methodOutputName", UnderscoresToCapitalizedCamelCase(file_->package()) + ".FetchReply");
  // server streaming fetch
  printer->Print("func fetchServerStream(callId: Int, request: $methodInputName$, session: $methodSessionName$) throws -> ServerStatus?\n",
    "methodInputName", UnderscoresToCapitalizedCamelCase(file_->package()) + ".FetchRequest",
    "methodSessionName", NameForPackageService(file_, service_) + "FetchServerStream" + "Session");
  // client streaming fetch
  printer->Print("func fetchClientStream(callId: Int, session: $methodSessionName$) throws -> $methodOutputName$?\n",
    "methodSessionName", NameForPackageService(file_, service_) + "FetchClientStream" + "Session",
    "methodOutputName", UnderscoresToCapitalizedCamelCase(file_->package()) + ".FetchReply");            
  // bidi streaming fetch
  printer->Print("func fetchBidiStream(callId: Int, session: $methodSessionName$) throws -> ServerStatus?\n",
    "methodSessionName", NameForPackageService(file_, service_) + "FetchBidiStream" + "Session");

  printer->Print("func routeHandler(for: String) -> RouteHandler?\n");
}

void RpcServiceGeneratorExtra::PrintInjectedMethodsInterfaces(io::Printer* printer) {
  // unary fetch
  // printer->Print("$access$ protocol $methodSessionName$: ServerSessionUnary {}\n\n",
  //   "access", "public",
  //   "methodSessionName", NameForPackageService(file_, service_) + "FetchUnary" + "Session");
  // printer->Print("fileprivate final class $methodSessionName$Base: ServerSessionUnaryBase<$methodInputName$, $methodOutputName$>, $methodSessionName$ {}\n",
  //   "methodSessionName", NameForPackageService(file_, service_) + "FetchUnary" + "Session",
  //   "methodInputName", UnderscoresToCapitalizedCamelCase(file_->package()) + "." + "FetchRequest",
  //   "methodOutputName", UnderscoresToCapitalizedCamelCase(file_->package()) + "." + "FetchReply");

  printer->Print("$access$ protocol $methodSessionName$: ServerSessionServerStreaming {\n",
    "access", "public",
    "methodSessionName", NameForPackageService(file_, service_) + "FetchUnary" + "Session");
  printer->Indent();
  PrintStreamSendMethods(printer, UnderscoresToCapitalizedCamelCase(file_->package()) + "." + "FetchReply");
  printer->Print("\n");
  PrintServerMethodClose(printer);
  printer->Outdent();
  printer->Print("}\n");
  PrintStreamSendExtension(printer, NameForPackageService(file_, service_) + "FetchUnary" + "Session", UnderscoresToCapitalizedCamelCase(file_->package()) + "." + "FetchReply");
  printer->Print("\nfileprivate final class $methodSessionName$Base: ServerSessionServerStreamingBase<$methodInputName$, $methodOutputName$>, $methodSessionName$ {\n",
    "methodSessionName", NameForPackageService(file_, service_) + "FetchUnary" + "Session",
    "methodInputName", UnderscoresToCapitalizedCamelCase(file_->package()) + "." + "FetchRequest",
    "methodOutputName", UnderscoresToCapitalizedCamelCase(file_->package()) + "." + "FetchReply");
  printer->Indent();
  printer->Print("$access$ func close(callId: Int, withStatus status: ServerStatus, completion: (() -> Void)?) throws {\n",
    "access", "public");
  printer->Indent();
  printer->Print("handler.sendStatus(callId: callId, status)\n");
  printer->Outdent();
  printer->Print("}\n");
  printer->Outdent();
  printer->Print("}\n");
  
  // client streaming fetch
  printer->Print("$access$ protocol $methodSessionName$: ServerSessionClientStreaming {\n",
    "access", "public",
    "methodSessionName", NameForPackageService(file_, service_) + "FetchClientStream" + "Session");
  printer->Indent();
  PrintStreamReceiveMethods(printer, UnderscoresToCapitalizedCamelCase(file_->package()) + "." + "FetchRequest");
  printer->Print("\n");
  PrintServerMethodSendAndClose(printer, UnderscoresToCapitalizedCamelCase(file_->package()) + "." + "FetchReply");
  printer->Outdent();
  printer->Print("}\n");
  PrintStreamReceiveExtension(printer, NameForPackageService(file_, service_) + "FetchClientStream" + "Session", UnderscoresToCapitalizedCamelCase(file_->package()) + "." + "FetchRequest");
  printer->Print("\nfileprivate final class $methodSessionName$Base: ServerSessionClientStreamingBase<$methodInputName$, $methodOutputName$>, $methodSessionName$ {}\n\n",
    "methodSessionName", NameForPackageService(file_, service_) + "FetchClientStream" + "Session",
    "methodInputName", UnderscoresToCapitalizedCamelCase(file_->package()) + "." + "FetchRequest",
    "methodOutputName", UnderscoresToCapitalizedCamelCase(file_->package()) + "." + "FetchReply");

  // server streaming fetch
  printer->Print("$access$ protocol $methodSessionName$: ServerSessionServerStreaming {\n",
    "access", "public",
    "methodSessionName", NameForPackageService(file_, service_) + "FetchServerStream" + "Session");
  printer->Indent();
  PrintStreamSendMethods(printer, UnderscoresToCapitalizedCamelCase(file_->package()) + "." + "FetchReply");
  printer->Print("\n");
  PrintServerMethodClose(printer);
  printer->Outdent();
  printer->Print("}\n");
  PrintStreamSendExtension(printer, NameForPackageService(file_, service_) + "FetchServerStream" + "Session", UnderscoresToCapitalizedCamelCase(file_->package()) + "." + "FetchReply");
  printer->Print("\nfileprivate final class $methodSessionName$Base: ServerSessionServerStreamingBase<$methodInputName$, $methodOutputName$>, $methodSessionName$ {\n",
    "methodSessionName", NameForPackageService(file_, service_) + "FetchServerStream" + "Session",
    "methodInputName", UnderscoresToCapitalizedCamelCase(file_->package()) + "." + "FetchRequest",
    "methodOutputName", UnderscoresToCapitalizedCamelCase(file_->package()) + "." + "FetchReply");
  printer->Indent();
  printer->Print("$access$ func close(callId: Int, withStatus status: ServerStatus, completion: (() -> Void)?) throws {\n",
    "access", "public");
  printer->Indent();
  printer->Print("handler.sendStatus(callId: callId, status)\n");
  printer->Outdent();
  printer->Print("}\n");
  printer->Outdent();
  printer->Print("}\n");

  // bidi streaming fetch
  printer->Print("$access$ protocol $methodSessionName$: ServerSessionBidirectionalStreaming {\n",
    "access", "public",
    "methodSessionName", NameForPackageService(file_, service_) + "FetchBidiStream" + "Session");
  printer->Indent();
  PrintStreamReceiveMethods(printer, UnderscoresToCapitalizedCamelCase(file_->package()) + "." + "FetchRequest");
  printer->Print("\n");
  PrintStreamSendMethods(printer, UnderscoresToCapitalizedCamelCase(file_->package()) + "." + "FetchReply");
  printer->Print("\n");
  PrintServerMethodClose(printer);
  printer->Outdent();
  printer->Print("}\n");
  PrintStreamReceiveExtension(printer, NameForPackageService(file_, service_) + "FetchBidiStream" + "Session", UnderscoresToCapitalizedCamelCase(file_->package()) + "." + "FetchRequest");
  printer->Print("\n");
  PrintStreamSendExtension(printer, NameForPackageService(file_, service_) + "FetchBidiStream" + "Session", UnderscoresToCapitalizedCamelCase(file_->package()) + "." + "FetchReply");
  printer->Print("\nfileprivate final class $methodSessionName$Base: ServerSessionBidirectionalStreamingBase<$methodInputName$, $methodOutputName$>, $methodSessionName$ {\n\n",
    "methodSessionName", NameForPackageService(file_, service_) + "FetchBidiStream" + "Session",
    "methodInputName", UnderscoresToCapitalizedCamelCase(file_->package()) + "." + "FetchRequest",
    "methodOutputName", UnderscoresToCapitalizedCamelCase(file_->package()) + "." + "FetchReply");
  printer->Indent();
  printer->Print("public func close(callId: Int, withStatus status: ServerStatus, completion: (() -> Void)?) throws {\n");
  printer->Indent();
  printer->Print("handler.sendStatus(callId: callId, status)\n");
  printer->Outdent();
  printer->Print("}\n");
  printer->Print("}\n");
  printer->Outdent();
}

}
}
}
}