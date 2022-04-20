// Copyright 2014 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chromeos-dbus-bindings/adaptor_generator.h"

#include <string>

#include <base/logging.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>

#include "chromeos-dbus-bindings/dbus_signature.h"
#include "chromeos-dbus-bindings/disallow_copy_and_assign.h"
#include "chromeos-dbus-bindings/header_generator.h"
#include "chromeos-dbus-bindings/indented_text.h"
#include "chromeos-dbus-bindings/interface.h"
#include "chromeos-dbus-bindings/name_parser.h"

using base::StringPrintf;
using std::string;
using std::vector;

namespace chromeos_dbus_bindings {

AdaptorGenerator::AdaptorGenerator() = default;

bool AdaptorGenerator::GenerateAdaptors(
    const std::vector<Interface>& interfaces,
    const base::FilePath& output_file) {
  IndentedText text;
  CHECK(!interfaces.empty()) << "At least one interface must be provided";

  text.AddLine("// Automatic generation of D-Bus interfaces:");
  for (const auto& interface : interfaces) {
    text.AddLine(StringPrintf("//  - %s", interface.name.c_str()));
  }
  string header_guard = GenerateHeaderGuard(output_file);
  text.AddLine(StringPrintf("#ifndef %s", header_guard.c_str()));
  text.AddLine(StringPrintf("#define %s", header_guard.c_str()));
  text.AddLine("#include <memory>");
  text.AddLine("#include <string>");
  text.AddLine("#include <tuple>");
  text.AddLine("#include <vector>");
  text.AddBlankLine();
  text.AddLine("#include <base/files/scoped_file.h>");
  text.AddLine("#include <base/macros.h>");
  text.AddLine("#include <dbus/object_path.h>");
  text.AddLine("#include <brillo/any.h>");
  text.AddLine("#include <brillo/dbus/dbus_object.h>");
  text.AddLine("#include <brillo/dbus/exported_object_manager.h>");
  text.AddLine("#include <brillo/dbus/file_descriptor.h>");
  text.AddLine("#include <brillo/variant_dictionary.h>");

  for (const auto& interface : interfaces)
    GenerateInterfaceAdaptor(interface, &text);

  text.AddLine(StringPrintf("#endif  // %s", header_guard.c_str()));

  return WriteTextToFile(output_file, text);
}

void AdaptorGenerator::GenerateInterfaceAdaptor(const Interface& interface,
                                                IndentedText* text) {
  NameParser parser{interface.name};
  string itf_name = parser.MakeInterfaceName(false);
  string class_name = parser.MakeAdaptorName(false);
  string full_itf_name = parser.MakeFullCppName();

  text->AddBlankLine();
  parser.AddOpenNamespaces(text, false);

  text->AddBlankLine();
  text->AddLine(
      StringPrintf("// Interface definition for %s.", full_itf_name.c_str()));
  text->AddComments(interface.doc_string);
  text->AddLine(StringPrintf("class %s {", itf_name.c_str()));
  text->AddLineWithOffset("public:", kScopeOffset);
  text->PushOffset(kBlockOffset);
  text->AddLine(StringPrintf("virtual ~%s() = default;", itf_name.c_str()));
  AddInterfaceMethods(interface, text);
  text->PopOffset();
  text->AddLine("};");

  text->AddBlankLine();
  text->AddLine(
      StringPrintf("// Interface adaptor for %s.", full_itf_name.c_str()));
  text->AddLine(StringPrintf("class %s {", class_name.c_str()));
  text->AddLineWithOffset("public:", kScopeOffset);
  text->PushOffset(kBlockOffset);
  AddConstructor(interface, class_name, itf_name, text);
  AddDisallowCopyAndAssign(class_name, text);
  AddRegisterWithDBusObject(itf_name, interface, text);
  AddSendSignalMethods(interface, text);
  AddPropertyMethodImplementation(interface, text);
  if (!interface.path.empty()) {
    text->AddBlankLine();
    text->AddLine("static dbus::ObjectPath GetObjectPath() {");
    text->PushOffset(kBlockOffset);
    text->AddLine(StringPrintf("return dbus::ObjectPath{\"%s\"};",
                               interface.path.c_str()));
    text->PopOffset();
    text->AddLine("}");
  }
  text->AddBlankLine();

  GenerateQuotedIntrospectionForInterface(interface, text);
  text->PopOffset();
  text->AddBlankLine();

  text->AddLineWithOffset("private:", kScopeOffset);
  text->PushOffset(kBlockOffset);
  AddSignalDataMembers(interface, text);
  AddPropertyDataMembers(interface, text);

  if (!interface.methods.empty()) {
    text->AddLine(
        StringPrintf("%s* interface_;  // Owned by container of this adapter.",
                     itf_name.c_str()));
  }

  text->PopOffset();
  text->AddLine("};");

  text->AddBlankLine();
  parser.AddCloseNamespaces(text, false);
}

void AdaptorGenerator::AddConstructor(const Interface& interface,
                                      const string& class_name,
                                      const string& itf_name,
                                      IndentedText* text) {
  if (interface.methods.empty()) {
    text->AddLine(StringPrintf("%s(%s* /* interface */) {}", class_name.c_str(),
                               itf_name.c_str()));

  } else {
    text->AddLine(StringPrintf("%s(%s* interface) : interface_(interface) {}",
                               class_name.c_str(), itf_name.c_str()));
  }
}

void AdaptorGenerator::AddRegisterWithDBusObject(const std::string& itf_name,
                                                 const Interface& interface,
                                                 IndentedText* text) {
  text->AddBlankLine();
  text->AddLine(
      "void RegisterWithDBusObject(brillo::dbus_utils::DBusObject* object) {");
  text->PushOffset(kBlockOffset);
  text->AddLine("brillo::dbus_utils::DBusInterface* itf =");
  text->AddLineWithOffset(StringPrintf("object->AddOrGetInterface(\"%s\");",
                                       interface.name.c_str()),
                          kLineContinuationOffset);
  RegisterInterface(itf_name, interface, text);
  text->PopOffset();
  text->AddLine("}");
}

void AdaptorGenerator::RegisterInterface(const string& itf_name,
                                         const Interface& interface,
                                         IndentedText* text) {
  if (!interface.methods.empty())
    text->AddBlankLine();
  for (const auto& method : interface.methods) {
    string add_handler_name;
    switch (method.kind) {
      case Interface::Method::Kind::kSimple:
        add_handler_name = "AddSimpleMethodHandler";
        break;
      case Interface::Method::Kind::kNormal:
        if (method.include_dbus_message)
          add_handler_name = "AddSimpleMethodHandlerWithErrorAndMessage";
        else
          add_handler_name = "AddSimpleMethodHandlerWithError";
        break;
      case Interface::Method::Kind::kAsync:
        if (method.include_dbus_message)
          add_handler_name = "AddMethodHandlerWithMessage";
        else
          add_handler_name = "AddMethodHandler";
        break;
      case Interface::Method::Kind::kRaw:
        add_handler_name = "AddRawMethodHandler";
        break;
    }

    text->AddLine(StringPrintf("itf->%s(", add_handler_name.c_str()));
    text->PushOffset(kLineContinuationOffset);
    text->AddLine(StringPrintf("\"%s\",", method.name.c_str()));
    text->AddLine("base::Unretained(interface_),");
    text->AddLine(
        StringPrintf("&%s::%s);", itf_name.c_str(), method.name.c_str()));
    text->PopOffset();
  }

  // Register signals.
  if (!interface.signals.empty())
    text->AddBlankLine();
  for (const auto& signal : interface.signals) {
    string signal_var_name = StringPrintf("signal_%s_", signal.name.c_str());
    string signal_type_name = StringPrintf("Signal%sType", signal.name.c_str());
    text->AddLine(StringPrintf("%s = itf->RegisterSignalOfType<%s>(\"%s\");",
                               signal_var_name.c_str(),
                               signal_type_name.c_str(), signal.name.c_str()));
  }

  // Register exported properties.
  if (!interface.properties.empty())
    text->AddBlankLine();
  for (const auto& property : interface.properties) {
    string variable_name = NameParser{property.name}.MakeVariableName();
    string write_access;
    if (property.access == "write") {
      write_access = "kWriteOnly";
    } else if (property.access == "readwrite") {
      write_access = "kReadWrite";
    }
    if (!write_access.empty()) {
      text->AddLine(StringPrintf("%s_.SetAccessMode(", variable_name.c_str()));
      text->PushOffset(kLineContinuationOffset);
      text->AddLine(
          StringPrintf("brillo::dbus_utils::ExportedPropertyBase::Access::%s);",
                       write_access.c_str()));
      text->PopOffset();
      text->AddLine(StringPrintf("%s_.SetValidator(", variable_name.c_str()));
      text->PushOffset(kLineContinuationOffset);
      text->AddLineAndPushOffsetTo(
          StringPrintf(
              "base::Bind(&%s::Validate%s,",
              NameParser{interface.name}.MakeAdaptorName(false).c_str(),
              property.name.c_str()),
          1, '(');
      text->AddLine("base::Unretained(this)));");
      text->PopOffset();
      text->PopOffset();
    }
    text->AddLine(StringPrintf("itf->AddProperty(%sName(), &%s_);",
                               property.name.c_str(), variable_name.c_str()));
  }
}

void AdaptorGenerator::AddInterfaceMethods(const Interface& interface,
                                           IndentedText* text) {
  IndentedText block;
  DBusSignature signature;
  if (!interface.methods.empty())
    block.AddBlankLine();

  for (const auto& method : interface.methods) {
    string const_method;
    if (method.is_const)
      const_method = " const";

    string return_type = "void";
    vector<string> method_params;
    auto input_arguments_copy = method.input_arguments;
    auto output_arguments_copy = method.output_arguments;
    switch (method.kind) {
      case Interface::Method::Kind::kSimple:
        if (output_arguments_copy.size() == 1) {
          auto type = signature.Parse(output_arguments_copy[0].type);
          CHECK(type);
          return_type = type->GetBaseType(DBusType::Direction::kAppend);
          output_arguments_copy.clear();
        }
        break;
      case Interface::Method::Kind::kNormal:
        method_params.push_back("brillo::ErrorPtr* error");
        if (method.include_dbus_message)
          method_params.push_back("dbus::Message* message");
        return_type = "bool";
        break;
      case Interface::Method::Kind::kAsync: {
        std::vector<std::string> out_types;
        for (const auto& argument : output_arguments_copy) {
          auto type = signature.Parse(argument.type);
          CHECK(type);
          out_types.push_back(type->GetBaseType(DBusType::Direction::kAppend));
        }
        method_params.push_back(base::StringPrintf(
            "std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<%s>> "
            "response",
            base::JoinString(out_types, ", ").c_str()));
        if (method.include_dbus_message)
          method_params.push_back("dbus::Message* message");
        output_arguments_copy.clear();
        break;
      }
      case Interface::Method::Kind::kRaw:
        method_params.push_back("dbus::MethodCall* method_call");
        method_params.push_back("brillo::dbus_utils::ResponseSender sender");
        // Raw methods don't take static parameters or return values directly.
        input_arguments_copy.clear();
        output_arguments_copy.clear();
        break;
    }
    block.AddComments(method.doc_string);
    string method_start = StringPrintf("virtual %s %s(", return_type.c_str(),
                                       method.name.c_str());
    string method_end = StringPrintf(")%s = 0;", const_method.c_str());
    int index = 0;
    for (const auto& argument : input_arguments_copy) {
      auto type = signature.Parse(argument.type);
      CHECK(type);
      string param_type = type->GetInArgType(DBusType::Receiver::kAdaptor);
      string param_name = GetArgName("in", argument.name, ++index);
      method_params.push_back(param_type + ' ' + param_name);
    }

    for (const auto& argument : output_arguments_copy) {
      auto type = signature.Parse(argument.type);
      CHECK(type);
      string param_type = type->GetOutArgType(DBusType::Receiver::kAdaptor);
      string param_name = GetArgName("out", argument.name, ++index);
      method_params.push_back(param_type + ' ' + param_name);
    }

    if (method_params.empty()) {
      block.AddLine(method_start + method_end);
    } else {
      block.AddLine(method_start);
      block.PushOffset(kLineContinuationOffset);
      for (size_t i = 0; i < method_params.size() - 1; i++)
        block.AddLine(method_params[i] + ',');
      block.AddLine(method_params.back() + method_end);
      block.PopOffset();
    }
  }
  text->AddBlock(block);
}

void AdaptorGenerator::AddSendSignalMethods(const Interface& interface,
                                            IndentedText* text) {
  IndentedText block;
  DBusSignature signature;

  if (!interface.signals.empty())
    block.AddBlankLine();

  for (const auto& signal : interface.signals) {
    block.AddComments(signal.doc_string);
    string method_start =
        StringPrintf("void Send%sSignal(", signal.name.c_str());
    string method_end = ") {";

    int index = 0;
    vector<string> method_params;
    vector<string> param_names;
    for (const auto& argument : signal.arguments) {
      auto type = signature.Parse(argument.type);
      CHECK(type);
      // We are the sender for signals, so pretend we're a proxy
      // when generating the type.
      string param_type = type->GetInArgType(DBusType::Receiver::kProxy);
      string param_name = GetArgName("in", argument.name, ++index);
      param_names.push_back(param_name);
      method_params.push_back(param_type + ' ' + param_name);
    }

    if (method_params.empty()) {
      block.AddLine(method_start + method_end);
    } else {
      block.AddLine(method_start);
      block.PushOffset(kLineContinuationOffset);
      for (size_t i = 0; i < method_params.size() - 1; i++)
        block.AddLine(method_params[i] + ',');
      block.AddLine(method_params.back() + method_end);
      block.PopOffset();
    }

    string args = base::JoinString(param_names, ", ");
    block.PushOffset(kBlockOffset);
    block.AddLine(
        StringPrintf("auto signal = signal_%s_.lock();", signal.name.c_str()));
    block.AddLine("if (signal)");
    block.AddLineWithOffset(StringPrintf("signal->Send(%s);", args.c_str()),
                            kBlockOffset);
    block.PopOffset();
    block.AddLine("}");
  }
  text->AddBlock(block);
}

void AdaptorGenerator::AddSignalDataMembers(const Interface& interface,
                                            IndentedText* text) {
  IndentedText block;
  DBusSignature signature;

  for (const auto& signal : interface.signals) {
    string signal_type_name = StringPrintf("Signal%sType", signal.name.c_str());
    string signal_type_alias_begin = StringPrintf(
        "using %s = brillo::dbus_utils::DBusSignal<", signal_type_name.c_str());
    string signal_type_alias_end = ">;";
    vector<string> params;
    for (const auto& argument : signal.arguments) {
      auto type = signature.Parse(argument.type);
      CHECK(type);
      string param = type->GetBaseType(DBusType::Direction::kAppend);
      if (!argument.name.empty())
        base::StringAppendF(&param, " /*%s*/", argument.name.c_str());
      params.push_back(param);
    }
    if (params.empty()) {
      block.AddLine(signal_type_alias_begin + signal_type_alias_end);
    } else {
      block.AddLine(signal_type_alias_begin);
      block.PushOffset(kLineContinuationOffset);
      for (size_t i = 0; i < params.size() - 1; i++)
        block.AddLine(params[i] + ',');
      block.AddLine(params.back() + signal_type_alias_end);
      block.PopOffset();
    }
    block.AddLine(StringPrintf("std::weak_ptr<%s> signal_%s_;",
                               signal_type_name.c_str(), signal.name.c_str()));
    block.AddBlankLine();
  }
  text->AddBlock(block);
}

void AdaptorGenerator::AddPropertyMethodImplementation(
    const Interface& interface, IndentedText* text) {
  IndentedText block;
  DBusSignature signature;

  for (const auto& property : interface.properties) {
    block.AddBlankLine();
    auto parsed_type = signature.Parse(property.type);
    CHECK(parsed_type && parsed_type->IsValidPropertyType());
    string type = parsed_type->GetBaseType(DBusType::Direction::kExtract);
    string variable_name = NameParser{property.name}.MakeVariableName();

    // Property name accessor.
    block.AddComments(property.doc_string);
    block.AddLine(StringPrintf("static const char* %sName() { return \"%s\"; }",
                               property.name.c_str(), property.name.c_str()));

    // Getter method.
    block.AddLine(StringPrintf("%s Get%s() const {", type.c_str(),
                               property.name.c_str()));
    block.PushOffset(kBlockOffset);
    block.AddLine(StringPrintf("return %s_.GetValue().Get<%s>();",
                               variable_name.c_str(), type.c_str()));
    block.PopOffset();
    block.AddLine("}");

    // Setter method.
    type = parsed_type->GetInArgType(DBusType::Receiver::kAdaptor);
    block.AddLine(StringPrintf("void Set%s(%s %s) {", property.name.c_str(),
                               type.c_str(), variable_name.c_str()));
    block.PushOffset(kBlockOffset);
    block.AddLine(StringPrintf("%s_.SetValue(%s);", variable_name.c_str(),
                               variable_name.c_str()));
    block.PopOffset();
    block.AddLine("}");

    // Validation method for property with write access.
    if (property.access != "read") {
      block.AddLine(
          StringPrintf("virtual bool Validate%s(", property.name.c_str()));
      block.PushOffset(kLineContinuationOffset);
      // Explicitly specify the "value" parameter as const & to match the
      // validator callback function signature.
      type = parsed_type->GetBaseType(DBusType::Direction::kExtract);
      block.AddLine(StringPrintf(
          "brillo::ErrorPtr* /*error*/, const %s& /*value*/) {", type.c_str()));
      block.PopOffset();
      block.PushOffset(kBlockOffset);
      block.AddLine("return true;");
      block.PopOffset();
      block.AddLine("}");
    }
  }
  text->AddBlock(block);
}

void AdaptorGenerator::AddPropertyDataMembers(const Interface& interface,
                                              IndentedText* text) {
  IndentedText block;
  DBusSignature signature;

  for (const auto& property : interface.properties) {
    auto parsed_type = signature.Parse(property.type);
    CHECK(parsed_type && parsed_type->IsValidPropertyType());
    string type = parsed_type->GetBaseType(DBusType::Direction::kExtract);
    string variable_name = NameParser{property.name}.MakeVariableName();

    block.AddLine(StringPrintf("brillo::dbus_utils::ExportedProperty<%s> %s_;",
                               type.c_str(), variable_name.c_str()));
  }
  if (!interface.properties.empty())
    block.AddBlankLine();

  text->AddBlock(block);
}

void AdaptorGenerator::GenerateQuotedIntrospectionForInterface(
    const Interface& interface, IndentedText* text) {
  text->AddLine("static const char* GetIntrospectionXml() {");
  text->PushOffset(kBlockOffset);

  // Create a utility function for handling arguments.
  auto AppendArgs = [](IndentedText* text, const string& extra,
                       const vector<Interface::Argument>& args) {
    for (const auto& arg : args) {
      string arg_type = arg.type;
      if (!arg_type.empty() && arg_type[0] == '^') {
        arg_type = "ay";
      }
      text->AddLine(
          StringPrintf(R"raw("      <arg name=\"%s\" type=\"%s\"%s/>\n")raw",
                       arg.name.c_str(), arg_type.c_str(), extra.c_str()));
    }
  };

  text->AddLine("return");
  text->PushOffset(kLineContinuationOffset);
  text->AddLine(StringPrintf(R"raw("  <interface name=\"%s\">\n")raw",
                             interface.name.c_str()));

  // Add the methods
  for (const auto& method : interface.methods) {
    text->AddLine(StringPrintf(R"raw("    <method name=\"%s\">\n")raw",
                               method.name.c_str()));

    // Add the input arguments
    AppendArgs(text, R"( direction=\"in\")", method.input_arguments);

    // Add the output arguments
    AppendArgs(text, R"( direction=\"out\")", method.output_arguments);

    text->AddLine(R"raw("    </method>\n")raw");
  }

  // Add the signals
  for (const auto& signal : interface.signals) {
    text->AddLine(StringPrintf(R"raw("    <signal name=\"%s\">\n")raw",
                               signal.name.c_str()));

    // Add the arguments
    AppendArgs(text, "", signal.arguments);

    text->AddLine(R"raw("    </signal>\n")raw");
  }

  text->AddLine(R"raw("  </interface>\n";)raw");

  text->PopOffset();
  text->PopOffset();
  text->AddLine("}");
}

}  // namespace chromeos_dbus_bindings
