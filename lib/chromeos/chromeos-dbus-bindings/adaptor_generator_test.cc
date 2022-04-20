// Copyright 2014 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chromeos-dbus-bindings/adaptor_generator.h"

#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <gtest/gtest.h>

#include "chromeos-dbus-bindings/interface.h"
#include "chromeos-dbus-bindings/test_utils.h"

using std::string;
using std::vector;
using testing::Test;

namespace chromeos_dbus_bindings {

namespace {

const char kDBusTypeArryOfObjects[] = "ao";
const char kDBusTypeBool[] = "b";
const char kDBusTypeInt32[] = "i";
const char kDBusTypeInt64[] = "x";
const char kDBusTypeString[] = "s";
const char kDBusTypeFileDescriptor[] = "h";

const char kPropertyAccessReadOnly[] = "read";
const char kPropertyAccessReadWrite[] = "readwrite";

const char kInterfaceName[] = "org.chromium.Test";
const char kInterfaceName2[] = "org.chromium.Test2";

const char kGenerateAdaptorsOutput[] = R"literal_string(
#include <memory>
#include <string>
#include <tuple>
#include <vector>

#include <base/files/scoped_file.h>
#include <base/macros.h>
#include <dbus/object_path.h>
#include <brillo/any.h>
#include <brillo/dbus/dbus_object.h>
#include <brillo/dbus/exported_object_manager.h>
#include <brillo/dbus/file_descriptor.h>
#include <brillo/variant_dictionary.h>

namespace org {
namespace chromium {

// Interface definition for org::chromium::Test.
class TestInterface {
 public:
  virtual ~TestInterface() = default;

  virtual bool Kaneda(
      brillo::ErrorPtr* error,
      dbus::Message* message,
      const std::string& in_iwata,
      const std::vector<dbus::ObjectPath>& in_clarke,
      std::string* out_3) = 0;
  virtual bool Tetsuo(
      brillo::ErrorPtr* error,
      int32_t in_1,
      int64_t* out_2) = 0;
  virtual bool Kei(
      brillo::ErrorPtr* error) = 0;
  virtual bool Kiyoko(
      brillo::ErrorPtr* error,
      int64_t* out_akira,
      std::string* out_2) = 0;
  virtual bool Takashi(
      brillo::ErrorPtr* error,
      const Onishi& in_onishi,
      Miyako* out_miyako) = 0;
};

// Interface adaptor for org::chromium::Test.
class TestAdaptor {
 public:
  TestAdaptor(TestInterface* interface) : interface_(interface) {}
  TestAdaptor(const TestAdaptor&) = delete;
  TestAdaptor& operator=(const TestAdaptor&) = delete;

  void RegisterWithDBusObject(brillo::dbus_utils::DBusObject* object) {
    brillo::dbus_utils::DBusInterface* itf =
        object->AddOrGetInterface("org.chromium.Test");

    itf->AddSimpleMethodHandlerWithErrorAndMessage(
        "Kaneda",
        base::Unretained(interface_),
        &TestInterface::Kaneda);
    itf->AddSimpleMethodHandlerWithError(
        "Tetsuo",
        base::Unretained(interface_),
        &TestInterface::Tetsuo);
    itf->AddSimpleMethodHandlerWithError(
        "Kei",
        base::Unretained(interface_),
        &TestInterface::Kei);
    itf->AddSimpleMethodHandlerWithError(
        "Kiyoko",
        base::Unretained(interface_),
        &TestInterface::Kiyoko);
    itf->AddSimpleMethodHandlerWithError(
        "Takashi",
        base::Unretained(interface_),
        &TestInterface::Takashi);

    signal_Update_ = itf->RegisterSignalOfType<SignalUpdateType>("Update");
    signal_Mapping_ = itf->RegisterSignalOfType<SignalMappingType>("Mapping");

    itf->AddProperty(CharacterNameName(), &character_name_);
    write_property_.SetAccessMode(
        brillo::dbus_utils::ExportedPropertyBase::Access::kReadWrite);
    write_property_.SetValidator(
        base::Bind(&TestAdaptor::ValidateWriteProperty,
                   base::Unretained(this)));
    itf->AddProperty(WritePropertyName(), &write_property_);
  }

  void SendUpdateSignal() {
    auto signal = signal_Update_.lock();
    if (signal)
      signal->Send();
  }
  void SendMappingSignal(
      const std::string& in_key,
      const std::vector<dbus::ObjectPath>& in_2) {
    auto signal = signal_Mapping_.lock();
    if (signal)
      signal->Send(in_key, in_2);
  }

  static const char* CharacterNameName() { return "CharacterName"; }
  std::string GetCharacterName() const {
    return character_name_.GetValue().Get<std::string>();
  }
  void SetCharacterName(const std::string& character_name) {
    character_name_.SetValue(character_name);
  }

  static const char* WritePropertyName() { return "WriteProperty"; }
  std::string GetWriteProperty() const {
    return write_property_.GetValue().Get<std::string>();
  }
  void SetWriteProperty(const std::string& write_property) {
    write_property_.SetValue(write_property);
  }
  virtual bool ValidateWriteProperty(
      brillo::ErrorPtr* /*error*/, const std::string& /*value*/) {
    return true;
  }

  static dbus::ObjectPath GetObjectPath() {
    return dbus::ObjectPath{"/org/chromium/Test"};
  }

  static const char* GetIntrospectionXml() {
    return
        "  <interface name=\"org.chromium.Test\">\n"
        "    <method name=\"Kaneda\">\n"
        "      <arg name=\"iwata\" type=\"s\" direction=\"in\"/>\n"
        "      <arg name=\"clarke\" type=\"ao\" direction=\"in\"/>\n"
        "      <arg name=\"\" type=\"s\" direction=\"out\"/>\n"
        "    </method>\n"
        "    <method name=\"Tetsuo\">\n"
        "      <arg name=\"\" type=\"i\" direction=\"in\"/>\n"
        "      <arg name=\"\" type=\"x\" direction=\"out\"/>\n"
        "    </method>\n"
        "    <method name=\"Kei\">\n"
        "    </method>\n"
        "    <method name=\"Kiyoko\">\n"
        "      <arg name=\"akira\" type=\"x\" direction=\"out\"/>\n"
        "      <arg name=\"\" type=\"s\" direction=\"out\"/>\n"
        "    </method>\n"
        "    <method name=\"Takashi\">\n"
        "      <arg name=\"onishi\" type=\"ay\" direction=\"in\"/>\n"
        "      <arg name=\"miyako\" type=\"ay\" direction=\"out\"/>\n"
        "    </method>\n"
        "    <signal name=\"Update\">\n"
        "    </signal>\n"
        "    <signal name=\"Mapping\">\n"
        "      <arg name=\"key\" type=\"s\"/>\n"
        "      <arg name=\"\" type=\"ao\"/>\n"
        "    </signal>\n"
        "  </interface>\n";
  }

 private:
  using SignalUpdateType = brillo::dbus_utils::DBusSignal<>;
  std::weak_ptr<SignalUpdateType> signal_Update_;

  using SignalMappingType = brillo::dbus_utils::DBusSignal<
      std::string /*key*/,
      std::vector<dbus::ObjectPath>>;
  std::weak_ptr<SignalMappingType> signal_Mapping_;

  brillo::dbus_utils::ExportedProperty<std::string> character_name_;
  brillo::dbus_utils::ExportedProperty<std::string> write_property_;

  TestInterface* interface_;  // Owned by container of this adapter.
};

}  // namespace chromium
}  // namespace org

namespace org {
namespace chromium {

// Interface definition for org::chromium::Test2.
class Test2Interface {
 public:
  virtual ~Test2Interface() = default;

  virtual std::string Kaneda2(
      const std::string& in_iwata) const = 0;
  virtual void Tetsuo2(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<int64_t>> response,
      int32_t in_1) = 0;
  virtual void Kei2(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<bool>> response,
      dbus::Message* message) = 0;
};

// Interface adaptor for org::chromium::Test2.
class Test2Adaptor {
 public:
  Test2Adaptor(Test2Interface* interface) : interface_(interface) {}
  Test2Adaptor(const Test2Adaptor&) = delete;
  Test2Adaptor& operator=(const Test2Adaptor&) = delete;

  void RegisterWithDBusObject(brillo::dbus_utils::DBusObject* object) {
    brillo::dbus_utils::DBusInterface* itf =
        object->AddOrGetInterface("org.chromium.Test2");

    itf->AddSimpleMethodHandler(
        "Kaneda2",
        base::Unretained(interface_),
        &Test2Interface::Kaneda2);
    itf->AddMethodHandler(
        "Tetsuo2",
        base::Unretained(interface_),
        &Test2Interface::Tetsuo2);
    itf->AddMethodHandlerWithMessage(
        "Kei2",
        base::Unretained(interface_),
        &Test2Interface::Kei2);
  }

  static const char* GetIntrospectionXml() {
    return
        "  <interface name=\"org.chromium.Test2\">\n"
        "    <method name=\"Kaneda2\">\n"
        "      <arg name=\"iwata\" type=\"s\" direction=\"in\"/>\n"
        "      <arg name=\"\" type=\"s\" direction=\"out\"/>\n"
        "    </method>\n"
        "    <method name=\"Tetsuo2\">\n"
        "      <arg name=\"\" type=\"i\" direction=\"in\"/>\n"
        "      <arg name=\"\" type=\"x\" direction=\"out\"/>\n"
        "    </method>\n"
        "    <method name=\"Kei2\">\n"
        "      <arg name=\"\" type=\"b\" direction=\"out\"/>\n"
        "    </method>\n"
        "  </interface>\n";
  }

 private:
  Test2Interface* interface_;  // Owned by container of this adapter.
};

}  // namespace chromium
}  // namespace org
)literal_string";

const char kNewFileDescriptorsOutput[] = R"literal_string(
#include <memory>
#include <string>
#include <tuple>
#include <vector>

#include <base/files/scoped_file.h>
#include <base/macros.h>
#include <dbus/object_path.h>
#include <brillo/any.h>
#include <brillo/dbus/dbus_object.h>
#include <brillo/dbus/exported_object_manager.h>
#include <brillo/dbus/file_descriptor.h>
#include <brillo/variant_dictionary.h>

namespace org {
namespace chromium {

// Interface definition for org::chromium::Test.
class TestInterface {
 public:
  virtual ~TestInterface() = default;

  virtual bool WrapFileDescriptor(
      brillo::ErrorPtr* error,
      const base::ScopedFD& in_1,
      brillo::dbus_utils::FileDescriptor* out_2) = 0;
};

// Interface adaptor for org::chromium::Test.
class TestAdaptor {
 public:
  TestAdaptor(TestInterface* interface) : interface_(interface) {}
  TestAdaptor(const TestAdaptor&) = delete;
  TestAdaptor& operator=(const TestAdaptor&) = delete;

  void RegisterWithDBusObject(brillo::dbus_utils::DBusObject* object) {
    brillo::dbus_utils::DBusInterface* itf =
        object->AddOrGetInterface("org.chromium.Test");

    itf->AddSimpleMethodHandlerWithError(
        "WrapFileDescriptor",
        base::Unretained(interface_),
        &TestInterface::WrapFileDescriptor);

    signal_File_ = itf->RegisterSignalOfType<SignalFileType>("File");
  }

  void SendFileSignal(
      const brillo::dbus_utils::FileDescriptor& in_1) {
    auto signal = signal_File_.lock();
    if (signal)
      signal->Send(in_1);
  }

  static dbus::ObjectPath GetObjectPath() {
    return dbus::ObjectPath{"/org/chromium/Test"};
  }

  static const char* GetIntrospectionXml() {
    return
        "  <interface name=\"org.chromium.Test\">\n"
        "    <method name=\"WrapFileDescriptor\">\n"
        "      <arg name=\"\" type=\"h\" direction=\"in\"/>\n"
        "      <arg name=\"\" type=\"h\" direction=\"out\"/>\n"
        "    </method>\n"
        "    <signal name=\"File\">\n"
        "      <arg name=\"\" type=\"h\"/>\n"
        "    </signal>\n"
        "  </interface>\n";
  }

 private:
  using SignalFileType = brillo::dbus_utils::DBusSignal<
      brillo::dbus_utils::FileDescriptor>;
  std::weak_ptr<SignalFileType> signal_File_;

  TestInterface* interface_;  // Owned by container of this adapter.
};

}  // namespace chromium
}  // namespace org
)literal_string";

}  // namespace
class AdaptorGeneratorTest : public Test {
 public:
  void SetUp() override { ASSERT_TRUE(temp_dir_.CreateUniqueTempDir()); }

 protected:
  base::FilePath CreateInputFile(const string& contents) {
    base::FilePath path;
    EXPECT_TRUE(base::CreateTemporaryFileInDir(temp_dir_.GetPath(), &path));
    int written = base::WriteFile(path, contents.c_str(), contents.size());
    EXPECT_EQ(contents.size(), static_cast<size_t>(written));
    return path;
  }

  base::ScopedTempDir temp_dir_;
};

TEST_F(AdaptorGeneratorTest, GenerateAdaptors) {
  Interface interface;
  interface.name = kInterfaceName;
  interface.path = "/org/chromium/Test";
  interface.methods.emplace_back(
      "Kaneda",
      vector<Interface::Argument>{{"iwata", kDBusTypeString},
                                  {"clarke", kDBusTypeArryOfObjects}},
      vector<Interface::Argument>{{"", kDBusTypeString}});
  interface.methods.back().include_dbus_message = true;
  interface.methods.emplace_back(
      "Tetsuo", vector<Interface::Argument>{{"", kDBusTypeInt32}},
      vector<Interface::Argument>{{"", kDBusTypeInt64}});
  interface.methods.emplace_back("Kei");
  // Interface methods with more than one return argument should be ignored.
  interface.methods.emplace_back(
      "Kiyoko", vector<Interface::Argument>{},
      vector<Interface::Argument>{{"akira", kDBusTypeInt64},
                                  {"", kDBusTypeString}});

  // Interface methods with protobuf class.
  interface.methods.emplace_back(
      "Takashi",
      vector<Interface::Argument>{{"onishi", string(kProtobufType) + "Onishi"}},
      vector<Interface::Argument>{
          {"miyako", string(kProtobufType) + "Miyako"}});

  // Signals generate helper methods to send them.
  interface.signals.emplace_back("Update", vector<Interface::Argument>{});
  interface.signals.emplace_back(
      "Mapping", vector<Interface::Argument>{{"key", kDBusTypeString},
                                             {"", kDBusTypeArryOfObjects}});
  interface.properties.emplace_back("CharacterName", kDBusTypeString,
                                    kPropertyAccessReadOnly);
  interface.properties.emplace_back("WriteProperty", kDBusTypeString,
                                    kPropertyAccessReadWrite);

  Interface interface2;
  interface2.name = kInterfaceName2;
  interface2.methods.emplace_back(
      "Kaneda2", vector<Interface::Argument>{{"iwata", kDBusTypeString}},
      vector<Interface::Argument>{{"", kDBusTypeString}});
  interface2.methods.back().is_const = true;
  interface2.methods.back().kind = Interface::Method::Kind::kSimple;
  interface2.methods.emplace_back(
      "Tetsuo2", vector<Interface::Argument>{{"", kDBusTypeInt32}},
      vector<Interface::Argument>{{"", kDBusTypeInt64}});
  interface2.methods.back().kind = Interface::Method::Kind::kAsync;
  interface2.methods.emplace_back(
      "Kei2", vector<Interface::Argument>{},
      vector<Interface::Argument>{{"", kDBusTypeBool}});
  interface2.methods.back().kind = Interface::Method::Kind::kAsync;
  interface2.methods.back().include_dbus_message = true;

  base::FilePath output_path = temp_dir_.GetPath().Append("output.h");
  AdaptorGenerator gen;
  EXPECT_TRUE(gen.GenerateAdaptors({interface, interface2}, output_path));
  string contents;
  EXPECT_TRUE(base::ReadFileToString(output_path, &contents));
  // The header guards contain the (temporary) filename, so we search for
  // the content we need within the string.
  test_utils::EXPECT_TEXT_CONTAINED(kGenerateAdaptorsOutput, contents);
}

TEST_F(AdaptorGeneratorTest, NewFileDescriptors) {
  Interface interface;
  interface.name = kInterfaceName;
  interface.path = "/org/chromium/Test";
  interface.methods.emplace_back(
      "WrapFileDescriptor",
      vector<Interface::Argument>{{"", kDBusTypeFileDescriptor}},
      vector<Interface::Argument>{{"", kDBusTypeFileDescriptor}});
  interface.signals.emplace_back(
      "File", vector<Interface::Argument>{{"", kDBusTypeFileDescriptor}});

  base::FilePath output_path = temp_dir_.GetPath().Append("output2.h");
  AdaptorGenerator gen;
  EXPECT_TRUE(gen.GenerateAdaptors({interface}, output_path));
  string contents;
  EXPECT_TRUE(base::ReadFileToString(output_path, &contents));
  // The header guards contain the (temporary) filename, so we search for
  // the content we need within the string.
  test_utils::EXPECT_TEXT_CONTAINED(kNewFileDescriptorsOutput, contents);
}

}  // namespace chromeos_dbus_bindings
