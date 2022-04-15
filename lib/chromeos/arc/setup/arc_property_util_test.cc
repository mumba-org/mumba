// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/setup/arc_property_util.h"

#include <memory>
#include <tuple>
#include <utility>

#include <base/command_line.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/strings/stringprintf.h>
#include <cdm_oemcrypto/proto_bindings/client_information.pb.h>
#include <chromeos/dbus/service_constants.h>
#include <chromeos-config/libcros_config/cros_config.h>
#include <chromeos-config/libcros_config/fake_cros_config.h>
#include <dbus/mock_bus.h>
#include <dbus/mock_object_proxy.h>
#include <gmock/gmock.h>
#include <testing/gtest/include/gtest/gtest.h>

using ::testing::_;
using ::testing::ByMove;
using ::testing::Return;
using ::testing::StartsWith;

namespace arc {
namespace {

constexpr char kCrosConfigPropertiesPath[] = "/arc/build-properties";

class ArcPropertyUtilTest : public testing::Test {
 public:
  ArcPropertyUtilTest() = default;
  ~ArcPropertyUtilTest() override = default;
  ArcPropertyUtilTest(const ArcPropertyUtilTest&) = delete;
  ArcPropertyUtilTest& operator=(const ArcPropertyUtilTest&) = delete;

  void SetUp() override {
    ASSERT_TRUE(dir_.CreateUniqueTempDir());
    dbus::Bus::Options options;
    options.bus_type = dbus::Bus::SYSTEM;
    bus_ = new dbus::MockBus(options);
    cdm_factory_daemon_object_proxy_ = new dbus::MockObjectProxy(
        bus_.get(), cdm_oemcrypto::kCdmFactoryDaemonServiceName,
        dbus::ObjectPath(cdm_oemcrypto::kCdmFactoryDaemonServicePath));
  }

 protected:
  const base::FilePath& GetTempDir() const { return dir_.GetPath(); }

  brillo::FakeCrosConfig* config() { return &config_; }

  scoped_refptr<dbus::MockBus> bus_;
  scoped_refptr<dbus::MockObjectProxy> cdm_factory_daemon_object_proxy_;

 private:
  brillo::FakeCrosConfig config_;
  base::ScopedTempDir dir_;
};

TEST_F(ArcPropertyUtilTest, TestPropertyExpansions) {
  config()->SetString("/arc/build-properties", "brand", "alphabet");

  std::string expanded;
  EXPECT_TRUE(ExpandPropertyContentsForTesting(
      "ro.a=line1\nro.b={brand}\nro.c=line3\nro.d={brand} {brand}", config(),
      /*debuggable=*/false, &expanded));
  EXPECT_EQ("ro.a=line1\nro.b=alphabet\nro.c=line3\nro.d=alphabet alphabet\n",
            expanded);
}

TEST_F(ArcPropertyUtilTest, TestPropertyExpansionsUnmatchedBrace) {
  config()->SetString("/arc/build-properties", "brand", "alphabet");

  std::string expanded;
  EXPECT_FALSE(ExpandPropertyContentsForTesting(
      "ro.a=line{1\nro.b=line}2\nro.c=line3", config(), /*debuggable=*/false,
      &expanded));
}

TEST_F(ArcPropertyUtilTest, TestPropertyExpansionsRecursive) {
  config()->SetString("/arc/build-properties", "brand", "alphabet");
  config()->SetString("/arc/build-properties", "model", "{brand} soup");

  std::string expanded;
  EXPECT_TRUE(ExpandPropertyContentsForTesting(
      "ro.a={model}", config(), /*debuggable=*/false, &expanded));
  EXPECT_EQ("ro.a=alphabet soup\n", expanded);
}

TEST_F(ArcPropertyUtilTest, TestPropertyExpansionsMissingProperty) {
  config()->SetString("/arc/build-properties", "model", "{brand} soup");

  std::string expanded;

  EXPECT_FALSE(ExpandPropertyContentsForTesting(
      "ro.a={missing-property}", config(), /*debuggable=*/false, &expanded));
  EXPECT_FALSE(ExpandPropertyContentsForTesting(
      "ro.a={model}", config(), /*debuggable=*/false, &expanded));
}

// Verify that ro.product.board gets copied to ro.oem.key1 as well.
TEST_F(ArcPropertyUtilTest, TestPropertyExpansionBoard) {
  config()->SetString("/arc/build-properties", "board", "testboard");

  std::string expanded;
  EXPECT_TRUE(ExpandPropertyContentsForTesting(
      "ro.product.board={board}", config(), /*debuggable=*/false, &expanded));
  EXPECT_EQ("ro.product.board=testboard\nro.oem.key1=testboard\n", expanded);
}

TEST_F(ArcPropertyUtilTest, TestPropertyExpansionDebuggable) {
  std::string expanded;
  EXPECT_TRUE(ExpandPropertyContentsForTesting(
      "ro.debuggable=0", config(), /*debuggable=*/false, &expanded));
  EXPECT_EQ("ro.debuggable=0\n", expanded);

  EXPECT_TRUE(ExpandPropertyContentsForTesting(
      "ro.debuggable=1", config(), /*debuggable=*/false, &expanded));
  EXPECT_EQ("ro.debuggable=0\n", expanded);

  EXPECT_TRUE(ExpandPropertyContentsForTesting("ro.debuggable=0", config(),
                                               /*debuggable*/ true, &expanded));
  EXPECT_EQ("ro.debuggable=1\n", expanded);

  EXPECT_TRUE(ExpandPropertyContentsForTesting("ro.debuggable=1", config(),
                                               /*debuggable*/ true, &expanded));
  EXPECT_EQ("ro.debuggable=1\n", expanded);
}

// Non-fingerprint property should do simple truncation.
TEST_F(ArcPropertyUtilTest, TestPropertyTruncation) {
  std::string truncated;
  EXPECT_TRUE(TruncateAndroidPropertyForTesting(
      "property.name="
      "012345678901234567890123456789012345678901234567890123456789"
      "01234567890123456789012345678901",
      &truncated));
  EXPECT_EQ(
      "property.name=0123456789012345678901234567890123456789"
      "012345678901234567890123456789012345678901234567890",
      truncated);
}

// Fingerprint truncation with /release-keys should do simple truncation.
TEST_F(ArcPropertyUtilTest, TestPropertyTruncationFingerprintRelease) {
  std::string truncated;
  EXPECT_TRUE(TruncateAndroidPropertyForTesting(
      "ro.bootimage.build.fingerprint=google/toolongdevicename/"
      "toolongdevicename_cheets:7.1.1/R65-10299.0.9999/4538390:user/"
      "release-keys",
      &truncated));
  EXPECT_EQ(
      "ro.bootimage.build.fingerprint=google/toolongdevicename/"
      "toolongdevicename_cheets:7.1.1/R65-10299.0.9999/4538390:user/relea",
      truncated);
}

// Fingerprint truncation with /dev-keys needs to preserve the /dev-keys.
TEST_F(ArcPropertyUtilTest, TestPropertyTruncationFingerprintDev) {
  std::string truncated;
  EXPECT_TRUE(TruncateAndroidPropertyForTesting(
      "ro.bootimage.build.fingerprint=google/toolongdevicename/"
      "toolongdevicename_cheets:7.1.1/R65-10299.0.9999/4538390:user/dev-keys",
      &truncated));
  EXPECT_EQ(
      "ro.bootimage.build.fingerprint=google/toolongdevicena/"
      "toolongdevicena_cheets/R65-10299.0.9999/4538390:user/dev-keys",
      truncated);
}

// Fingerprint truncation with the wrong format should fail.
TEST_F(ArcPropertyUtilTest, TestPropertyTruncationBadFingerprint) {
  std::string truncated;
  EXPECT_FALSE(TruncateAndroidPropertyForTesting(
      "ro.bootimage.build.fingerprint=google/toolongdevicename/"
      "toolongdevicename_cheets:7.1.1:123456789012345678901234567890/dev-keys",
      &truncated));
}

// Fingerprint truncation without enough room should fail.
TEST_F(ArcPropertyUtilTest, TestPropertyTruncationFingerprintShortDevice) {
  std::string truncated;
  EXPECT_FALSE(TruncateAndroidPropertyForTesting(
      "ro.bootimage.build.fingerprint=google/dev/"
      "dev_cheets:7.1.1/R65-10299.0.9999/453839012345678901234567890"
      "12345678901234567890:user/dev-keys",
      &truncated));
}

// Tests that ExpandPropertyFile works as intended when no property expantion
// is needed.
TEST_F(ArcPropertyUtilTest, ExpandPropertyFile_NoExpansion) {
  constexpr const char kValidProp[] = "ro.foo=bar\nro.baz=boo";
  base::FilePath path;
  ASSERT_TRUE(CreateTemporaryFileInDir(GetTempDir(), &path));
  base::WriteFile(path, kValidProp, strlen(kValidProp));

  const base::FilePath dest = GetTempDir().Append("new.prop");
  EXPECT_TRUE(ExpandPropertyFileForTesting(path, dest, config()));
  std::string content;
  EXPECT_TRUE(base::ReadFileToString(dest, &content));
  EXPECT_EQ(std::string(kValidProp) + "\n", content);
}

// Tests that ExpandPropertyFile works as intended when property expantion
// is needed.
TEST_F(ArcPropertyUtilTest, ExpandPropertyFile_Expansion) {
  config()->SetString(kCrosConfigPropertiesPath, "k1", "v1");
  config()->SetString(kCrosConfigPropertiesPath, "k2", "v2");

  constexpr const char kValidProp[] = "ro.foo={k1}\nro.baz={k2}";
  base::FilePath path;
  ASSERT_TRUE(CreateTemporaryFileInDir(GetTempDir(), &path));
  base::WriteFile(path, kValidProp, strlen(kValidProp));

  const base::FilePath dest = GetTempDir().Append("new.prop");
  EXPECT_TRUE(ExpandPropertyFileForTesting(path, dest, config()));
  std::string content;
  EXPECT_TRUE(base::ReadFileToString(dest, &content));
  EXPECT_EQ("ro.foo=v1\nro.baz=v2\n", content);
}

// Tests that ExpandPropertyFile works as intended when nested property
// expantion is needed.
TEST_F(ArcPropertyUtilTest, ExpandPropertyFile_NestedExpansion) {
  config()->SetString(kCrosConfigPropertiesPath, "k1", "{k2}");
  config()->SetString(kCrosConfigPropertiesPath, "k2", "v2");

  constexpr const char kValidProp[] = "ro.foo={k1}\nro.baz={k2}";
  base::FilePath path;
  ASSERT_TRUE(CreateTemporaryFileInDir(GetTempDir(), &path));
  base::WriteFile(path, kValidProp, strlen(kValidProp));

  const base::FilePath dest = GetTempDir().Append("new.prop");
  EXPECT_TRUE(ExpandPropertyFileForTesting(path, dest, config()));
  std::string content;
  EXPECT_TRUE(base::ReadFileToString(dest, &content));
  EXPECT_EQ("ro.foo=v2\nro.baz=v2\n", content);
}

// Test that ExpandPropertyFile handles the case where a property is not found.
TEST_F(ArcPropertyUtilTest, ExpandPropertyFile_CannotExpand) {
  constexpr const char kValidProp[] =
      "ro.foo={nonexistent-property}\nro.baz=boo\n";
  base::FilePath path;
  ASSERT_TRUE(CreateTemporaryFileInDir(GetTempDir(), &path));
  base::WriteFile(path, kValidProp, strlen(kValidProp));
  const base::FilePath dest = GetTempDir().Append("new.prop");
  EXPECT_FALSE(ExpandPropertyFileForTesting(path, dest, config()));
}

// Test that ExpandPropertyFile handles the case where the input file is not
// found.
TEST_F(ArcPropertyUtilTest, ExpandPropertyFile_NoSourceFile) {
  EXPECT_FALSE(ExpandPropertyFileForTesting(base::FilePath("/nonexistent"),
                                            base::FilePath("/nonexistent2"),
                                            config()));
}

// Test that ExpandPropertyFile handles the case where the output file cannot
// be written.
TEST_F(ArcPropertyUtilTest, ExpandPropertyFile_CannotWrite) {
  constexpr const char kValidProp[] = "ro.foo=bar\nro.baz=boo\n";
  base::FilePath path;
  ASSERT_TRUE(CreateTemporaryFileInDir(GetTempDir(), &path));
  base::WriteFile(path, kValidProp, strlen(kValidProp));
  EXPECT_FALSE(ExpandPropertyFileForTesting(
      path, base::FilePath("/nonexistent2"), config()));
}

TEST_F(ArcPropertyUtilTest, ExpandPropertyFiles) {
  // Both source and dest are not found.
  EXPECT_FALSE(ExpandPropertyFiles(base::FilePath("/nonexistent1"),
                                   base::FilePath("/nonexistent2"),
                                   /*single_file=*/false,
                                   /*add_native_bridge...=*/false,
                                   /*hw_oemcrypto_support=*/false,
                                   /*debuggable=*/false, nullptr));

  // Both source and dest exist, but the source directory is empty.
  base::FilePath source_dir;
  ASSERT_TRUE(base::CreateTemporaryDirInDir(GetTempDir(), "test", &source_dir));
  base::FilePath dest_dir;
  ASSERT_TRUE(base::CreateTemporaryDirInDir(GetTempDir(), "test", &dest_dir));
  EXPECT_FALSE(ExpandPropertyFiles(source_dir, dest_dir, false, false, false,
                                   false, nullptr));

  // Add default.prop to the source, but not build.prop.
  base::FilePath default_prop = source_dir.Append("default.prop");
  // Add a non-ro property to make sure that the property is NOT filetered out
  // when not in the "append" mode.
  constexpr const char kDefaultProp[] = "dalvik.a=b\nro.foo=bar\n";
  base::WriteFile(default_prop, kDefaultProp, strlen(kDefaultProp));
  EXPECT_FALSE(ExpandPropertyFiles(source_dir, dest_dir, false, false, false,
                                   false, nullptr));

  // Add build.prop too. The call should not succeed still.
  base::FilePath build_prop = source_dir.Append("build.prop");
  constexpr const char kBuildProp[] = "ro.baz=boo\n";
  base::WriteFile(build_prop, kBuildProp, strlen(kBuildProp));
  EXPECT_FALSE(ExpandPropertyFiles(source_dir, dest_dir, false, false, false,
                                   false, nullptr));

  // Add vendor_build.prop too. Then the call should succeed.
  base::FilePath vendor_build_prop = source_dir.Append("vendor_build.prop");
  constexpr const char kVendorBuildProp[] = "ro.a=b\n";
  base::WriteFile(vendor_build_prop, kVendorBuildProp,
                  strlen(kVendorBuildProp));
  EXPECT_TRUE(ExpandPropertyFiles(source_dir, dest_dir, false, false, false,
                                  false, nullptr));

  // Verify all dest files are there.
  EXPECT_TRUE(base::PathExists(dest_dir.Append("default.prop")));
  EXPECT_TRUE(base::PathExists(dest_dir.Append("build.prop")));
  EXPECT_TRUE(base::PathExists(dest_dir.Append("vendor_build.prop")));

  // Verify their content.
  std::string content;
  EXPECT_TRUE(
      base::ReadFileToString(dest_dir.Append("default.prop"), &content));
  EXPECT_EQ(std::string(kDefaultProp) + "\n", content);
  EXPECT_TRUE(base::ReadFileToString(dest_dir.Append("build.prop"), &content));
  EXPECT_EQ(std::string(kBuildProp) + "\n", content);
  EXPECT_TRUE(
      base::ReadFileToString(dest_dir.Append("vendor_build.prop"), &content));
  EXPECT_EQ(std::string(kVendorBuildProp) + "\n", content);

  // Expand it again, verify the previous result is cleared.
  EXPECT_TRUE(ExpandPropertyFiles(source_dir, dest_dir, false, false, false,
                                  false, nullptr));
  EXPECT_TRUE(
      base::ReadFileToString(dest_dir.Append("default.prop"), &content));
  EXPECT_EQ(std::string(kDefaultProp) + "\n", content);

  // If default.prop does not exist in the source path, it should still process
  // the other files, while also ensuring that default.prop is removed from the
  // destination path.
  base::DeleteFile(dest_dir.Append("default.prop"));

  EXPECT_TRUE(ExpandPropertyFiles(source_dir, dest_dir, false, false, false,
                                  false, nullptr));

  EXPECT_TRUE(base::ReadFileToString(dest_dir.Append("build.prop"), &content));
  EXPECT_EQ(std::string(kBuildProp) + "\n", content);
  EXPECT_TRUE(
      base::ReadFileToString(dest_dir.Append("vendor_build.prop"), &content));
  EXPECT_EQ(std::string(kVendorBuildProp) + "\n", content);

  // Finally, test the case where source is valid but the dest is not.
  EXPECT_FALSE(ExpandPropertyFiles(source_dir, base::FilePath("/nonexistent"),
                                   false, false, false, false, nullptr));
}

// Do the same as the previous test, but with |single_file| == true.
TEST_F(ArcPropertyUtilTest, ExpandPropertyFiles_SingleFile) {
  // Both source and dest are not found.
  EXPECT_FALSE(ExpandPropertyFiles(base::FilePath("/nonexistent1"),
                                   base::FilePath("/nonexistent2"),
                                   /*single_file=*/true,
                                   /*add_native_bridge...=*/false,
                                   /*hw_oemcrypto_support=*/false,
                                   /*debuggable=*/false, nullptr));

  // Both source and dest exist, but the source directory is empty.
  base::FilePath source_dir;
  ASSERT_TRUE(base::CreateTemporaryDirInDir(GetTempDir(), "test", &source_dir));
  base::FilePath dest_prop_file;
  ASSERT_TRUE(
      base::CreateTemporaryDirInDir(GetTempDir(), "test", &dest_prop_file));
  dest_prop_file = dest_prop_file.Append("combined.prop");
  EXPECT_FALSE(ExpandPropertyFiles(source_dir, dest_prop_file, true, false,
                                   false, false, nullptr));

  // Add default.prop to the source, but not build.prop.
  const base::FilePath default_prop = source_dir.Append("default.prop");
  // Add a non-ro property to make sure that the property is filetered out when
  // in the "append" mode.
  constexpr const char kDefaultPropNonRo[] = "dalvik.a=b\n";
  constexpr const char kDefaultProp[] = "ro.foo=bar\n";
  base::WriteFile(default_prop,
                  base::StringPrintf("%s%s", kDefaultPropNonRo, kDefaultProp));
  EXPECT_FALSE(ExpandPropertyFiles(source_dir, dest_prop_file, true, false,
                                   false, false, nullptr));

  // Add build.prop too. The call should not succeed still.
  const base::FilePath build_prop = source_dir.Append("build.prop");
  constexpr const char kBuildProp[] = "ro.baz=boo\n";
  base::WriteFile(build_prop, kBuildProp, strlen(kBuildProp));
  EXPECT_FALSE(ExpandPropertyFiles(source_dir, dest_prop_file, true, false,
                                   false, false, nullptr));

  // Add vendor_build.prop too. Then the call should succeed.
  const base::FilePath vendor_build_prop =
      source_dir.Append("vendor_build.prop");
  constexpr const char kVendorBuildProp[] = "ro.a=b\n";
  base::WriteFile(vendor_build_prop, kVendorBuildProp,
                  strlen(kVendorBuildProp));
  EXPECT_TRUE(ExpandPropertyFiles(source_dir, dest_prop_file, true, false,
                                  false, false, nullptr));

  // Add other optional files too. Then the call should succeed.
  const base::FilePath system_ext_build_prop =
      source_dir.Append("system_ext_build.prop");
  constexpr const char kSystemExtBuildProp[] = "ro.c=d\n";
  base::WriteFile(system_ext_build_prop, kSystemExtBuildProp,
                  strlen(kSystemExtBuildProp));
  EXPECT_TRUE(ExpandPropertyFiles(source_dir, dest_prop_file, true, false,
                                  false, false, nullptr));

  const base::FilePath odm_build_prop = source_dir.Append("odm_build.prop");
  constexpr const char kOdmBuildProp[] = "ro.e=f\n";
  base::WriteFile(odm_build_prop, kOdmBuildProp, strlen(kOdmBuildProp));
  EXPECT_TRUE(ExpandPropertyFiles(source_dir, dest_prop_file, true, false,
                                  false, false, nullptr));

  const base::FilePath product_build_prop =
      source_dir.Append("product_build.prop");
  constexpr const char kProductBuildProp[] = "ro.g=h\n";
  base::WriteFile(product_build_prop, kProductBuildProp,
                  strlen(kProductBuildProp));
  EXPECT_TRUE(ExpandPropertyFiles(source_dir, dest_prop_file, true, false,
                                  false, false, nullptr));

  // Verify only one dest file exists.
  EXPECT_FALSE(
      base::PathExists(dest_prop_file.DirName().Append("default.prop")));
  EXPECT_FALSE(base::PathExists(dest_prop_file.DirName().Append("build.prop")));
  EXPECT_FALSE(
      base::PathExists(dest_prop_file.DirName().Append("vendor_build.prop")));
  EXPECT_FALSE(base::PathExists(
      dest_prop_file.DirName().Append("system_ext_build.prop")));
  EXPECT_FALSE(
      base::PathExists(dest_prop_file.DirName().Append("odm_build.prop")));
  EXPECT_FALSE(
      base::PathExists(dest_prop_file.DirName().Append("product_build.prop")));
  EXPECT_TRUE(base::PathExists(dest_prop_file));

  // Verify the content.
  std::string content;
  EXPECT_TRUE(base::ReadFileToString(dest_prop_file, &content));
  // Don't include kDefaultPropNonRo since that one should be filtered out.
  EXPECT_EQ(base::StringPrintf("%s%s%s%s%s%s", kDefaultProp, kBuildProp,
                               kSystemExtBuildProp, kVendorBuildProp,
                               kOdmBuildProp, kProductBuildProp),
            content);

  // Expand it again, verify the previous result is cleared.
  EXPECT_TRUE(ExpandPropertyFiles(source_dir, dest_prop_file, true, false,
                                  false, false, nullptr));
  EXPECT_TRUE(base::ReadFileToString(dest_prop_file, &content));
  EXPECT_EQ(base::StringPrintf("%s%s%s%s%s%s", kDefaultProp, kBuildProp,
                               kSystemExtBuildProp, kVendorBuildProp,
                               kOdmBuildProp, kProductBuildProp),
            content);

  // If optional ones e.g. default.prop does not exist in the source path, it
  // should still process the other files.
  base::DeleteFile(source_dir.Append("default.prop"));
  base::DeleteFile(source_dir.Append("odm_build.prop"));
  EXPECT_TRUE(ExpandPropertyFiles(source_dir, dest_prop_file, true, false,
                                  false, false, nullptr));
  EXPECT_TRUE(base::ReadFileToString(dest_prop_file, &content));
  EXPECT_EQ(base::StringPrintf("%s%s%s%s", kBuildProp, kSystemExtBuildProp,
                               kVendorBuildProp, kProductBuildProp),
            content);

  // Finally, test the case where source is valid but the dest is not.
  EXPECT_FALSE(ExpandPropertyFiles(source_dir, base::FilePath("/nonexistent"),
                                   true, false, false, false, nullptr));
}

// Test that ExpandPropertyFiles handles properties related to native bridge
// 64-bit support properly.
TEST_F(ArcPropertyUtilTest, TestNativeBridge64Support) {
  // Set up some properties files.
  base::FilePath source_dir;
  ASSERT_TRUE(base::CreateTemporaryDirInDir(GetTempDir(), "test", &source_dir));
  base::FilePath dest_dir;
  ASSERT_TRUE(base::CreateTemporaryDirInDir(GetTempDir(), "test", &dest_dir));

  base::FilePath default_prop = source_dir.Append("default.prop");
  constexpr const char kDefaultProp[] = "ro.foo=bar\n";
  base::WriteFile(default_prop, kDefaultProp, strlen(kDefaultProp));

  base::FilePath build_prop = source_dir.Append("build.prop");
  constexpr const char kBuildProp[] =
      "ro.baz=boo\n"
      "ro.product.cpu.abilist=x86_64,x86,armeabi-v7a,armeabi\n"
      "ro.product.cpu.abilist64=x86_64\n";
  base::WriteFile(build_prop, kBuildProp, strlen(kBuildProp));

  base::FilePath vendor_build_prop = source_dir.Append("vendor_build.prop");
  constexpr const char kVendorBuildProp[] =
      "ro.a=b\n"
      "ro.vendor.product.cpu.abilist=x86_64,x86,armeabi-v7a,armeabi\n"
      "ro.vendor.product.cpu.abilist64=x86_64\n";
  base::WriteFile(vendor_build_prop, kVendorBuildProp,
                  strlen(kVendorBuildProp));

  // Expand with experiment off, verify properties are untouched.
  std::string content;
  EXPECT_TRUE(ExpandPropertyFiles(source_dir, dest_dir, false, false, false,
                                  false, nullptr));
  EXPECT_TRUE(
      base::ReadFileToString(dest_dir.Append("default.prop"), &content));
  EXPECT_EQ(std::string(kDefaultProp) + "\n", content);
  EXPECT_TRUE(base::ReadFileToString(dest_dir.Append("build.prop"), &content));
  EXPECT_EQ(std::string(kBuildProp) + "\n", content);
  EXPECT_TRUE(
      base::ReadFileToString(dest_dir.Append("vendor_build.prop"), &content));
  EXPECT_EQ(std::string(kVendorBuildProp) + "\n", content);

  // Expand with experiment on, verify properties are added / modified in
  // build.prop but not other files.
  EXPECT_TRUE(ExpandPropertyFiles(source_dir, dest_dir, false, true, false,
                                  false, nullptr));
  EXPECT_TRUE(
      base::ReadFileToString(dest_dir.Append("default.prop"), &content));
  EXPECT_EQ(std::string(kDefaultProp) + "\n", content);
  EXPECT_TRUE(base::ReadFileToString(dest_dir.Append("build.prop"), &content));
  constexpr const char kBuildPropModifiedFirst[] =
      "ro.baz=boo\n"
      "ro.product.cpu.abilist=x86_64,x86,arm64-v8a,armeabi-v7a,armeabi\n"
      "ro.product.cpu.abilist64=x86_64,arm64-v8a\n";
  constexpr const char kBuildPropModifiedSecond[] =
      "ro.dalvik.vm.isa.arm64=x86_64\n";
  EXPECT_EQ(base::StringPrintf("%s\n%s", kBuildPropModifiedFirst,
                               kBuildPropModifiedSecond),
            content);
  EXPECT_TRUE(
      base::ReadFileToString(dest_dir.Append("vendor_build.prop"), &content));
  constexpr const char kVendorBuildPropModified[] =
      "ro.a=b\n"
      "ro.vendor.product.cpu.abilist=x86_64,x86,arm64-v8a,armeabi-v7a,armeabi\n"
      "ro.vendor.product.cpu.abilist64=x86_64,arm64-v8a\n";
  EXPECT_EQ(std::string(kVendorBuildPropModified) + "\n", content);

  // Expand to a single file with experiment on, verify properties are added /
  // modified as expected.
  base::FilePath dest_prop_file;
  ASSERT_TRUE(
      base::CreateTemporaryDirInDir(GetTempDir(), "test", &dest_prop_file));
  dest_prop_file = dest_prop_file.Append("combined.prop");
  EXPECT_TRUE(ExpandPropertyFiles(source_dir, dest_prop_file, true, true, false,
                                  false, nullptr));

  // Verify the contents.
  EXPECT_TRUE(base::ReadFileToString(dest_prop_file, &content));
  EXPECT_EQ(
      base::StringPrintf("%s%s%s%s", kDefaultProp, kBuildPropModifiedFirst,
                         kBuildPropModifiedSecond, kVendorBuildPropModified),
      content);

  // Verify that unexpected property values generate an error.
  constexpr const char kBuildPropUnexpected[] =
      "ro.baz=boo\n"
      "ro.product.cpu.abilist=x86_64,armeabi-v7a,armeabi,unexpected-abi\n"
      "ro.product.cpu.abilist64=x86_64\n";
  base::WriteFile(build_prop, kBuildPropUnexpected,
                  strlen(kBuildPropUnexpected));
  EXPECT_FALSE(ExpandPropertyFiles(source_dir, dest_dir, false, true, false,
                                   false, nullptr));
  constexpr const char kBuildPropUnexpected2[] =
      "ro.baz=boo\n"
      "ro.product.cpu.abilist=x86_64,x86,armeabi-v7a,armeabi\n"
      "ro.product.cpu.abilist64=x86_64,unexpected-abi_64\n";
  base::WriteFile(build_prop, kBuildPropUnexpected2,
                  strlen(kBuildPropUnexpected2));
  EXPECT_FALSE(ExpandPropertyFiles(source_dir, dest_dir, false, true, false,
                                   false, nullptr));
}

// Verify that comments and non ro. properties are not written.
TEST_F(ArcPropertyUtilTest, ExpandPropertyFiles_SingleFile_NonRo) {
  base::FilePath source_dir;
  ASSERT_TRUE(base::CreateTemporaryDirInDir(GetTempDir(), "test", &source_dir));
  base::FilePath dest_dir;
  ASSERT_TRUE(base::CreateTemporaryDirInDir(GetTempDir(), "test", &dest_dir));

  const base::FilePath default_prop = source_dir.Append("default.prop");
  constexpr const char kDefaultProp[] = "###\ndalvik.foo=bar\nro.foo=bar\n";
  base::WriteFile(default_prop, kDefaultProp, strlen(kDefaultProp));

  const base::FilePath build_prop = source_dir.Append("build.prop");
  constexpr const char kBuildProp[] = "###\ndalvik.baz=boo\nro.baz=boo\n";
  base::WriteFile(build_prop, kBuildProp, strlen(kBuildProp));

  const base::FilePath vendor_build_prop =
      source_dir.Append("vendor_build.prop");
  constexpr const char kVendorBuildProp[] = "###\ndalvik.a=b\nro.a=b\n";
  base::WriteFile(vendor_build_prop, kVendorBuildProp,
                  strlen(kVendorBuildProp));

  const base::FilePath dest_prop_file = dest_dir.Append("combined.prop");
  EXPECT_TRUE(ExpandPropertyFiles(source_dir, dest_prop_file, true, false,
                                  false, false, nullptr));

  // Verify the content.
  std::string content;
  EXPECT_TRUE(base::ReadFileToString(dest_prop_file, &content));
  EXPECT_EQ("ro.foo=bar\nro.baz=boo\nro.a=b\n", content);
}

// Verify that the CDM properties received from cdm-oemcrypto over D-Bus are
// written to the properties file.
TEST_F(ArcPropertyUtilTest, TestAddingCdmProperties) {
  base::FilePath source_dir;
  ASSERT_TRUE(base::CreateTemporaryDirInDir(GetTempDir(), "test", &source_dir));
  base::FilePath dest_dir;
  ASSERT_TRUE(base::CreateTemporaryDirInDir(GetTempDir(), "test", &dest_dir));

  base::FilePath default_prop = source_dir.Append("default.prop");
  constexpr const char kDefaultProp[] = "ro.foo=bar\n";
  base::WriteFile(default_prop, kDefaultProp, strlen(kDefaultProp));

  base::FilePath build_prop = source_dir.Append("build.prop");
  constexpr const char kBuildProp[] = "ro.baz=boo\n";
  base::WriteFile(build_prop, kBuildProp, strlen(kBuildProp));

  base::FilePath vendor_build_prop = source_dir.Append("vendor_build.prop");
  constexpr const char kVendorBuildProp[] = "ro.a=b\n";
  base::WriteFile(vendor_build_prop, kVendorBuildProp,
                  strlen(kVendorBuildProp));

  base::FilePath product_build_prop = source_dir.Append("product_build.prop");
  constexpr const char kProductBuildProp[] = "ro.c=d\n";
  base::WriteFile(product_build_prop, kProductBuildProp,
                  strlen(kProductBuildProp));

  EXPECT_CALL(*bus_, GetObjectProxy(_, _))
      .WillOnce(Return(cdm_factory_daemon_object_proxy_.get()));

  std::unique_ptr<dbus::Response> response = dbus::Response::CreateEmpty();
  dbus::MessageWriter writer(response.get());
  chromeos::cdm::ClientInformation client_info;
  constexpr char kManufacturer[] = "fake_manufacturer";
  constexpr char kMake[] = "fake_make";
  constexpr char kModel[] = "fake_model";
  client_info.set_manufacturer(kManufacturer);
  client_info.set_make(kMake);
  client_info.set_model(kModel);
  writer.AppendProtoAsArrayOfBytes(client_info);
  EXPECT_CALL(*cdm_factory_daemon_object_proxy_,
              CallMethodAndBlockWithErrorDetails(_, _, _))
      .WillOnce(Return(ByMove(std::move(response))));

  const base::FilePath dest_prop_file = dest_dir.Append("combined.prop");
  EXPECT_TRUE(ExpandPropertyFiles(source_dir, dest_prop_file, true, false, true,
                                  false, bus_));

  // Verify the content.
  std::string content;
  EXPECT_TRUE(base::ReadFileToString(dest_prop_file, &content));
  EXPECT_EQ(std::string() + kDefaultProp + kBuildProp + kVendorBuildProp +
                kProductBuildProp + "ro.product.cdm.manufacturer=" +
                kManufacturer + "\nro.product.cdm.model=" + kModel +
                "\nro.product.cdm.device=" + kMake + "\n",
            content);
}

// Verify that a failure reading the CDM properties from cdm-oemcrypto over
// D-Bus is handled properly and doesn't change the properties file.
TEST_F(ArcPropertyUtilTest, TestAddingCdmProperties_DbusFailure) {
  base::FilePath source_dir;
  ASSERT_TRUE(base::CreateTemporaryDirInDir(GetTempDir(), "test", &source_dir));
  base::FilePath dest_dir;
  ASSERT_TRUE(base::CreateTemporaryDirInDir(GetTempDir(), "test", &dest_dir));

  base::FilePath default_prop = source_dir.Append("default.prop");
  constexpr const char kDefaultProp[] = "ro.foo=bar\n";
  base::WriteFile(default_prop, kDefaultProp, strlen(kDefaultProp));

  base::FilePath build_prop = source_dir.Append("build.prop");
  constexpr const char kBuildProp[] = "ro.baz=boo\n";
  base::WriteFile(build_prop, kBuildProp, strlen(kBuildProp));

  base::FilePath vendor_build_prop = source_dir.Append("vendor_build.prop");
  constexpr const char kVendorBuildProp[] = "ro.a=b\n";
  base::WriteFile(vendor_build_prop, kVendorBuildProp,
                  strlen(kVendorBuildProp));

  base::FilePath product_build_prop = source_dir.Append("product_build.prop");
  constexpr const char kProductBuildProp[] = "ro.c=d\n";
  base::WriteFile(product_build_prop, kProductBuildProp,
                  strlen(kProductBuildProp));

  EXPECT_CALL(*bus_, GetObjectProxy(_, _))
      .WillOnce(Return(cdm_factory_daemon_object_proxy_.get()));

  std::unique_ptr<dbus::Response> response = dbus::Response::CreateEmpty();
  EXPECT_CALL(*cdm_factory_daemon_object_proxy_,
              CallMethodAndBlockWithErrorDetails(_, _, _))
      .WillOnce(Return(ByMove(std::move(response))));

  const base::FilePath dest_prop_file = dest_dir.Append("combined.prop");
  EXPECT_TRUE(ExpandPropertyFiles(source_dir, dest_prop_file, true, false, true,
                                  false, bus_));

  // Verify the content.
  std::string content;
  EXPECT_TRUE(base::ReadFileToString(dest_prop_file, &content));
  EXPECT_EQ(std::string() + kDefaultProp + kBuildProp + kVendorBuildProp +
                kProductBuildProp,
            content);
}

TEST_F(ArcPropertyUtilTest, AppendIntelSocProperties) {
  int case_no = 0;

  for (auto& testcase :
       {std::tuple<const char*, const char*>{
            "nomatch\nmodel name\t: Intel(R) Core(TM) i5-10510U CPU @ 999GHz\n",
            "ro.soc.manufacturer=Intel\nro.soc.model=i5-10510U\n"},
        {"xyz\nmodel name\t\t: Intel(R) Core(TM) i7-920 CPU @ 2.67GHz\nabc\n",
         "ro.soc.manufacturer=Intel\nro.soc.model=i7-920\n"},
        {"nomatch\nnomatch\nnomatch\n", ""},

        // For an Octopus board.
        {"model name: Intel(R) Celeron(R) N4000 CPU @ 1.10GHz\n",
         "ro.soc.manufacturer=Intel\nro.soc.model=N4000\n"}}) {
    base::StringPiece cpuinfo = std::get<0>(testcase);
    base::StringPiece expected = std::get<1>(testcase);
    auto cpuinfo_path =
        GetTempDir().Append(base::StringPrintf("cpuinfo%d", case_no++));

    ASSERT_TRUE(base::WriteFile(cpuinfo_path, cpuinfo));

    // Make sure the file is opened read-only by turning off the writable perms.
    ASSERT_EQ(chmod(cpuinfo_path.value().c_str(), 0444), 0);

    std::string actual;
    AppendIntelSocProperties(cpuinfo_path, &actual);

    EXPECT_EQ(expected, actual);
  }
}

TEST_F(ArcPropertyUtilTest, AppendIntelSocPropertiesDoesNotOverwrite) {
  auto cpuinfo_path = GetTempDir().Append("cpuinfo");

  ASSERT_TRUE(base::WriteFile(cpuinfo_path,
                              "model name : Intel(R) Core(TM) i7-5200U CPU\n"));

  std::string dest = "xyz=123\n";
  AppendIntelSocProperties(cpuinfo_path, &dest);
  EXPECT_THAT(dest, StartsWith("xyz=123\nro.soc."));
}

TEST_F(ArcPropertyUtilTest, AppendArmSocPropertiesNoMatch) {
  auto socinfo_devices_dir = GetTempDir();
  auto soc0_path = socinfo_devices_dir.Append("soc0");
  auto machine_path = soc0_path.Append("machine");
  auto family_path = soc0_path.Append("family");

  ASSERT_TRUE(base::CreateDirectory(soc0_path));
  ASSERT_TRUE(base::WriteFile(machine_path, "unknown486\n"));
  ASSERT_TRUE(base::WriteFile(family_path, "unknownFamily\n"));

  std::string dest = "4=2+2\n";
  AppendArmSocProperties(socinfo_devices_dir, &dest);
  EXPECT_EQ(dest, "4=2+2\n");
}

TEST_F(ArcPropertyUtilTest, AppendArmSocPropertiesMatch) {
  auto socinfo_devices_dir = GetTempDir();
  auto soc0_path = socinfo_devices_dir.Append("soc0");
  auto machine_path = soc0_path.Append("machine");
  auto family_path = soc0_path.Append("family");

  ASSERT_TRUE(base::CreateDirectory(soc0_path));
  ASSERT_TRUE(base::WriteFile(machine_path, "SC7180\n"));
  ASSERT_TRUE(base::WriteFile(family_path, "Snapdragon\n"));

  // Make sure the file is opened read-only by turning off the writable perms.
  ASSERT_EQ(chmod(machine_path.value().c_str(), 0444), 0);
  ASSERT_EQ(chmod(family_path.value().c_str(), 0444), 0);

  std::string dest = "jkl=aoe\n";
  AppendArmSocProperties(socinfo_devices_dir, &dest);
  EXPECT_EQ(dest,
            "jkl=aoe\n"
            "ro.soc.manufacturer=Qualcomm\n"
            "ro.soc.model=SC7180\n");
}

TEST_F(ArcPropertyUtilTest, AppendArmSocPropertiesSymlink) {
  auto sysfs_dir = GetTempDir();
  auto devices_dir = sysfs_dir.Append("devices");
  auto soc0_path = devices_dir.Append("soc0");
  auto machine_path = soc0_path.Append("machine");
  auto family_path = soc0_path.Append("family");
  auto bus_dir = sysfs_dir.Append("bus");
  auto socinfo_dir = bus_dir.Append("soc");
  auto socinfo_devices_dir = bus_dir.Append("devices");
  auto socinfo_soc0_path = socinfo_devices_dir.Append("soc0");

  // Try to replicate something akin to the real structure of sysfs, which has
  // symlinks. This helps confirm we aren't using "safe" functions to read.
  ASSERT_TRUE(base::CreateDirectory(devices_dir));
  ASSERT_TRUE(base::CreateDirectory(soc0_path));
  ASSERT_TRUE(base::WriteFile(machine_path, "SC7180\n"));
  ASSERT_TRUE(base::WriteFile(family_path, "Snapdragon\n"));
  ASSERT_TRUE(base::CreateDirectory(bus_dir));
  ASSERT_TRUE(base::CreateDirectory(socinfo_dir));
  ASSERT_TRUE(base::CreateDirectory(socinfo_devices_dir));
  ASSERT_TRUE(base::CreateSymbolicLink(soc0_path, socinfo_soc0_path));

  // Make sure the file is opened read-only by turning off the writable perms.
  ASSERT_EQ(chmod(machine_path.value().c_str(), 0444), 0);

  std::string dest = "symlinks=fun\n";
  AppendArmSocProperties(socinfo_devices_dir, &dest);
  EXPECT_EQ(dest,
            "symlinks=fun\n"
            "ro.soc.manufacturer=Qualcomm\n"
            "ro.soc.model=SC7180\n");
}

TEST_F(ArcPropertyUtilTest, AppendArmSocPropertiesTwo) {
  auto socinfo_devices_dir = GetTempDir();
  auto soc0_path = socinfo_devices_dir.Append("soc0");
  auto soc_id0_path = soc0_path.Append("soc_id");
  auto family0_path = soc0_path.Append("family");
  auto soc1_path = socinfo_devices_dir.Append("soc1");
  auto soc_id1_path = soc1_path.Append("soc_id");
  auto machine1_path = soc1_path.Append("machine");
  auto family1_path = soc1_path.Append("family");

  // soc0 will exist, but _not_ have a machine file. It will represent the
  // generic version of the driver that directly exposes the firmware.
  ASSERT_TRUE(base::CreateDirectory(soc0_path));
  ASSERT_TRUE(base::WriteFile(soc_id0_path, "jep106:0070:7180\n"));
  ASSERT_TRUE(base::WriteFile(family0_path, "jep106:0070\n"));

  // soc1 will be exposing a "nicer" SoC-specific driver.
  ASSERT_TRUE(base::CreateDirectory(soc1_path));
  ASSERT_TRUE(base::WriteFile(soc_id1_path, "425\n"));
  ASSERT_TRUE(base::WriteFile(machine1_path, "SC7180\n"));
  ASSERT_TRUE(base::WriteFile(family1_path, "Snapdragon\n"));

  // Make sure the file is opened read-only by turning off the writable perms.
  ASSERT_EQ(chmod(soc_id1_path.value().c_str(), 0444), 0);
  ASSERT_EQ(chmod(machine1_path.value().c_str(), 0444), 0);
  ASSERT_EQ(chmod(family1_path.value().c_str(), 0444), 0);

  std::string dest = "one=two\n";
  AppendArmSocProperties(socinfo_devices_dir, &dest);
  EXPECT_EQ(dest,
            "one=two\n"
            "ro.soc.manufacturer=Qualcomm\n"
            "ro.soc.model=SC7180\n");
}

TEST_F(ArcPropertyUtilTest, AppendIntelSocPropertiesCannotOpenCpuinfo) {
  auto cpuinfo_path = GetTempDir().Append("cpuinfo.nothere");

  std::string dest;
  AppendIntelSocProperties(cpuinfo_path, &dest);
  EXPECT_EQ(dest, "");
}

TEST_F(ArcPropertyUtilTest, AppendArmSocPropertiesCannotOpenMachineFile) {
  auto temp_dir = GetTempDir();
  auto socinfo_path = temp_dir.Append("directory.nothere");

  std::string dest;
  AppendArmSocProperties(socinfo_path, &dest);
  EXPECT_EQ(dest, "");
}

}  // namespace
}  // namespace arc
