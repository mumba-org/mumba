// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/media/cdm_registry_impl.h"

#include <algorithm>
#include <string>
#include <vector>

#include "base/base_paths.h"
#include "base/files/file_path.h"
#include "base/strings/string_split.h"
#include "base/strings/string_util.h"
#include "base/strings/utf_string_conversions.h"
#include "base/version.h"
#include "core/common/cdm_info.h"
#include "media/base/video_codecs.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace host {

const char kTestCdmName[] = "Test CDM";
const char kTestCdmGuid[] = "62FE9C4B-384E-48FD-B28A-9F6F248BC8CC";
const char kTestPath[] = "/aa/bb";
const char kVersion1[] = "1.1.1.1";
const char kVersion2[] = "1.1.1.2";
const char kTestKeySystem[] = "com.example.somesystem";
const char kTestFileSystemId[] = "file_system_id";

// For simplicity and to make failures easier to diagnose, this test uses
// std::string instead of base::FilePath and std::vector<std::string>.
class CdmRegistryImplTest : public testing::Test {
 public:
  CdmRegistryImplTest() {}
  ~CdmRegistryImplTest() override {}

 protected:
  void Register(const std::string& name,
                const std::string& version,
                const std::string& path,
                const std::vector<media::VideoCodec>& supported_video_codecs,
                bool supports_persistent_license,
                std::string supported_key_system,
                bool supports_sub_key_systems = false) {
    cdm_registry_.RegisterCdm(
        CdmInfo(name, kTestCdmGuid, base::Version(version),
                base::FilePath::FromUTF8Unsafe(path), kTestFileSystemId,
                supported_video_codecs, supports_persistent_license,
                supported_key_system, supports_sub_key_systems));
  }

  bool IsRegistered(const std::string& name, const std::string& version) {
    for (const auto& cdm : cdm_registry_.GetAllRegisteredCdms()) {
      if (cdm.name == name && cdm.version.GetString() == version)
        return true;
    }
    return false;
  }

  std::vector<std::string> GetVersions(const std::string& guid) {
    std::vector<std::string> versions;
    for (const auto& cdm : cdm_registry_.GetAllRegisteredCdms()) {
      if (cdm.guid == guid)
        versions.push_back(cdm.version.GetString());
    }
    return versions;
  }

 protected:
  CdmRegistryImpl cdm_registry_;
};

TEST_F(CdmRegistryImplTest, Register) {
  Register(kTestCdmName, kVersion1, kTestPath,
           {media::kCodecVP8, media::kCodecVP9}, true, kTestKeySystem, true);
  std::vector<CdmInfo> cdms = cdm_registry_.GetAllRegisteredCdms();
  ASSERT_EQ(1u, cdms.size());
  CdmInfo cdm = cdms[0];
  EXPECT_EQ(kTestCdmName, cdm.name);
  EXPECT_EQ(kVersion1, cdm.version.GetString());
  EXPECT_EQ(kTestPath, cdm.path.MaybeAsASCII());
  EXPECT_EQ(kTestFileSystemId, cdm.file_system_id);
  EXPECT_EQ(2u, cdm.supported_video_codecs.size());
  EXPECT_EQ(media::kCodecVP8, cdm.supported_video_codecs[0]);
  EXPECT_EQ(media::kCodecVP9, cdm.supported_video_codecs[1]);
  EXPECT_TRUE(cdm.supports_persistent_license);
  EXPECT_EQ(kTestKeySystem, cdm.supported_key_system);
  EXPECT_TRUE(cdm.supports_sub_key_systems);
}

TEST_F(CdmRegistryImplTest, ReRegister) {
  Register(kTestCdmName, kVersion1, "/bb/cc", {}, false, kTestKeySystem);
  EXPECT_TRUE(IsRegistered(kTestCdmName, kVersion1));

  // Now register same key system with different values.
  Register(kTestCdmName, kVersion1, kTestPath, {}, false, kTestKeySystem);
  EXPECT_TRUE(IsRegistered(kTestCdmName, kVersion1));
}

TEST_F(CdmRegistryImplTest, MultipleVersions) {
  Register(kTestCdmName, kVersion1, kTestPath, {}, false, kTestKeySystem);
  Register(kTestCdmName, kVersion2, "/bb/cc", {}, false, kTestKeySystem);
  EXPECT_TRUE(IsRegistered(kTestCdmName, kVersion1));
  EXPECT_TRUE(IsRegistered(kTestCdmName, kVersion2));
}

TEST_F(CdmRegistryImplTest, NewVersionInsertedLast) {
  Register(kTestCdmName, kVersion1, kTestPath, {}, false, kTestKeySystem);
  Register(kTestCdmName, kVersion2, "/bb/cc", {}, false, kTestKeySystem);

  const std::vector<std::string> versions = GetVersions(kTestCdmGuid);
  EXPECT_EQ(2u, versions.size());
  EXPECT_EQ(kVersion1, versions[0]);
  EXPECT_EQ(kVersion2, versions[1]);
}

}  // namespace host
