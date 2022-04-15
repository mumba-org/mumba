// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "brillo/blkdev_utils/mock_lvm.h"

#include <base/files/file_util.h>
#include <gtest/gtest.h>

using testing::DoAll;

namespace brillo {

namespace {
constexpr const char kSampleReport[] =
    "{\"report\": [ { \"%s\": [ {\"%s\":\"%s\", \"%s\":\"%s\", \"%s\":\"%s\" } "
    "] } ] }";
}  // namespace

TEST(PhysicalVolumeTest, InvalidPhysicalVolumeTest) {
  auto lvm = std::make_shared<MockLvmCommandRunner>();
  PhysicalVolume pv(base::FilePath(""), lvm);

  EXPECT_FALSE(pv.Check());
  EXPECT_FALSE(pv.Repair());
  EXPECT_FALSE(pv.Remove());
}

TEST(PhysicalVolumeTest, PhysicalVolumeSanityTest) {
  auto lvm = std::make_shared<MockLvmCommandRunner>();
  base::FilePath device_path("/dev/sda1");
  PhysicalVolume pv(device_path, lvm);

  EXPECT_EQ(device_path, pv.GetPath());
  EXPECT_TRUE(pv.Remove());
  EXPECT_EQ(base::FilePath(""), pv.GetPath());
}

TEST(VolumeGroupTest, InvalidVolumeGroupTest) {
  auto lvm = std::make_shared<MockLvmCommandRunner>();
  VolumeGroup vg("", lvm);

  EXPECT_FALSE(vg.Check());
  EXPECT_FALSE(vg.Activate());
  EXPECT_FALSE(vg.Deactivate());
  EXPECT_FALSE(vg.Repair());
  EXPECT_FALSE(vg.Remove());
}

TEST(VolumeGroupTest, VolumeGroupSanityTest) {
  auto lvm = std::make_shared<MockLvmCommandRunner>();
  VolumeGroup vg("FooBar", lvm);

  EXPECT_EQ(base::FilePath("/dev/FooBar"), vg.GetPath());
  EXPECT_EQ("FooBar", vg.GetName());

  EXPECT_TRUE(vg.Remove());
  EXPECT_EQ("", vg.GetName());
}

TEST(ThinpoolTest, InvalidThinpoolTest) {
  auto lvm = std::make_shared<MockLvmCommandRunner>();
  Thinpool thinpool("", "", lvm);

  EXPECT_FALSE(thinpool.Check());
  EXPECT_FALSE(thinpool.Activate());
  EXPECT_FALSE(thinpool.Deactivate());
  EXPECT_FALSE(thinpool.Repair());
  EXPECT_FALSE(thinpool.Remove());
}

TEST(ThinpoolTest, ThinpoolSanityTest) {
  auto lvm = std::make_shared<MockLvmCommandRunner>();
  Thinpool thinpool("Foo", "Bar", lvm);

  EXPECT_EQ("Bar/Foo", thinpool.GetName());
  EXPECT_TRUE(thinpool.Remove());
  EXPECT_EQ("", thinpool.GetName());
}

TEST(ThinpoolTest, ThinpoolSpaceTest) {
  auto lvm = std::make_shared<MockLvmCommandRunner>();
  Thinpool thinpool("foo", "bar", lvm);

  std::string report =
      base::StringPrintf(kSampleReport, "lv", "lv_name", "thinpool", "lv_size",
                         "1000000B", "data_percent", "2.5");

  EXPECT_CALL(*lvm, RunProcess(_, _))
      .WillRepeatedly(DoAll(SetArgPointee<1>(report), Return(true)));

  int64_t total_space, free_space;
  EXPECT_TRUE(thinpool.GetTotalSpace(&total_space));
  EXPECT_TRUE(thinpool.GetFreeSpace(&free_space));
  EXPECT_EQ(total_space, 1000000LL);
  EXPECT_EQ(free_space, 975000LL);
}

TEST(LogicalVolumeTest, InvalidLogicalVolumeTest) {
  auto lvm = std::make_shared<MockLvmCommandRunner>();
  LogicalVolume lv("", "", lvm);

  EXPECT_FALSE(lv.Activate());
  EXPECT_FALSE(lv.Deactivate());
  EXPECT_FALSE(lv.Remove());
}

TEST(LogicalVolumeTest, LogicalVolumeSanityTest) {
  auto lvm = std::make_shared<MockLvmCommandRunner>();
  LogicalVolume lv("Foo", "Bar", lvm);

  EXPECT_EQ(base::FilePath("/dev/Bar/Foo"), lv.GetPath());
  EXPECT_EQ("Bar/Foo", lv.GetName());
  EXPECT_TRUE(lv.Remove());
  EXPECT_EQ("", lv.GetName());
}

}  // namespace brillo
