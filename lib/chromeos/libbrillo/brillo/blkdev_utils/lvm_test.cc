// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <optional>

#include "brillo/blkdev_utils/mock_lvm.h"

#include <base/files/file_util.h>
#include <gtest/gtest.h>

using testing::_;
using testing::DoAll;

namespace brillo {
namespace {
// LogicalVolumeManager is a glorified json parser. Use the following templates
// to generate valid pv/vg/lv reports.
constexpr const char kSampleReport[] =
    "{\"report\": [ { \"%s\": [ {\"%s\":\"%s\", \"%s\":\"%s\" } ] } ] }";
constexpr const char kSampleMultiReport[] =
    "{\"report\": [ { \"%s\": [ {\"%s\":\"%s\", \"%s\":\"%s\" }, "
    "{\"%s\":\"%s\", \"%s\":\"%s\" } ] } ] }";

}  // namespace

TEST(GetPhysicalVolumeTest, InvalidReportTest) {
  auto lvm = std::make_shared<MockLvmCommandRunner>();
  LogicalVolumeManager lvmanager(lvm);
  std::string report(kSampleReport);

  EXPECT_CALL(*lvm, RunProcess(_, _))
      .WillOnce(DoAll(SetArgPointee<1>(report), Return(true)));

  auto pv = lvmanager.GetPhysicalVolume(base::FilePath("/dev/pv"));
  EXPECT_EQ(pv, std::nullopt);
}

TEST(GetPhysicalVolumeTest, ValidReportTest) {
  auto lvm = std::make_shared<MockLvmCommandRunner>();
  LogicalVolumeManager lvmanager(lvm);
  std::string report = base::StringPrintf(kSampleReport, "pv", "pv_name",
                                          "/dev/pv", "vg_name", "bar");

  EXPECT_CALL(*lvm, RunProcess(_, _))
      .WillOnce(DoAll(SetArgPointee<1>(report), Return(true)));

  auto pv = lvmanager.GetPhysicalVolume(base::FilePath("/dev/pv"));
  EXPECT_NE(pv, std::nullopt);
  EXPECT_TRUE(pv->IsValid());
  EXPECT_EQ(base::FilePath("/dev/pv"), pv->GetPath());
}

TEST(GetVolumeGroupTest, InvalidReportTest) {
  auto lvm = std::make_shared<MockLvmCommandRunner>();
  LogicalVolumeManager lvmanager(lvm);
  PhysicalVolume pv(base::FilePath("/dev/foo"), lvm);
  std::string report(kSampleReport);

  EXPECT_CALL(*lvm, RunProcess(_, _))
      .WillOnce(DoAll(SetArgPointee<1>(report), Return(true)));

  auto vg = lvmanager.GetVolumeGroup(pv);

  EXPECT_EQ(vg, std::nullopt);
}

TEST(GetVolumeGroupTest, ValidReportTest) {
  auto lvm = std::make_shared<MockLvmCommandRunner>();
  LogicalVolumeManager lvmanager(lvm);
  PhysicalVolume pv(base::FilePath("/dev/foo"), lvm);
  std::string report = base::StringPrintf(kSampleReport, "pv", "pv_name",
                                          "/dev/foo", "vg_name", "bar");

  EXPECT_CALL(*lvm, RunProcess(_, _))
      .WillOnce(DoAll(SetArgPointee<1>(report), Return(true)));

  auto vg = lvmanager.GetVolumeGroup(pv);
  EXPECT_NE(vg, std::nullopt);
  EXPECT_TRUE(vg->IsValid());
  EXPECT_EQ("bar", vg->GetName());
}

TEST(GetThinpoolTest, InvalidReportTest) {
  auto lvm = std::make_shared<MockLvmCommandRunner>();
  LogicalVolumeManager lvmanager(lvm);
  VolumeGroup vg("bar", lvm);
  std::string report(kSampleReport);

  EXPECT_CALL(*lvm, RunProcess(_, _))
      .WillOnce(DoAll(SetArgPointee<1>(report), Return(true)));

  auto thinpool = lvmanager.GetThinpool(vg, "thinpool");

  EXPECT_EQ(thinpool, std::nullopt);
}

TEST(GetThinpoolTest, ValidReportTest) {
  auto lvm = std::make_shared<MockLvmCommandRunner>();
  LogicalVolumeManager lvmanager(lvm);
  VolumeGroup vg("bar", lvm);
  std::string report = base::StringPrintf(kSampleReport, "lv", "lv_name",
                                          "thinpool", "vg_name", "bar");

  EXPECT_CALL(*lvm, RunProcess(_, _))
      .WillOnce(DoAll(SetArgPointee<1>(report), Return(true)));

  auto thinpool = lvmanager.GetThinpool(vg, "thinpool");

  EXPECT_NE(thinpool, std::nullopt);
  EXPECT_TRUE(thinpool->IsValid());
  EXPECT_EQ("bar/thinpool", thinpool->GetName());
}

TEST(GetLogicalVolumeTest, InvalidReportTest) {
  auto lvm = std::make_shared<MockLvmCommandRunner>();
  LogicalVolumeManager lvmanager(lvm);
  VolumeGroup vg("bar", lvm);
  std::string report(kSampleReport);

  EXPECT_CALL(*lvm, RunProcess(_, _))
      .WillOnce(DoAll(SetArgPointee<1>(report), Return(true)));

  auto lv = lvmanager.GetLogicalVolume(vg, "foo");
  EXPECT_EQ(lv, std::nullopt);
}

TEST(GetLogicalVolumeTest, ValidReportTest) {
  auto lvm = std::make_shared<MockLvmCommandRunner>();
  LogicalVolumeManager lvmanager(lvm);
  VolumeGroup vg("bar", lvm);
  std::string report = base::StringPrintf(kSampleReport, "lv", "lv_name", "foo",
                                          "vg_name", "bar");

  EXPECT_CALL(*lvm, RunProcess(_, _))
      .WillOnce(DoAll(SetArgPointee<1>(report), Return(true)));

  auto lv = lvmanager.GetLogicalVolume(vg, "foo");

  EXPECT_NE(lv, std::nullopt);
  EXPECT_TRUE(lv->IsValid());
  EXPECT_EQ("bar/foo", lv->GetName());
  EXPECT_EQ(base::FilePath("/dev/bar/foo"), lv->GetPath());
}

TEST(ListLogicalVolumesTest, InvalidReportTest) {
  auto lvm = std::make_shared<MockLvmCommandRunner>();
  LogicalVolumeManager lvmanager(lvm);
  VolumeGroup vg("bar", lvm);
  std::string report(kSampleReport);

  EXPECT_CALL(*lvm, RunProcess(_, _))
      .WillOnce(DoAll(SetArgPointee<1>(report), Return(true)));

  auto lv_vector = lvmanager.ListLogicalVolumes(vg);
  EXPECT_EQ(0, lv_vector.size());
}

TEST(ListLogicalVolumesTest, ValidReportTest) {
  auto lvm = std::make_shared<MockLvmCommandRunner>();
  LogicalVolumeManager lvmanager(lvm);
  VolumeGroup vg("bar", lvm);
  std::string report =
      base::StringPrintf(kSampleMultiReport, "lv", "lv_name", "foo0", "vg_name",
                         "bar", "lv_name", "foo1", "vg_name", "bar");

  EXPECT_CALL(*lvm, RunProcess(_, _))
      .WillOnce(DoAll(SetArgPointee<1>(report), Return(true)));

  auto lv_vector = lvmanager.ListLogicalVolumes(vg);
  EXPECT_EQ(2, lv_vector.size());
  for (int i = 0; i < 2; i++) {
    EXPECT_EQ(base::StringPrintf("bar/foo%d", i), lv_vector[i].GetName());
    EXPECT_EQ(base::FilePath(base::StringPrintf("/dev/bar/foo%d", i)),
              lv_vector[i].GetPath());
  }
}

}  // namespace brillo
