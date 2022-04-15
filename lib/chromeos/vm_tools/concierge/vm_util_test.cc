// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vm_tools/concierge/vm_util.h"

#include <base/containers/contains.h>
#include <base/strings/string_number_conversions.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <optional>

namespace vm_tools {
namespace concierge {
namespace {
void LoadCustomParameters(const std::string& data, base::StringPairs* args) {
  CustomParametersForDev custom(data);
  custom.Apply(args);
}
std::string JoinStringPairs(const base::StringPairs& pairs) {
  std::string result;
  for (auto& pair : pairs) {
    result += (pair.first + "=" + pair.second + " ");
  }
  return result;
}
}  // namespace

TEST(VMUtilTest, LoadCustomParametersSupportsEmptyInput) {
  base::StringPairs args;
  LoadCustomParameters("", &args);
  base::StringPairs expected;
  EXPECT_THAT(args, testing::ContainerEq(expected));
}

TEST(VMUtilTest, LoadCustomParametersParsesManyPairs) {
  base::StringPairs args;
  LoadCustomParameters(R"(--Key1=Value1
--Key2=Value2
--Key3=Value3)",
                       &args);
  base::StringPairs expected = {
      {"--Key1", "Value1"}, {"--Key2", "Value2"}, {"--Key3", "Value3"}};
  EXPECT_THAT(args, testing::ContainerEq(expected));
}

TEST(VMUtilTest, LoadCustomParametersSkipsComments) {
  base::StringPairs args;
  LoadCustomParameters(R"(--Key1=Value1
#--Key2=Value2
--Key3=Value3)",
                       &args);
  base::StringPairs expected{{"--Key1", "Value1"}, {"--Key3", "Value3"}};
  EXPECT_THAT(args, testing::ContainerEq(expected));
}

TEST(VMUtilTest, LoadCustomParametersSkipsEmptyLines) {
  base::StringPairs args;
  LoadCustomParameters(R"(--Key1=Value1




--Key2=Value2



)",
                       &args);
  base::StringPairs expected{{"--Key1", "Value1"}, {"--Key2", "Value2"}};
  EXPECT_THAT(args, testing::ContainerEq(expected));
}

TEST(VMUtilTest, LoadCustomParametersSupportsKeyWithoutValue) {
  base::StringPairs args;
  LoadCustomParameters(R"(--Key1=Value1
--Key2



--Key3)",
                       &args);
  base::StringPairs expected{
      {"--Key1", "Value1"}, {"--Key2", ""}, {"--Key3", ""}};
  EXPECT_THAT(args, testing::ContainerEq(expected));
}

TEST(VMUtilTest, LoadCustomParametersSupportsRemoving) {
  base::StringPairs args = {{"--KeyToBeReplaced", "OldValue"},
                            {"--KeyToBeKept", "ValueToBeKept"}};
  LoadCustomParameters(
      R"(--Key1=Value1
--Key2=Value2
!--KeyToBeReplaced
--KeyToBeReplaced=NewValue)",
      &args);
  base::StringPairs expected{{"--KeyToBeKept", "ValueToBeKept"},
                             {"--Key1", "Value1"},
                             {"--Key2", "Value2"},
                             {"--KeyToBeReplaced", "NewValue"}};
  EXPECT_THAT(args, testing::ContainerEq(expected));
}

TEST(VMUtilTest, LoadCustomParametersSupportsRemovingByPrefix) {
  base::StringPairs args = {{"foo", ""},
                            {"foo", "bar"},
                            {"foobar", ""},
                            {"foobar", "baz"},
                            {"barfoo", ""}};
  LoadCustomParameters("!foo", &args);
  base::StringPairs expected{{"barfoo", ""}};
  EXPECT_THAT(args, testing::ContainerEq(expected));
}

TEST(CustomParametersForDevTest, KernelWithCustom) {
  base::StringPairs args = {{"--Key1", "Value1"}};
  CustomParametersForDev custom(R"(--Key2=Value2
KERNEL_PATH=/a/b/c
--Key3=Value3)");
  custom.Apply(&args);
  const std::string resolved_kernel_path =
      custom.ObtainSpecialParameter("KERNEL_PATH").value_or("default_path");

  base::StringPairs expected{
      {"--Key1", "Value1"}, {"--Key2", "Value2"}, {"--Key3", "Value3"}};
  EXPECT_THAT(args, testing::ContainerEq(expected));
  EXPECT_THAT(resolved_kernel_path, "/a/b/c");
}

TEST(CustomParametersForDevTest, KernelWithDefault) {
  base::StringPairs args = {{"--Key1", "Value1"}};
  CustomParametersForDev custom(R"(--Key2=Value2
--Key3=Value3
SOME_OTHER_PATH=/a/b/c)");
  custom.Apply(&args);
  const std::string resolved_kernel_path =
      custom.ObtainSpecialParameter("KERNEL_PATH").value_or("default_path");

  base::StringPairs expected{
      {"--Key1", "Value1"},
      {"--Key2", "Value2"},
      {"--Key3", "Value3"},
  };
  EXPECT_THAT(args, testing::ContainerEq(expected));
  EXPECT_THAT(resolved_kernel_path, "default_path");
}

TEST(CustomParametersForDevTest, ODirect) {
  base::StringPairs args = {{"--Key1", "Value1"}};
  CustomParametersForDev custom(R"(O_DIRECT=true)");
  custom.Apply(&args);
  const std::string o_direct =
      custom.ObtainSpecialParameter("O_DIRECT").value_or("false");

  base::StringPairs expected{
      {"--Key1", "Value1"},
  };
  EXPECT_THAT(args, testing::ContainerEq(expected));
  EXPECT_THAT(o_direct, "true");
}

TEST(VMUtilTest, BlockSize) {
  Disk::Config config;
  Disk disk(base::FilePath("/path/to/image.img"), config);
  EXPECT_FALSE(
      base::Contains(JoinStringPairs(disk.GetCrosvmArgs()), "block_size"));

  config.block_size = 4096;
  Disk disk_with_block_size(base::FilePath("/path/to/image.img"), config);
  EXPECT_TRUE(
      base::Contains(JoinStringPairs(disk_with_block_size.GetCrosvmArgs()),
                     "block_size=4096"));
}

TEST(VMUtilTest, GetCpuAffinityFromClustersNoGroups) {
  std::vector<std::vector<std::string>> cpu_clusters;
  std::map<int32_t, std::vector<std::string>> cpu_capacity_groups;

  auto cpu_affinity =
      GetCpuAffinityFromClusters(cpu_clusters, cpu_capacity_groups);
  EXPECT_EQ(cpu_affinity, std::nullopt);
}

TEST(VMUtilTest, GetCpuAffinityFromClustersGroupSizesOne) {
  std::vector<std::vector<std::string>> cpu_clusters;
  std::map<int32_t, std::vector<std::string>> cpu_capacity_groups;

  cpu_clusters.push_back({"0", "1", "2", "3"});

  cpu_capacity_groups.insert({1024, {"0", "1", "2", "3"}});

  auto cpu_affinity =
      GetCpuAffinityFromClusters(cpu_clusters, cpu_capacity_groups);
  EXPECT_EQ(cpu_affinity, std::nullopt);
}

TEST(VMUtilTest, GetCpuAffinityFromClustersTwoClusters) {
  std::vector<std::vector<std::string>> cpu_clusters;
  std::map<int32_t, std::vector<std::string>> cpu_capacity_groups;

  cpu_clusters.push_back({"0", "1"});
  cpu_clusters.push_back({"2", "3"});

  cpu_capacity_groups.insert({1024, {"0", "1", "2", "3"}});

  auto cpu_affinity =
      GetCpuAffinityFromClusters(cpu_clusters, cpu_capacity_groups);
  ASSERT_TRUE(cpu_affinity);
  EXPECT_EQ(*cpu_affinity, "0=0,1:1=0,1:2=2,3:3=2,3");
}

TEST(VMUtilTest, GetCpuAffinityFromClustersTwoCapacityGroups) {
  std::vector<std::vector<std::string>> cpu_clusters;
  std::map<int32_t, std::vector<std::string>> cpu_capacity_groups;

  cpu_clusters.push_back({"0", "1", "2", "3"});

  cpu_capacity_groups.insert({100, {"0", "2"}});
  cpu_capacity_groups.insert({200, {"1", "3"}});

  auto cpu_affinity =
      GetCpuAffinityFromClusters(cpu_clusters, cpu_capacity_groups);
  ASSERT_TRUE(cpu_affinity);
  EXPECT_EQ(*cpu_affinity, "0=0,2:2=0,2:1=1,3:3=1,3");
}

TEST(VMUtilTest, GetCpuAffinityFromClustersBothPresent) {
  std::vector<std::vector<std::string>> cpu_clusters;
  std::map<int32_t, std::vector<std::string>> cpu_capacity_groups;

  cpu_clusters.push_back({"0", "1"});
  cpu_clusters.push_back({"2", "3"});

  cpu_capacity_groups.insert({100, {"0", "2"}});
  cpu_capacity_groups.insert({200, {"1", "3"}});

  auto cpu_affinity =
      GetCpuAffinityFromClusters(cpu_clusters, cpu_capacity_groups);
  ASSERT_TRUE(cpu_affinity);
  // Clusters take precedence over capacity groups, so this matches the
  // TwoClusters result.
  EXPECT_EQ(*cpu_affinity, "0=0,1:1=0,1:2=2,3:3=2,3");
}

// CPU0-CPU1 LITTLE cores, CPU2-CPU3 big cores
TEST(VMUtilTest, CreateArcVMAffinityTwoGroups) {
  ArcVmCPUTopology topology(4, 1);

  topology.AddCpuToCapacityGroupForTesting(0, 42);
  topology.AddCpuToCapacityGroupForTesting(1, 42);
  topology.AddCpuToCapacityGroupForTesting(2, 128);
  topology.AddCpuToCapacityGroupForTesting(3, 128);
  topology.AddCpuToPackageGroupForTesting(0, 0);
  topology.AddCpuToPackageGroupForTesting(1, 0);
  topology.AddCpuToPackageGroupForTesting(2, 1);
  topology.AddCpuToPackageGroupForTesting(3, 1);
  topology.CreateCPUAffinityForTesting();

  EXPECT_EQ(topology.NumCPUs(), 5);
  EXPECT_EQ(topology.NumRTCPUs(), 1);
  EXPECT_EQ(topology.RTCPUMask(), "4");
  EXPECT_EQ(topology.NonRTCPUMask(), "0,1,2,3");
  EXPECT_FALSE(topology.IsSymmetricCPU());
  EXPECT_EQ(topology.AffinityMask(), "0=0,1:1=0,1:4=0,1:2=2,3:3=2,3");
  EXPECT_EQ(topology.CapacityMask(), "0=42,1=42,2=128,3=128,4=42");

  auto& package = topology.PackageMask();
  ASSERT_EQ(package.size(), 2);
  EXPECT_EQ(package[0], "0,1,4");
  EXPECT_EQ(package[1], "2,3");
}

TEST(VMUtilTest, CreateArcVMAffinityOnePackage) {
  ArcVmCPUTopology topology(4, 1);

  topology.AddCpuToCapacityGroupForTesting(0, 42);
  topology.AddCpuToCapacityGroupForTesting(1, 42);
  topology.AddCpuToCapacityGroupForTesting(2, 128);
  topology.AddCpuToCapacityGroupForTesting(3, 128);
  topology.AddCpuToPackageGroupForTesting(0, 0);
  topology.AddCpuToPackageGroupForTesting(1, 0);
  topology.AddCpuToPackageGroupForTesting(2, 0);
  topology.AddCpuToPackageGroupForTesting(3, 0);
  topology.CreateCPUAffinityForTesting();

  EXPECT_EQ(topology.NumCPUs(), 5);
  EXPECT_EQ(topology.NumRTCPUs(), 1);
  EXPECT_EQ(topology.RTCPUMask(), "4");
  EXPECT_EQ(topology.NonRTCPUMask(), "0,1,2,3");
  EXPECT_EQ(topology.AffinityMask(), "0=0,1:1=0,1:4=0,1:2=2,3:3=2,3");
  EXPECT_EQ(topology.CapacityMask(), "0=42,1=42,2=128,3=128,4=42");

  auto& package = topology.PackageMask();
  ASSERT_EQ(package.size(), 1);
  EXPECT_EQ(package[0], "0,1,2,3,4");
}

TEST(VMUtilTest, CreateArcVMAffinityOnePackageOneCapacity) {
  ArcVmCPUTopology topology(4, 1);

  topology.AddCpuToCapacityGroupForTesting(0, 42);
  topology.AddCpuToCapacityGroupForTesting(1, 42);
  topology.AddCpuToCapacityGroupForTesting(2, 42);
  topology.AddCpuToCapacityGroupForTesting(3, 42);
  topology.AddCpuToPackageGroupForTesting(0, 0);
  topology.AddCpuToPackageGroupForTesting(1, 0);
  topology.AddCpuToPackageGroupForTesting(2, 0);
  topology.AddCpuToPackageGroupForTesting(3, 0);
  topology.CreateCPUAffinityForTesting();

  EXPECT_EQ(topology.NumCPUs(), 5);
  EXPECT_EQ(topology.NumRTCPUs(), 1);
  EXPECT_EQ(topology.RTCPUMask(), "4");
  EXPECT_EQ(topology.NonRTCPUMask(), "0,1,2,3");
  EXPECT_TRUE(topology.IsSymmetricCPU());
  EXPECT_EQ(topology.CapacityMask(), "0=42,1=42,2=42,3=42,4=42");

  auto& package = topology.PackageMask();
  ASSERT_EQ(package.size(), 1);
  EXPECT_EQ(package[0], "0,1,2,3,4");
}

// CPU2-CPU3 LITTLE cores, CPU0-CPU1 big cores
TEST(VMUtilTest, CreateArcVMAffinityTwoCapacityClustersReverse) {
  ArcVmCPUTopology topology(4, 1);

  topology.AddCpuToCapacityGroupForTesting(2, 42);
  topology.AddCpuToCapacityGroupForTesting(3, 42);
  topology.AddCpuToCapacityGroupForTesting(0, 128);
  topology.AddCpuToCapacityGroupForTesting(1, 128);
  topology.AddCpuToPackageGroupForTesting(0, 0);
  topology.AddCpuToPackageGroupForTesting(1, 0);
  topology.AddCpuToPackageGroupForTesting(2, 0);
  topology.AddCpuToPackageGroupForTesting(3, 0);
  topology.CreateCPUAffinityForTesting();

  EXPECT_EQ(topology.NumCPUs(), 5);
  EXPECT_EQ(topology.NumRTCPUs(), 1);
  EXPECT_EQ(topology.RTCPUMask(), "4");
  EXPECT_EQ(topology.NonRTCPUMask(), "0,1,2,3");
  EXPECT_FALSE(topology.IsSymmetricCPU());
  EXPECT_EQ(topology.AffinityMask(), "2=2,3:3=2,3:4=2,3:0=0,1:1=0,1");
  EXPECT_EQ(topology.CapacityMask(), "2=42,3=42,0=128,1=128,4=42");

  auto& package = topology.PackageMask();
  ASSERT_EQ(package.size(), 1);
  EXPECT_EQ(package[0], "0,1,2,3,4");
}

// All cores are in the same capacity group
TEST(VMUtilTest, CreateArcVMAffinityOneCapacityCluster) {
  ArcVmCPUTopology topology(4, 1);

  topology.AddCpuToCapacityGroupForTesting(0, 42);
  topology.AddCpuToCapacityGroupForTesting(1, 42);
  topology.AddCpuToCapacityGroupForTesting(2, 42);
  topology.AddCpuToCapacityGroupForTesting(3, 42);
  topology.AddCpuToPackageGroupForTesting(0, 0);
  topology.AddCpuToPackageGroupForTesting(1, 0);
  topology.AddCpuToPackageGroupForTesting(2, 0);
  topology.AddCpuToPackageGroupForTesting(3, 0);
  topology.CreateCPUAffinityForTesting();

  EXPECT_EQ(topology.NumCPUs(), 5);
  EXPECT_EQ(topology.NumRTCPUs(), 1);
  EXPECT_EQ(topology.RTCPUMask(), "4");
  EXPECT_EQ(topology.NonRTCPUMask(), "0,1,2,3");
  EXPECT_TRUE(topology.IsSymmetricCPU());
  EXPECT_EQ(topology.CapacityMask(), "0=42,1=42,2=42,3=42,4=42");

  auto& package = topology.PackageMask();
  ASSERT_EQ(package.size(), 1);
  EXPECT_EQ(package[0], "0,1,2,3,4");
}

// No RT CPU requested
TEST(VMUtilTest, CreateArcVMAffinityOneCapacityClusterNoRT) {
  ArcVmCPUTopology topology(4, 0);

  topology.AddCpuToCapacityGroupForTesting(0, 42);
  topology.AddCpuToCapacityGroupForTesting(1, 42);
  topology.AddCpuToCapacityGroupForTesting(2, 42);
  topology.AddCpuToCapacityGroupForTesting(3, 42);
  topology.AddCpuToPackageGroupForTesting(0, 0);
  topology.AddCpuToPackageGroupForTesting(1, 0);
  topology.AddCpuToPackageGroupForTesting(2, 0);
  topology.AddCpuToPackageGroupForTesting(3, 0);
  topology.CreateCPUAffinityForTesting();

  ASSERT_EQ(topology.RTCPUMask().size(), 0);
  EXPECT_EQ(topology.NumCPUs(), 4);
  EXPECT_EQ(topology.NumRTCPUs(), 0);
  EXPECT_TRUE(topology.IsSymmetricCPU());
  EXPECT_EQ(topology.CapacityMask(), "0=42,1=42,2=42,3=42");

  auto& package = topology.PackageMask();
  ASSERT_EQ(package.size(), 1);
  EXPECT_EQ(package[0], "0,1,2,3");
}

// SMP cores without capacities.
TEST(VMUtilTest, CreateArcVMAffinitySMP2Core) {
  ArcVmCPUTopology topology(2, 1);

  topology.AddCpuToCapacityGroupForTesting(0, 0);
  topology.AddCpuToCapacityGroupForTesting(1, 0);
  topology.AddCpuToPackageGroupForTesting(0, 0);
  topology.AddCpuToPackageGroupForTesting(1, 0);
  topology.CreateCPUAffinityForTesting();

  EXPECT_EQ(topology.NumCPUs(), 3);
  EXPECT_EQ(topology.NumRTCPUs(), 1);
  ASSERT_EQ(topology.RTCPUMask(), "2");
  EXPECT_EQ(topology.NonRTCPUMask(), "0,1");
  EXPECT_TRUE(topology.IsSymmetricCPU());

  auto& package = topology.PackageMask();
  ASSERT_EQ(package.size(), 1);
  EXPECT_EQ(package[0], "0,1,2");
}

TEST(VMUtilTest, CreateArcVMAffinitySMP4Core) {
  ArcVmCPUTopology topology(4, 1);

  topology.AddCpuToCapacityGroupForTesting(0, 0);
  topology.AddCpuToCapacityGroupForTesting(1, 0);
  topology.AddCpuToCapacityGroupForTesting(2, 0);
  topology.AddCpuToCapacityGroupForTesting(3, 0);
  topology.AddCpuToPackageGroupForTesting(0, 0);
  topology.AddCpuToPackageGroupForTesting(1, 0);
  topology.AddCpuToPackageGroupForTesting(2, 0);
  topology.AddCpuToPackageGroupForTesting(3, 0);
  topology.CreateCPUAffinityForTesting();

  EXPECT_EQ(topology.NumCPUs(), 5);
  EXPECT_EQ(topology.NumRTCPUs(), 1);
  ASSERT_EQ(topology.RTCPUMask(), "4");
  EXPECT_EQ(topology.NonRTCPUMask(), "0,1,2,3");
  EXPECT_TRUE(topology.IsSymmetricCPU());

  auto& package = topology.PackageMask();
  ASSERT_EQ(package.size(), 1);
  EXPECT_EQ(package[0], "0,1,2,3,4");
}

}  // namespace concierge
}  // namespace vm_tools
