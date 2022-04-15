// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/vm/sensor_service/sensor_data_forwarder.h"

#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include <memory>
#include <utility>
#include <vector>

#include <base/files/file_util.h>
#include <base/rand_util.h>
#include <gtest/gtest.h>

namespace arc {

namespace {

class SensorDataForwarderTest : public ::testing::Test {
 public:
  void SetUp() override {
    base::ScopedFD in_pipe_read_end, in_pipe_write_end;
    ASSERT_TRUE(base::CreatePipe(&in_pipe_read_end, &in_pipe_write_end));

    base::ScopedFD out_pipe_read_end, out_pipe_write_end;
    ASSERT_TRUE(base::CreatePipe(&out_pipe_read_end, &out_pipe_write_end));

    in_pipe_ = std::move(in_pipe_write_end);
    out_pipe_ = std::move(out_pipe_read_end);
    forwarder_ = std::make_unique<SensorDataForwarder>(
        std::move(in_pipe_read_end), std::move(out_pipe_write_end));

    ASSERT_TRUE(forwarder_->Init());
  }

  void TearDown() override {
    forwarder_ = nullptr;
    out_pipe_.reset();
    in_pipe_.reset();
  }

 protected:
  int GetPipeBufferSize() { return fcntl(in_pipe_.get(), F_GETPIPE_SZ); }

  base::ScopedFD in_pipe_, out_pipe_;
  std::unique_ptr<SensorDataForwarder> forwarder_;
};

}  // namespace

// Tests that the forwarder can stop.
TEST_F(SensorDataForwarderTest, Stop) {
  forwarder_ = nullptr;
}

// Tests that the forwarder can forward small data.
TEST_F(SensorDataForwarderTest, ForwardSmallData) {
  constexpr char kData[] = "0123456789";
  ASSERT_TRUE(base::WriteFileDescriptor(in_pipe_.get(), kData));

  char buf[sizeof(kData)] = {};
  ASSERT_TRUE(base::ReadFromFD(out_pipe_.get(), buf, strlen(kData)));

  EXPECT_EQ(0, memcmp(kData, buf, sizeof(kData))) << buf;
}

// Tests that the forwarder can forward data larger than the pipe's buffer.
TEST_F(SensorDataForwarderTest, ForwardLargeData) {
  std::vector<uint8_t> data(GetPipeBufferSize() * 2);
  base::RandBytes(data.data(), data.size());

  ASSERT_TRUE(base::WriteFileDescriptor(in_pipe_.get(), data));

  std::vector<uint8_t> buf(data.size());
  ASSERT_TRUE(base::ReadFromFD(
      out_pipe_.get(), reinterpret_cast<char*>(buf.data()), buf.size()));

  EXPECT_EQ(data, buf);
}

// Tests that the forwarder can stop while forwarding data larger than the
// pipe's buffer.
TEST_F(SensorDataForwarderTest, StopForwardingLargeData) {
  std::vector<uint8_t> data(GetPipeBufferSize() * 2);
  base::RandBytes(data.data(), data.size());

  ASSERT_TRUE(base::WriteFileDescriptor(in_pipe_.get(), data));

  // Stop the forwarder without reading the data from out_pipe_.
  forwarder_ = nullptr;

  EXPECT_FALSE(base::WriteFileDescriptor(in_pipe_.get(), data));
  EXPECT_EQ(errno, EPIPE);
}

}  // namespace arc
