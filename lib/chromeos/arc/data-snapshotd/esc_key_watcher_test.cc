// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "arc/data-snapshotd/mock_esc_key_watcher.h"

using testing::_;

namespace arc {
namespace data_snapshotd {

class EscKeyWatcherTest : public ::testing::Test {
 public:
  MockEscKeyWatcherDelegate* delegate() { return &delegate_; }
  MockEscKeyWatcher* watcher() { return &watcher_; }

 private:
  MockEscKeyWatcherDelegate delegate_;
  MockEscKeyWatcher watcher_{&delegate_};
};

TEST_F(EscKeyWatcherTest, InitFdFailure) {
  EXPECT_CALL(*watcher(), GetValidFds()).WillOnce(testing::Return(false));
  EXPECT_FALSE(watcher()->Init());
}

TEST_F(EscKeyWatcherTest, InitEpollFailure) {
  EXPECT_CALL(*watcher(), GetValidFds()).WillOnce(testing::Return(true));
  EXPECT_CALL(*watcher(), EpollCreate(_)).WillOnce(testing::Return(false));
  EXPECT_FALSE(watcher()->Init());
}

TEST_F(EscKeyWatcherTest, OnKeyEventFailure) {
  EXPECT_CALL(*watcher(), GetEpEvent(_, _, _)).WillOnce(testing::Return(false));
  watcher()->OnKeyEvent();
}

// Test that the delegate is not notified if incorrect key is pressed.
TEST_F(EscKeyWatcherTest, OnKeyEventCodeFailure) {
  struct input_event ev {
    .type = EV_KEY, .code = KEY_MAX + 1, .value = 0,
  };
  EXPECT_CALL(*watcher(), GetEpEvent(_, _, _))
      .WillOnce(
          testing::DoAll(testing::SetArgPointee<1>(ev), testing::Return(true)));
  watcher()->OnKeyEvent();
}

// Test that the delegate is not notified if no key event happens.
TEST_F(EscKeyWatcherTest, OnKeyEventTypeFailure) {
  struct input_event ev {
    .type = 0, .code = KEY_ESC, .value = 0,
  };
  EXPECT_CALL(*watcher(), GetEpEvent(_, _, _))
      .WillOnce(
          testing::DoAll(testing::SetArgPointee<1>(ev), testing::Return(true)));
  EXPECT_CALL(*delegate(), SendCancelSignal()).Times(0);
  watcher()->OnKeyEvent();
}

// Test that the delegate is not notified if other than ESC key is pressed.
TEST_F(EscKeyWatcherTest, OnKeyEventKeyFailure) {
  struct input_event ev {
    .type = EV_KEY, .code = 0, .value = 0,
  };
  EXPECT_CALL(*watcher(), GetEpEvent(_, _, _))
      .WillOnce(
          testing::DoAll(testing::SetArgPointee<1>(ev), testing::Return(true)));
  EXPECT_CALL(*delegate(), SendCancelSignal()).Times(0);
  watcher()->OnKeyEvent();
}

// Test that the delegate is notified if ESC key is pressed.
TEST_F(EscKeyWatcherTest, OnKeyEventSuccess) {
  struct input_event ev {
    .type = EV_KEY, .code = KEY_ESC, .value = 0,
  };
  EXPECT_CALL(*watcher(), GetEpEvent(_, _, _))
      .WillOnce(
          testing::DoAll(testing::SetArgPointee<1>(ev), testing::Return(true)));
  EXPECT_CALL(*delegate(), SendCancelSignal()).Times(1);
  watcher()->OnKeyEvent();
}

}  // namespace data_snapshotd
}  // namespace arc
