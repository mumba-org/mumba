// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ARC_DATA_SNAPSHOTD_MOCK_ESC_KEY_WATCHER_H_
#define ARC_DATA_SNAPSHOTD_MOCK_ESC_KEY_WATCHER_H_

#include "arc/data-snapshotd/esc_key_watcher.h"

namespace arc {
namespace data_snapshotd {

// This is a mock EscKeyWatcher::Delegate class. It should be used for testing.
class MockEscKeyWatcherDelegate : public EscKeyWatcher::Delegate {
 public:
  MockEscKeyWatcherDelegate() = default;
  MockEscKeyWatcherDelegate(const MockEscKeyWatcherDelegate&) = delete;
  MockEscKeyWatcherDelegate& operator=(const MockEscKeyWatcherDelegate&) =
      delete;
  ~MockEscKeyWatcherDelegate() override = default;

  MOCK_METHOD(void, SendCancelSignal, (), (override));
};

// This is a mock EscKeyWatcher class. It should be used for partial testing of
// EscKeyWatcher.
class MockEscKeyWatcher : public EscKeyWatcher {
 public:
  explicit MockEscKeyWatcher(MockEscKeyWatcherDelegate* delegate)
      : EscKeyWatcher(delegate) {}

  MOCK_METHOD(bool,
              GetEpEvent,
              (int epfd, struct input_event* ev, int* index),
              (override));
  MOCK_METHOD(bool, GetValidFds, (), (override));
  MOCK_METHOD(bool, EpollCreate, (base::ScopedFD * epfd), (override));
};

// This class does nothing and should be used as a stub in tests.
class FakeEscKeyWatcher : public EscKeyWatcher {
 public:
  explicit FakeEscKeyWatcher(MockEscKeyWatcherDelegate* delegate)
      : EscKeyWatcher(delegate) {}

  bool GetEpEvent(int epfd, struct input_event* ev, int* index) override {
    return false;
  }

  bool GetValidFds() override { return false; }
  bool EpollCreate(base::ScopedFD* epfd) override { return false; }
};

}  // namespace data_snapshotd
}  // namespace arc

#endif  // ARC_DATA_SNAPSHOTD_MOCK_ESC_KEY_WATCHER_H_
