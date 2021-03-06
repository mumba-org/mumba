// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MEDIA_BASE_USER_INPUT_MONITOR_H_
#define MEDIA_BASE_USER_INPUT_MONITOR_H_

#include <stddef.h>

#include <memory>

#include "base/macros.h"
#include "base/memory/read_only_shared_memory_region.h"
#include "base/memory/ref_counted.h"
#include "base/synchronization/lock.h"
#include "media/base/media_export.h"

namespace base {
class SingleThreadTaskRunner;
}  // namespace base

namespace media {

// Utility functions for correctly and atomically reading from/writing to a
// shared memory mapping containing key press count.
uint32_t MEDIA_EXPORT
ReadKeyPressMonitorCount(const base::ReadOnlySharedMemoryMapping& shmem);
void MEDIA_EXPORT
WriteKeyPressMonitorCount(const base::WritableSharedMemoryMapping& shmem,
                          uint32_t count);

// Base class for audio:: and media:: UserInputMonitor implementations.
class MEDIA_EXPORT UserInputMonitor {
 public:
  UserInputMonitor();
  virtual ~UserInputMonitor();

  // Creates a platform-specific instance of UserInputMonitorBase.
  // |io_task_runner| is the task runner for an IO thread.
  // |ui_task_runner| is the task runner for a UI thread.
  static std::unique_ptr<UserInputMonitor> Create(
      scoped_refptr<base::SingleThreadTaskRunner> io_task_runner,
      scoped_refptr<base::SingleThreadTaskRunner> ui_task_runner);

  virtual void EnableKeyPressMonitoring() = 0;
  virtual void DisableKeyPressMonitoring() = 0;

  // Returns the number of keypresses. The starting point from when it is
  // counted is not guaranteed, but consistent within the pair of calls of
  // EnableKeyPressMonitoring and DisableKeyPressMonitoring. So a caller can
  // use the difference between the values returned at two times to get the
  // number of keypresses happened within that time period, but should not make
  // any assumption on the initial value.
  virtual uint32_t GetKeyPressCount() const = 0;

 private:
  DISALLOW_COPY_AND_ASSIGN(UserInputMonitor);
};

// Monitors and notifies about keyboard events.
// Thread safe.
class MEDIA_EXPORT UserInputMonitorBase : public UserInputMonitor {
 public:
  UserInputMonitorBase();
  ~UserInputMonitorBase() override;

  // A caller must call EnableKeyPressMonitoring and
  // DisableKeyPressMonitoring in pair.
  void EnableKeyPressMonitoring() override;
  void DisableKeyPressMonitoring() override;

 private:
  virtual void StartKeyboardMonitoring() = 0;
  virtual void StopKeyboardMonitoring() = 0;

  // Aquired in EnableKeyPressMonitoring()/DisableKeyPressMonitoring(). Together
  // with |references_| updated under lock, it is used to ensure operation
  // ordering for start/stop keyboard monitoring, i.e. start is always followed
  // by stop and start is only called when keyboard monitoring is stopped.
  base::Lock lock_;
  size_t references_ = 0;

  DISALLOW_COPY_AND_ASSIGN(UserInputMonitorBase);
};

}  // namespace media

#endif  // MEDIA_BASE_USER_INPUT_MONITOR_H_
