// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ARC_DATA_SNAPSHOTD_ESC_KEY_WATCHER_H_
#define ARC_DATA_SNAPSHOTD_ESC_KEY_WATCHER_H_

#include <memory>
#include <vector>

#include <linux/input.h>

#include <base/files/file_descriptor_watcher_posix.h>
#include <base/files/scoped_file.h>

namespace arc {
namespace data_snapshotd {

// This class watches for ESC key presses and notifies its Delegate.
// TODO(pbond): fix to be using KeyReader library once available.
class EscKeyWatcher {
 public:
  class Delegate {
   public:
    virtual ~Delegate() = default;
    // This method is called when ESC key is pressed by user. It means the
    // ongoing flow must be cancelled.
    virtual void SendCancelSignal() = 0;
  };

  explicit EscKeyWatcher(Delegate* delegate);
  EscKeyWatcher(const EscKeyWatcher&) = delete;
  EscKeyWatcher& operator=(const EscKeyWatcher&) = delete;
  virtual ~EscKeyWatcher();

  // Initializes the |epfd_| and sets the callback. Listens for input ESC key
  // presses. Returns false on error.
  bool Init();
  // Get epoll event using GetEpEvent. If the event is an ESC key event, it
  // calls the Delegate::SendCancelSignal function to cancel the flow.
  void OnKeyEvent();

 private:
  // These methods are made virtual for partial testing.
  // Creates the epoll and gets event data. Sets epoll file descriptor and on
  // returns true on success.
  virtual bool EpollCreate(base::ScopedFD* epfd);
  // Checks all the valid files under kDevInputEvent, stores the valid
  // keyboard devices to |fds_|.
  // Returns false if there are no available file descriptors.
  virtual bool GetValidFds();
  // Waits for a valid key event and reads it into the input event struct. Sets
  // fd index and returns true on success.
  virtual bool GetEpEvent(int epfd, struct input_event* ev, int* index);

  Delegate* delegate_;

  // Stores open event connections.
  std::vector<base::ScopedFD> fds_;
  // Stores epoll file descriptor.
  base::ScopedFD epfd_;

  // Watches the epoll file descriptor and calls OnKeyEvent.
  std::unique_ptr<base::FileDescriptorWatcher::Controller> watcher_;
};

}  // namespace data_snapshotd
}  // namespace arc

#endif  // ARC_DATA_SNAPSHOTD_ESC_KEY_WATCHER_H_
