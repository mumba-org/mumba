// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ARC_VM_FORWARD_PSTORE_SERVICE_H_
#define ARC_VM_FORWARD_PSTORE_SERVICE_H_

#include <memory>
#include <string>

#include <base/callback_forward.h>
#include <base/files/scoped_file.h>
#include <base/files/file_descriptor_watcher_posix.h>
#include <base/memory/scoped_refptr.h>
#include <base/memory/weak_ptr.h>
#include <base/timer/timer.h>
#include <brillo/files/safe_fd.h>
#include <dbus/bus.h>
#include <dbus/message.h>

namespace arc {

class Service {
 public:
  explicit Service(base::Closure quit_closure);
  Service(const Service&) = delete;
  Service& operator=(const Service&) = delete;
  ~Service();

  void Start();

 private:
  void OnDbusSignalConnected(const std::string& interface_name,
                             const std::string& signal_name,
                             bool is_connected);

  void HandleSigterm();

  void OnVmIdChangedSignal(dbus::Signal* signal);
  void OnVmStoppedSignal(dbus::Signal* signal);

  void ForwardPstore(const std::string& owner_id);
  bool ForwardContents(const std::string& owner_id);
  void CopyPstoreToSourcePath(const std::string& owner_id);

  scoped_refptr<dbus::Bus> bus_;
  brillo::SafeFD root_fd_;
  brillo::SafeFD pstore_fd_;
  brillo::SafeFD dest_fd_;
  base::ScopedFD signal_fd_;
  std::unique_ptr<base::FileDescriptorWatcher::Controller> watcher_;
  base::Closure quit_closure_;
  base::RepeatingTimer timer_;
  base::WeakPtrFactory<Service> weak_ptr_factory_;
};

}  // namespace arc

#endif  // ARC_VM_FORWARD_PSTORE_SERVICE_H_
