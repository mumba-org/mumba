// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_CONCIERGE_MANATEE_MEMORY_SERVICE_H_
#define VM_TOOLS_CONCIERGE_MANATEE_MEMORY_SERVICE_H_

#include <map>
#include <memory>
#include <utility>
#include <vector>

#include <base/files/scoped_file.h>
#include <base/files/file_descriptor_watcher_posix.h>
#include <base/threading/thread.h>

#include "vm_tools/concierge/balloon_policy.h"
#include "vm_tools/concierge/vm_interface.h"

namespace vm_tools {
namespace concierge {

using TaggedBalloonStats = std::vector<std::pair<VmMemoryId, BalloonStats>>;
using TaggedMemoryMiBDeltas = std::vector<std::pair<VmMemoryId, int64_t>>;

// Class responsible for communicating with the ManaTEE memory service, to
// manage the memory allocation between the various VMs.
class ManateeMemoryService {
 public:
  static std::unique_ptr<ManateeMemoryService> Create(
      base::ScopedFD mms_socket);
  ~ManateeMemoryService() = default;

  // Get balloon stats for the specified ids.
  void GetBalloonStats(std::vector<VmMemoryId> ids,
                       base::OnceCallback<void(TaggedBalloonStats)> stats_cb);

  // Rebalance memory according to the requested deltas.
  //
  // For each VM specified by a VmMemoryId, modify its memory allocation
  // by the corresponding delta.
  //
  // |rebalance_cb| is invoked with the argument specifying whether
  // the specified deltas were fully applied. Note that the deltas
  // may be partially applied even if the result is false.
  void RebalanceMemory(TaggedMemoryMiBDeltas deltas,
                       base::OnceCallback<void(bool)> rebalance_cb);

  // Launch a new VM whose memory size is |mem_size_mb|.
  //
  // |start_vm_cb| will be invoked only if the manatee memory service can
  // reserve enough memory for the new VM. The caller should start the new VM
  // using the given VmMemoryId.
  //
  // |result_cb| will be invoked with the argument specifying whether or not
  // the VM was successfully launched. This is always invoked. Note that this
  // can be invoked even if |start_vm_cb| is invoked and succeeds.
  //
  // |stop_vm_cb| will be invoked before |result_cb| if an error occurs during
  // startup after |start_vm_cb| has been invoked successfully. The callback
  // must stop the VM and remove it via RemoveVm.
  void LaunchVm(int64_t mem_size_mb,
                base::OnceCallback<bool(VmMemoryId id)> start_vm_cb,
                base::OnceCallback<void(void)> stop_vm_cb,
                base::OnceCallback<void(bool)> result_cb);

  // Cleans up manatee memory service state associated with the VM |id|.
  void RemoveVm(VmMemoryId id);

 private:
  explicit ManateeMemoryService(base::ScopedFD mms_socket);
  ManateeMemoryService(const ManateeMemoryService&) = delete;
  ManateeMemoryService& operator=(const ManateeMemoryService&) = delete;

  bool Init();

  TaggedBalloonStats GetBalloonStatsOnThread(std::vector<VmMemoryId> ids);
  bool RebalanceMemoryOnThread(TaggedMemoryMiBDeltas deltas,
                               int64_t reserve_delta);
  bool LaunchVmOnThread(int64_t mem_size_mb,
                        base::OnceCallback<bool(VmMemoryId)> start_vm_cb,
                        base::OnceCallback<void(void)> stop_vm_cb,
                        scoped_refptr<base::SequencedTaskRunner> cb_runner);
  bool RebalanceForNewVmOnThread(int64_t init_mem_size, int64_t mem_size);
  void ResetReservedMemoryOnThread(int64_t old_reserves);
  void RemoveVmOnThread(VmMemoryId id);

  // A worker thread on which to communicate with ManaTEE memory service. Some
  // operations can take time, and we don't want to block the main thread as
  // doing so could at the very least introduce a delay to shutting down
  // concierge via SIGTERM.
  base::Thread mms_thread_{"mms thread"};

  // Put the socket after the thread so that it gets closed before the thread
  // is join'ed. That will interrupt the thread if it is waiting, to ensure
  // that it exists in a timely manner and doesn't block the dtor.
  base::ScopedFD mms_socket_;

  base::WeakPtrFactory<ManateeMemoryService> weak_ptr_factory_;
};

}  // namespace concierge
}  // namespace vm_tools

#endif  // VM_TOOLS_CONCIERGE_MANATEE_MEMORY_SERVICE_H_
