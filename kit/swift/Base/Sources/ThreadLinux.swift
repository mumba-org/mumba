// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/// TODO: We will disable it for now, but add it later

// fileprivate let cgroupDirectory: String = "/sys/fs/cgroup"

// internal func threadPriorityToCgroupDirectory(cgroupFilepath: FilePath,
//                                               priority: ThreadPriority) -> FilePath {
//   switch priority {
//     case .normal:
//       return cgroupFilepath;
//     case .background:
//       return cgroupFilepath.append("non-urgent")
//     case .display:
//     case .realtimeAudio:
//       return cgroupFilepath.append("urgent")
//   }
//   assert(false)
//   return FilePath()
// }

// internal func setThreadCgroup(threadId: PlatformThreadId,
//                               cgroupDirectory: FilePath) {
//   let tasksFilepath = cgroupDirectory.append("tasks")
//   let tid: String = intToString(threadId)
//   let bytesWritten = writeFile(tasksFilepath, tid, tid.count)
//   if bytesWritten != tid.count {
//     print("Failed to add \(tid) to \(tasksFilepath)")
//   }
// }

// internal func setThreadCgroupForThreadPriority(threadId: PlatformThreadId,
//                                                cgroupFilepath: FilePath,
//                                                priority: ThreadPriority) {
//   // Append "mumba" suffix.
//   let cgroupDirectory: FilePath = threadPriorityToCgroupDirectory(cgroupFilepath.append("mumba"), priority)
//   // Silently ignore request if cgroup directory doesn't exist.
//   if !directoryExists(cgroupDirectory) {
//     return
//   }

//   setThreadCgroup(threadId, cgroupDirectory)
// }

internal func setThreadCgroupsForThreadPriority(threadId: PlatformThreadId,
                                                priority: ThreadPriority) {
  // FilePath cgroup_filepath(cgroupDirectory)
  // setThreadCgroupForThreadPriority(
  //     threadId, cgroupFilepath.append("cpuset"), priority)
  // setThreadCgroupForThreadPriority(
  //     threadId, cgroupFilepath.append("schedtune"),
  //     priority)
}