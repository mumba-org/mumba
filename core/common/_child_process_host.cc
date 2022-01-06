// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/common/child_process_host.h"

#include <limits>

#include "base/atomic_sequence_num.h"
#include "base/command_line.h"
#include "base/files/file_path.h"
#include "base/hash.h"
#include "base/logging.h"
#include "base/metrics/histogram.h"
#include "base/numerics/safe_math.h"
#include "base/path_service.h"
#include "base/process/process_metrics.h"
#include "base/rand_util.h"
#include "base/strings/stringprintf.h"
#include "base/third_party/dynamic_annotations/dynamic_annotations.h"
#include "core/common/child_process_messages.h"
#include "core/shared/common/child_process_host_delegate.h"
#include "core/common/gpu/client/gpu_memory_buffer_impl_shared_memory.h"
#include "core/common/paths.h"
#include "core/shared/common/switches.h"
#include "ipc/ipc_channel.h"
#include "ipc/ipc_logging.h"
#include "ipc/message_filter.h"
#if defined(OS_LINUX)
#include "base/linux_util.h"
#endif  // OS_LINUX

namespace common {

namespace {
 // Global atomic to generate child process unique IDs.
 base::StaticAtomicSequenceNumber g_unique_id;

 // Global atomic to generate gpu memory buffer unique IDs.
 base::StaticAtomicSequenceNumber g_next_gpu_memory_buffer_id;
}

int ChildProcessHost::kInvalidUniqueID = -1;

uint64 ChildProcessHost::kBrowserTracingProcessId =
std::numeric_limits<uint64>::max();

// static 
void ChildProcessHost::AllocateSharedMemory(
      size_t buffer_size, base::ProcessHandle child_process,
      base::SharedMemoryHandle* shared_memory_handle) {
 base::SharedMemory shared_buf;
 if (!shared_buf.CreateAnonymous(buffer_size)) {
   *shared_memory_handle = base::SharedMemory::NULLHandle();
   NOTREACHED() << "Cannot create shared memory buffer";
   return;
 }
 shared_buf.GiveToProcess(child_process, shared_memory_handle);
}

// static 
int ChildProcessHost::GenerateChildProcessUniqueId() {
 // This function must be threadsafe.
 //
 // Historically, this function returned ids started with 1, so in several
 // places in the code a value of 0 (rather than kInvalidUniqueID) was used as
 // an invalid value. So we retain those semantics.
 int id = g_unique_id.GetNext() + 1;

 CHECK_NE(0, id);
 CHECK_NE(kInvalidUniqueID, id);

 return id;
}

// static 
uint64 ChildProcessHost::ChildProcessUniqueIdToTracingProcessId(
    int child_process_id) {
  // In single process mode, all the children are hosted in the same process,
  // therefore the generated memory dump guids should not be conditioned by the
  // child process id. The clients need not be aware of SPM and the conversion
  // takes care of the SPM special case while translating child process ids to
  // tracing process ids.
  if (base::CommandLine::ForCurrentProcess()->HasSwitch(
          switches::kSingleProcess))
    return ChildProcessHost::kBrowserTracingProcessId;

  // The hash value is incremented so that the tracing id is never equal to
  // MemoryDumpManager::kInvalidTracingProcessId.
  return static_cast<uint64>(
             base::Hash(reinterpret_cast<const char*>(&child_process_id),
                        sizeof(child_process_id))) +
         1;
}

// static 
ChildProcessHost* ChildProcessHost::Create(ChildProcessHostDelegate* delegate) {
 return new ChildProcessHost(delegate);
}

// static 
base::FilePath ChildProcessHost::GetChildPath(int flags) {
 base::FilePath child_path;

 child_path = base::CommandLine::ForCurrentProcess()->GetSwitchValuePath(
     switches::kKernelSubprocessPath);

#if defined(OS_LINUX)
 // Use /proc/self/exe rather than our known binary path so updates
 // can't swap out the binary from underneath us.
 // When running under Valgrind, forking /proc/self/exe ends up forking the
 // Valgrind executable, which then crashes. However, it's almost safe to
 // assume that the updates won't happen while testing with Valgrind tools.
 if (child_path.empty() && flags & CHILD_ALLOW_SELF) //&& !RunningOnValgrind())
   child_path = base::FilePath(base::kProcSelfExe);
#endif

 // On most platforms, the child executable is the same as the current
 // executable.
 if (child_path.empty())
  PathService::Get(CHILD_PROCESS_EXE, &child_path);

#if defined(OS_MACOSX)
 DCHECK(!(flags & CHILD_NO_PIE && flags & CHILD_ALLOW_HEAP_EXECUTION));

 // If needed, choose an executable with special flags set that inform the
 // kernel to enable or disable specific optional process-wide features.
 if (flags & CHILD_NO_PIE) {
  // "NP" is "No PIE". This results in Chromium Helper NP.app or
  // Google Chrome Helper NP.app.
  child_path = TransformPathForFeature(child_path, "NP");
 } else if (flags & CHILD_ALLOW_HEAP_EXECUTION) {
  // "EH" is "Executable Heap". A non-executable heap is only available to
  // 32-bit processes on Mac OS X 10.7. Most code can and should run with a
  // non-executable heap, but the "EH" feature is provided to allow code
  // intolerant of a non-executable heap to work properly on 10.7. This
  // results in Chromium Helper EH.app or Google Chrome Helper EH.app.
  child_path = TransformPathForFeature(child_path, "EH");
 }
#endif

 return child_path;
}

ChildProcessHost::ChildProcessHost(ChildProcessHostDelegate* delegate): delegate_(delegate),
      opening_channel_(false) {

}

ChildProcessHost::~ChildProcessHost() {
 for (size_t i = 0; i < filters_.size(); ++i) {
    filters_[i]->OnChannelClosing();
    filters_[i]->OnFilterRemoved();
  }
}

void ChildProcessHost::ForceShutdown() {
 Send(new ChildProcessMsg_Shutdown());
}

std::string ChildProcessHost::CreateChannel() {
 channel_id_ = IPC::Channel::GenerateVerifiedChannelID(std::string());
 channel_ = IPC::Channel::CreateServer(channel_id_, this);
 if (!channel_->Connect())
   return std::string();

 for (size_t i = 0; i < filters_.size(); ++i)
   filters_[i]->OnFilterAdded(channel_.get());

  // Make sure these messages get sent first.
//#if defined(IPC_MESSAGE_LOG_ENABLED)
// bool enabled = IPC::Logging::GetInstance()->Enabled();
// Send(new ChildProcessMsg_SetIPCLoggingEnabled(enabled));
//#endif

 opening_channel_ = true;

 return channel_id_;
}

bool ChildProcessHost::IsChannelOpening() {
 return opening_channel_;
}

void ChildProcessHost::AddFilter(IPC::MessageFilter* filter) {
 filters_.push_back(filter);

 if (channel_)
   filter->OnFilterAdded(channel_.get());
}

#if defined(OS_POSIX)
base::ScopedFD ChildProcessHost::TakeClientFileDescriptor() {
 return channel_->TakeClientFileDescriptor();
}
#endif

bool ChildProcessHost::Send(IPC::Message* message) {
 if (!channel_) {
   delete message;
   return false;
 }
 return channel_->Send(message);
}

bool ChildProcessHost::OnMessageReceived(const IPC::Message& msg) {
#ifdef IPC_MESSAGE_LOG_ENABLED
  IPC::Logging* logger = IPC::Logging::GetInstance();
  if (msg.type() == IPC_LOGGING_ID) {
    logger->OnReceivedLoggingMessage(msg);
    return true;
  }

  if (logger->Enabled())
    logger->OnPreDispatchMessage(msg);
#endif

  bool handled = false;
  for (size_t i = 0; i < filters_.size(); ++i) {
    if (filters_[i]->OnMessageReceived(msg)) {
      handled = true;
      break;
    }
  }

  if (!handled) {
    handled = true;
    IPC_BEGIN_MESSAGE_MAP(ChildProcessHost, msg)
      IPC_MESSAGE_HANDLER(ChildProcessHostMsg_ShutdownRequest,
                          OnShutdownRequest)
     IPC_MESSAGE_HANDLER(ChildProcessHostMsg_SyncAllocateSharedMemory,
      OnAllocateSharedMemory)
     IPC_MESSAGE_HANDLER(ChildProcessHostMsg_SyncAllocateGpuMemoryBuffer,
      OnAllocateGpuMemoryBuffer)
     IPC_MESSAGE_HANDLER(ChildProcessHostMsg_DeletedGpuMemoryBuffer,
      OnDeletedGpuMemoryBuffer)
      IPC_MESSAGE_UNHANDLED(handled = false)
    IPC_END_MESSAGE_MAP()

    if (!handled)
      handled = delegate_->OnMessageReceived(msg);
  }

#ifdef IPC_MESSAGE_LOG_ENABLED
  if (logger->Enabled())
    logger->OnPostDispatchMessage(msg, channel_id_);
#endif
  return handled;
}

void ChildProcessHost::OnChannelConnected(int32 peer_pid) {
 if (!peer_process_.IsValid()) {
  peer_process_ = base::Process::OpenWithExtraPrivileges(peer_pid);
  
  if (!peer_process_.IsValid())
   peer_process_ = delegate_->GetProcess().Duplicate();
  DCHECK(peer_process_.IsValid());
 }
 
 opening_channel_ = false;
 delegate_->OnChannelConnected(peer_pid);
 
 for (size_t i = 0; i < filters_.size(); ++i)
  filters_[i]->OnChannelConnected(peer_pid);
}

void ChildProcessHost::OnChannelError() {
 opening_channel_ = false;
 delegate_->OnChannelError();

 for (size_t i = 0; i < filters_.size(); ++i)
  filters_[i]->OnChannelError();

 // This will delete host_, which will also destroy this!
 delegate_->OnChildDisconnected();
}

void ChildProcessHost::OnBadMessageReceived(const IPC::Message& message) {
 delegate_->OnBadMessageReceived(message);
}
 
void ChildProcessHost::OnShutdownRequest() {
 if (delegate_->CanShutdown())
  Send(new ChildProcessMsg_Shutdown());
}

void ChildProcessHost::OnAllocateSharedMemory(
 uint32 buffer_size,
 base::SharedMemoryHandle* handle) {
 AllocateSharedMemory(buffer_size, peer_process_.Handle(), handle);
}

void ChildProcessHost::OnAllocateGpuMemoryBuffer(
 gfx::GpuMemoryBufferId id,
 uint32 width,
 uint32 height,
 gfx::BufferFormat format,
 gfx::BufferUsage usage,
 gfx::GpuMemoryBufferHandle* handle) {
 // TODO(reveman): Add support for other types of GpuMemoryBuffers.

 // AllocateForChildProcess() will check if |width| and |height| are valid
 // and handle failure in a controlled way when not. We just need to make
 // sure |usage| is supported here.
 if (GpuMemoryBufferImplSharedMemory::IsUsageSupported(usage)) {
  *handle = GpuMemoryBufferImplSharedMemory::AllocateForChildProcess(
   id, gfx::Size(width, height), format, peer_process_.Handle());
 }
}

void ChildProcessHost::OnDeletedGpuMemoryBuffer(
 gfx::GpuMemoryBufferId id,
 const gpu::SyncToken& sync_token) {
 // Note: Nothing to do here as ownership of shared memory backed
 // GpuMemoryBuffers is passed with IPC.
}

}