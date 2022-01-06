// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/child_process_launcher_helper.h"

#include "base/macros.h"
#include "base/uuid.h"
#include "base/command_line.h"
#include "base/metrics/histogram_macros.h"
#include "base/no_destructor.h"
#include "base/single_thread_task_runner.h"
#include "base/threading/thread_restrictions.h"
#include "base/task_scheduler/lazy_task_runner.h"
#include "base/task_scheduler/post_task.h"
#include "base/task_scheduler/single_thread_task_runner_thread_mode.h"
#include "base/task_scheduler/task_traits.h"
#include "core/host/child_process_launcher.h"
#include "core/host/child_process_launcher_utils.h"
#include "core/shared/common/switches.h"
#include "core/common/sandboxed_process_launcher_delegate.h"
#include "mojo/edk/embedder/platform_channel_pair.h"
#include "mojo/edk/embedder/named_platform_handle_utils.h"
#include "mojo/edk/embedder/named_platform_handle.h"

#if defined(OS_ANDROID)
#include "core/host/android/launcher_thread.h"
#endif

namespace host {

static base::LazySingleThreadTaskRunner launcher_task_runner =
      LAZY_SINGLE_THREAD_TASK_RUNNER_INITIALIZER(
          base::TaskTraits({base::MayBlock(), base::TaskPriority::USER_BLOCKING,
                            base::TaskShutdownBehavior::BLOCK_SHUTDOWN}),
          base::SingleThreadTaskRunnerThreadMode::DEDICATED);  

namespace internal {

namespace {


void RecordHistogramsOnLauncherThread(base::TimeDelta launch_time) {
  DCHECK(CurrentlyOnProcessLauncherTaskRunner());
  // Log the launch time, separating out the first one (which will likely be
  // slower due to the rest of the host initializing at the same time).
  static bool done_first_launch = false;
  if (done_first_launch) {
    UMA_HISTOGRAM_TIMES("MPArch.ChildProcessLaunchSubsequent", launch_time);
  } else {
    UMA_HISTOGRAM_TIMES("MPArch.ChildProcessLaunchFirst", launch_time);
    done_first_launch = true;
  }
}

}  // namespace

ChildProcessLauncherHelper::Process::Process(Process&& other)
    : process(std::move(other.process))
#if BUILDFLAG(USE_ZYGOTE_HANDLE)
      ,
      zygote(other.zygote)
#endif
{
}

ChildProcessLauncherHelper::Process&
ChildProcessLauncherHelper::Process::Process::operator=(
    ChildProcessLauncherHelper::Process&& other) {
  DCHECK_NE(this, &other);
  process = std::move(other.process);
#if BUILDFLAG(USE_ZYGOTE_HANDLE)
  zygote = other.zygote;
#endif
  return *this;
}

ChildProcessLauncherHelper::ChildProcessLauncherHelper(
    int child_process_id,
    HostThread::ID client_thread_id,
    std::unique_ptr<base::CommandLine> command_line,
    std::unique_ptr<common::SandboxedProcessLauncherDelegate> delegate,
    const base::WeakPtr<ChildProcessLauncher>& child_process_launcher,
    bool terminate_on_shutdown,
    std::unique_ptr<mojo::edk::OutgoingBrokerClientInvitation>
        broker_client_invitation,
    const mojo::edk::ProcessErrorCallback& process_error_callback)
    : child_process_id_(child_process_id),
      client_thread_id_(client_thread_id),
      command_line_(std::move(command_line)),
      delegate_(std::move(delegate)),
      child_process_launcher_(child_process_launcher),
      terminate_on_shutdown_(terminate_on_shutdown),
      broker_client_invitation_(std::move(broker_client_invitation)),
      process_error_callback_(process_error_callback) {
      }

ChildProcessLauncherHelper::~ChildProcessLauncherHelper() {
}

void ChildProcessLauncherHelper::StartLaunchOnClientThread(bool named_pipe) {
  DCHECK_CURRENTLY_ON(client_thread_id_);

  BeforeLaunchOnClientThread();

  mojo_server_handle_ = CreateServerPlatformHandle(named_pipe);
  if (!mojo_server_handle_.is_valid()) {
    mojo::edk::PlatformChannelPair channel_pair;
    mojo_server_handle_ = channel_pair.PassServerHandle();
    mojo_client_handle_ = channel_pair.PassClientHandle();
  }

  GetProcessLauncherTaskRunner()->PostTask(
      FROM_HERE,
      base::BindOnce(&ChildProcessLauncherHelper::LaunchOnLauncherThread,
                     this,
                     named_pipe));
}

void ChildProcessLauncherHelper::LaunchOnLauncherThread(bool named_pipe) {
  DCHECK(CurrentlyOnProcessLauncherTaskRunner());
 
  begin_launch_time_ = base::TimeTicks::Now();

  std::unique_ptr<FileMappedForLaunch> files_to_register;
  if (!named_pipe) { 
    files_to_register = GetFilesToMap(); 
  }

  bool is_synchronous_launch = true;
  int launch_result = LAUNCH_RESULT_FAILURE;
  base::LaunchOptions options;

  Process process;
  if (BeforeLaunchOnLauncherThread(named_pipe, *files_to_register, &options)) {
    process =
        LaunchProcessOnLauncherThread(options, std::move(files_to_register),
                                      &is_synchronous_launch, &launch_result);

    AfterLaunchOnLauncherThread(process, options);
  }

  if (is_synchronous_launch) {
    PostLaunchOnLauncherThread(std::move(process), launch_result);
  }
}

void ChildProcessLauncherHelper::PostLaunchOnLauncherThread(
    ChildProcessLauncherHelper::Process process,
    int launch_result) {
  // Release the client handle now that the process has been started (the pipe
  // may not signal when the process dies otherwise and we would not detect the
  // child process died).
  mojo_client_handle_.reset();

  if (process.process.IsValid()) {
    RecordHistogramsOnLauncherThread(base::TimeTicks::Now() -
                                     begin_launch_time_);
  }

  // Take ownership of the broker client invitation here so it's destroyed when
  // we go out of scope regardless of the outcome below.
  std::unique_ptr<mojo::edk::OutgoingBrokerClientInvitation> invitation =
      std::move(broker_client_invitation_);
  if (process.process.IsValid()) {
    // Set up Mojo IPC to the new process.
    DCHECK(invitation);
    invitation->Send(
        process.process.Handle(),
        mojo::edk::ConnectionParams(mojo::edk::TransportProtocol::kLegacy,
                                    std::move(mojo_server_handle_)),
        process_error_callback_);
  }

  HostThread::PostTask(
      client_thread_id_, FROM_HERE,
      base::BindOnce(&ChildProcessLauncherHelper::PostLaunchOnClientThread,
                     this, std::move(process), launch_result));
}

void ChildProcessLauncherHelper::PostLaunchOnClientThread(
    ChildProcessLauncherHelper::Process process,
    int error_code) {
  if (child_process_launcher_) {
    child_process_launcher_->Notify(std::move(process), error_code);
  } else if (process.process.IsValid() && terminate_on_shutdown_) {
    // Client is gone, terminate the process.
    ForceNormalProcessTerminationAsync(std::move(process));
  }
}

std::string ChildProcessLauncherHelper::GetProcessType() {
  if (command_line()->HasSwitch(switches::kGpuProcess)) {
    return "gpu";
  } else if (command_line()->HasSwitch(switches::kDomainProcess)) {
    return "domain";
  } else if (command_line()->HasSwitch(switches::kHostProcess)) {
    return "host";
  }
  //NOTREACHED();
  return "host";
  //return command_line()->GetSwitchValueASCII(switches::kProcessType);
}

// static
void ChildProcessLauncherHelper::ForceNormalProcessTerminationAsync(
    ChildProcessLauncherHelper::Process process) {
  if (CurrentlyOnProcessLauncherTaskRunner()) {
    ForceNormalProcessTerminationSync(std::move(process));
    return;
  }
  // On Posix, EnsureProcessTerminated can lead to 2 seconds of sleep!
  // So don't do this on the UI/IO threads.
  GetProcessLauncherTaskRunner()->PostTask(
      FROM_HERE,
      base::BindOnce(
          &ChildProcessLauncherHelper::ForceNormalProcessTerminationSync,
          std::move(process)));
}

mojo::ScopedPlatformHandle ChildProcessLauncherHelper::CreateServerPlatformHandle(bool named_pipe) {
  base::ScopedAllowBlockingForTesting allow_block;
  mojo::ScopedPlatformHandle platform_channel;
  if (named_pipe) {
    //std::string channel_name = "socket/";
    std::string channel_name = "/tmp/";
    channel_name.append(command_line_->GetSwitchValueASCII("uuid"));
    mojo::edk::NamedPlatformHandle named_handle(channel_name);
    platform_channel = mojo::edk::CreateServerHandle(named_handle);
  }
  if (!platform_channel.is_valid()) {
    return PrepareMojoPipeHandlesOnClientThread();
  }
  return platform_channel;
}

}  // namespace internal

//static
base::SingleThreadTaskRunner* GetProcessLauncherTaskRunner() {
#if defined(OS_ANDROID)
  // Android specializes Launcher thread so it is accessible in java.
  // Note Android never does clean shutdown, so shutdown use-after-free
  // concerns are not a problem in practice.
  // This process launcher thread will use the Java-side process-launching
  // thread, instead of creating its own separate thread on C++ side. Note
  // that means this thread will not be joined on shutdown, and may cause
  // use-after-free if anything tries to access objects deleted by
  // AtExitManager, such as non-leaky LazyInstance.
  static base::NoDestructor<scoped_refptr<base::SingleThreadTaskRunner>>
      launcher_task_runner(
          android::LauncherThread::GetMessageLoop()->task_runner());
  return (*launcher_task_runner).get();
#else   // defined(OS_ANDROID)
  // TODO(http://crbug.com/820200): Investigate whether we could use
  // SequencedTaskRunner on platforms other than Windows.
  // static base::LazySingleThreadTaskRunner launcher_task_runner =
  //     LAZY_SINGLE_THREAD_TASK_RUNNER_INITIALIZER(
  //         base::TaskTraits({base::MayBlock(), base::TaskPriority::USER_BLOCKING,
  //                           base::TaskShutdownBehavior::BLOCK_SHUTDOWN}),
  //         base::SingleThreadTaskRunnerThreadMode::DEDICATED);
  return launcher_task_runner.Get().get();
#endif  // defined(OS_ANDROID)
}

// The code on top is not working for us, so we are using this for now..
// Should be temporary til we fix that
// base::SingleThreadTaskRunner* GetProcessLauncherTaskRunner() {
//   return HostThread::GetTaskRunnerForThread(HostThread::PROCESS_LAUNCHER).get();
// }

// static
bool CurrentlyOnProcessLauncherTaskRunner() {
  return GetProcessLauncherTaskRunner()->RunsTasksInCurrentSequence();
}

}  // namespace host
