// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ApplicationShims.h"

#include <stdint.h>

#include "CompositorHelper.h"
#include "CompositorShims.h"
#include "CompositorStructsPrivate.h"

#include "base/macros.h"
#include "base/strings/utf_string_conversions.h"
#include "base/strings/string_number_conversions.h"
#include "base/at_exit.h"
#include "base/template_util.h"
#include "base/command_line.h"
#include "base/files/file_path.h"
#include "base/logging.h"
#include "base/i18n/icu_util.h"
#include "base/message_loop/message_loop.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/path_service.h"
#include "core/shared/common/switches.h"
#include "core/shared/common/paths.h"
#include "core/shared/application/application_thread.h"
#include "core/shared/application/application_process.h"
#include "core/shared/application/application_window_dispatcher.h"
#include "core/shared/application/blink_platform_impl.h"
#include "core/shared/application/frame_swap_message_queue.h"
#include "core/shared/application/queue_message_swap_promise.h"
#include "components/viz/common/surfaces/frame_sink_id.h"
#include "components/viz/common/surfaces/surface_id.h"
#include "cc/trees/layer_tree_host.h"
#include "cc/trees/render_frame_metadata.h"
#include "cc/trees/render_frame_metadata_observer.h"
#include "cc/trees/frame_token_allocator.h"
#include "core/shared/common/screen_info.h"
#include "core/shared/common/render_frame_metadata.mojom.h"
#include "core/shared/common/mojo_init.h"
#include "mojo/public/cpp/bindings/binding.h"
#include "third_party/blink/public/platform/scheduler/web_main_thread_scheduler.h"

#if defined(OS_LINUX)
#include "core/shared/common/common_sandbox_support_linux.h"
#include "services/service_manager/sandbox/linux/sandbox_linux.h"
#include "sandbox/linux/bpf_dsl/policy.h"
#include "sandbox/linux/services/credentials.h"
#include "sandbox/linux/syscall_broker/broker_command.h"
#include "sandbox/linux/syscall_broker/broker_file_permission.h"
#include "sandbox/linux/syscall_broker/broker_process.h"
#include "services/service_manager/embedder/set_process_title.h"
#include "services/service_manager/sandbox/linux/bpf_cros_amd_gpu_policy_linux.h"
#include "services/service_manager/sandbox/linux/bpf_cros_arm_gpu_policy_linux.h"
#include "services/service_manager/sandbox/linux/bpf_gpu_policy_linux.h"
#include "services/service_manager/sandbox/linux/sandbox_linux.h"

using sandbox::bpf_dsl::Policy;
using sandbox::syscall_broker::BrokerFilePermission;
using sandbox::syscall_broker::BrokerProcess;

#endif


namespace {

#if defined(OS_LINUX)

void AddApplicationDirectoriesAndFiles(
    const base::FilePath& root_dir,
    std::vector<BrokerFilePermission>* permissions,
    const service_manager::SandboxSeccompBPF::Options& options) {
  // if (options.accelerated_video_decode_enabled) {
  //   // Device nodes for V4L2 video decode accelerator drivers.
  //   static const base::FilePath::CharType kDevicePath[] =
  //       FILE_PATH_LITERAL("/dev/");
  //   static const base::FilePath::CharType kVideoDecPattern[] = "video-dec[0-9]";
  //   base::FileEnumerator enumerator(base::FilePath(kDevicePath), false,
  //                                   base::FileEnumerator::FILES,
  //                                   base::FilePath(kVideoDecPattern).value());
  //   for (base::FilePath name = enumerator.Next(); !name.empty();
  //        name = enumerator.Next())
  //     permissions->push_back(BrokerFilePermission::ReadWrite(name.value()));
  // }

  // if (options.accelerated_video_encode_enabled) {
  //   // Device node for V4L2 video encode accelerator drivers.
  //   static const char kDevVideoEncPath[] = "/dev/video-enc";
  //   permissions->push_back(BrokerFilePermission::ReadWrite(kDevVideoEncPath));
  // }

  // Device node for V4L2 JPEG decode accelerator drivers.
  //static const char kDevJpegDecPath[] = "/dev/jpeg-dec";
  //permissions->push_back(BrokerFilePermission::ReadWrite(kDevJpegDecPath));
  static const char kDevURandomPath[] = "/dev/urandom";
  permissions->push_back(BrokerFilePermission::ReadOnly(kDevURandomPath));
  permissions->push_back(BrokerFilePermission::ReadWriteCreateRecursive(root_dir.value() + "/"));
}

std::vector<BrokerFilePermission> FilePermissionsForApplication(
  const base::FilePath& root_dir,
  const service_manager::SandboxSeccompBPF::Options& options) {
  std::vector<BrokerFilePermission> permissions;
  AddApplicationDirectoriesAndFiles(root_dir, &permissions, options);
  return permissions;
}

bool LoadLibrariesForApplication(
    const service_manager::SandboxSeccompBPF::Options& options) {
  // if (IsChromeOS()) {
  //   if (UseV4L2Codec())
  //     LoadV4L2Libraries(options);
  //   if (IsArchitectureArm()) {
  //     LoadArmGpuLibraries();
  //     return true;
  //   }
  //   if (options.use_amd_specific_policies)
  //     return LoadAmdGpuLibraries();
  // }
  return true;
}

bool BrokerProcessPreSandboxHook(
    service_manager::SandboxLinux::Options options) {
  // Oddly enough, we call back into gpu to invoke this service manager
  // method, since it is part of the embedder component, and the service
  // mananger's sandbox component is a lower layer that can't depend on it.
  service_manager::SetProcessTitleFromCommandLine(nullptr);
  return true;
}

sandbox::syscall_broker::BrokerCommandSet CommandSetForApplication(
    const service_manager::SandboxLinux::Options& options) {
  sandbox::syscall_broker::BrokerCommandSet command_set;
  command_set.set(sandbox::syscall_broker::COMMAND_ACCESS);
  command_set.set(sandbox::syscall_broker::COMMAND_OPEN);
  command_set.set(sandbox::syscall_broker::COMMAND_STAT);
  //if (IsChromeOS() && options.use_amd_specific_policies) {
    command_set.set(sandbox::syscall_broker::COMMAND_READLINK);
  //}
  return command_set;
}


bool ApplicationProcessPreSandboxHook(const base::FilePath& root_dir, service_manager::SandboxLinux::Options options) {
  service_manager::SandboxLinux::GetInstance()->StartBrokerProcess(
      CommandSetForApplication(options), FilePermissionsForApplication(root_dir, options),
      base::BindOnce(BrokerProcessPreSandboxHook), options);

  if (!LoadLibrariesForApplication(options))
    return false;

  // TODO(tsepez): enable namspace sandbox here once crashes are understood.

  errno = 0;
  return true;
}

bool StartSandboxLinux(const base::FilePath& root_dir) {
  TRACE_EVENT0("application,startup", "Initialize sandbox");
  
  // SandboxLinux::InitializeSandbox() must always be called
  // with only one thread.
  service_manager::SandboxLinux::Options sandbox_options;
  // the launcher process (host) should already set us in a namespace sandbox
  //sandbox_options.engage_namespace_sandbox = true;
  
  //DLOG(INFO) << "application::StartSandboxLinux: InitializeSandbox() -> dir = " << root_dir;
  bool res = service_manager::SandboxLinux::GetInstance()->InitializeSandbox(
      service_manager::SandboxTypeFromCommandLine(
          *base::CommandLine::ForCurrentProcess()),
      base::BindOnce(ApplicationProcessPreSandboxHook, root_dir), sandbox_options);

  base::Process proc = base::Process::Current();
  //DLOG(INFO) << "\n\n pid = " << proc.Handle();
  CHECK(proc.Handle() == 1);
  if (!sandbox::Credentials::ChrootTo(proc.Handle(), root_dir)) {
    return false;
  }

  return res;
}
#endif  // defined(OS_LINUX)

#if defined(OS_WIN)
bool StartSandboxWindows(const sandbox::SandboxInterfaceInfo* sandbox_info) {
  TRACE_EVENT0("gpu,startup", "Lower token");

  // For Windows, if the target_services interface is not zero, the process
  // is sandboxed and we must call LowerToken() before rendering untrusted
  // content.
  sandbox::TargetServices* target_services = sandbox_info->target_services;
  if (target_services) {
    target_services->LowerToken();
    return true;
  }

  return false;
}
#endif  // defined(OS_WIN)

}  // namespace.

// Warning: Redecl

struct _SwapPromise {
  enum Type {
    kUNKNOWN = 0,
    kLATENCY = 1,
    kALWAYSDRAW = 2,
    kREPORTTIME = 2,
  };

  Type type;
  std::unique_ptr<cc::SwapPromise> handle;
 
 _SwapPromise(cc::SwapPromise* ptr): type(kUNKNOWN), handle(ptr) {}
 _SwapPromise(std::unique_ptr<cc::SwapPromise> ptr): type(kUNKNOWN), handle(std::move(ptr)) {}

};

class RenderFrameMetadataObserver
    : public cc::RenderFrameMetadataObserver,
      public common::mojom::RenderFrameMetadataObserver {
 public:
  RenderFrameMetadataObserver(
      common::mojom::RenderFrameMetadataObserverRequest request,
      common::mojom::RenderFrameMetadataObserverClientPtrInfo client_info);
  ~RenderFrameMetadataObserver() override;

  // cc::RenderFrameMetadataObserver:
  void BindToCurrentThread(
      cc::FrameTokenAllocator* frame_token_allocator) override;
  void OnRenderFrameSubmission(cc::RenderFrameMetadata metadata) override;

  // mojom::RenderFrameMetadataObserver:
  void ReportAllFrameSubmissionsForTesting(bool enabled) override;

 private:
  // When true this will notifiy |render_frame_metadata_observer_client_| of all
  // frame submissions.
  bool report_all_frame_submissions_for_testing_enabled_ = false;

  uint32_t last_frame_token_ = 0;
  base::Optional<cc::RenderFrameMetadata> last_render_frame_metadata_;

  // Not owned.
  cc::FrameTokenAllocator* frame_token_allocator_ = nullptr;

  // These are destroyed when BindToCurrentThread() is called.
  common::mojom::RenderFrameMetadataObserverRequest request_;
  common::mojom::RenderFrameMetadataObserverClientPtrInfo client_info_;

  mojo::Binding<common::mojom::RenderFrameMetadataObserver>
      render_frame_metadata_observer_binding_;
  common::mojom::RenderFrameMetadataObserverClientPtr
      render_frame_metadata_observer_client_;

  DISALLOW_COPY_AND_ASSIGN(RenderFrameMetadataObserver);
};

RenderFrameMetadataObserver::RenderFrameMetadataObserver(
    common::mojom::RenderFrameMetadataObserverRequest request,
    common::mojom::RenderFrameMetadataObserverClientPtrInfo client_info)
    : request_(std::move(request)),
      client_info_(std::move(client_info)),
      render_frame_metadata_observer_binding_(this) {}

RenderFrameMetadataObserver::~RenderFrameMetadataObserver() {}

void RenderFrameMetadataObserver::BindToCurrentThread(
    cc::FrameTokenAllocator* frame_token_allocator) {
  DCHECK(request_.is_pending());
  frame_token_allocator_ = frame_token_allocator;
  render_frame_metadata_observer_binding_.Bind(std::move(request_));
  render_frame_metadata_observer_client_.Bind(std::move(client_info_));
}

void RenderFrameMetadataObserver::OnRenderFrameSubmission(
    cc::RenderFrameMetadata metadata) {
  // By default only report metadata changes for fields which have a low
  // frequency of change. However if there are changes in high frequency
  // fields these can be reported while testing is enabled.
  bool send_metadata = false;
  if (render_frame_metadata_observer_client_) {
    if (report_all_frame_submissions_for_testing_enabled_) {
      last_frame_token_ = frame_token_allocator_->GetOrAllocateFrameToken();
      render_frame_metadata_observer_client_->OnFrameSubmissionForTesting(
          last_frame_token_);
      send_metadata = !last_render_frame_metadata_ ||
                      *last_render_frame_metadata_ != metadata;
    } else {
      send_metadata = !last_render_frame_metadata_ ||
                      cc::RenderFrameMetadata::HasAlwaysUpdateMetadataChanged(
                          *last_render_frame_metadata_, metadata);
    }
  }

  // Allways cache the full metadata, so that it can correctly be sent upon
  // ReportAllFrameSubmissionsForTesting. This must only be done after we've
  // compared the two for changes.
  last_render_frame_metadata_ = metadata;

  // If the metadata is different, updates all the observers; or the metadata is
  // generated for first time and same as the default value, update the default
  // value to all the observers.
  if (send_metadata && render_frame_metadata_observer_client_) {
    // Sending |root_scroll_offset| outside of tests would leave the browser
    // process with out of date information. It is an optional parameter
    // which we clear here.
    if (!report_all_frame_submissions_for_testing_enabled_)
      metadata.root_scroll_offset = base::nullopt;

    last_frame_token_ = frame_token_allocator_->GetOrAllocateFrameToken();
    render_frame_metadata_observer_client_->OnRenderFrameMetadataChanged(
        last_frame_token_, metadata);
  }

  // Always cache the initial frame token, so that if a test connects later on
  // it can be notified of the initial state.
  if (!last_frame_token_)
    last_frame_token_ = frame_token_allocator_->GetOrAllocateFrameToken();
}

void RenderFrameMetadataObserver::ReportAllFrameSubmissionsForTesting(
    bool enabled) {
  report_all_frame_submissions_for_testing_enabled_ = enabled;

  if (!enabled || !last_frame_token_)
    return;

  // When enabled for testing send the cached metadata.
  DCHECK(render_frame_metadata_observer_client_);
  DCHECK(last_render_frame_metadata_.has_value());
  render_frame_metadata_observer_client_->OnRenderFrameMetadataChanged(
      last_frame_token_, *last_render_frame_metadata_);
}


ApplicationInstanceRef _ApplicationInstanceCreate(
  void* instance_state,
  int argc, 
  const char** argv,
  void* window_state, 
  struct CWindowCallbacks window_callbacks,
  struct CApplicationCallbacks app_callbacks) {
  base::FilePath home_dir;
  base::CommandLine::Init(argc, argv);
  bool headless = false;

  const base::CommandLine& command_line = *base::CommandLine::ForCurrentProcess();

  // we are meant to use AtExitManager at stack scope.. but being
  // a wrapper to swift, we have no option other than heap allocate them
  
  std::unique_ptr<base::AtExitManager> at_exit(new base::AtExitManager());
  std::unique_ptr<base::MessageLoop> message_loop(new base::MessageLoop());
  base::PlatformThread::SetName("ApplicationInstanceMainThread");

  common::RegisterPathProvider();
 
  if(!base::PathService::Get(common::DIR_PROFILE, &home_dir)) {
    LOG(ERROR) << "application process fatal: failed to get the users home directory";
    return nullptr;
  }

  if (!command_line.HasSwitch(switches::kWorkspaceId)) {
   LOG(ERROR) << "application process fatal: no workspace id provided. exiting..";
   return nullptr;
  }
  
  if (command_line.HasSwitch("headless")) {
    //DLOG(INFO) << "application: -- headless mode activated --";
    headless = true;
  }

  std::string workspace_id = command_line.GetSwitchValueASCII(switches::kWorkspaceId);

  std::string uuid_string = command_line.GetSwitchValueASCII(switches::kDomainUUID);
  if (uuid_string.empty()) {
    //DLOG(ERROR) << "Application process: --" << switches::kDomainUUID << " was not set with the application uuid";
    return nullptr;
  }
  std::string url_string = command_line.GetSwitchValueASCII("url");
  if (url_string.empty()) {
    //DLOG(ERROR) << "Application process: --url was not set with the application initial url";
    return nullptr;
  }
  base::FilePath app_root = home_dir.AppendASCII(workspace_id).AppendASCII("apps").AppendASCII(uuid_string);
  bool no_sandbox = base::CommandLine::ForCurrentProcess()->HasSwitch(switches::kNoSandbox);

  if (!no_sandbox) {
#if defined(OS_LINUX)
    StartSandboxLinux(app_root);
#endif
#if defined(OS_WIN)
    // TODO: params
    StartSandboxWindows();
#endif
  }
  
  // we are not cloned as in the case of a child process of the same executable
  // here, so we dont share a couple of heap elements our launcher have
  // so we are on our own here and have to initiate a couple of
  // important/core libraries here
  // (we could move this to Process or Thread maybe)
  common::InitializeMojo();

  //std::string icu_data;
  //std::unique_ptr<base::Environment> env = base::Environment::Create();
  //env->GetVar("ICU_DATA", &icu_data);
  //DLOG(INFO) << "ICU_DATA = " << icu_data;

  base::i18n::InitializeICU();

  application::ApplicationProcess* process = new application::ApplicationProcess(
    std::move(at_exit));
  std::unique_ptr<blink::scheduler::WebMainThreadScheduler>
      main_thread_scheduler(blink::scheduler::WebMainThreadScheduler::Create(
          base::Optional<base::Time>()));
  
  int application_window_id = -1; 
  DCHECK(base::StringToInt(command_line.GetSwitchValueASCII("application-window-id"), &application_window_id));
  int application_process_id = -1;
  DCHECK(base::StringToInt(command_line.GetSwitchValueASCII("application-process-id"), &application_process_id));
  
  application::ApplicationThread* thread = new application::ApplicationThread(
    instance_state,
    application_process_id,
    application_window_id,
    url_string,
    std::move(message_loop),
    std::move(main_thread_scheduler),
    std::move(window_callbacks), 
    window_state,
    std::move(app_callbacks),
    headless);

  process->set_main_thread(thread);
  
  return process;
}

void _ApplicationInstanceDestroy(ApplicationInstanceRef instance) {
  delete reinterpret_cast<application::ApplicationProcess *>(instance);
}

void _ApplicationInstanceRunLoop(ApplicationInstanceRef instance) {
  base::RunLoop runloop;
  application::ApplicationProcess* process = reinterpret_cast<application::ApplicationProcess *>(instance);
  // make the at_exit manager early allocated on init to destroy when
  // we get out of scope here when the runloop breaks
  std::unique_ptr<base::AtExitManager> at_exit = process->ReleaseAtExitManager();
  
  // save the runloop quit closure on process for later
  process->BindQuitClosure(runloop.QuitClosure());
  
  runloop.Run();
  
  //DLOG(INFO) << "_ApplicationInstanceRunLoop: exiting..";
  //reinterpret_cast<application::ApplicationProcess *>(instance)->main_thread()->message_loop()->Run();
}

void _ApplicationInstanceExitLoop(ApplicationInstanceRef instance) {
  application::ApplicationProcess* process = reinterpret_cast<application::ApplicationProcess *>(instance);
  if (process->is_running()) {
    process->Exit();
  }
}

ApplicationInstanceRef _ApplicationInstanceGetCurrent() {
  application::ApplicationProcess* process = application::ApplicationProcess::current();
  return process;
}

int _ApplicationInstanceIsHeadless(ApplicationInstanceRef instance) {
  return reinterpret_cast<application::ApplicationProcess *>(instance)->main_thread()->headless() ? 1 : 0;
}

int32_t _ApplicationInstanceGetApplicationProcessHostId(ApplicationInstanceRef instance) {
  return reinterpret_cast<application::ApplicationProcess *>(instance)->main_thread()->application_process_id();
}

int32_t _ApplicationInstanceGetApplicationWindowHostId(ApplicationInstanceRef instance) {
  return reinterpret_cast<application::ApplicationProcess *>(instance)->main_thread()->application_window_id();
}

int32_t _ApplicationInstanceGetRoutingId(ApplicationInstanceRef instance) {
  return reinterpret_cast<application::ApplicationProcess *>(instance)->main_thread()->routing_id();
}

char* _ApplicationInstanceGetInitialUrl(ApplicationInstanceRef instance, int* size) {
  //DLOG(INFO) << "_ApplicationInstanceGetInitialUrl";
  char* result = nullptr;
  const std::string& initial_url = reinterpret_cast<application::ApplicationProcess *>(instance)->main_thread()->initial_url();
  result = static_cast<char *>(malloc(initial_url.size()));
  *size = initial_url.size();
  memcpy(result, initial_url.data(), initial_url.size());
  return result;
}

void _ApplicationInstanceAddRefProcess(ApplicationInstanceRef instance) {
  reinterpret_cast<application::ApplicationProcess *>(instance)->AddRefProcess(); 
}

void _ApplicationInstanceReleaseProcess(ApplicationInstanceRef instance) {
  reinterpret_cast<application::ApplicationProcess *>(instance)->ReleaseProcess(); 
}

void _ApplicationInstanceSetColorSpace(
  ApplicationInstanceRef instance,
  uint8_t primaries,
  uint8_t transfer,
  uint8_t matrix,
  uint8_t range,
  int64_t icc_profile) {
  gfx::ColorSpace color_space {
    static_cast<gfx::ColorSpace::PrimaryID>(primaries), 
    static_cast<gfx::ColorSpace::TransferID>(transfer), 
    static_cast<gfx::ColorSpace::MatrixID>(matrix), 
    static_cast<gfx::ColorSpace::RangeID>(range),
    icc_profile
  };
  reinterpret_cast<application::ApplicationProcess *>(instance)->main_thread()->SetRenderingColorSpace(color_space);
}

void _ApplicationInstanceWindowCreated(ApplicationInstanceRef instance) {
  reinterpret_cast<application::ApplicationProcess *>(instance)->main_thread()->WindowCreated();
}

void _ApplicationInstanceWindowHidden(ApplicationInstanceRef instance) {
  reinterpret_cast<application::ApplicationProcess *>(instance)->main_thread()->WindowHidden(); 
}

void _ApplicationInstanceWindowRestored(ApplicationInstanceRef instance) {
  reinterpret_cast<application::ApplicationProcess *>(instance)->main_thread()->WindowRestored();
}

void _ApplicationInstanceRequestNewLayerTreeFrameSink(ApplicationInstanceRef instance,
  LayerTreeHostRef layer_tree_host,
  void* state,
  void(*cb)(void*, void*)) {
  common::mojom::RenderFrameMetadataObserverPtr ptr;
  common::mojom::RenderFrameMetadataObserverRequest request = mojo::MakeRequest(&ptr);
  common::mojom::RenderFrameMetadataObserverClientPtrInfo client_info;
  common::mojom::RenderFrameMetadataObserverClientRequest client_request =
      mojo::MakeRequest(&client_info);

  auto render_frame_metadata_observer =
      std::make_unique<RenderFrameMetadataObserver>(std::move(request),
                                                    std::move(client_info));
  
  reinterpret_cast<_LayerTreeHost *>(layer_tree_host)->handle->SetRenderFrameObserver(
      std::move(render_frame_metadata_observer));
  
  application::ApplicationThread* app_thread = reinterpret_cast<application::ApplicationProcess *>(instance)->main_thread();
  app_thread->RequestNewLayerTreeFrameSink(
      app_thread->application_window_id(),
      app_thread->frame_swap_message_queue(),
      GURL(),
      base::Bind(&application::ApplicationThread::OnRequestNewLayerTreeFrameSink, 
        base::Unretained(app_thread),
        base::Unretained(state),
        base::Unretained(cb)),
      std::move(client_request), 
      std::move(ptr));
}

SwapPromiseRef _ApplicationInstanceQueueVisualStateResponse(ApplicationInstanceRef reference, int32_t source_frame_number, uint64_t id) {
  application::ApplicationThread* app_thread = reinterpret_cast<application::ApplicationProcess *>(reference)->main_thread();
  std::unique_ptr<cc::SwapPromise> promise = app_thread->QueueVisualStateResponse(source_frame_number, id);
  if (promise) {
    return new _SwapPromise(std::move(promise));
  }
  return nullptr;
}

void _ApplicationInstanceSendWindowCreatedAck(ApplicationInstanceRef instance) {
  application::ApplicationThread* thread = reinterpret_cast<application::ApplicationProcess *>(instance)->main_thread();
  thread->window_dispatcher()->WindowCreatedAck();
}

WindowRef _WindowCreate(ApplicationInstanceRef instance) {
  application::ApplicationThread* thread = reinterpret_cast<application::ApplicationProcess *>(instance)->main_thread();
  return thread->window_dispatcher();
}

void _WindowDestroy(WindowRef state) {
  //DLOG(INFO) << "_WindowDestroy";
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
  application::ApplicationThread* thread = dispatcher->main_thread();
  thread->DestroyWindowDispatcher(dispatcher); 
}

void _WindowSetTextureLayerForCanvas(WindowRef state, const char* target, LayerRef texture_layer) {
  application::ApplicationThread* thread = reinterpret_cast<application::ApplicationWindowDispatcher *>(state)->main_thread();
  application::BlinkPlatformImpl* platform = thread->blink_platform();
  //DLOG(INFO) << "\n\nblink_platform_impl_ = " << platform;
  DCHECK(platform);
  _Layer* layer_shim = reinterpret_cast<_Layer *>(texture_layer);
  DCHECK(layer_shim->type() == 3); // assert its a texture layer
  cc::TextureLayer* texture = static_cast<cc::TextureLayer*>(layer_shim->layer()); 
  //DLOG(INFO) << "\n\ncc::TextureLayer = " << texture;
  DCHECK(texture);
  _LayerClientImpl* client = layer_shim->layer_client();
  DCHECK(client);
  platform->SetExternalTextureLayerForCanvas(blink::WebString::FromUTF8(target), texture, client);
}

void _WindowLayerTreeFrameSinkInitialized(WindowRef state) {
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
  dispatcher->LayerTreeFrameSinkInitialized();
}

void _WindowApplicationProcessGone(WindowRef state, int status, int exit_code) {
  //DLOG(INFO) << "_WindowApplicationProcessGone";
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
  dispatcher->ApplicationProcessGone(status, exit_code);
}

void _WindowHittestData(WindowRef state, /* surface_id */ uint32_t sid_client_id, uint32_t sid_sink_id, uint32_t sid_parent, uint32_t sid_child, uint64_t sid_token_high, uint64_t sid_token_low /* end surface_id*/, int ignored_for_hittest) {
  //DLOG(INFO) << "_WindowHittestData";
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state); 
  viz::LocalSurfaceId local_surface_id(sid_parent, sid_child, base::UnguessableToken::Deserialize(sid_token_high, sid_token_low));
  viz::FrameSinkId frame_sink_id(sid_client_id, sid_sink_id);
  viz::SurfaceId surface_id(frame_sink_id, local_surface_id);
  dispatcher->HittestData(surface_id, ignored_for_hittest != 0);
}

void _WindowClose(WindowRef state) {
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
  dispatcher->Close();
}

void _WindowUpdateScreenRectsAck(WindowRef state) {
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
  dispatcher->UpdateScreenRectsAck();
}

void _WindowRequestMove(WindowRef state, int px, int py, int pw, int ph) {
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
  dispatcher->RequestMove(gfx::Rect(px, py, pw, ph));
}

void _WindowSetTooltipText(WindowRef state, const char* text, int text_direction) {
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
  dispatcher->SetTooltipText(base::ASCIIToUTF16(text), static_cast<base::i18n::TextDirection>(text_direction));
}

void _WindowResizeOrRepaintACK(WindowRef state, int view_width, int view_height, int flags, int optional_local_surface_is_set, /* surface_id */ uint32_t sid_parent, uint32_t sid_child, uint64_t sid_token_high, uint64_t sid_token_low /* end surface_id*/) {
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
  gfx::Size view_size(view_width, view_height);
  if (optional_local_surface_is_set) {
    viz::LocalSurfaceId local_surface_id(sid_parent, sid_child, base::UnguessableToken::Deserialize(sid_token_high, sid_token_low));
    dispatcher->ResizeOrRepaintACK(view_size, flags, local_surface_id);
  } else {
    dispatcher->ResizeOrRepaintACK(view_size, flags, base::Optional<viz::LocalSurfaceId>());
  }
}

void _WindowSetCursor(WindowRef state, int type, int hotspot_x, int hotspot_y, float scale, ImageRef custom_data) {
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
  common::CursorInfo cursor_info;
  cursor_info.type = static_cast<blink::WebCursorInfo::Type>(type);
  if (custom_data != nullptr) {
    cursor_info.custom_image = *reinterpret_cast<SkBitmap *>(custom_data);
  }
  cursor_info.hotspot = gfx::Point(hotspot_x, hotspot_y);
  cursor_info.image_scale_factor = scale;
  common::WebCursor web_cursor;
  web_cursor.InitFromCursorInfo(cursor_info);
  dispatcher->SetCursor(web_cursor);
}

void _WindowUpdateState(WindowRef state) {
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
  common::mojom::PageStatePtr page_state = common::mojom::PageState::New();
  page_state->top = common::mojom::FrameState::New();
  page_state->top->http_body = common::mojom::HttpBody::New();
  dispatcher->UpdateState(std::move(page_state));
}

void _WindowAutoscrollStart(WindowRef state, float px, float py) {
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
  dispatcher->AutoscrollStart(gfx::PointF(px, py));
}

void _WindowAutoscrollFling(WindowRef state, float vx, float vy) {
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
  dispatcher->AutoscrollFling(gfx::Vector2dF(vx, vy));
}

void _WindowAutoscrollEnd(WindowRef state) {
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
  dispatcher->AutoscrollEnd();
}

void _WindowTextInputStateChanged(WindowRef state,
  int type, 
  int mode, 
  int flags,
  const char* value, 
  int selection_start,
  int selection_end,
  int composition_start,
  int composition_end,
  int can_compose_inline,
  int show_ime_if_needed, 
  int reply_to_request) {
  
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
  
  common::TextInputState text_input;
  text_input.type = static_cast<ui::TextInputType>(type); 
  text_input.mode = static_cast<ui::TextInputMode>(mode);
  text_input.flags = flags;
  text_input.value = std::string(value);
  text_input.selection_start = selection_start;
  text_input.selection_end = selection_end;
  text_input.composition_start = composition_start;
  text_input.composition_end = composition_end;
  text_input.can_compose_inline = can_compose_inline != 0;
  text_input.show_ime_if_needed = show_ime_if_needed != 0;
  text_input.reply_to_request = reply_to_request != 0;

  dispatcher->TextInputStateChanged(text_input);
}

void _WindowLockMouse(WindowRef state, int user_gesture, int privileged) {
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
  dispatcher->LockMouse(user_gesture != 0, privileged != 0);
}

void _WindowUnlockMouse(WindowRef state) {
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
  dispatcher->UnlockMouse();
}

void _WindowSelectionBoundsChanged(WindowRef state, 
  int ax, int ay, int aw, int ah,
  int anchor_text_dir,
  int fx, int fy, int fw, int fh,
  int focus_text_dir,
  int is_anchor_first) {
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
  
  common::mojom::SelectionBoundsParamsPtr sel_params = common::mojom::SelectionBoundsParams::New();
  
  sel_params->anchor_rect = gfx::Rect(ax, ay, aw, ah);
  sel_params->anchor_dir = static_cast<base::i18n::TextDirection>(anchor_text_dir);
  sel_params->focus_rect = gfx::Rect(fx, fy, fw, fh);
  sel_params->focus_dir = static_cast<base::i18n::TextDirection>(focus_text_dir);
  sel_params->is_anchor_first = is_anchor_first != 0;
  
  dispatcher->SelectionBoundsChanged(std::move(sel_params));
}

void _WindowFocusedNodeTouched(WindowRef state, int editable) {
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
  dispatcher->FocusedNodeTouched(editable != 0);
}

void _WindowStartDragging(WindowRef state, 
  int view_id,
  const char* url,
  const char* url_title,
  const char* download_metadata,
  int ops_allowed, 
  BitmapRef image, 
  int offset_x, int offset_y, 
  int ev_loc_x, int ev_loc_y,
  int event_source) {
  
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
  
  common::DropData drop_data;
  
  drop_data.view_id = view_id;
  drop_data.did_originate_from_renderer = true;
  if (url)
    drop_data.url = GURL(url);
  if (url_title)
    drop_data.url_title = base::ASCIIToUTF16(url_title);
  if (download_metadata)
    drop_data.download_metadata = base::ASCIIToUTF16(download_metadata);

  // TODO: implement

  //std::vector<ui::FileInfo> filenames;
  //std::vector<base::string16> file_mime_types;
  //base::string16 filesystem_id;
  //std::vector<FileSystemFileInfo> file_system_files;
  //base::NullableString16 text;
  //base::NullableString16 html;
  //GURL html_base_url;
  //std::string file_contents;
  //GURL file_contents_source_url;
  //base::FilePath::StringType file_contents_filename_extension;
  //std::string file_contents_content_disposition;
  //std::unordered_map<base::string16, base::string16> custom_data;
  //int key_modifiers;

  SkBitmap bitmap = image ? *reinterpret_cast<SkBitmap *>(image) : SkBitmap();
  
  common::DragEventSourceInfo event_info;
  event_info.event_location = gfx::Point(ev_loc_x, ev_loc_y);
  event_info.event_source = static_cast<ui::DragDropTypes::DragEventSource>(event_source);

  dispatcher->StartDragging(drop_data, static_cast<blink::WebDragOperation>(ops_allowed), bitmap, gfx::Vector2d(offset_x, offset_y), event_info);
}

void _WindowUpdateDragCursor(WindowRef state, int drag_operation) {
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
  dispatcher->UpdateDragCursor(static_cast<blink::WebDragOperation>(drag_operation));
}

void _WindowFrameSwapMessagesReceived(WindowRef state, uint32_t frame_token) {
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
  dispatcher->FrameSwapMessagesReceived(frame_token);
}

void _WindowShowWindow(WindowRef state, int route_id, int x, int y, int w, int h) {
  //DLOG(INFO) << "_WindowShowWindow";
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
  dispatcher->ShowWindow(route_id, gfx::Rect(x, y, w, h));
}

void _WindowShowFullscreenWindow(WindowRef state, int route_id) {
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
  dispatcher->ShowFullscreenWindow(route_id);
}

void _WindowUpdateTargetURL(WindowRef state, const char* url) {
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
  dispatcher->UpdateTargetURL(url);
}

void _WindowDocumentAvailableInMainFrame(WindowRef state, int uses_temporary_zoom_level) {
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
  dispatcher->DocumentAvailableInMainFrame(uses_temporary_zoom_level != 0);
}

void _WindowDidContentsPreferredSizeChange(WindowRef state, int x, int y) {
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
  dispatcher->DidContentsPreferredSizeChange(gfx::Size(x, y));
}

void _WindowRouteCloseEvent(WindowRef state) {
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
  dispatcher->RouteCloseEvent();
}

void _WindowTakeFocus(WindowRef state, int reverse) {
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
  dispatcher->TakeFocus(reverse != 0);
}

void _WindowClosePageACK(WindowRef state) {
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
  dispatcher->ClosePageACK();
}

void _WindowFocus(WindowRef state) {
  //DLOG(INFO) << "_WindowFocus";
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
  dispatcher->Focus();
}

void _WindowCreateNewWindowOnHost(
  WindowRef state, 
  int user_gesture,
  int window_container_type,
  const char* window_name,
  int opener_suppressed,
  int window_disposition,
  const char* target_url,
  int window_id,
  int swapped_out,
  int hidden,
  int never_visible,
  int enable_auto_resize,
  int sw,
  int sh,
  float zoom_level,
  float window_features_x,
  float window_features_y,
  float window_features_w,
  float window_features_h) {

  //DLOG(INFO) << "_WindowCreateNewWindowOnHost";  

  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
 
  common::mojom::CreateNewWindowParamsPtr params = common::mojom::CreateNewWindowParams::New();
  params->user_gesture = user_gesture != 0;
  params->window_container_type = static_cast<common::mojom::WindowContainerType>(window_container_type);
  params->window_name = std::string(window_name);
  params->opener_suppressed = opener_suppressed != 0;
  params->disposition = static_cast<WindowOpenDisposition>(window_disposition);
  params->target_url = GURL(target_url);
  //params->features = std::move(features);
  params->window_id = window_id;
  // params.renderer_preferences
  // params.web_preferences
  params->swapped_out = swapped_out != 0;
  params->hidden = hidden != 0;
  params->never_visible = never_visible != 0;
  params->enable_auto_resize = enable_auto_resize != 0;
  // params.min_size;
  // params.max_size;
  params->initial_size.new_size = gfx::Size(sw, sh);
  params->page_zoom_level = zoom_level;

  blink::mojom::WindowFeaturesPtr features = blink::mojom::WindowFeatures::New();

  if (window_features_x != -1.f) {
    features->has_x = true;
    features->x = window_features_x;
  } else {
    features->has_x = false;
  }
  if (window_features_y != -1.f) {
    features->has_y = true;
    features->y = window_features_y;
  } else {
    features->has_y = false;
  }
  if (window_features_w != -1.f) {
    features->has_width = true;
    features->width = window_features_w;
  } else {
    features->has_width = false;
  }
  if (window_features_h != -1.f) {
    features->has_height = true;
    features->height = window_features_h;
  } else {
    features->has_height = false;
  }

  params->features = std::move(features);

  dispatcher->CreateNewWindowOnHost(std::move(params));
}

void _WindowDidCommitProvisionalLoad(WindowRef state, 
  int http_status_code, 
  int url_is_unreachable, 
  const char* method) {
  //DLOG(INFO) << "_WindowDidCommitProvisionalLoad";
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
  // TODO: really implement
  common::mojom::DidCommitProvisionalLoadParamsPtr params = common::mojom::DidCommitProvisionalLoadParams::New();
  params->http_status_code = http_status_code;
  params->url_is_unreachable = url_is_unreachable != 0;
  params->method = std::string(method);
  params->page_state = common::mojom::PageState::New();
  params->page_state->top = common::mojom::FrameState::New();
  params->page_state->top->http_body = common::mojom::HttpBody::New();
  params->nav_entry_id = -1;
  params->item_sequence_number = -1;
  params->document_sequence_number = -1;
  params->url = GURL();
  params->base_url = GURL();
  params->referrer = common::Referrer();
  //params->redirects
  params->should_update_history = false;
  params->contents_mime_type = std::string();
  params->socket_address = std::string();
  params->did_create_new_entry = false;
  params->should_replace_current_entry = false;
  params->post_id = -1;
  params->original_request_url = GURL();
  params->is_overriding_user_agent = false;
  params->history_list_was_cleared = false;
  params->origin = GURL();
  params->ui_timestamp = base::TimeTicks();
  params->has_potentially_trustworthy_unique_origin = false;
  params->content_source_id = 0;

  dispatcher->DidCommitProvisionalLoad(std::move(params), service_manager::mojom::InterfaceProviderRequest());
}

void _WindowDidCommitSameDocumentNavigation(WindowRef state) {
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
  common::mojom::DidCommitProvisionalLoadParamsPtr params = common::mojom::DidCommitProvisionalLoadParams::New();
  dispatcher->DidCommitSameDocumentNavigation(std::move(params));
}

void _WindowBeginNavigation(WindowRef state, const char* url) {
  //DLOG(INFO) << "_WindowBeginNavigation";
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
  dispatcher->BeginNavigation(std::string(url));
}

void _WindowDidChangeName(WindowRef state, const char* name) {
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
  dispatcher->DidChangeName(name, name);
}

void _WindowDidChangeOpener(WindowRef state, int opener) {
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
  dispatcher->DidChangeOpener(opener);
}

void _WindowDetachFrame(WindowRef state, int id) {
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
  dispatcher->DetachFrame(id);
}

void _WindowFrameSizeChanged(WindowRef state, int x, int y) {
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
  dispatcher->FrameSizeChanged(gfx::Size(x, y));
}

void _WindowOnUpdatePictureInPictureSurfaceId(WindowRef state, /* surface_id */ uint32_t sid_client_id, uint32_t sid_sink_id, uint32_t sid_parent, uint32_t sid_child, uint64_t sid_token_high, uint64_t sid_token_low /* end surface_id*/, int sx, int sy) {
  viz::LocalSurfaceId local_surface_id(sid_parent, sid_child, base::UnguessableToken::Deserialize(sid_token_high, sid_token_low));
  viz::FrameSinkId frame_sink_id(sid_client_id, sid_sink_id);
  viz::SurfaceId surface_id(frame_sink_id, local_surface_id);
  
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
  dispatcher->OnUpdatePictureInPictureSurfaceId(surface_id, gfx::Size(sx, sy));
}

void _WindowOnExitPictureInPicture(WindowRef state) {
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
  dispatcher->OnExitPictureInPicture();
}

void _WindowOnSwappedOut(WindowRef state) {
  //DLOG(INFO) << "_WindowOnSwappedOut";
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
  dispatcher->OnSwappedOut();
}

void _WindowCancelTouchTimeout(WindowRef state) {
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
  dispatcher->CancelTouchTimeout();
}

void _WindowSetWhiteListedTouchAction(
    WindowRef state,
    int touch_action,
    uint32_t unique_touch_event_id,
    int input_event_state) {
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
  dispatcher->SetWhiteListedTouchAction(
    static_cast<cc::TouchAction>(touch_action), 
    unique_touch_event_id, 
    static_cast<common::InputEventAckState>(input_event_state));
}

void _WindowDidOverscroll(
  WindowRef state,
  float accumulated_overscroll_x,
  float accumulated_overscroll_y,
  float latest_overscroll_delta_x,
  float latest_overscroll_delta_y,
  float current_fling_velocity_x,
  float current_fling_velocity_y,
  float causal_event_viewport_point_x,
  float causal_event_viewport_point_y,
  int overscroll_behavior_x,
  int overscroll_behavior_y) {
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
 
  ui::DidOverscrollParams did_overscroll_params;

  did_overscroll_params.accumulated_overscroll = gfx::Vector2dF(accumulated_overscroll_x, accumulated_overscroll_y);
  did_overscroll_params.latest_overscroll_delta = gfx::Vector2dF(latest_overscroll_delta_x, latest_overscroll_delta_y);
  did_overscroll_params.current_fling_velocity = gfx::Vector2dF(current_fling_velocity_x, current_fling_velocity_y);
  did_overscroll_params.causal_event_viewport_point = gfx::PointF(causal_event_viewport_point_x, causal_event_viewport_point_y);
  did_overscroll_params.overscroll_behavior = cc::OverscrollBehavior(
      static_cast<cc::OverscrollBehavior::OverscrollBehaviorType>(overscroll_behavior_x),
      static_cast<cc::OverscrollBehavior::OverscrollBehaviorType>(overscroll_behavior_y));

  dispatcher->DidOverscroll(did_overscroll_params);
}

void _WindowDidStopFlinging(WindowRef state) {
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
  dispatcher->DidStopFlinging();
}

void _WindowDidStartScrollingViewport(WindowRef state) {
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
  dispatcher->DidStartScrollingViewport();
}

void _WindowImeCancelComposition(WindowRef state) {
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
  dispatcher->ImeCancelComposition();
}

void _WindowImeCompositionRangeChanged(
  WindowRef state,
  uint32_t range_start, 
  uint32_t range_end,
  int* bounds_x,
  int* bounds_y,
  int* bounds_w,
  int* bounds_h,
  int bounds_count) {
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
    
  std::vector<gfx::Rect> bounds;
  for (int i = 0; i < bounds_count; ++i) {
    gfx::Rect rect(bounds_x[i], bounds_y[i], bounds_w[i], bounds_h[i]);
    bounds.push_back(std::move(rect));
  }

  dispatcher->ImeCompositionRangeChanged(
    gfx::Range(range_start, range_end),
    std::move(bounds));
}

void _WindowHasTouchEventHandlers(WindowRef state, int has_handlers) {
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
  dispatcher->HasTouchEventHandlers(has_handlers != 0);
}

void _WindowSelectWordAroundCaretAck(WindowRef state, int did_select, int start, int end) {
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
  dispatcher->SelectWordAroundCaretAck(did_select != 0, start, end);
}

void _WindowSwapOutAck(WindowRef state) {
  //DLOG(INFO) << "_WindowSwapOutAck";
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
  dispatcher->SwapOutAck();
}

// void _WindowDetach(WindowRef state) {
//   application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
//   dispatcher->Detach();
// }

void _WindowFrameFocused(WindowRef state){
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
  dispatcher->FrameFocused();
}

void _WindowDidStartProvisionalLoad(WindowRef state, const char* url, int64_t navigation_start) {
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
  dispatcher->DidStartProvisionalLoad(GURL(url), std::vector<GURL>(), base::TimeTicks::FromInternalValue(navigation_start));
}

void _WindowDidFailProvisionalLoadWithError(WindowRef state, int32_t error_code, const uint16_t* error_description, const char* url) {
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
  dispatcher->DidFailProvisionalLoadWithError(error_code, error_description ? base::string16(error_description) : base::string16(), GURL(url));
}

void _WindowDidFinishDocumentLoad(WindowRef state) {
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
  dispatcher->DidFinishDocumentLoad();
}

void _WindowDidFailLoadWithError(WindowRef state, const char* url, int32_t error_code, const uint16_t* error_description) {
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
  dispatcher->DidFailLoadWithError(GURL(url), error_code, base::string16(error_description));
}

void _WindowDidStartLoading(WindowRef state, int to_different_document) {
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
  dispatcher->DidStartLoading(to_different_document != 0);
}

void _WindowSendDidStopLoading(WindowRef state) {
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
  dispatcher->SendDidStopLoading();
}

void _WindowDidChangeLoadProgress(WindowRef state, double load_progress) {
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
  dispatcher->DidChangeLoadProgress(load_progress);
}

void _WindowOpenURL(WindowRef state, const char* url) {
  //DLOG(INFO) << "_WindowOpenURL";
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
  dispatcher->OpenURL(GURL(url));
}

void _WindowDidFinishLoad(WindowRef state, const char* url) {
  //DLOG(INFO) << "_WindowDidFinishLoad";
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
  dispatcher->DidFinishLoad(GURL(url));
}

void _WindowDocumentOnLoadCompleted(WindowRef state, int64_t timestamp) {
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
  dispatcher->DocumentOnLoadCompleted(base::TimeTicks::FromInternalValue(timestamp));
}

void _WindowDidAccessInitialDocument(WindowRef state) {
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
  dispatcher->DidAccessInitialDocument();
}

void _WindowUpdateTitle(WindowRef state, const int8_t* title, int title_len, int text_direction) {
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
  base::string16 title_utf16;
  if (title) {
    base::UTF8ToUTF16(reinterpret_cast<const char*>(title), title_len, &title_utf16);
  }
  dispatcher->UpdateTitle(title_utf16, static_cast<base::i18n::TextDirection>(text_direction));
}

void _WindowBeforeUnloadAck(WindowRef state, int proceed, int64_t start_ticks, int64_t end_ticks) {
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
  dispatcher->BeforeUnloadAck(
    proceed != 0, 
    base::TimeTicks::FromInternalValue(start_ticks), 
    base::TimeTicks::FromInternalValue(end_ticks));
}

void _WindowSynchronizeVisualProperties(
   WindowRef state,
   uint32_t surface_id_client_id,
   uint32_t surface_id_sink_id, 
   uint32_t surface_id_parent_sequence_number,
   uint32_t surface_id_child_sequence_number,
   uint64_t surface_id_token_high, 
   uint64_t surface_id_token_low,
   float screen_info_device_scale_factor,
   //colorspace
   int screen_info_primaries,
   int screen_info_transfer,
   int screen_info_matrix,
   int screen_info_range,
   int64_t screen_info_icc_profile,
   uint32_t screen_info_depth,
   uint32_t screen_info_depth_per_component,
   int screen_info_is_monochrome,
   int screen_info_rect_x,
   int screen_info_rect_y,
   int screen_info_rect_w,
   int screen_info_rect_h,
   int screen_info_available_rect_x,
   int screen_info_available_rect_y,
   int screen_info_available_rect_w,
   int screen_info_available_rect_h,
   int screen_info_orientation_type,
   uint16_t screen_info_orientation_angle,
   int auto_resize_enabled, 
   int min_size_for_auto_resize_w, 
   int min_size_for_auto_resize_h, 
   int max_size_for_auto_resize_w, 
   int max_size_for_auto_resize_h,
   int screen_space_rect_x, 
   int screen_space_rect_y,
   int screen_space_rect_w,
   int screen_space_rect_h,   
   int local_frame_size_w,
   int local_frame_size_h,
   int32_t capture_sequence_number) {
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
  
  common::ScreenInfo screen_info;
  screen_info.color_space = gfx::ColorSpace {
    static_cast<gfx::ColorSpace::PrimaryID>(screen_info_primaries), 
    static_cast<gfx::ColorSpace::TransferID>(screen_info_transfer), 
    static_cast<gfx::ColorSpace::MatrixID>(screen_info_matrix), 
    static_cast<gfx::ColorSpace::RangeID>(screen_info_range),
    screen_info_icc_profile 
  };
  screen_info.is_monochrome = screen_info_is_monochrome != 0;
  screen_info.rect = gfx::Rect(screen_info_rect_x, screen_info_rect_y, screen_info_rect_w, screen_info_rect_h);
  screen_info.available_rect = gfx::Rect(screen_info_available_rect_x, screen_info_available_rect_y, screen_info_available_rect_w, screen_info_available_rect_h);
  screen_info.orientation_type = static_cast<common::ScreenOrientationValues>(screen_info_orientation_type);
  screen_info.orientation_angle = screen_info_orientation_angle;

  dispatcher->SynchronizeVisualProperties(
    viz::SurfaceId(
      viz::FrameSinkId(surface_id_client_id, surface_id_sink_id),
      viz::LocalSurfaceId(
        surface_id_parent_sequence_number,
        surface_id_child_sequence_number,
        base::UnguessableToken::Deserialize(surface_id_token_high, surface_id_token_low))),
    screen_info,
    auto_resize_enabled != 0,
    gfx::Size(min_size_for_auto_resize_w, min_size_for_auto_resize_h),
    gfx::Size(max_size_for_auto_resize_w, max_size_for_auto_resize_h),
    gfx::Rect(screen_space_rect_x, screen_space_rect_y, screen_space_rect_w, screen_space_rect_h),
    gfx::Size(local_frame_size_w, local_frame_size_h),
    capture_sequence_number);
}

void _WindowUpdateViewportIntersection(WindowRef state, int intersection_x, int intersection_y, int intersection_w, int intersection_h, int visible_x, int visible_y, int visible_w, int visible_h) {
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
  dispatcher->UpdateViewportIntersection(gfx::Rect(intersection_x, intersection_y, intersection_w, intersection_h), gfx::Rect(visible_x, visible_y, visible_w, visible_h));
}

void _WindowVisibilityChanged(WindowRef state, int visible) {
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
  dispatcher->VisibilityChanged(visible != 0);
}

void _WindowSendUpdateRenderThrottlingStatus(WindowRef state, int is_throttled, int subtree_throttled) {
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
  dispatcher->SendUpdateRenderThrottlingStatus(is_throttled != 0, subtree_throttled != 0);
}

void _WindowSetHasReceivedUserGesture(WindowRef state) {
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
  dispatcher->SetHasReceivedUserGesture();
}

void _WindowSetHasReceivedUserGestureBeforeNavigation(WindowRef state, int value) {
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
  dispatcher->SetHasReceivedUserGestureBeforeNavigation(value != 0);
}

void _WindowContextMenu(WindowRef state) {
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
  dispatcher->ContextMenu();
}

void _WindowSelectionChanged(WindowRef state, const uint16_t* selection, uint32_t offset, int range_start, int range_end) {
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
  dispatcher->SelectionChanged(base::string16(selection), offset, gfx::Range(range_start, range_end));
}

void _WindowVisualStateResponse(WindowRef state, uint64_t id) {
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
  dispatcher->VisualStateResponse(id);
}

void _WindowEnterFullscreen(WindowRef state) {
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
  dispatcher->EnterFullscreen();
}

void _WindowExitFullscreen(WindowRef state) {
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
  dispatcher->ExitFullscreen();
}

void _WindowSendDispatchLoad(WindowRef state) {
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
  dispatcher->SendDispatchLoad();
}

void _WindowSendCheckCompleted(WindowRef state) {
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
  dispatcher->SendCheckCompleted();
}

void _WindowUpdateFaviconURL(WindowRef state, const char** favicons_url, int favicon_count) {
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
  std::vector<GURL> urls;
  for (int i = 0; i < favicon_count; i++) {
    urls.push_back(GURL(favicons_url[i]));
  }
  dispatcher->UpdateFaviconURL(urls);
}

void _WindowScrollRectToVisibleInParentFrame(WindowRef state, int rect_x, int rect_y, int rect_w, int rect_h) {
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
  dispatcher->ScrollRectToVisibleInParentFrame(gfx::Rect(rect_x, rect_y, rect_w, rect_h));
}

void _WindowFrameDidCallFocus(WindowRef state) {
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
  dispatcher->FrameDidCallFocus();
}

void _WindowTextSurroundingSelectionResponse(
  WindowRef state,
  const uint16_t* content,
  uint32_t start_offset, 
  uint32_t end_offset) {
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
  dispatcher->TextSurroundingSelectionResponse(base::string16(content), start_offset, end_offset);
}

void _WindowCloseAck(WindowRef state) {
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
  dispatcher->CloseAck(); 
}

void _WindowSendOnMediaDestroyed(WindowRef state, int delegate_id) {
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
  dispatcher->OnMediaDestroyed(delegate_id);
}

void _WindowSendOnMediaPaused(WindowRef state, int delegate_id, int reached_end_of_stream) {
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
  dispatcher->OnMediaPaused(delegate_id, reached_end_of_stream);  
}

void _WindowSendOnMediaPlaying(WindowRef state, int delegate_id, 
  int has_video,
  int has_audio,
  int is_remote,
  int content_type) {
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
  dispatcher->OnMediaPlaying(delegate_id, has_video, has_audio, is_remote, content_type);
}

void _WindowSendOnMediaMutedStatusChanged(WindowRef state, int delegate_id, int muted) {
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
  dispatcher->OnMediaMutedStatusChanged(delegate_id, muted);
}

void _WindowSendOnMediaEffectivelyFullscreenChanged(WindowRef state, int delegate_id, int fullscreen_status) {
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
  dispatcher->OnMediaEffectivelyFullscreenChanged(delegate_id, fullscreen_status);
}

void _WindowSendOnMediaSizeChanged(WindowRef state, int delegate_id, int sw, int sh) {
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
  dispatcher->OnMediaSizeChanged(delegate_id, sw, sh);  
}

void _WindowSendOnPictureInPictureSourceChanged(WindowRef state, int delegate_id) {
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
  dispatcher->OnPictureInPictureSourceChanged(delegate_id);
}

void _WindowSendOnPictureInPictureModeEnded(WindowRef state, int delegate_id) {
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
  dispatcher->OnPictureInPictureModeEnded(delegate_id); 
}

void _WindowOnWebFrameCreated(WindowRef state, WebFrameRef frame, int is_main) {
  application::ApplicationWindowDispatcher* dispatcher = reinterpret_cast<application::ApplicationWindowDispatcher *>(state);
  dispatcher->OnWebFrameCreated(reinterpret_cast<blink::WebLocalFrame*>(frame), is_main != 0); 
}
