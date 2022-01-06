// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file. 

#include "ProcessMainRunner.h"
#include "shell_crash_reporter_client.h"

#include "base/at_exit.h"
#include "base/allocator/allocator_check.h"
#include "base/allocator/allocator_extension.h"
#include "base/allocator/buildflags.h"
#include "base/command_line.h"
#include "base/debug/debugger.h"
#include "base/files/file_path.h"
#include "base/lazy_instance.h"
#include "base/logging.h"
#include "base/path_service.h"
#include "base/process/launch.h"
#include "base/process/memory.h"
#include "base/process/process_handle.h"
#include "base/base_switches.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "core/shared/common/mojo_init.h"
#include "core/common/main_params.h"
#include "core/shared/common/switches.h"
#include "core/shared/common/client.h"
#include "core/common/sandbox_init.h"
#include "core/common/zygote_buildflags.h"
#include "core/domain/domain_main.h"
#include "core/host/host_main.h"
#include "core/host/host_client.h"
#include "core/utility/chrome_content_utility_client.h"
#include "core/gpu/content_gpu_client_impl.h"
#include "components/tracing/common/trace_startup.h"
#include "components/crash/core/common/crash_key.h"
#include "components/crash/content/app/crashpad.h"
#include "ui/base/resource/resource_bundle.h"
#include "ui/base/ui_base_paths.h"
#include "ui/base/ui_base_switches.h"
#include "services/service_manager/embedder/switches.h"
#include "services/service_manager/sandbox/sandbox_type.h"
#include "services/service_manager/sandbox/switches.h"
#include "media/base/media.h"
#include "media/media_buildflags.h"
#if defined(USE_TCMALLOC)
#include "third_party/tcmalloc/chromium/src/gperftools/tcmalloc.h"
#include "third_party/tcmalloc/chromium/src/gperftools/malloc_extension.h"
#endif

#if defined(OS_POSIX)
#include <signal.h>

#include "base/file_descriptor_store.h"
#include "base/posix/global_descriptors.h"
#include "core/shared/common/content_descriptors.h"

#if !defined(OS_MACOSX)
#include "core/common/zygote_fork_delegate_linux.h"
#endif
#if !defined(OS_MACOSX) && !defined(OS_ANDROID)
#include "core/zygote/zygote_main.h"
#include "sandbox/linux/services/libc_interceptor.h"
#endif

#endif  // OS_POSIX

#if defined(OS_WIN)
#include "ui/display/win/dpi.h"
#endif

#if defined(OS_LINUX)
#include "base/native_library.h"
#include "base/rand_util.h"
#include "core/common/font_config_ipc_linux.h"
#include "core/shared/common/common_sandbox_support_linux.h"
#include "components/crash/content/app/breakpad_linux.h"
#include "third_party/blink/public/platform/web_font_render_style.h"
#include "third_party/boringssl/src/include/openssl/crypto.h"
#include "third_party/boringssl/src/include/openssl/rand.h"
#include "third_party/skia/include/ports/SkFontConfigInterface.h"
#include "third_party/skia/include/ports/SkFontMgr.h"
#include "third_party/skia/include/ports/SkFontMgr_android.h"
#if BUILDFLAG(ENABLE_WEBRTC)
#include "third_party/webrtc_overrides/init_webrtc.h"  // nogncheck
#endif
#endif

#if BUILDFLAG(USE_ZYGOTE_HANDLE)
#include "core/host/sandbox_host_linux.h"
#include "core/host/zygote_host/zygote_communication_linux.h"
#include "core/host/zygote_host/zygote_host_impl_linux.h"
#include "core/shared/common/common_sandbox_support_linux.h"
#include "core/common/zygote_handle.h"
#include "media/base/media_switches.h"
#endif

using base::CommandLine;

namespace gpu {
int GpuMain(const common::MainParams& parameters);  
}
namespace utility {
int UtilityMain(const common::MainParams& parameters);
}

base::LazyInstance<host::HostClient>::DestructorAtExit
 g_host_client = LAZY_INSTANCE_INITIALIZER;

base::LazyInstance<gpu::ContentGpuClientImpl>::DestructorAtExit
 g_gpu_client = LAZY_INSTANCE_INITIALIZER;

base::LazyInstance<utility::ChromeContentUtilityClient>::DestructorAtExit
 g_utility_client = LAZY_INSTANCE_INITIALIZER;

#if !defined(OS_FUCHSIA)
base::LazyInstance<HostCrashReporterClient>::Leaky
    g_host_crash_client = LAZY_INSTANCE_INITIALIZER;
#endif

//base::LazyInstance<shell::ShellClient>
// g_shell_client = LAZY_INSTANCE_INITIALIZER;
//
//base::LazyInstance<application::ApplicationClient>
// g_application_client = LAZY_INSTANCE_INITIALIZER;

class ClientInitializer {
public:
  static void Set(const std::string& process_type,
   ProcessMainRunner* runner) {
   common::Client* client = common::GetClient();
   if (process_type.empty()) {
    if (runner)
     client->host_client_ = runner->CreateHostClient();
    //if (!content_client->browser_)
    // content_client->browser_ = &g_empty_content_browser_client.Get();
   }

   if (process_type == switches::kUtilityProcess) {
     if (runner)
      client->utility_client_ = runner->CreateUtilityClient();
   }

   if (process_type == switches::kGpuProcess) {
     if (runner)
      client->gpu_client_ = runner->CreateGpuClient();
   }


   //if (process_type == switches::kShellProcess) {
   // if (runner)
   //  client->shell_client_ = runner->CreateShellClient();
   // //if (!content_client->renderer_)
   // //content_client->renderer_ = &g_empty_content_renderer_client.Get();
   //}

   //if (process_type == switches::kApplicationProcess) {
   // if (runner)
   //  client->application_client_ = runner->CreateApplicationClient();
   //}
  }
 };

#if BUILDFLAG(USE_ZYGOTE_HANDLE)
pid_t LaunchZygoteHelper(base::CommandLine* cmd_line,
                         base::ScopedFD* control_fd) {
  // Append any switches from the browser process that need to be forwarded on
  // to the zygote/renderers.
  static const char* const kForwardSwitches[] = {
     // switches::kAndroidFontsPath, 
     // switches::kClearKeyCdmPathForTesting,
      switches::kEnableLogging,  // Support, e.g., --enable-logging=stderr.
      // Need to tell the zygote that it is headless so that we don't try to use
      // the wrong type of main delegate.
      //switches::kHeadless,
      // Zygote process needs to know what resources to have loaded when it
      // becomes a renderer process.
      //switches::kForceDeviceScaleFactor, switches::kLoggingLevel,
      //switches::kPpapiInProcess, switches::kRegisterPepperPlugins, switches::kV,
      //switches::kVModule,
  };
  cmd_line->CopySwitchesFrom(*base::CommandLine::ForCurrentProcess(),
                             kForwardSwitches, arraysize(kForwardSwitches));

  //GetContentClient()->browser()->AppendExtraCommandLineSwitches(cmd_line, -1);

  // Start up the sandbox host process and get the file descriptor for the
  // sandboxed processes to talk to it.
  base::FileHandleMappingVector additional_remapped_fds;
  additional_remapped_fds.emplace_back(
      host::SandboxHostLinux::GetInstance()->GetChildSocket(), common::GetSandboxFD());

  return host::ZygoteHostImpl::GetInstance()->LaunchZygote(
      cmd_line, control_fd, std::move(additional_remapped_fds));
}

// Initializes the Zygote sandbox host. No thread should be created before this
// call, as InitializeZygoteSandboxForBrowserProcess() will end-up using fork().
void InitializeZygoteSandboxForHostProcess(
    const base::CommandLine& parsed_command_line) {
  TRACE_EVENT0("startup", "SetupSandbox");
  // SandboxHostLinux needs to be initialized even if the sandbox and
  // zygote are both disabled. It initializes the sandboxed process socket.
  host::SandboxHostLinux::GetInstance()->Init();

  if (parsed_command_line.HasSwitch(switches::kNoZygote) &&
      !parsed_command_line.HasSwitch(service_manager::switches::kNoSandbox)) {
    LOG(ERROR) << "--no-sandbox should be used together with --no--zygote";
    exit(EXIT_FAILURE);
  }

  // Tickle the zygote host so it forks now.
  host::ZygoteHostImpl::GetInstance()->Init(parsed_command_line);
  common::ZygoteHandle generic_zygote =
      common::CreateGenericZygote(base::BindOnce(LaunchZygoteHelper));

  // TODO(kerrnel): Investigate doing this without the ZygoteHostImpl as a
  // proxy. It is currently done this way due to concerns about race
  // conditions.
  host::ZygoteHostImpl::GetInstance()->SetRendererSandboxStatus(
      generic_zygote->GetSandboxStatus());
}
#endif  // BUILDFLAG(USE_ZYGOTE_HANDLE)

#if defined(OS_LINUX)
#if BUILDFLAG(USE_ZYGOTE_HANDLE)
void PreSandboxInit() {
#if defined(ARCH_CPU_ARM_FAMILY)
  // On ARM, BoringSSL requires access to /proc/cpuinfo to determine processor
  // features. Query this before entering the sandbox.
  CRYPTO_library_init();
#endif

  // Pass BoringSSL a copy of the /dev/urandom file descriptor so RAND_bytes
  // will work inside the sandbox.
  RAND_set_urandom_fd(base::GetUrandomFD());

#if BUILDFLAG(ENABLE_LIBRARY_CDMS)
  // Ensure access to the library CDMs before the sandbox is turned on.
  PreloadLibraryCdms();
#endif
#if BUILDFLAG(ENABLE_WEBRTC)
  InitializeWebRtcModule();
#endif

  SkFontConfigInterface::SetGlobal(new common::FontConfigIPC(common::GetSandboxFD()))->unref();

  // Set the android SkFontMgr for blink. We need to ensure this is done
  // before the sandbox is initialized to allow the font manager to access
  // font configuration files on disk.
  // if (base::CommandLine::ForCurrentProcess()->HasSwitch(
  //         switches::kAndroidFontsPath)) {
  //   std::string android_fonts_dir =
  //       base::CommandLine::ForCurrentProcess()->GetSwitchValueASCII(
  //           switches::kAndroidFontsPath);

  //   if (android_fonts_dir.size() > 0 && android_fonts_dir.back() != '/')
  //     android_fonts_dir += '/';

  //   SkFontMgr_Android_CustomFonts custom;
  //   custom.fSystemFontUse =
  //       SkFontMgr_Android_CustomFonts::SystemFontUse::kOnlyCustom;
  //   custom.fBasePath = android_fonts_dir.c_str();

  //   std::string font_config;
  //   std::string fallback_font_config;
  //   if (android_fonts_dir.find("kitkat") != std::string::npos) {
  //     font_config = android_fonts_dir + "system_fonts.xml";
  //     fallback_font_config = android_fonts_dir + "fallback_fonts.xml";
  //     custom.fFallbackFontsXml = fallback_font_config.c_str();
  //   } else {
  //     font_config = android_fonts_dir + "fonts.xml";
  //     custom.fFallbackFontsXml = nullptr;
  //   }
  //   custom.fFontsXml = font_config.c_str();
  //   custom.fIsolated = true;

  //   blink::WebFontRenderStyle::SetSkiaFontManager(
  //       SkFontMgr_New_Android(&custom));
  // }
}
#endif  // BUILDFLAG(USE_ZYGOTE_HANDLE)
#endif  // OS_LINUX

#if defined(OS_POSIX) && !defined(OS_IOS)

 // Setup signal-handling state: resanitize most signals, ignore SIGPIPE.
 void SetupSignalHandlers() {
  // Sanitise our signal handling state. Signals that were ignored by our
  // parent will also be ignored by us. We also inherit our parent's sigmask.
  sigset_t empty_signal_set;
  CHECK(0 == sigemptyset(&empty_signal_set));
  CHECK(0 == sigprocmask(SIG_SETMASK, &empty_signal_set, NULL));

  struct sigaction sigact;
  memset(&sigact, 0, sizeof(sigact));
  sigact.sa_handler = SIG_DFL;
  static const int signals_to_reset[] =
  { SIGHUP, SIGINT, SIGQUIT, SIGILL, SIGABRT, SIGFPE, SIGSEGV,
  SIGALRM, SIGTERM, SIGCHLD, SIGBUS, SIGTRAP };  // SIGPIPE is set below.
  for (unsigned i = 0; i < arraysize(signals_to_reset); i++) {
   CHECK(0 == sigaction(signals_to_reset[i], &sigact, NULL));
  }

  // Always ignore SIGPIPE.  We check the return value of write().
  CHECK(signal(SIGPIPE, SIG_IGN) != SIG_ERR);
 }

#endif // defined(OS_POSIX) && !defined(OS_IOS)

std::string GetProcessTypeName() {
   const base::CommandLine& command_line =
   *base::CommandLine::ForCurrentProcess();

  if (command_line.HasSwitch(switches::kApplicationProcess)) {
   return switches::kApplicationProcess;
  } else if (command_line.HasSwitch(switches::kDomainProcess)) {
   return switches::kDomainProcess;
  } else if (command_line.HasSwitch(switches::kGpuProcess)) {
   return switches::kGpuProcess;
  } else if (command_line.HasSwitch(switches::kUtilityProcess)) {
   return switches::kUtilityProcess;
  } 
#if BUILDFLAG(USE_ZYGOTE_HANDLE)
  else if (command_line.HasSwitch(switches::kZygoteProcess)) { 
   return switches::kZygoteProcess;
  }
#endif
  return switches::kHostProcess;
}

bool IsHostProcess() {
   const base::CommandLine& command_line =
   *base::CommandLine::ForCurrentProcess();

  if (command_line.HasSwitch(switches::kApplicationProcess)) {
   return false;
  } else if (command_line.HasSwitch(switches::kDomainProcess)) {
   return false;
  } else if (command_line.HasSwitch(switches::kGpuProcess)) {
   return false;
  } else if (command_line.HasSwitch(switches::kUtilityProcess)) {
   return false;
  }
#if BUILDFLAG(USE_ZYGOTE_HANDLE)
  else if (command_line.HasSwitch(switches::kZygoteProcess)) { 
   return false;
  }
#endif
  return true;
}

struct MainFunction {
  const char* name;
  int (*function)(const common::MainParams&);
};

#if BUILDFLAG(USE_ZYGOTE_HANDLE)
// On platforms that use the zygote, we have a special subset of
// subprocesses that are launched via the zygote.  This function
// fills in some process-launching bits around ZygoteMain().
// Returns the exit code of the subprocess.
int RunZygote() {//RunZygote(common::MainDelegate* delegate) {
  static const MainFunction kMainFunctions[] = {
    {switches::kDomainProcess, domain::Main},
    {switches::kUtilityProcess, utility::UtilityMain},
//#if BUILDFLAG(ENABLE_PLUGINS)
//    {switches::kPpapiPluginProcess, PpapiPluginMain},
//#endif
  };

  std::vector<std::unique_ptr<common::ZygoteForkDelegate>> zygote_fork_delegates;
  //if (delegate) {
  //  delegate->ZygoteStarting(&zygote_fork_delegates);
    media::InitializeMediaLibrary();
  //}

#if defined(OS_LINUX)
  PreSandboxInit();
#endif

  // This function call can return multiple times, once per fork().
  if (!zygote::ZygoteMain(std::move(zygote_fork_delegates)))
    return 1;

  //if (delegate)
  //  delegate->ZygoteForked();

  // Zygote::HandleForkRequest may have reallocated the command
  // line so update it here with the new version.
  const base::CommandLine& command_line =
      *base::CommandLine::ForCurrentProcess();
 // std::string process_type =
   //   command_line.GetSwitchValueASCII(switches::kProcessType);
  //ContentClientInitializer::Set(process_type, delegate);

#if !defined(OS_ANDROID)
  tracing::EnableStartupTracingIfNeeded();
#endif  // !OS_ANDROID

  common::MainParams main_params(command_line);
  main_params.zygote_child = true;

  //std::unique_ptr<base::FieldTrialList> field_trial_list;
  //InitializeFieldTrialAndFeatureList(&field_trial_list);

  service_manager::SandboxType sandbox_type =
      service_manager::SandboxTypeFromCommandLine(command_line);
  if (sandbox_type == service_manager::SANDBOX_TYPE_PROFILING)
    sandbox::SetUseLocaltimeOverride(false);

  for (size_t i = 0; i < arraysize(kMainFunctions); ++i) {
    //if (process_type == kMainFunctions[i].name)
    if (command_line.HasSwitch(kMainFunctions[i].name)) {
      return kMainFunctions[i].function(main_params);
    }
  }

  //if (delegate)
  //  return delegate->RunProcess(process_type, main_params);

  NOTREACHED() << "Unknown zygote process type";//: " << process_type;
  return 1;
}
#endif  // BUILDFLAG(USE_ZYGOTE_HANDLE)

// #if defined(USE_TCMALLOC)
//  // static
// bool ProcessMainRunner::GetAllocatorWasteSizeThunk(size_t* size) {
//  size_t heap_size, allocated_bytes, unmapped_bytes;
//  MallocExtension* ext = MallocExtension::instance();
//  if (ext->GetNumericProperty("generic.heap_size", &heap_size) &&
//   ext->GetNumericProperty("generic.current_allocated_bytes",
//   &allocated_bytes) &&
//   ext->GetNumericProperty("tcmalloc.pageheap_unmapped_bytes",
//   &unmapped_bytes)) {
//   *size = heap_size - allocated_bytes - unmapped_bytes;
//   return true;
//  }
//  DCHECK(false);
//  return false;
// }

//  // static
// void ProcessMainRunner::GetStatsThunk(char* buffer, int buffer_length) {
//  MallocExtension::instance()->GetStats(buffer, buffer_length);
// }

//  // static
// void ProcessMainRunner::ReleaseFreeMemoryThunk() {
//  MallocExtension::instance()->ReleaseFreeMemory();
// }
// #endif

// This sets up two singletons responsible for managing field trials. The
// |field_trial_list| singleton lives on the stack and must outlive the Run()
// method of the process.
void InitializeFieldTrialAndFeatureList(
    std::unique_ptr<base::FieldTrialList>* field_trial_list) {
  const base::CommandLine& command_line =
      *base::CommandLine::ForCurrentProcess();

  // Initialize statistical testing infrastructure.  We set the entropy
  // provider to nullptr to disallow non-browser processes from creating
  // their own one-time randomized trials; they should be created in the
  // browser process.
  field_trial_list->reset(new base::FieldTrialList(nullptr));

  // Ensure any field trials in browser are reflected into the child
  // process.
#if defined(OS_POSIX)
  // On POSIX systems that use the zygote, we get the trials from a shared
  // memory segment backed by an fd instead of the command line.
  base::FieldTrialList::CreateTrialsFromCommandLine(
      command_line, switches::kFieldTrialHandle, kFieldTrialDescriptor);
#else
  base::FieldTrialList::CreateTrialsFromCommandLine(
      command_line, switches::kFieldTrialHandle, -1);
#endif

  std::unique_ptr<base::FeatureList> feature_list(new base::FeatureList);
  base::FieldTrialList::CreateFeaturesFromCommandLine(
      command_line, switches::kEnableFeatures, switches::kDisableFeatures,
      feature_list.get());
  base::FeatureList::SetInstance(std::move(feature_list));
}


ProcessMainRunner::ProcessMainRunner() : is_initialized_(false),
 is_shutdown_(false) {
#if defined(OS_WIN)
    memset(&sandbox_info_, 0, sizeof(sandbox_info_));
#endif
}

ProcessMainRunner::~ProcessMainRunner() {
 if (is_initialized_ && !is_shutdown_)
  Shutdown();
}

void ProcessMainRunner::PreSandboxStartup() {
#if defined(ARCH_CPU_ARM_FAMILY) && (defined(OS_ANDROID) || defined(OS_LINUX))
  // Create an instance of the CPU class to parse /proc/cpuinfo and cache
  // cpu_brand info.
  base::CPU cpu_info;
#endif
 auto* cmd_line = base::CommandLine::ForCurrentProcess();
// Disable platform crash handling and initialize the crash reporter, if
// requested.
// TODO(crbug.com/753619): Implement crash reporter integration for Fuchsia.
#if !defined(OS_FUCHSIA)
  if (cmd_line->HasSwitch(
          switches::kEnableCrashReporter)) {
    crash_reporter::SetCrashReporterClient(g_host_crash_client.Pointer());
#if defined(OS_MACOSX) || defined(OS_WIN)
    crash_reporter::InitializeCrashpad(cmd_line->HasSwitch(switches::kHostProcess), GetProcessTypeName());
#elif defined(OS_LINUX)
    // Reporting for sub-processes will be initialized in ZygoteForked.
    if (!cmd_line->HasSwitch(switches::kZygoteProcess))
      breakpad::InitCrashReporter(GetProcessTypeName());
#elif defined(OS_ANDROID)
    if (IsHostProcess())
      breakpad::InitCrashReporter("host");
    else
      breakpad::InitNonBrowserCrashReporterForAndroid(GetProcessTypeName());
#endif  // defined(OS_ANDROID)
  }
#endif  // !defined(OS_FUCHSIA)

  crash_reporter::InitializeCrashKeys();

  InitializeResourceBundle();
}

void ProcessMainRunner::InitializeResourceBundle() {
#if defined(OS_ANDROID)
  // On Android, the renderer runs with a different UID and can never access
  // the file system. Use the file descriptor passed in at launch time.
  auto* global_descriptors = base::GlobalDescriptors::GetInstance();
  int pak_fd = global_descriptors->MaybeGet(kHostPakDescriptor);
  base::MemoryMappedFile::Region pak_region;
  if (pak_fd >= 0) {
    pak_region = global_descriptors->GetRegion(kHostPakDescriptor);
  } else {
    pak_fd =
        base::android::OpenApkAsset("assets/content_host.pak", &pak_region);
    // Loaded from disk for browsertests.
    if (pak_fd < 0) {
      base::FilePath pak_file;
      bool r = PathService::Get(base::DIR_ANDROID_APP_DATA, &pak_file);
      DCHECK(r);
      pak_file = pak_file.Append(FILE_PATH_LITERAL("paks"));
      pak_file = pak_file.Append(FILE_PATH_LITERAL("content_host.pak"));
      int flags = base::File::FLAG_OPEN | base::File::FLAG_READ;
      pak_fd = base::File(pak_file, flags).TakePlatformFile();
      pak_region = base::MemoryMappedFile::Region::kWholeFile;
    }
    global_descriptors->Set(kHostPakDescriptor, pak_fd, pak_region);
  }
  DCHECK_GE(pak_fd, 0);
  // This is clearly wrong. See crbug.com/330930
  ui::ResourceBundle::InitSharedInstanceWithPakFileRegion(base::File(pak_fd),
                                                          pak_region);
  ui::ResourceBundle::GetSharedInstance().AddDataPackFromFileRegion(
      base::File(pak_fd), pak_region, ui::SCALE_FACTOR_100P);
#elif defined(OS_MACOSX)
  ui::ResourceBundle::InitSharedInstanceWithPakPath(GetResourcesPakFilePath());
#else
  base::FilePath pak_file;
  bool r = PathService::Get(base::DIR_ASSETS, &pak_file);
  DCHECK(r);
  pak_file = pak_file.Append(FILE_PATH_LITERAL("gen/mumba/app/resources/content_resources_100_percent.pak"));
  //pak_file = pak_file.Append(FILE_PATH_LITERAL("gen/core/host/host_resources.pak"));
  ui::ResourceBundle::InitSharedInstanceWithPakPath(pak_file);
#endif
}

int ProcessMainRunner::Initialize(const common::MainParams& params) {
  ui_task_ = params.ui_task;
  //created_main_parts_closure_ = params.created_main_parts_closure;

#if defined(OS_WIN)
  sandbox_info_ = *params.sandbox_info;
#else  // !OS_WIN

#if defined(OS_MACOSX)
  autorelease_pool_ = params.autorelease_pool;
#endif  // defined(OS_MACOSX)
#if defined(OS_ANDROID)
    // See note at the initialization of ExitManager, below; basically,
    // only Android builds have the ctor/dtor handlers set up to use
    // TRACE_EVENT right away.
    TRACE_EVENT0("startup,benchmark,rail", "ContentMainRunnerImpl::Initialize");
#endif  // OS_ANDROID

   base::GlobalDescriptors* g_fds = base::GlobalDescriptors::GetInstance();
   ALLOW_UNUSED_LOCAL(g_fds);

// On Android, the ipc_fd is passed through the Java service.
#if !defined(OS_ANDROID)
   g_fds->Set(kMojoIPCChannel,
               kMojoIPCChannel + base::GlobalDescriptors::kBaseDescriptor);

   g_fds->Set(
       kFieldTrialDescriptor,
       kFieldTrialDescriptor + base::GlobalDescriptors::kBaseDescriptor);
#endif  // !OS_ANDROID

#if defined(OS_LINUX) || defined(OS_OPENBSD)
   g_fds->Set(kCrashDumpSignal,
               kCrashDumpSignal + base::GlobalDescriptors::kBaseDescriptor);
#endif  // OS_LINUX || OS_OPENBSD

#endif  // !OS_WIN
  is_initialized_ = true;

#if !defined(OS_ANDROID)
  if (!ui_task_) {
    exit_manager_.reset(new base::AtExitManager);
}
#endif

  const base::CommandLine& command_line =
    *base::CommandLine::ForCurrentProcess();

#if defined(OS_WIN)
    if (command_line.HasSwitch(switches::kDeviceScaleFactor)) {
      std::string scale_factor_string = command_line.GetSwitchValueASCII(
          switches::kDeviceScaleFactor);
      double scale_factor = 0;
      if (base::StringToDouble(scale_factor_string, &scale_factor))
        display::win::SetDefaultDeviceScaleFactor(scale_factor);
    }
#endif

    //if (!GetContentClient())
    //  SetContentClient(&empty_content_client_);
    //ContentClientInitializer::Set(process_type, delegate_);

    if (!common::GetClient())
      common::SetClient(&client_);
    // set only browser for now
    ClientInitializer::Set("", this);
 

#if !defined(OS_ANDROID)
    // Enable startup tracing asap to avoid early TRACE_EVENT calls being
    // ignored. For Android, startup tracing is enabled in an even earlier place
    // content/app/android/library_loader_hooks.cc.
    //
    // Startup tracing flags are not (and should not) passed to Zygote
    // processes. We will enable tracing when forked, if needed.
    if (!command_line.HasSwitch(switches::kZygoteProcess))
      tracing::EnableStartupTracingIfNeeded();
#endif  // !OS_ANDROID

//#if defined(OS_WIN)
    // Enable exporting of events to ETW if requested on the command line.
   // if (command_line.HasSwitch(switches::kTraceExportEventsToETW))
   //   base::trace_event::TraceEventETWExport::EnableETWExport();
//#endif  // OS_WIN

#if !defined(OS_ANDROID)
    // Android tracing started at the beginning of the method.
    // Other OSes have to wait till we get here in order for all the memory
    // management setup to be completed.
    TRACE_EVENT0("startup,benchmark,rail", "ContentMainRunnerImpl::Initialize");
#endif  // !OS_ANDROID

#if defined(OS_MACOSX)
    // We need to allocate the IO Ports before the Sandbox is initialized or
    // the first instance of PowerMonitor is created.
    // It's important not to allocate the ports for processes which don't
    // register with the power monitor - see crbug.com/88867.
    if (process_type.empty() ||
        (delegate_ &&
         delegate_->ProcessRegistersWithSystemProcess(process_type))) {
      base::PowerMonitorDeviceSource::AllocateSystemIOPorts();
    }

    if (!process_type.empty() &&
        (!delegate_ || delegate_->ShouldSendMachPort(process_type))) {
      MachBroker::ChildSendTaskPortToParent();
    }
#endif

  // If we are on a platform where the default allocator is overridden (shim
  // layer on windows, tcmalloc on Linux Desktop) smoke-tests that the
  // overriding logic is working correctly. If not causes a hard crash, as its
  // unexpected absence has security implications.
  CHECK(base::allocator::IsAllocatorInitialized());

  PreSandboxStartup();

#if defined(OS_POSIX)
    if (!IsHostProcess()) {
      // When you hit Ctrl-C in a terminal running the browser
      // process, a SIGINT is delivered to the entire process group.
      // When debugging the browser process via gdb, gdb catches the
      // SIGINT for the browser process (and dumps you back to the gdb
      // console) but doesn't for the child processes, killing them.
      // The fix is to have child processes ignore SIGINT; they'll die
      // on their own when the browser process goes away.
      //
      // Note that we *can't* rely on BeingDebugged to catch this case because
      // we are the child process, which is not being debugged.
      // TODO(evanm): move this to some shared subprocess-init function.
      if (!base::debug::BeingDebugged())
        signal(SIGINT, SIG_IGN);
    }
#endif

#if defined(OS_WIN)
    if (!common::InitializeSandbox(
            service_manager::SandboxTypeFromCommandLine(command_line),
            params.sandbox_info)) {
      return 0;//TerminateForFatalInitializationError();
    }    
#elif defined(OS_MACOSX)
    // Do not initialize the sandbox at this point if the V2
    // sandbox is enabled for the process type.
    bool v2_enabled = base::CommandLine::ForCurrentProcess()->HasSwitch(
        switches::kEnableV2Sandbox);
// Do not initialize the sandbox at this point if the V2
    // sandbox is enabled for the process type.
    bool v2_enabled = base::CommandLine::ForCurrentProcess()->HasSwitch(
        switches::kEnableV2Sandbox);

    if (process_type == switches::kShellProcess || v2_enabled ||
        (delegate_ && delegate_->DelaySandboxInitialization(process_type))) {
      // On OS X the renderer sandbox needs to be initialized later in the
      // startup sequence in RendererMainPlatformDelegate::EnableSandbox().
    } else {
      if (!InitializeSandbox())
        return 0;//TerminateForFatalInitializationError();
    }
#endif

    //if (delegate_)
    //  delegate_->SandboxInitialized(process_type);

//#if BUILDFLAG(USE_ZYGOTE_HANDLE)
//    if (IsHostProcess()) {//process_type.empty()) {
      // The sandbox host needs to be initialized before forking a thread to
      // start the ServiceManager, and after setting up the sandbox and invoking
      // SandboxInitialized().
//      InitializeZygoteSandboxForHostProcess(
//          *base::CommandLine::ForCurrentProcess());
//    }
//#endif  // BUILDFLAG(USE_ZYGOTE_HANDLE)

//#if defined(OS_LINUX) && !defined(CONTENT_IMPLEMENTATION)
//  if (IsHostProcess()) {  
//    host::SandboxHostLinux::GetInstance()->Init();
//  }
//#endif  

  //google::InitGoogleLogging(argv[0]);

  //common::InitializeMojo();

  // Return -1 to indicate no early termination.
  return -1;
 }

 int ProcessMainRunner::Run() {
  DCHECK(is_initialized_);
  DCHECK(!is_shutdown_);

  const base::CommandLine& command_line =
   *base::CommandLine::ForCurrentProcess();

  // default: engine
  common::ProcessType type = common::PROCESS_TYPE_HOST;

  //if (command_line.HasSwitch(switches::kCommandProcess)) {
  // type = common::PROCESS_TYPE_COMMAND;
  //} 
  if (command_line.HasSwitch(switches::kApplicationProcess)) {
   type = common::PROCESS_TYPE_APPLICATION;
  } else if (command_line.HasSwitch(switches::kDomainProcess)) {
   type = common::PROCESS_TYPE_DOMAIN;
  } else if (command_line.HasSwitch(switches::kGpuProcess)) {
   type = common::PROCESS_TYPE_GPU;
  } else if (command_line.HasSwitch(switches::kUtilityProcess)) {
   type = common::PROCESS_TYPE_UTILITY;
  }
#if BUILDFLAG(USE_ZYGOTE_HANDLE)
  else if (command_line.HasSwitch(switches::kZygoteProcess)) { 
   type = common::PROCESS_TYPE_ZYGOTE;
  }
#endif  

   // Run this logic on all child processes. Zygotes will run this at a later
  // point in time when the command line has been updated.
  std::unique_ptr<base::FieldTrialList> field_trial_list;
  //if (type != common::PROCESS_TYPE_DOMAIN)
  InitializeFieldTrialAndFeatureList(&field_trial_list);

  common::MainParams main_params(command_line);

  return RunProcess(type, main_params);
 }

void ProcessMainRunner::Shutdown() {
 DCHECK(is_initialized_);
 DCHECK(!is_shutdown_);
 //DLOG(INFO) << "ProcessMainRunner::Shutdown";

 exit_manager_.reset(NULL);

 is_shutdown_ = true;
}

int ProcessMainRunner::RunProcess(
 common::ProcessType type,
 const common::MainParams& main_params) {

 if (type == common::PROCESS_TYPE_HOST) {
   //DLOG(INFO) << "running host";
   return host::Main(main_params);
 } else if (type == common::PROCESS_TYPE_DOMAIN) {
   //DLOG(INFO) << "running domain";
   return domain::Main(main_params);
 } else if (type == common::PROCESS_TYPE_GPU) {
   //DLOG(INFO) << "running gpu";
  return gpu::GpuMain(main_params);
 } else if (type == common::PROCESS_TYPE_UTILITY) {
  //DLOG(INFO) << "running utility";
  return utility::UtilityMain(main_params);
 }
#if BUILDFLAG(USE_ZYGOTE_HANDLE)
  else if (type == common::PROCESS_TYPE_ZYGOTE) {
  // Zygote startup is special -- see RunZygote comments above
 // DLOG(INFO) << "running zygote";
  return RunZygote();
 }
#endif  // BUILDFLAG(USE_ZYGOTE_HANDLE)

 NOTREACHED() << "Unknown process type: " << type;
 return 1;
}

host::HostClient* ProcessMainRunner::CreateHostClient() {
  return g_host_client.Pointer();
}

gpu::ContentGpuClient* ProcessMainRunner::CreateGpuClient() {
  return g_gpu_client.Pointer();
}

utility::ContentUtilityClient* ProcessMainRunner::CreateUtilityClient() {
  return g_utility_client.Pointer();
}
 

//
//application::ApplicationClient* MainRunner::CreateApplicationClient() {
// return g_application_client.Pointer();
//}
