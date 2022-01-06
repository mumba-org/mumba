// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/common/switches.h"

namespace switches {

const char kDomainProcess[] = "domain";
//const char kSystemProcess[] = "system";
const char kHostProcess[] = "host";
const char kApplicationProcess[] = "application";
const char kGpuProcess[] = "gpu";
const char kUtilityProcess[] = "utility";
//const char kReplProcess[] = "repl";
//const char kToolsProcess[] = "tools";

// modules
// const char kServiceManagerProcess[] = "service-manager";
// const char kShellManagerProcess[] = "shell-manager";
// const char kDeviceManagerProcess[] = "device-manager";
// const char kIdentityManagerProcess[] = "identity-manager";
// const char kLogManagerProcess[] = "log-manager";
// const char kNotificationProcess[] = "notification";
// const char kPackageManagerProcess[] = "package-manager";
// const char kRegistryProcess[] = "registry";
// const char kWorkspaceManagerProcess[] = "workspace-manager";
// const char kAppManagerProcess[] = "app-manager";

const char kCrashDumpsDir[] = "crash-dumps-dir";

const char kChannelID[] = "channel-id";
const char kRequestID[] = "request";
const char kSessionID[] = "session";
const char kPortNumber[] = "port-number";
const char kDomainUUID[] = "app-uuid";
const char kDomainName[] = "app-name";
const char kRepl[] = "repl";

const char kIPCConnectionTimeout[] = "ipc-connection-timeout";
const char kHostSubprocessPath[] = "host-subprocess-path";

// Don't send HTTP-Referer headers.
const char kNoReferrers[] = "no-referrers";
const char kReducedReferrerGranularity[] = "reduced-referrer-granularity";
const char kSingleProcess[] = "single-process";
const char kInProcessGPU[] = "in-process-gpu";
// Prioritizes the UI's command stream in the GPU process
const char kUIPrioritizeInGpuProcess[] = "ui-prioritize-in-gpu-process";

//const char kEnableGpuClientTracing[] = "enable-gpu-client-tracing";

// Disables hardware acceleration of video decode, where available.
const char kDisableAcceleratedVideoDecode[] =
"disable-accelerated-video-decode";

const char kDisableAcceleratedVideoEncode[] = "disable-accelerated-video-encode";

// Disable gpu-accelerated 2d canvas.
const char kDisableAccelerated2dCanvas[] = "disable-accelerated-2d-canvas";

// Disable hardware acceleration of mjpeg decode for captured frame, where
// available.
const char kDisableAcceleratedMjpegDecode[] =
"disable-accelerated-mjpeg-decode";

// Prevent the compositor from using its GPU implementation.
const char kDisableGpuCompositing[] = "disable-gpu-compositing";

// Disable all versions of WebGL.
const char kDisableWebGL[] = "disable-webgl";

// Disable WebGL2.
const char kDisableWebGL2[] = "disable-webgl2";

// Number of worker threads used to rasterize content.
const char kNumRasterThreads[] = "num-raster-threads";

// Enable rasterizer that writes directly to GPU memory associated with tiles.
const char kEnableZeroCopy[] = "enable-zero-copy";

// Disable GPU rasterization, i.e. rasterize on the CPU only.
// Overrides the kEnableGpuRasterization and kForceGpuRasterization flags.
//const char kDisableGpuRasterization[] = "disable-gpu-rasterization";

// Allow heuristics to determine when a layer tile should be drawn with the
// Skia GPU backend. Only valid with GPU accelerated compositing +
// impl-side painting.
//const char kEnableGpuRasterization[] = "enable-gpu-rasterization";

// Specify that all compositor resources should be backed by GPU memory buffers.
const char kEnableGpuMemoryBufferCompositorResources[] =
"enable-gpu-memory-buffer-compositor-resources";

// Always use the Skia GPU backend for drawing layer tiles. Only valid with GPU
// accelerated compositing + impl-side painting. Overrides the
// kEnableGpuRasterization flag.
const char kForceGpuRasterization[] = "force-gpu-rasterization";

// Use the new surfaces system to handle compositor delegation.
const char kUseSurfaces[] = "use-surfaces";

// Disable the use of the new surfaces system to handle compositor delegation.
const char kDisableSurfaces[] = "disable-surfaces";

// The number of multisample antialiasing samples for GPU rasterization.
// Requires MSAA support on GPU to have an effect. 0 disables MSAA.
const char kGpuRasterizationMSAASampleCount[] =
"gpu-rasterization-msaa-sample-count";

// Enable native GPU memory buffer support when available.
//const char kEnableNativeGpuMemoryBuffers[] = "enable-native-gpu-memory-buffers";

const char kDisableGpu[] = "disable-gpu";

// Skip gpu info collection, blacklist loading, and blacklist auto-update
// scheduling at browser startup time.
// Therefore, all GPU features are available, and about:gpu page shows empty
// content. The switch is intended only for layout tests.
// TODO(gab): Get rid of this switch entirely.
const char kSkipGpuDataLoading[] = "skip-gpu-data-loading";

// Ignores GPU blacklist.
//const char kIgnoreGpuBlacklist[] = "ignore-gpu-blacklist";

// Disable the thread that crashes the GPU process if it stops responding to
// messages.
const char kDisableGpuWatchdog[] = "disable-gpu-watchdog";

// Passes gpu vendor_id from browser process to GPU process.
const char kGpuVendorID[] = "gpu-vendor-id";

// Passes gpu device_id from browser process to GPU process.
const char kGpuDeviceID[] = "gpu-device-id";

// Passes gpu driver_vendor from browser process to GPU process.
const char kGpuDriverVendor[] = "gpu-driver-vendor";

// Passes gpu driver_version from browser process to GPU process.
const char kGpuDriverVersion[] = "gpu-driver-version";

// Logs GPU control list decisions when enforcing blacklist rules.
const char kLogGpuControlListDecisions[] = "log-gpu-control-list-decisions";

// Disables the use of a 3D software rasterizer.
const char kDisableSoftwareRasterizer[] = "disable-software-rasterizer";

// Disable the limit on the number of times the GPU process may be restarted
// This switch is intended only for tests.
const char kDisableGpuProcessCrashLimit[] = "disable-gpu-process-crash-limit";

// Disable the GPU process sandbox.
const char kDisableGpuSandbox[] = "disable-gpu-sandbox";

// Force logging to be disabled.  Logging is enabled by default in debug
// builds.
const char kDisableLogging[] = "disable-logging";

// Disable the seccomp filter sandbox (seccomp-bpf) (Linux only).
const char kDisableSeccompFilterSandbox[] = "disable-seccomp-filter-sandbox";

// Force logging to be enabled.  Logging is disabled by default in release
// builds.
const char kEnableLogging[] = "enable-logging";

// Extra command line options for launching the GPU process (normally used
// for debugging). Use like renderer-cmd-prefix.
const char kGpuLauncher[] = "gpu-launcher";

// Causes the GPU process to display a dialog on launch.
const char kGpuStartupDialog[] = "gpu-startup-dialog";

// Allows shmat() system call in the GPU sandbox.
const char kGpuSandboxAllowSysVShm[] = "gpu-sandbox-allow-sysv-shm";

// Makes GPU sandbox failures fatal.
const char kGpuSandboxFailuresFatal[] = "gpu-sandbox-failures-fatal";

const char kGpuSandboxStartEarly[] = "gpu-sandbox-start-early";

// Sets the minimum log level. Valid values are from 0 to 3:
// INFO = 0, WARNING = 1, LOG_ERROR = 2, LOG_FATAL = 3.
const char kLoggingLevel[] = "log-level";

// Disables the sandbox for all process types that are normally sandboxed.
const char kNoSandbox[] = "no-sandbox";

const char kEnableMemoryBenchmarking[] = "enable-memory-benchmarking";

// Upscale defaults to "good".
const char kTabCaptureDownscaleQuality[] = "tab-capture-downscale-quality";

// Scaling quality for capturing tab. Should be one of "fast", "good" or "best".
// One flag for upscaling, one for downscaling.
// Upscale defaults to "best".
const char kTabCaptureUpscaleQuality[] = "tab-capture-upscale-quality";

const char kDisableVaapiAcceleratedVideoEncode[] = "disable-vaapi-accelerated-video-encode";

const char kDisableWebRtcHWEncoding[] = "disable-webrtc-hw-encoding";

const char kMaxDecodedImageSizeMb[] = "max-decoded-image-size-mb";

const char kFieldTrialHandle[] = "field-trial-handle";

const char kDisableKillAfterBadIPC[] = "disable-kill-after-bad-ipc";

#if defined(OS_WIN)
// Enables experimental hardware acceleration for VP8/VP9 video decoding.
const char kEnableAcceleratedVpxDecode[] = "enable-accelerated-vpx-decode";
const char kDisableLowLatencyDxva[] = "disable-low-latency-dxva";
const char kDisableZeroCopyDxgiVideo[] = "disable-zero-copy-dxgi-video";
const char kDisableNv12DxgiVideo[] = "disable-nv12-dxgi-video";
const char kDeviceScaleFactor[] = "device-scale-factor";
// Used in combination with kNotificationLaunchId to specify the inline reply
// entered in the toast in the Windows Action Center.
const char kNotificationInlineReply[] = "notification-inline-reply";
// Used for launching Chrome when a toast displayed in the Windows Action Center
// has been activated. Should contain the launch ID encoded by Chrome.
const char kNotificationLaunchId[] = "notification-launch-id";

const char kWaitForDebuggerChildren[] = "wait-for-debugger-children";
#endif

// On Windows only: requests that Chrome connect to the running Metro viewer
// process.
//const char kViewerConnect[] = "connect-to-metro-viewer";

// Disable partial raster in the renderer. Disabling this switch also disables
// the use of persistent gpu memory buffers.
const char kDisablePartialRaster[] = "disable-partial-raster";

// Enable partial raster in the renderer.
const char kEnablePartialRaster[] = "enable-partial-raster";
// Do not force that all compositor resources be backed by GPU memory buffers.
const char kDisableGpuMemoryBufferCompositorResources[] =
    "disable-gpu-memory-buffer-compositor-resources";

// Disable the per-domain blocking for 3D APIs after GPU reset.
// This switch is intended only for tests.
const char kDisableDomainBlockingFor3DAPIs[] =
    "disable-domain-blocking-for-3d-apis";

const char kNoZygote[] = "no-zygote";
// The prefix used when starting the zygote process. (i.e. 'gdb --args')
const char kZygoteCmdPrefix[] = "zygote-cmd-prefix";

// Causes the process to run as a renderer zygote.
const char kZygoteProcess[] = "zygote";

const char kUtilityCmdPrefix[] = "utility-cmd-prefix";

const char kEnableVulkan[] = "enable-vulkan";

const char kWebRtcLocalEventLogging[] = "webrtc-event-logging";

const char kEnableBlinkFeatures[] = "enable-blink-features";

const char kDisableBlinkFeatures[] = "disable-blink-features";
// Indicates the utility process should run with a message loop type of UI.
const char kMessageLoopTypeUi[] = "message-loop-type-ui";

// Enables experimental Harmony (ECMAScript 6) features.
const char kJavaScriptHarmony[]             = "javascript-harmony";

// Specifies the flags passed to JS engine
const char kJavaScriptFlags[]               = "js-flags";

// ES6 Modules dynamic imports.
const base::Feature kModuleScriptsDynamicImport{
    "ModuleScriptsDynamicImport", base::FEATURE_ENABLED_BY_DEFAULT};

// ES6 Modules import.meta.url.
const base::Feature kModuleScriptsImportMetaUrl{
    "ModuleScriptsImportMetaUrl", base::FEATURE_ENABLED_BY_DEFAULT};

// Enables asm.js to WebAssembly V8 backend.
// http://asmjs.org/spec/latest/
const base::Feature kAsmJsToWebAssembly{"AsmJsToWebAssembly",
                                        base::FEATURE_ENABLED_BY_DEFAULT};

// Enable WebAssembly structured cloning.
// http://webassembly.org/
const base::Feature kWebAssembly{"WebAssembly",
                                 base::FEATURE_DISABLED_BY_DEFAULT};

// Enable WebAssembly streamed compilation.
const base::Feature kWebAssemblyStreaming{"WebAssemblyStreaming",
                                          base::FEATURE_ENABLED_BY_DEFAULT};

// Enable WebAssembly baseline compilation and tier up.
//const base::Feature kWebAssemblyBaseline{"WebAssemblyBaseline",
//                                         base::FEATURE_DISABLED_BY_DEFAULT};

// Enable WebAssembly trap handler.
const base::Feature kWebAssemblyTrapHandler{"WebAssemblyTrapHandler",
                                            base::FEATURE_DISABLED_BY_DEFAULT};

// Disable latest shipping ECMAScript 6 features.
const char kDisableJavaScriptHarmonyShipping[] =
    "disable-javascript-harmony-shipping";

// Enables future V8 VM features
const base::Feature kV8VmFuture{"V8VmFuture",
                                base::FEATURE_DISABLED_BY_DEFAULT};

// Enable WebAssembly baseline compilation and tier up.
//const base::Feature kWebAssemblyBaseline{"WebAssemblyBaseline",
//                                         base::FEATURE_DISABLED_BY_DEFAULT};

// http://tc39.github.io/ecmascript_sharedmem/shmem.html
const base::Feature kSharedArrayBuffer{"SharedArrayBuffer",
                                       base::FEATURE_DISABLED_BY_DEFAULT};

// Enable WebAssembly trap handler.
//const base::Feature kWebAssemblyTrapHandler{"WebAssemblyTrapHandler",
//                                            base::FEATURE_DISABLED_BY_DEFAULT};


// Override the maximum framerate as can be specified in calls to getUserMedia.
// This flag expects a value.  Example: --max-gum-fps=17.5
const char kWebRtcMaxCaptureFramerate[] = "max-gum-fps";
// Configure the maximum CPU time percentage of a single core that can be
// consumed for desktop capturing. Default is 50. Set 100 to disable the
// throttling of the capture.
const char kWebRtcMaxCpuConsumptionPercentage[] =
    "webrtc-max-cpu-consumption-percentage";
// Renderer process parameter for WebRTC Stun probe trial to determine the
// interval. Please see SetupStunProbeTrial in
// chrome_browser_field_trials_desktop.cc for more detail.
const char kWebRtcStunProbeTrialParameter[] = "webrtc-stun-probe-trial";

const char kProfilePath[] = "profile-path";
const char kWorkspaceId[] = "workspace-id";
const char kAdminServiceHost[] = "admin-service-host";
const char kAdminServicePort[] = "admin-service-port";

}