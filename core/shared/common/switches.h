// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef COMMON_SWITCHES_H__
#define COMMON_SWITCHES_H__

#include "base/feature_list.h"
#include "build/build_config.h"
#include "core/shared/common/content_export.h"

namespace switches {

extern CONTENT_EXPORT const char kDomainProcess[];
//extern CONTENT_EXPORT const char kSystemProcess[];
extern CONTENT_EXPORT const char kHostProcess[];
extern CONTENT_EXPORT const char kApplicationProcess[];
extern CONTENT_EXPORT const char kGpuProcess[];
extern CONTENT_EXPORT const char kUtilityProcess[];
//extern CONTENT_EXPORT const char kReplProcess[];
//extern CONTENT_EXPORT const char kToolsProcess[];

// modules
// extern CONTENT_EXPORT const char kServiceManagerProcess[];
// extern CONTENT_EXPORT const char kShellManagerProcess[];
// extern CONTENT_EXPORT const char kDeviceManagerProcess[];
// extern CONTENT_EXPORT const char kIdentityManagerProcess[];
// extern CONTENT_EXPORT const char kLogManagerProcess[];
// extern CONTENT_EXPORT const char kNotificationProcess[];
// extern CONTENT_EXPORT const char kPackageManagerProcess[];
// extern CONTENT_EXPORT const char kRegistryProcess[];
// extern CONTENT_EXPORT const char kWorkspaceManagerProcess[];
// extern CONTENT_EXPORT const char kAppManagerProcess[];

extern CONTENT_EXPORT const char kCrashDumpsDir[];

extern CONTENT_EXPORT const char kChannelID[];
extern CONTENT_EXPORT const char kRequestID[];
extern CONTENT_EXPORT const char kDomainUUID[];
extern CONTENT_EXPORT const char kDomainName[];
extern CONTENT_EXPORT const char kSessionID[];
extern CONTENT_EXPORT const char kPortNumber[];
extern CONTENT_EXPORT const char kRepl[];

extern CONTENT_EXPORT const char kIPCConnectionTimeout[];

extern CONTENT_EXPORT const char kHostSubprocessPath[];

extern CONTENT_EXPORT const char kNoReferrers[];
extern CONTENT_EXPORT const char kReducedReferrerGranularity[];

extern CONTENT_EXPORT const char kSingleProcess[];
extern CONTENT_EXPORT const char kInProcessGPU[];

extern CONTENT_EXPORT const char kDisableAcceleratedVideoDecode[];
extern CONTENT_EXPORT const char kEnableGpuClientTracing[];
extern CONTENT_EXPORT const char kUIPrioritizeInGpuProcess[];

extern CONTENT_EXPORT const char kDisableAccelerated2dCanvas[];
extern CONTENT_EXPORT const char kDisableAcceleratedMjpegDecode[];
extern CONTENT_EXPORT const char kDisableAcceleratedVideoDecode[];
extern CONTENT_EXPORT const char kDisableAcceleratedVideoEncode[];
extern CONTENT_EXPORT const char kDisableGpuCompositing[];
extern CONTENT_EXPORT const char kDisableWebGL[];
extern CONTENT_EXPORT const char kDisableWebGL2[];
extern CONTENT_EXPORT const char kNumRasterThreads[];
extern CONTENT_EXPORT const char kEnableZeroCopy[];
extern CONTENT_EXPORT const char kEnablePartialRaster[];
//extern CONTENT_EXPORT const char kDisableGpuRasterization[];
//extern CONTENT_EXPORT const char kEnableGpuRasterization[];
extern CONTENT_EXPORT const char kEnableGpuMemoryBufferCompositorResources[];
extern CONTENT_EXPORT const char kForceGpuRasterization[];
extern CONTENT_EXPORT const char kUseSurfaces[];
extern CONTENT_EXPORT const char kDisableSurfaces[];
extern CONTENT_EXPORT const char kGpuRasterizationMSAASampleCount[];
extern CONTENT_EXPORT const char kEnableNativeGpuMemoryBuffers[];
extern CONTENT_EXPORT const char kDisableGpu[];
extern CONTENT_EXPORT const char kSkipGpuDataLoading[];
//extern CONTENT_EXPORT const char kIgnoreGpuBlacklist[];
extern CONTENT_EXPORT const char kDisableGpuWatchdog[];
extern CONTENT_EXPORT const char kGpuVendorID[];
extern CONTENT_EXPORT const char kGpuDeviceID[];
extern CONTENT_EXPORT const char kGpuDriverVendor[];
extern CONTENT_EXPORT const char kGpuDriverVersion[];
extern CONTENT_EXPORT const char kLogGpuControlListDecisions[];
extern CONTENT_EXPORT const char kDisableSoftwareRasterizer[];
extern CONTENT_EXPORT const char kDisableGpuProcessCrashLimit[];
extern CONTENT_EXPORT const char kDisableGpuSandbox[];
extern CONTENT_EXPORT const char kDisableLogging[];
extern CONTENT_EXPORT const char kDisableSeccompFilterSandbox[];
extern CONTENT_EXPORT const char kEnableLogging[];
extern CONTENT_EXPORT const char kGpuLauncher[];
extern CONTENT_EXPORT const char kGpuStartupDialog[];
extern CONTENT_EXPORT const char kGpuSandboxAllowSysVShm[];
extern CONTENT_EXPORT const char kGpuSandboxFailuresFatal[];
extern CONTENT_EXPORT const char kGpuSandboxStartEarly[];
extern CONTENT_EXPORT const char kLoggingLevel[];
extern CONTENT_EXPORT const char kNoSandbox[];
extern CONTENT_EXPORT const char kEnableMemoryBenchmarking[];
extern CONTENT_EXPORT const char kTabCaptureDownscaleQuality[];
extern CONTENT_EXPORT const char kTabCaptureUpscaleQuality[];
extern CONTENT_EXPORT const char kDisableVaapiAcceleratedVideoEncode[];
extern CONTENT_EXPORT const char kDisableWebRtcHWEncoding[];
extern CONTENT_EXPORT const char kMaxDecodedImageSizeMb[];
extern CONTENT_EXPORT const char kFieldTrialHandle[];
extern CONTENT_EXPORT const char kDisableKillAfterBadIPC[];
#if defined(OS_WIN)
extern CONTENT_EXPORT const char kEnableAcceleratedVpxDecode[];
extern CONTENT_EXPORT const char kDisableLowLatencyDxva[];
extern CONTENT_EXPORT const char kDisableZeroCopyDxgiVideo[];
extern CONTENT_EXPORT const char kDisableNv12DxgiVideo[];
extern CONTENT_EXPORT const char kNotificationInlineReply[];
extern CONTENT_EXPORT const char kNotificationLaunchId[];
extern CONTENT_EXPORT const char kWaitForDebuggerChildren[];
extern CONTENT_EXPORT const char kDeviceScaleFactor[];
#endif

extern CONTENT_EXPORT const char kDisablePartialRaster[];
extern CONTENT_EXPORT const char kEnablePartialRaster[];
extern CONTENT_EXPORT const char kDisableGpuMemoryBufferCompositorResources[];
extern CONTENT_EXPORT const char kDisableDomainBlockingFor3DAPIs[];
extern CONTENT_EXPORT const char kNoZygote[];
extern CONTENT_EXPORT const char kZygoteCmdPrefix[];
extern CONTENT_EXPORT const char kZygoteProcess[];
extern CONTENT_EXPORT const char kUtilityCmdPrefix[];
extern CONTENT_EXPORT const char kEnableVulkan[];
extern CONTENT_EXPORT const char kWebRtcLocalEventLogging[];
extern CONTENT_EXPORT const char kEnableBlinkFeatures[];
extern CONTENT_EXPORT const char kDisableBlinkFeatures[];
extern CONTENT_EXPORT const char kMessageLoopTypeUi[];

CONTENT_EXPORT extern const char kJavaScriptFlags[];
CONTENT_EXPORT extern const char kJavaScriptHarmony[];
CONTENT_EXPORT extern const base::Feature kModuleScriptsDynamicImport;
CONTENT_EXPORT extern const base::Feature kModuleScriptsImportMetaUrl;
CONTENT_EXPORT extern const base::Feature kAsmJsToWebAssembly;
CONTENT_EXPORT extern const base::Feature kWebAssembly;
CONTENT_EXPORT extern const base::Feature kWebAssemblyStreaming;
CONTENT_EXPORT extern const base::Feature kWebAssemblyTrapHandler;
CONTENT_EXPORT extern const char kDisableJavaScriptHarmonyShipping[];
CONTENT_EXPORT extern const base::Feature kV8VmFuture;
//CONTENT_EXPORT extern const base::Feature kWebAssemblyBaseline;
CONTENT_EXPORT extern const base::Feature kSharedArrayBuffer;
CONTENT_EXPORT extern const base::Feature kWebAssemblyTrapHandler;

CONTENT_EXPORT extern const char kWebRtcMaxCaptureFramerate[];
extern const char kWebRtcMaxCpuConsumptionPercentage[];
CONTENT_EXPORT extern const char kWebRtcStunProbeTrialParameter[];
CONTENT_EXPORT extern const char kWebRtcLocalEventLogging[];

CONTENT_EXPORT extern const char kProfilePath[];
CONTENT_EXPORT extern const char kWorkspaceId[];
CONTENT_EXPORT extern const char kAdminServiceHost[];
CONTENT_EXPORT extern const char kAdminServicePort[];

//from ui/base/ui_base_switches.h
//extern CONTENT_EXPORT const char kViewerConnect[];
}

#endif