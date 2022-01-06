// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/gpu/content_gpu_client_impl.h"

#include <string>
#include <utility>

#include "base/threading/thread_task_runner_handle.h"
#include "base/time/time.h"
#include "build/build_config.h"
#include "core/shared/common/child_thread.h"
#include "mojo/public/cpp/bindings/strong_binding.h"

#if BUILDFLAG(ENABLE_LIBRARY_CDMS)
#include "media/cdm/cdm_paths.h"
#include "media/cdm/library_cdm/clear_key_cdm/clear_key_cdm_proxy.h"
#include "widevine_cdm_version.h"  // In SHARED_INTERMEDIATE_DIR.
//#if defined(WIDEVINE_CDM_AVAILABLE) && defined(OS_WIN)
//#include "chrome/gpu/widevine_cdm_proxy_factory.h"
//#include "third_party/widevine/cdm/widevine_cdm_common.h"
//#endif  // defined(WIDEVINE_CDM_AVAILABLE) && defined(OS_WIN)
#endif  // BUILDFLAG(ENABLE_LIBRARY_CDMS)

#if defined(OS_CHROMEOS)
#include "components/arc/video_accelerator/gpu_arc_video_decode_accelerator.h"
#include "components/arc/video_accelerator/gpu_arc_video_encode_accelerator.h"
#include "components/arc/video_accelerator/gpu_arc_video_protected_buffer_allocator.h"
#include "components/arc/video_accelerator/protected_buffer_manager.h"
#include "components/arc/video_accelerator/protected_buffer_manager_proxy.h"
#include "core/shared/common/service_manager_connection.h"
#include "services/service_manager/public/cpp/binder_registry.h"
#include "ui/ozone/public/ozone_platform.h"
#include "ui/ozone/public/surface_factory_ozone.h"
#endif

namespace gpu {

ContentGpuClientImpl::ContentGpuClientImpl()
   {// : main_thread_profiler_(ThreadProfiler::CreateAndStartOnMainThread()) {
#if defined(OS_CHROMEOS)
  protected_buffer_manager_ = new arc::ProtectedBufferManager();
#endif
}

ContentGpuClientImpl::~ContentGpuClientImpl() {}

void ContentGpuClientImpl::InitializeRegistry(
    service_manager::BinderRegistry* registry) {
#if defined(OS_CHROMEOS)
  registry->AddInterface(
      base::Bind(&ContentGpuClientImpl::CreateArcVideoDecodeAccelerator,
                 base::Unretained(this)),
      base::ThreadTaskRunnerHandle::Get());
  registry->AddInterface(
      base::Bind(&ContentGpuClientImpl::CreateArcVideoEncodeAccelerator,
                 base::Unretained(this)),
      base::ThreadTaskRunnerHandle::Get());
  registry->AddInterface(
      base::Bind(
          &ContentGpuClientImpl::CreateArcVideoProtectedBufferAllocator,
          base::Unretained(this)),
      base::ThreadTaskRunnerHandle::Get());
  registry->AddInterface(
      base::Bind(&ContentGpuClientImpl::CreateProtectedBufferManager,
                 base::Unretained(this)),
      base::ThreadTaskRunnerHandle::Get());
#endif
}

void ContentGpuClientImpl::GpuServiceInitialized(
    const gpu::GpuPreferences& gpu_preferences) {
#if defined(OS_CHROMEOS)
  gpu_preferences_ = gpu_preferences;
  ui::OzonePlatform::GetInstance()
      ->GetSurfaceFactoryOzone()
      ->SetGetProtectedNativePixmapDelegate(
          base::Bind(&arc::ProtectedBufferManager::GetProtectedNativePixmapFor,
                     base::Unretained(protected_buffer_manager_.get())));
#endif

  //main_thread_profiler_->SetMainThreadTaskRunner(
   //   base::ThreadTaskRunnerHandle::Get());
  //ThreadProfiler::SetServiceManagerConnectorForChildProcess(
  //    content::ChildThread::Get()->GetConnector());
}

void ContentGpuClientImpl::PostIOThreadCreated(
    base::SingleThreadTaskRunner* io_task_runner) {
  //io_task_runner->PostTask(
  //    FROM_HERE, base::BindOnce(&ThreadProfiler::StartOnChildThread,
  //                              metrics::CallStackProfileParams::IO_THREAD));
}

void ContentGpuClientImpl::PostCompositorThreadCreated(
    base::SingleThreadTaskRunner* task_runner) {
  //task_runner->PostTask(
  //    FROM_HERE,
  //    base::BindOnce(&ThreadProfiler::StartOnChildThread,
  //                   metrics::CallStackProfileParams::COMPOSITOR_THREAD));
}

#if BUILDFLAG(ENABLE_LIBRARY_CDMS)
std::unique_ptr<media::CdmProxy> ContentGpuClientImpl::CreateCdmProxy(
    const std::string& cdm_guid) {
  if (cdm_guid == media::kClearKeyCdmGuid)
    return std::make_unique<media::ClearKeyCdmProxy>();

#if defined(WIDEVINE_CDM_AVAILABLE) && defined(OS_WIN)
  if (cdm_guid == kWidevineCdmGuid)
    return CreateWidevineCdmProxy();
#endif  // defined(WIDEVINE_CDM_AVAILABLE) && defined(OS_WIN)

  return nullptr;
}
#endif  // BUILDFLAG(ENABLE_LIBRARY_CDMS)

#if defined(OS_CHROMEOS)
void ContentGpuClientImpl::CreateArcVideoDecodeAccelerator(
    ::arc::mojom::VideoDecodeAcceleratorRequest request) {
  mojo::MakeStrongBinding(std::make_unique<arc::GpuArcVideoDecodeAccelerator>(
                              gpu_preferences_, protected_buffer_manager_),
                          std::move(request));
}

void ContentGpuClientImpl::CreateArcVideoEncodeAccelerator(
    ::arc::mojom::VideoEncodeAcceleratorRequest request) {
  mojo::MakeStrongBinding(
      std::make_unique<arc::GpuArcVideoEncodeAccelerator>(gpu_preferences_),
      std::move(request));
}

void ContentGpuClientImpl::CreateArcVideoProtectedBufferAllocator(
    ::arc::mojom::VideoProtectedBufferAllocatorRequest request) {
  auto gpu_arc_video_protected_buffer_allocator =
      arc::GpuArcVideoProtectedBufferAllocator::Create(
          protected_buffer_manager_);
  if (!gpu_arc_video_protected_buffer_allocator)
    return;
  mojo::MakeStrongBinding(std::move(gpu_arc_video_protected_buffer_allocator),
                          std::move(request));
}

void ContentGpuClientImpl::CreateProtectedBufferManager(
    ::arc::mojom::ProtectedBufferManagerRequest request) {
  mojo::MakeStrongBinding(
      std::make_unique<arc::GpuArcProtectedBufferManagerProxy>(
          protected_buffer_manager_),
      std::move(request));
}
#endif

}