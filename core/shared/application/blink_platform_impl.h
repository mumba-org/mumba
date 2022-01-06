// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_APPLICATION_BLINK_PLATFORM_IMPL_H_
#define MUMBA_APPLICATION_BLINK_PLATFORM_IMPL_H_

#include <stddef.h>
#include <stdint.h>

#include "base/compiler_specific.h"
#include "base/single_thread_task_runner.h"
#include "base/threading/thread_local_storage.h"
#include "base/timer/timer.h"
#include "base/trace_event/trace_event.h"
#include "build/build_config.h"
#include "components/webcrypto/webcrypto_impl.h"
#include "cc/blink/web_compositor_support_impl.h"
#include "core/shared/common/webfallbackthemeengine_impl.h"
#include "core/shared/common/content_export.h"
#include "core/shared/common/possibly_associated_interface_ptr.h"
#include "core/shared/application/top_level_blame_context.h"
#include "media/blink/webmediacapabilitiesclient_impl.h"
#include "services/network/public/mojom/url_loader_factory.mojom.h"
#include "services/service_manager/public/cpp/interface_provider.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/web_gesture_device.h"
#include "third_party/blink/public/platform/web_url_error.h"
#include "third_party/blink/public/public_buildflags.h"
#include "ui/base/layout.h"
#include "runtime/MumbaShims/ApplicationHandler.h"

#if BUILDFLAG(USE_DEFAULT_RENDER_THEME)
#include "core/shared/common/webthemeengine_impl_default.h"
#elif defined(OS_WIN)
#include "core/shared/common/webthemeengine_impl_win.h"
#elif defined(OS_MACOSX)
#include "core/shared/common/webthemeengine_impl_mac.h"
#elif defined(OS_ANDROID)
#include "core/shared/common/webthemeengine_impl_android.h"
#endif

namespace base {
class WaitableEvent;
}

namespace blink {
namespace scheduler {
class WebThreadBase;
class WebMainThreadScheduler;
}
}

namespace IPC {
class SyncMessageFilter;  
}

namespace application {
class ThreadSafeSender;
class WebCryptoImpl;
class ApplicationThread;
class ChildURLLoaderFactoryBundle;
class BlinkInterfaceProviderImpl;
class WebBlobRegistryImpl;

class CONTENT_EXPORT BlinkPlatformImpl : public blink::Platform {
 public:
  BlinkPlatformImpl(
    ApplicationThread* thread,
    blink::scheduler::WebMainThreadScheduler* main_thread_scheduler,
    CApplicationCallbacks callbacks,
    void* state);
  ~BlinkPlatformImpl() override;


  scoped_refptr<cc::TextureLayer> GetExternalTextureLayerForCanvas(cc::TextureLayerClient* canvas_client) override;
  void SetExternalTextureLayerForCanvas(const blink::WebString& target, scoped_refptr<cc::TextureLayer>) override;
  void SetExternalTextureLayerForCanvas(const blink::WebString& target, scoped_refptr<cc::TextureLayer>, cc::TextureLayerClient* application_client);
  void OnExternalTextureLayerForCanvasInjected(cc::TextureLayerClient* client) override;
  
  // Platform methods (partial implementation):
  blink::WebThemeEngine* ThemeEngine() override;
  blink::WebFallbackThemeEngine* FallbackThemeEngine() override;
  blink::Platform::FileHandle DatabaseOpenFile(
      const blink::WebString& vfs_file_name,
      int desired_flags) override;
  int DatabaseDeleteFile(const blink::WebString& vfs_file_name,
                         bool sync_dir) override;
  long DatabaseGetFileAttributes(
      const blink::WebString& vfs_file_name) override;
  long long DatabaseGetFileSize(const blink::WebString& vfs_file_name) override;
  long long DatabaseGetSpaceAvailableForOrigin(
      const blink::WebSecurityOrigin& origin) override;
  bool DatabaseSetFileSize(const blink::WebString& vfs_file_name,
                           long long size) override;
  size_t NumberOfProcessors() override;

  size_t MaxDecodedImageBytes() override;
  bool IsLowEndDevice() override;
  uint32_t GetUniqueIdForProcess() override;
  blink::WebString UserAgent() override;
  std::unique_ptr<blink::WebThread> CreateThread(
      const blink::WebThreadCreationParams& params) override;
  std::unique_ptr<blink::WebThread> CreateWebAudioThread() override;
  blink::WebThread* CurrentThread() override;
  blink::BlameContext* GetTopLevelBlameContext() override;
  void RecordAction(const blink::UserMetricsAction&) override;
  blink::WebThread* CompositorThread() const override;
  blink::WebData GetDataResource(const char* name) override;
  blink::WebString QueryLocalizedString(
      blink::WebLocalizedString::Name name) override;
  virtual blink::WebString queryLocalizedString(
      blink::WebLocalizedString::Name name,
      int numeric_value);
  viz::FrameSinkId GenerateFrameSinkId() override;
  bool IsThreadedCompositingEnabled() override;
  bool IsThreadedAnimationEnabled() override;
  bool IsGpuCompositingDisabled() override;
  base::Optional<std::string> WebRtcStunProbeTrialParameter();
  std::unique_ptr<blink::WebGraphicsContext3DProvider>
  CreateOffscreenGraphicsContext3DProvider(    
      const blink::Platform::ContextAttributes& attributes,
      const blink::WebURL& top_document_web_url,
      blink::Platform::GraphicsInfo* gl_info) override;
  std::unique_ptr<blink::WebGraphicsContext3DProvider>
  CreateSharedOffscreenGraphicsContext3DProvider() override;
  gpu::GpuMemoryBufferManager* GetGpuMemoryBufferManager() override;
  blink::WebCompositorSupport* CompositorSupport() override;
  service_manager::Connector* GetConnector() override;
  blink::InterfaceProvider* GetInterfaceProvider() override;
  blink::WebString QueryLocalizedString(blink::WebLocalizedString::Name name,
                                        const blink::WebString& value) override;
  blink::WebString QueryLocalizedString(
      blink::WebLocalizedString::Name name,
      const blink::WebString& value1,
      const blink::WebString& value2) override;
  // Returns a value such as "en-US".
  blink::WebString DefaultLocale() override { 
    return blink::WebString("en-US"); 
  }
  void SuddenTerminationChanged(bool enabled) override {}
  bool IsRendererSideResourceSchedulerEnabled() const final;
  std::unique_ptr<blink::WebGestureCurve> CreateFlingAnimationCurve(
      blink::WebGestureDevice device_source,
      const blink::WebFloatPoint& velocity,
      const blink::WebSize& cumulative_scroll) override;
  bool AllowScriptExtensionForServiceWorker(
      const blink::WebURL& script_url) override;
  blink::WebCrypto* Crypto() override;
  const char* GetBrowserServiceName() const override;
  blink::WebBlobRegistry* GetBlobRegistry() override;
  blink::WebMediaCapabilitiesClient* MediaCapabilitiesClient() override;

  blink::WebString DomCodeStringFromEnum(int dom_code) override;
  int DomEnumFromCodeString(const blink::WebString& codeString) override;
  blink::WebString DomKeyStringFromEnum(int dom_key) override;
  int DomKeyEnumFromString(const blink::WebString& key_string) override;
  bool IsDomKeyForModifier(int dom_key) override;

  void WaitUntilWebThreadTLSUpdate(blink::scheduler::WebThreadBase* thread);

  scoped_refptr<base::SingleThreadTaskRunner> GetIOTaskRunner() const override;
  std::unique_ptr<NestedMessageLoopRunner> CreateNestedMessageLoopRunner()
      const override;

  std::unique_ptr<blink::WebURLLoaderFactory> CreateDefaultURLLoaderFactory() override;
  std::unique_ptr<blink::WebDataConsumerHandle> CreateDataConsumerHandle(
      mojo::ScopedDataPipeConsumerHandle handle) override;
  //std::unique_ptr<blink::WebURLLoaderFactory> WrapURLLoaderFactory(
  //    mojo::ScopedMessagePipeHandle url_loader_factory_handle) override;

  void DidStartWorkerThread() override;
  void WillStopWorkerThread() override;
  void WorkerContextCreated(const v8::Local<v8::Context>& worker) override;

  void SetCompositorThread(blink::scheduler::WebThreadBase* compositor_thread);    

  scoped_refptr<ChildURLLoaderFactoryBundle> CreateDefaultURLLoaderFactoryBundle();
  common::PossiblyAssociatedInterfacePtr<network::mojom::URLLoaderFactory>
    CreateNetworkURLLoaderFactory();

  std::unique_ptr<blink::WebServiceWorkerCacheStorage> CreateCacheStorage(
      service_manager::InterfaceProvider* mojo_provider);

 private:

  struct TextureItem {
    std::string target_name;
    scoped_refptr<cc::TextureLayer> texture_layer;
    cc::TextureLayerClient* canvas_client = nullptr;
    cc::TextureLayerClient* application_client = nullptr;
  };

  void UpdateWebThreadTLS(blink::WebThread* thread, base::WaitableEvent* event);

  bool IsMainThread() const;

  ApplicationThread* thread_;
  scoped_refptr<base::SingleThreadTaskRunner> main_thread_task_runner_;
  scoped_refptr<base::SingleThreadTaskRunner> io_thread_task_runner_;
  
  blink::scheduler::WebThreadBase* compositor_thread_;
  std::unique_ptr<blink::WebThread> main_thread_;
  
  common::WebThemeEngineImpl native_theme_engine_;
  common::WebFallbackThemeEngineImpl fallback_theme_engine_;
  base::ThreadLocalStorage::Slot current_thread_slot_;
  webcrypto::WebCryptoImpl web_crypto_;
  media::WebMediaCapabilitiesClientImpl media_capabilities_client_;

  std::unique_ptr<service_manager::Connector> connector_;

  scoped_refptr<base::SingleThreadTaskRunner> default_task_runner_;
  scoped_refptr<IPC::SyncMessageFilter> sync_message_filter_;
  scoped_refptr<ThreadSafeSender> thread_safe_sender_;

  cc_blink::WebCompositorSupportImpl compositor_support_;

  std::unique_ptr<BlinkInterfaceProviderImpl> blink_interface_provider_;

  std::unique_ptr<WebBlobRegistryImpl> blob_registry_;

  TopLevelBlameContext top_level_blame_context_;
  blink::scheduler::WebMainThreadScheduler* main_thread_scheduler_;

  std::vector<std::unique_ptr<TextureItem>> texture_layers_;

  base::Lock texture_vector_lock_;
  
  CApplicationCallbacks callbacks_;
  void* state_;

  DISALLOW_COPY_AND_ASSIGN(BlinkPlatformImpl);
};

}  // namespace application

#endif  // CONTENT_CHILD_BLINK_PLATFORM_IMPL_H_
