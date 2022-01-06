// Copyright 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/domain/main_shadow_page.h"

#include "core/shared/common/frame_sink_provider.mojom.h"
#include "third_party/blink/public/mojom/page/page_visibility_state.mojom-blink.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/web/web_settings.h"
#include "third_party/blink/public/web/web_frame_widget.h"
#include "third_party/blink/renderer/core/exported/web_view_impl.h"
#include "third_party/blink/renderer/core/frame/csp/content_security_policy.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/loader/frame_load_request.h"
#include "third_party/blink/renderer/platform/loader/fetch/substitute_data.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "cc/trees/layer_tree_host.h"
#include "cc/trees/ukm_manager.h"
#include "cc/trees/layer_tree_frame_sink.h"
#include "components/viz/client/client_layer_tree_frame_sink.h"
#include "components/viz/client/hit_test_data_provider_surface_layer.h"
#include "components/viz/client/hit_test_data_provider_draw_quad.h"
#include "components/viz/common/features.h"
#include "components/viz/client/local_surface_id_provider.h"
#include "core/shared/common/gpu_stream_constants.h"
#include "services/ui/public/cpp/gpu/context_provider_command_buffer.h"
#include "services/ui/public/cpp/gpu/gpu.h"
#include "services/ui/public/interfaces/constants.mojom.h"
#include "gpu/GLES2/gl2extchromium.h"
#include "gpu/command_buffer/client/gles2_interface.h"
#include "gpu/command_buffer/client/raster_interface.h"
#include "gpu/command_buffer/client/shared_memory_limits.h"
#include "gpu/config/gpu_switches.h"
#include "gpu/ipc/client/command_buffer_proxy_impl.h"
#include "gpu/ipc/client/gpu_channel_host.h"
#include "core/shared/common/application_window_surface_properties.h"
#include "ui/native_theme/native_theme_features.h"
#include "ui/native_theme/overlay_scrollbar_constants_aura.h"
#include "services/metrics/public/cpp/mojo_ukm_recorder.h"
#include "core/domain/layer_tree_view.h"

namespace domain {

namespace {

class DomainLocalSurfaceIdProvider : public viz::LocalSurfaceIdProvider {
 public:
  const viz::LocalSurfaceId& GetLocalSurfaceIdForFrame(
      const viz::CompositorFrame& frame) override {
    auto new_surface_properties =
        common::ApplicationWindowSurfaceProperties::FromCompositorFrame(frame);
    if (!parent_local_surface_id_allocator_.GetCurrentLocalSurfaceId()
             .is_valid() ||
        new_surface_properties != surface_properties_) {
      parent_local_surface_id_allocator_.GenerateId();
      surface_properties_ = new_surface_properties;
    }
    return parent_local_surface_id_allocator_.GetCurrentLocalSurfaceId();
  }

 private:
  viz::ParentLocalSurfaceIdAllocator parent_local_surface_id_allocator_;
  common::ApplicationWindowSurfaceProperties surface_properties_;
};

}

cc::LayerTreeSettings MainShadowPage::GenerateLayerTreeSettings(
  common::CompositorDependencies* compositor_deps,
  bool is_for_subframe,
  const gfx::Size& initial_screen_size,
  float initial_device_scale_factor) {
  cc::LayerTreeSettings settings;
  const bool is_threaded = !!compositor_deps->GetCompositorImplThreadTaskRunner();
  
  settings.resource_settings.use_r16_texture = false;
      //base::FeatureList::IsEnabled(media::kUseR16Texture);

  settings.commit_to_active_tree = !is_threaded;
  settings.is_layer_tree_for_subframe = is_for_subframe;

  // For web contents, layer transforms should scale up the contents of layers
  // to keep content always crisp when possible.
  settings.layer_transforms_should_scale_layer_contents = true;

  // settings.main_frame_before_activation_enabled =
  //     cmd.HasSwitch(cc::switches::kEnableMainFrameBeforeActivation);

  settings.enable_checker_imaging = false;
      //cmd.HasSwitch(cc::switches::kEnableCheckerImaging);
#if defined(OS_ANDROID)
  // We can use a more aggressive limit on Android since decodes tend to take
  // longer on these devices.
  settings.min_image_bytes_to_checker = 512 * 1024;  // 512kB

  // Re-rasterization of checker-imaged content with software raster can be too
  // costly on Android.
  settings.only_checker_images_with_gpu_raster = true;
#endif

  // TODO(danakj): This should not be a setting O_O; it should change when the
  // device scale factor on LayerTreeHost changes.
  settings.default_tile_size = gfx::Size(256, 256);//CalculateDefaultTileSize(screen_info);
  // if (cmd.HasSwitch(switches::kDefaultTileWidth)) {
  //   int tile_width = 0;
  //   GetSwitchValueAsInt(cmd, switches::kDefaultTileWidth, 1,
  //                       std::numeric_limits<int>::max(), &tile_width);
  //   settings.default_tile_size.set_width(tile_width);
  // }
  // if (cmd.HasSwitch(switches::kDefaultTileHeight)) {
  //   int tile_height = 0;
  //   GetSwitchValueAsInt(cmd, switches::kDefaultTileHeight, 1,
  //                       std::numeric_limits<int>::max(), &tile_height);
  //   settings.default_tile_size.set_height(tile_height);
  // }

  int max_untiled_layer_width = settings.max_untiled_layer_size.width();
  // if (cmd.HasSwitch(switches::kMaxUntiledLayerWidth)) {
  //   GetSwitchValueAsInt(cmd, switches::kMaxUntiledLayerWidth, 1,
  //                       std::numeric_limits<int>::max(),
  //                       &max_untiled_layer_width);
  // }
  int max_untiled_layer_height = settings.max_untiled_layer_size.height();
  // if (cmd.HasSwitch(switches::kMaxUntiledLayerHeight)) {
  //   GetSwitchValueAsInt(cmd, switches::kMaxUntiledLayerHeight, 1,
  //                       std::numeric_limits<int>::max(),
  //                       &max_untiled_layer_height);
  // }

  settings.max_untiled_layer_size =
      gfx::Size(max_untiled_layer_width, max_untiled_layer_height);

  settings.gpu_rasterization_msaa_sample_count =
      compositor_deps->GetGpuRasterizationMSAASampleCount();
  settings.gpu_rasterization_forced =
      compositor_deps->IsGpuRasterizationForced();

  settings.can_use_lcd_text = compositor_deps->IsLcdTextEnabled();
  settings.use_zero_copy = compositor_deps->IsZeroCopyEnabled();
  settings.use_partial_raster = compositor_deps->IsPartialRasterEnabled();
  settings.enable_elastic_overscroll =
      compositor_deps->IsElasticOverscrollEnabled();
  settings.resource_settings.use_gpu_memory_buffer_resources =
      compositor_deps->IsGpuMemoryBufferCompositorResourcesEnabled();
  settings.enable_oop_rasterization = true;

  // Build LayerTreeSettings from command line args.
  //LayerTreeSettingsFactory::SetBrowserControlsSettings(settings, cmd);

  //settings.use_layer_lists = cmd.HasSwitch(cc::switches::kEnableLayerLists);

  // The means the renderer compositor has 2 possible modes:
  // - Threaded compositing with a scheduler.
  // - Single threaded compositing without a scheduler (for layout tests only).
  // Using the scheduler in layout tests introduces additional composite steps
  // that create flakiness.
  settings.single_thread_proxy_scheduler = false;

  // These flags should be mirrored by UI versions in ui/compositor/.
  // if (cmd.HasSwitch(cc::switches::kShowCompositedLayerBorders))
  //   settings.initial_debug_state.show_debug_borders.set();
  // settings.initial_debug_state.show_layer_animation_bounds_rects =
  //     cmd.HasSwitch(cc::switches::kShowLayerAnimationBounds);
  // settings.initial_debug_state.show_paint_rects =
  //     cmd.HasSwitch(switches::kShowPaintRects);
  // settings.initial_debug_state.show_property_changed_rects =
  //     cmd.HasSwitch(cc::switches::kShowPropertyChangedRects);
  // settings.initial_debug_state.show_surface_damage_rects =
  //     cmd.HasSwitch(cc::switches::kShowSurfaceDamageRects);
  // settings.initial_debug_state.show_screen_space_rects =
  //     cmd.HasSwitch(cc::switches::kShowScreenSpaceRects);

  // settings.initial_debug_state.SetRecordRenderingStats(
  //     cmd.HasSwitch(cc::switches::kEnableGpuBenchmarking));
  settings.enable_surface_synchronization = true;
      //features::IsSurfaceSynchronizationEnabled();

  // if (cmd.HasSwitch(cc::switches::kSlowDownRasterScaleFactor)) {
  //   const int kMinSlowDownScaleFactor = 0;
  //   const int kMaxSlowDownScaleFactor = INT_MAX;
  //   GetSwitchValueAsInt(
  //       cmd, cc::switches::kSlowDownRasterScaleFactor, kMinSlowDownScaleFactor,
  //       kMaxSlowDownScaleFactor,
  //       &settings.initial_debug_state.slow_down_raster_scale_factor);
  // }

  // This is default overlay scrollbar settings for Android and DevTools mobile
  // emulator. Aura Overlay Scrollbar will override below.
  settings.scrollbar_animator = cc::LayerTreeSettings::ANDROID_OVERLAY;
  settings.solid_color_scrollbar_color = SkColorSetARGB(128, 128, 128, 128);
  settings.scrollbar_fade_delay = base::TimeDelta::FromMilliseconds(300);
  settings.scrollbar_fade_duration = base::TimeDelta::FromMilliseconds(300);


#if defined(OS_ANDROID)
  bool using_synchronous_compositor =
      GetContentClient()->UsingSynchronousCompositing();
  bool using_low_memory_policy = base::SysInfo::IsLowEndDevice();

  settings.use_stream_video_draw_quad = true;
  settings.using_synchronous_renderer_compositor = using_synchronous_compositor;
  if (using_synchronous_compositor) {
    // Android WebView uses system scrollbars, so make ours invisible.
    // http://crbug.com/677348: This can't be done using hide_scrollbars
    // setting because supporting -webkit custom scrollbars is still desired
    // on sublayers.
    settings.scrollbar_animator = cc::LayerTreeSettings::NO_ANIMATOR;
    settings.solid_color_scrollbar_color = SK_ColorTRANSPARENT;

    settings.enable_early_damage_check =
        cmd.HasSwitch(cc::switches::kCheckDamageEarly);
  }
  // Android WebView handles root layer flings itself.
  settings.ignore_root_layer_flings = using_synchronous_compositor;
  // Memory policy on Android WebView does not depend on whether device is
  // low end, so always use default policy.
  if (using_low_memory_policy && !using_synchronous_compositor) {
    // On low-end we want to be very carefull about killing other
    // apps. So initially we use 50% more memory to avoid flickering
    // or raster-on-demand.
    settings.max_memory_for_prepaint_percentage = 67;
  } else {
    // On other devices we have increased memory excessively to avoid
    // raster-on-demand already, so now we reserve 50% _only_ to avoid
    // raster-on-demand, and use 50% of the memory otherwise.
    settings.max_memory_for_prepaint_percentage = 50;
  }

  // TODO(danakj): Only do this on low end devices.
  settings.create_low_res_tiling = true;

#else  // defined(OS_ANDROID)
  bool using_synchronous_compositor = false;  // Only for Android WebView.
  // On desktop, we never use the low memory policy unless we are simulating
  // low-end mode via a switch.
  bool using_low_memory_policy = false;
      //cmd.HasSwitch(switches::kEnableLowEndDeviceMode);

  if (ui::IsOverlayScrollbarEnabled()) {
    settings.scrollbar_animator = cc::LayerTreeSettings::AURA_OVERLAY;
    settings.scrollbar_fade_delay = ui::kOverlayScrollbarFadeDelay;
    settings.scrollbar_fade_duration = ui::kOverlayScrollbarFadeDuration;
    settings.scrollbar_thinning_duration =
        ui::kOverlayScrollbarThinningDuration;
    settings.scrollbar_flash_after_any_scroll_update =
        ui::OverlayScrollbarFlashAfterAnyScrollUpdate();
    settings.scrollbar_flash_when_mouse_enter =
        ui::OverlayScrollbarFlashWhenMouseEnter();
  }

  // On desktop, if there's over 4GB of memory on the machine, increase the
  // working set size to 256MB for both gpu and software.
  // const int kImageDecodeMemoryThresholdMB = 4 * 1024;
  // if (base::SysInfo::AmountOfPhysicalMemoryMB() >=
  //     kImageDecodeMemoryThresholdMB) {
  //   settings.decoded_image_working_set_budget_bytes = 256 * 1024 * 1024;
  // } else {
    // This is the default, but recorded here as well.
    settings.decoded_image_working_set_budget_bytes = 128 * 1024 * 1024;
  //}
#endif  // defined(OS_ANDROID)

  // if (using_low_memory_policy) {
  //   // RGBA_4444 textures are only enabled:
  //   //  - If the user hasn't explicitly disabled them
  //   //  - If system ram is <= 512MB (1GB devices are sometimes low-end).
  //   //  - If we are not running in a WebView, where 4444 isn't supported.
  //   if (!cmd.HasSwitch(switches::kDisableRGBA4444Textures) &&
  //       base::SysInfo::AmountOfPhysicalMemoryMB() <= 512 &&
  //       !using_synchronous_compositor) {
  //     settings.use_rgba_4444 = viz::RGBA_4444;

  //     // If we are going to unpremultiply and dither these tiles, we need to
  //     // allocate an additional RGBA_8888 intermediate for each tile
  //     // rasterization when rastering to RGBA_4444 to allow for dithering.
  //     // Setting a reasonable sized max tile size allows this intermediate to
  //     // be consistently reused.
  //     if (base::FeatureList::IsEnabled(
  //             kUnpremultiplyAndDitherLowBitDepthTiles)) {
  //       settings.max_gpu_raster_tile_size = gfx::Size(512, 256);
  //       settings.unpremultiply_and_dither_low_bit_depth_tiles = true;
  //     }
  //   }
  // }

  // if (cmd.HasSwitch(switches::kEnableLowResTiling))
  //   settings.create_low_res_tiling = true;
  // if (cmd.HasSwitch(switches::kDisableLowResTiling))
  //   settings.create_low_res_tiling = false;

  // if (cmd.HasSwitch(switches::kEnableRGBA4444Textures) &&
  //     !cmd.HasSwitch(switches::kDisableRGBA4444Textures)) {
  //settings.use_rgba_4444 = true;
  //}

  settings.use_rgba_4444 = false;

  settings.max_staging_buffer_usage_in_bytes = 32 * 1024 * 1024;  // 32MB

  cc::ManagedMemoryPolicy defaults = settings.memory_policy;
  defaults.bytes_limit_when_visible = 512 * 1024 * 1024;
  defaults.priority_cutoff_when_visible =
      gpu::MemoryAllocation::CUTOFF_ALLOW_NICE_TO_HAVE;
  settings.memory_policy = defaults;

  settings.disallow_non_exact_resource_reuse = false;
      //cmd.HasSwitch(switches::kDisallowNonExactResourceReuse);
#if defined(OS_ANDROID)
  // TODO(crbug.com/746931): This feature appears to be causing visual
  // corruption on certain android devices. Will investigate and re-enable.
  settings.disallow_non_exact_resource_reuse = true;
#endif

  // if (cmd.HasSwitch(switches::kRunAllCompositorStagesBeforeDraw)) {
  //   settings.wait_for_all_pipeline_stages_before_draw = true;
  //   settings.enable_latency_recovery = false;
  // }

  settings.enable_image_animation_resync = true;
      //!cmd.HasSwitch(switches::kDisableImageAnimationResync);

  settings.always_request_presentation_time = false;
      //cmd.HasSwitch(cc::switches::kAlwaysRequestPresentationTime);

  settings.use_painted_device_scale_factor = false;

  settings.use_layer_lists = true;
  settings.main_frame_before_activation_enabled = true;

  return settings;
}

MainShadowPage::MainShadowPage(MainShadowPageDelegate* delegate, common::ScreenInfo screen_info, float device_scale_factor)
    : delegate_(delegate),
      screen_info_(screen_info),
      device_scale_factor_(device_scale_factor),
      initialized_(false) {
  DCHECK(IsMainThread());
}

MainShadowPage::~MainShadowPage() {
  DCHECK(IsMainThread());
  // Detach the client before closing the view to avoid getting called back.
  main_frame_->SetClient(nullptr);
  web_view_->Close();
  main_frame_->Close();
}

void MainShadowPage::Initialize() {
  String script_url = String::FromUTF8("about://blank");
  DCHECK(IsMainThread());

  web_view_ = blink::WebViewImpl::Create(this,
                                    blink::mojom::PageVisibilityState::kVisible,
                                    nullptr);

  main_frame_ = blink::WebLocalFrameImpl::CreateMainFrame(web_view_,
                                                  this,
                                                  nullptr,
                                                  nullptr,
                                                  g_empty_atom,
                                                  blink::WebSandboxFlags::kNone);
  //web_view_->GetSettings()->SetAcceleratedCompositingEnabled(false);
  web_view_->GetSettings()->SetAcceleratedCompositingEnabled(true);
  main_frame_->GetFrame()->GetSettings()->SetIsShadowPage(true);
  
  widget_ = blink::WebFrameWidget::Create(this, static_cast<blink::WebLocalFrame *>(blink::WebLocalFrame::FromFrame(main_frame_->GetFrame())));

  // Construct substitute data source. We only need it to have same origin as
  // the worker so the loading checks work correctly.
  CString content("");
  scoped_refptr<blink::SharedBuffer> buffer(
      blink::SharedBuffer::Create(content.data(), content.length()));
  main_frame_->GetFrame()->Loader().Load(blink::FrameLoadRequest(
      nullptr, blink::ResourceRequest(script_url), blink::SubstituteData(buffer)));
}

void MainShadowPage::SetContentSecurityPolicyAndReferrerPolicy(
    blink::ContentSecurityPolicy* content_security_policy,
    String referrer_policy) {
  DCHECK(IsMainThread());
  content_security_policy->SetOverrideURLForSelf(GetDocument()->Url());
  GetDocument()->InitContentSecurityPolicy(content_security_policy);
  if (!referrer_policy.IsNull())
    GetDocument()->ParseAndSetReferrerPolicy(referrer_policy);
}

void MainShadowPage::DidFinishDocumentLoad() {
  base::ScopedAllowBaseSyncPrimitivesForTesting scoped_allow_sync;
  DCHECK(IsMainThread());
  initialized_ = true;
  delegate_->OnMainShadowPageInitialized();
}

std::unique_ptr<blink::WebApplicationCacheHost>
MainShadowPage::CreateApplicationCacheHost(
    blink::WebApplicationCacheHostClient* appcache_host_client) {
  DCHECK(IsMainThread());
  return delegate_->CreateApplicationCacheHost(appcache_host_client);
}

std::unique_ptr<blink::WebURLLoaderFactory>
MainShadowPage::CreateURLLoaderFactory() {
  DCHECK(IsMainThread());
  return blink::Platform::Current()->CreateDefaultURLLoaderFactory();
}

base::UnguessableToken MainShadowPage::GetDevToolsFrameToken() {
  // TODO(dgozman): instrumentation token will have to be passed directly to
  // DevTools once we stop using a frame for workers. Currently, we rely on
  // the frame's instrumentation token to match the worker.
  return delegate_->GetDevToolsWorkerToken();
}

blink::WebLayerTreeView* MainShadowPage::InitializeLayerTreeView() {
  DCHECK(delegate_);
  layer_tree_view_ = std::make_unique<LayerTreeView>(
    this,
    delegate_->GetCompositorMainThreadTaskRunner(),
    delegate_->GetCompositorImplThreadTaskRunner(),
    delegate_->GetTaskGraphRunner(),
    delegate_->GetWebMainThreadScheduler());
  layer_tree_view_->Initialize(
      GenerateLayerTreeSettings(delegate_, false,
                                screen_info_.rect.size(),
                                device_scale_factor_),
                                delegate_->CreateUkmRecorderFactory());
  layer_tree_host_ = layer_tree_view_->layer_tree_host();
  layer_tree_host_->SetViewportSizeAndScale(
      //compositor_viewport_pixel_rect.size(),
      screen_info_.rect.size(),
      device_scale_factor_,
      local_surface_id_allocation_from_parent_);
  layer_tree_host_->SetViewportVisibleRect(screen_info_.rect);//ViewportVisibleRect());
  layer_tree_host_->SetRasterColorSpace(
      screen_info_.color_space.GetRasterColorSpace());
  
  layer_tree_view_->SetVisible(false);
  return layer_tree_view_.get();
}

std::unique_ptr<blink::WebSocketHandshakeThrottle>
MainShadowPage::CreateWebSocketHandshakeThrottle() {
  return blink::Platform::Current()->CreateWebSocketHandshakeThrottle();
}

bool MainShadowPage::WasInitialized() const {
  return initialized_;
}

blink::Document* MainShadowPage::GetDocument() { 
  return main_frame_->GetFrame()->GetDocument(); 
}

blink::WebDocumentLoader* MainShadowPage::DocumentLoader() {
  return main_frame_->GetDocumentLoader();
}

void MainShadowPage::ApplyViewportDeltas(
      const gfx::Vector2dF& inner_delta,
      const gfx::Vector2dF& outer_delta,
      const gfx::Vector2dF& elastic_overscroll_delta,
      float page_scale,
      float top_controls_delta) {
  
}

void MainShadowPage::RecordWheelAndTouchScrollingCount(
    bool has_scrolled_by_wheel,
    bool has_scrolled_by_touch) {}

void MainShadowPage::BeginMainFrame(base::TimeTicks frame_time) {
  web_view_->BeginFrame(frame_time);
}

void MainShadowPage::RequestNewLayerTreeFrameSink(
    LayerTreeFrameSinkCallback callback) {
  viz::ClientLayerTreeFrameSink::InitParams params;
  params.compositor_task_runner = delegate_->GetCompositorImplThreadTaskRunner();
  params.enable_surface_synchronization = true;
      //features::IsSurfaceSynchronizationEnabled();
  params.local_surface_id_provider =
      std::make_unique<DomainLocalSurfaceIdProvider>();
  if (features::IsVizHitTestingDrawQuadEnabled()) {
    params.hit_test_data_provider =
        std::make_unique<viz::HitTestDataProviderDrawQuad>(
            true /* should_ask_for_child_region */);
  } else if (features::IsVizHitTestingSurfaceLayerEnabled()) {
    params.hit_test_data_provider =
      std::make_unique<viz::HitTestDataProviderSurfaceLayer>();
  }

  // The renderer runs animations and layout for animate_only BeginFrames.
  params.wants_animate_only_begin_frames = true;

  viz::mojom::CompositorFrameSinkRequest compositor_frame_sink_request =
      mojo::MakeRequest(&params.pipes.compositor_frame_sink_info);
  viz::mojom::CompositorFrameSinkClientPtr compositor_frame_sink_client;
  params.pipes.client_request =
      mojo::MakeRequest(&compositor_frame_sink_client);

  // if (is_gpu_compositing_disabled_) {
  //   //DLOG(ERROR) << "ApplicationThread::RequestNewLayerTreeFrameSink: BAD is_gpu_compositing_disabled_ = true";   
  //   callback.Run(std::make_unique<viz::ClientLayerTreeFrameSink>(
  //       nullptr, nullptr, &params));
  //   return;
  // }

  scoped_refptr<gpu::GpuChannelHost> gpu_channel_host = delegate_->EstablishGpuChannelSync();
  if (!gpu_channel_host) {
    // Wait and try again. We may hear that the compositing mode has switched
    // to software in the meantime.
    std::move(callback).Run(nullptr);
    return;
  }

  scoped_refptr<viz::RasterContextProvider> worker_context_provider = delegate_->SharedCompositorWorkerContextProvider();
  if (!worker_context_provider) {
    // Cause the compositor to wait and try again.
    std::move(callback).Run(nullptr);
    return;
  }

  // The renderer compositor context doesn't do a lot of stuff, so we don't
  // expect it to need a lot of space for commands or transfer. Raster and
  // uploads happen on the worker context instead.
  gpu::SharedMemoryLimits limits = gpu::SharedMemoryLimits::ForMailboxContext();

  // This is for an offscreen context for the compositor. So the default
  // framebuffer doesn't need alpha, depth, stencil, antialiasing.
  
  gpu::ContextCreationAttribs attributes;
  attributes.alpha_size = -1;
  attributes.depth_size = 0;
  attributes.stencil_size = 0;
  attributes.samples = 0;
  attributes.sample_buffers = 0;
  attributes.bind_generates_resource = false;
  attributes.lose_context_when_out_of_memory = true;
  attributes.enable_gles2_interface = true;
  attributes.enable_raster_interface = false;
  attributes.enable_oop_rasterization = false;

  constexpr bool automatic_flushes = false;
  constexpr bool support_locking = false;
  constexpr bool support_grcontext = false;

  scoped_refptr<ui::ContextProviderCommandBuffer> context_provider(
      new ui::ContextProviderCommandBuffer(
          gpu_channel_host, delegate_->GetGpuMemoryBufferManager(), 
          common::kGpuStreamIdDefault,
          common::kGpuStreamPriorityDefault, 
          gpu::kNullSurfaceHandle, 
          GURL(),
          automatic_flushes, support_locking, support_grcontext, limits,
          attributes, ui::command_buffer_metrics::RENDER_COMPOSITOR_CONTEXT));

  
  if (!params.compositor_task_runner) {
    params.compositor_task_runner = delegate_->GetCompositorMainThreadTaskRunner();
  }

  // frame_sink_provider_->CreateForWidget(
  //     routing_id, std::move(compositor_frame_sink_request),
  //     std::move(compositor_frame_sink_client));
  // frame_sink_provider_->RegisterRenderFrameMetadataObserver(
  //     routing_id, std::move(render_frame_metadata_observer_client_request),
  //     std::move(render_frame_metadata_observer_ptr));
  
  delegate_->frame_sink_provider()->CreateForService(std::move(compositor_frame_sink_request), std::move(compositor_frame_sink_client));
  
  params.gpu_memory_buffer_manager = delegate_->GetGpuMemoryBufferManager();

  std::move(callback).Run(std::make_unique<viz::ClientLayerTreeFrameSink>(
       std::move(context_provider), std::move(worker_context_provider),
       &params));
}

void MainShadowPage::DidCommitAndDrawCompositorFrame() {
  
}

void MainShadowPage::DidCommitCompositorFrame() {

}

void MainShadowPage::DidCompletePageScaleAnimation() {
  
}

void MainShadowPage::DidReceiveCompositorFrameAck() {
  
}

bool MainShadowPage::IsClosing() const {
  return false;
}

void MainShadowPage::RequestScheduleAnimation() {
  
}

void MainShadowPage::UpdateVisualState(VisualStateUpdate requested_update) {
  
}

void MainShadowPage::WillBeginCompositorFrame() {
  
}

std::unique_ptr<cc::SwapPromise> MainShadowPage::RequestCopyOfOutputForLayoutTest(
    std::unique_ptr<viz::CopyOutputRequest> request) {
  return delegate_->RequestCopyOfOutputForLayoutTest(std::move(request));
}

}  // namespace domain