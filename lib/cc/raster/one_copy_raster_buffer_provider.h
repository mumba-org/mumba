// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CC_RASTER_ONE_COPY_RASTER_BUFFER_PROVIDER_H_
#define CC_RASTER_ONE_COPY_RASTER_BUFFER_PROVIDER_H_

#include <stdint.h>

#include "base/macros.h"
#include "cc/raster/raster_buffer_provider.h"
#include "cc/raster/staging_buffer_pool.h"
#include "cc/resources/layer_tree_resource_provider.h"
#include "gpu/command_buffer/common/sync_token.h"

namespace viz {
class ContextProvider;
class RasterContextProvider;
}  // namespace viz

namespace cc {
struct StagingBuffer;
class StagingBufferPool;

class CC_EXPORT OneCopyRasterBufferProvider : public RasterBufferProvider {
 public:
  OneCopyRasterBufferProvider(
      scoped_refptr<base::SequencedTaskRunner> task_runner,
      viz::ContextProvider* compositor_context_provider,
      viz::RasterContextProvider* worker_context_provider,
      LayerTreeResourceProvider* resource_provider,
      int max_copy_texture_chromium_size,
      bool use_partial_raster,
      bool use_gpu_memory_buffer_resources,
      int max_staging_buffer_usage_in_bytes,
      viz::ResourceFormat tile_format);
  ~OneCopyRasterBufferProvider() override;

  // Overridden from RasterBufferProvider:
  std::unique_ptr<RasterBuffer> AcquireBufferForRaster(
      const ResourcePool::InUsePoolResource& resource,
      uint64_t resource_content_id,
      uint64_t previous_content_id) override;
  void Flush() override;
  viz::ResourceFormat GetResourceFormat() const override;
  bool IsResourceSwizzleRequired() const override;
  bool IsResourcePremultiplied() const override;
  bool CanPartialRasterIntoProvidedResource() const override;
  bool IsResourceReadyToDraw(
      const ResourcePool::InUsePoolResource& resource) const override;
  uint64_t SetReadyToDrawCallback(
      const std::vector<const ResourcePool::InUsePoolResource*>& resources,
      const base::Closure& callback,
      uint64_t pending_callback_id) const override;
  void Shutdown() override;

  // Playback raster source and copy result into |resource|.
  gpu::SyncToken PlaybackAndCopyOnWorkerThread(
      const gpu::Mailbox& mailbox,
      GLenum mailbox_texture_target,
      bool mailbox_texture_is_overlay_candidate,
      bool mailbox_texture_storage_allocated,
      const gpu::SyncToken& sync_token,
      const RasterSource* raster_source,
      const gfx::Rect& raster_full_rect,
      const gfx::Rect& raster_dirty_rect,
      const gfx::AxisTransform2d& transform,
      const gfx::Size& resource_size,
      viz::ResourceFormat resource_format,
      const gfx::ColorSpace& color_space,
      const RasterSource::PlaybackSettings& playback_settings,
      uint64_t previous_content_id,
      uint64_t new_content_id);

 private:
  class OneCopyGpuBacking;

  class RasterBufferImpl : public RasterBuffer {
   public:
    RasterBufferImpl(OneCopyRasterBufferProvider* client,
                     LayerTreeResourceProvider* resource_provider,
                     const ResourcePool::InUsePoolResource& in_use_resource,
                     OneCopyGpuBacking* backing,
                     const gpu::SyncToken& before_raster_sync_token,
                     uint64_t previous_content_id);
    ~RasterBufferImpl() override;

    // Overridden from RasterBuffer:
    void Playback(
        const RasterSource* raster_source,
        const gfx::Rect& raster_full_rect,
        const gfx::Rect& raster_dirty_rect,
        uint64_t new_content_id,
        const gfx::AxisTransform2d& transform,
        const RasterSource::PlaybackSettings& playback_settings) override;

   private:
    // These fields may only be used on the compositor thread.
    OneCopyRasterBufferProvider* const client_;
    OneCopyGpuBacking* backing_;

    // These fields are for use on the worker thread.
    const gfx::Size resource_size_;
    const viz::ResourceFormat resource_format_;
    const gfx::ColorSpace color_space_;
    const uint64_t previous_content_id_;
    const gpu::SyncToken before_raster_sync_token_;
    const gpu::Mailbox mailbox_;
    const GLenum mailbox_texture_target_;
    const bool mailbox_texture_is_overlay_candidate_;
    // Set to true once allocation is done in the worker thread.
    bool mailbox_texture_storage_allocated_;
    // A SyncToken to be returned from the worker thread, and waited on before
    // using the rastered resource.
    gpu::SyncToken after_raster_sync_token_;

    DISALLOW_COPY_AND_ASSIGN(RasterBufferImpl);
  };

  void PlaybackToStagingBuffer(
      StagingBuffer* staging_buffer,
      const RasterSource* raster_source,
      const gfx::Rect& raster_full_rect,
      const gfx::Rect& raster_dirty_rect,
      const gfx::AxisTransform2d& transform,
      viz::ResourceFormat format,
      const gfx::ColorSpace& dst_color_space,
      const RasterSource::PlaybackSettings& playback_settings,
      uint64_t previous_content_id,
      uint64_t new_content_id);
  gpu::SyncToken CopyOnWorkerThread(StagingBuffer* staging_buffer,
                                    const RasterSource* raster_source,
                                    const gfx::Rect& rect_to_copy,
                                    viz::ResourceFormat resource_format,
                                    const gfx::Size& resource_size,
                                    const gpu::Mailbox& mailbox,
                                    GLenum mailbox_texture_target,
                                    bool mailbox_texture_is_overlay_candidate,
                                    bool mailbox_texture_storage_allocated,
                                    const gpu::SyncToken& sync_token,
                                    const gfx::ColorSpace& color_space);
  gfx::BufferUsage StagingBufferUsage() const;

  viz::ContextProvider* const compositor_context_provider_;
  viz::RasterContextProvider* const worker_context_provider_;
  LayerTreeResourceProvider* const resource_provider_;
  const int max_bytes_per_copy_operation_;
  const bool use_partial_raster_;
  const bool use_gpu_memory_buffer_resources_;

  // Context lock must be acquired when accessing this member.
  int bytes_scheduled_since_last_flush_;

  const viz::ResourceFormat tile_format_;
  StagingBufferPool staging_pool_;

  DISALLOW_COPY_AND_ASSIGN(OneCopyRasterBufferProvider);
};

}  // namespace cc

#endif  // CC_RASTER_ONE_COPY_RASTER_BUFFER_PROVIDER_H_
