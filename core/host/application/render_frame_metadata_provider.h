// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_RENDER_FRAME_METADATA_PROVIDER_IMPL_H_
#define MUMBA_HOST_APPLICATION_RENDER_FRAME_METADATA_PROVIDER_IMPL_H_

#include "base/macros.h"
#include "base/memory/weak_ptr.h"
#include "base/observer_list.h"
#include "core/shared/common/content_export.h"
#include "core/shared/common/render_frame_metadata.mojom.h"
#include "cc/trees/render_frame_metadata.h"
#include "mojo/public/cpp/bindings/binding.h"

namespace host {
class FrameTokenMessageQueue;

// Observes RenderFrameMetadata associated with the submission of a frame for a
// given ApplicationWindowHost. The renderer will notify this when sumitting a
// CompositorFrame.
//
// When ReportAllFrameSubmissionsForTesting(true) is called, this will be
// notified of all frame submissions.
//
// All RenderFrameMetadataProvider::Observer will be notified.
class CONTENT_EXPORT RenderFrameMetadataProvider
    : public common::mojom::RenderFrameMetadataObserverClient {
 public:
  class Observer {
   public:
    virtual ~Observer() {}

    virtual void OnRenderFrameMetadataChanged() = 0;
    virtual void OnRenderFrameSubmission() = 0;
  };
  explicit RenderFrameMetadataProvider(
      FrameTokenMessageQueue* frame_token_message_queue);
  ~RenderFrameMetadataProvider() override;

  void AddObserver(Observer* observer);
  void RemoveObserver(Observer* observer);

  void Bind(common::mojom::RenderFrameMetadataObserverClientRequest client_request,
            common::mojom::RenderFrameMetadataObserverPtr observer);

  // Notifies the renderer to begin sending a notification on all frame
  // submissions.
  void ReportAllFrameSubmissionsForTesting(bool enabled);

  const cc::RenderFrameMetadata& LastRenderFrameMetadata() const;

 private:
  friend class FakeApplicationWindowHostViewAura;

  // Paired with the mojom::RenderFrameMetadataObserverClient overrides, these
  // methods are enqueued in |frame_token_message_queue_|. They are invoked when
  // the browser process receives their associated frame tokens. These then
  // notify any |observers_|.
  void OnFrameTokenRenderFrameMetadataChanged(cc::RenderFrameMetadata metadata);
  void OnFrameTokenFrameSubmissionForTesting();

  // Set |last_render_frame_metadata_| to the given |metadata| for testing
  // purpose.
  void SetLastRenderFrameMetadataForTest(cc::RenderFrameMetadata metadata);

  // mojom::RenderFrameMetadataObserverClient:
  void OnRenderFrameMetadataChanged(
      uint32_t frame_token,
      const cc::RenderFrameMetadata& metadata) override;
  void OnFrameSubmissionForTesting(uint32_t frame_token) override;

  base::ObserverList<Observer> observers_;

  cc::RenderFrameMetadata last_render_frame_metadata_;

  // Not owned.
  FrameTokenMessageQueue* const frame_token_message_queue_;

  mojo::Binding<common::mojom::RenderFrameMetadataObserverClient>
      render_frame_metadata_observer_client_binding_;
  common::mojom::RenderFrameMetadataObserverPtr render_frame_metadata_observer_ptr_;

  base::WeakPtrFactory<RenderFrameMetadataProvider> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(RenderFrameMetadataProvider);
};

}  // namespace host

#endif  // MUMBA_HOST_APPLICATION_RENDER_FRAME_METADATA_PROVIDER_IMPL_H_
