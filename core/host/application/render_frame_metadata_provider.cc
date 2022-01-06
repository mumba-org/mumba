// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/application/render_frame_metadata_provider.h"

#include "base/bind.h"
#include "core/host/application/frame_token_message_queue.h"

namespace host {

RenderFrameMetadataProvider::RenderFrameMetadataProvider(
    FrameTokenMessageQueue* frame_token_message_queue)
    : frame_token_message_queue_(frame_token_message_queue),
      render_frame_metadata_observer_client_binding_(this),
      weak_factory_(this) {}

RenderFrameMetadataProvider::~RenderFrameMetadataProvider() = default;

void RenderFrameMetadataProvider::AddObserver(Observer* observer) {
  observers_.AddObserver(observer);
}

void RenderFrameMetadataProvider::RemoveObserver(Observer* observer) {
  observers_.RemoveObserver(observer);
}

void RenderFrameMetadataProvider::Bind(
    common::mojom::RenderFrameMetadataObserverClientRequest client_request,
    common::mojom::RenderFrameMetadataObserverPtr observer) {
  render_frame_metadata_observer_ptr_ = std::move(observer);
  render_frame_metadata_observer_client_binding_.Close();
  render_frame_metadata_observer_client_binding_.Bind(
      std::move(client_request));
}

void RenderFrameMetadataProvider::ReportAllFrameSubmissionsForTesting(
    bool enabled) {
  DCHECK(render_frame_metadata_observer_ptr_);
  render_frame_metadata_observer_ptr_->ReportAllFrameSubmissionsForTesting(
      enabled);
}

const cc::RenderFrameMetadata&
RenderFrameMetadataProvider::LastRenderFrameMetadata() const {
  return last_render_frame_metadata_;
}

void RenderFrameMetadataProvider::OnFrameTokenRenderFrameMetadataChanged(
    cc::RenderFrameMetadata metadata) {
  last_render_frame_metadata_ = std::move(metadata);
  for (Observer& observer : observers_)
    observer.OnRenderFrameMetadataChanged();
}

void RenderFrameMetadataProvider::OnFrameTokenFrameSubmissionForTesting() {
  for (Observer& observer : observers_)
    observer.OnRenderFrameSubmission();
}

void RenderFrameMetadataProvider::SetLastRenderFrameMetadataForTest(
    cc::RenderFrameMetadata metadata) {
  last_render_frame_metadata_ = metadata;
}

void RenderFrameMetadataProvider::OnRenderFrameMetadataChanged(
    uint32_t frame_token,
    const cc::RenderFrameMetadata& metadata) {
  // Both RenderFrameMetadataProvider and FrameTokenMessageQueue are owned
  // by the same ApplicationWindowHost. During shutdown the queue is cleared
  // without running the callbacks.
  frame_token_message_queue_->EnqueueOrRunFrameTokenCallback(
      frame_token,
      base::BindOnce(&RenderFrameMetadataProvider::
                         OnFrameTokenRenderFrameMetadataChanged,
                     weak_factory_.GetWeakPtr(), std::move(metadata)));
}

void RenderFrameMetadataProvider::OnFrameSubmissionForTesting(
    uint32_t frame_token) {
  frame_token_message_queue_->EnqueueOrRunFrameTokenCallback(
      frame_token, base::BindOnce(&RenderFrameMetadataProvider::
                                      OnFrameTokenFrameSubmissionForTesting,
                                  weak_factory_.GetWeakPtr()));
}

}  // namespace host
