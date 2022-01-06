// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/android/scoped_surface_request_manager.h"

#include "core/host/host_thread.h"

namespace host {

// static
ScopedSurfaceRequestManager* ScopedSurfaceRequestManager::GetInstance() {
  return base::Singleton<
      ScopedSurfaceRequestManager,
      base::LeakySingletonTraits<ScopedSurfaceRequestManager>>::get();
}

base::UnguessableToken
ScopedSurfaceRequestManager::RegisterScopedSurfaceRequest(
    const ScopedSurfaceRequestCB& request_cb) {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  DCHECK(!request_cb.is_null());

  base::UnguessableToken request_token = base::UnguessableToken::Create();

  DCHECK(!request_callbacks_.count(request_token));
  request_callbacks_.insert(std::make_pair(request_token, request_cb));

  return request_token;
}

void ScopedSurfaceRequestManager::UnregisterScopedSurfaceRequest(
    const base::UnguessableToken& request_token) {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  GetAndUnregisterInternal(request_token);
}

ScopedSurfaceRequestManager::ScopedSurfaceRequestCB
ScopedSurfaceRequestManager::GetAndUnregisterInternal(
    const base::UnguessableToken& request_token) {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  DCHECK(!request_token.is_empty());

  ScopedSurfaceRequestManager::ScopedSurfaceRequestCB request;

  auto it = request_callbacks_.find(request_token);
  if (it != request_callbacks_.end()) {
    request = it->second;
    request_callbacks_.erase(it);
  }

  return request;
}

void ScopedSurfaceRequestManager::ForwardSurfaceTextureForSurfaceRequest(
    const base::UnguessableToken& request_token,
    const gl::SurfaceTexture* surface_texture) {
  FulfillScopedSurfaceRequest(request_token,
                              gl::ScopedJavaSurface(surface_texture));
}

void ScopedSurfaceRequestManager::FulfillScopedSurfaceRequest(
    const base::UnguessableToken& request_token,
    gl::ScopedJavaSurface surface) {
  // base::Unretained is safe because the lifetime of this object is tied to
  // the lifetime of the host process.
  HostThread::PostTask(
      HostThread::UI, FROM_HERE,
      base::Bind(&ScopedSurfaceRequestManager::CompleteRequestOnUiThread,
                 base::Unretained(this), request_token,
                 base::Passed(&surface)));
}

void ScopedSurfaceRequestManager::CompleteRequestOnUiThread(
    const base::UnguessableToken& request_token,
    gl::ScopedJavaSurface surface) {
  DCHECK_CURRENTLY_ON(HostThread::UI);

  ScopedSurfaceRequestManager::ScopedSurfaceRequestCB request =
      GetAndUnregisterInternal(request_token);

  if (!request.is_null())
    request.Run(std::move(surface));
}

ScopedSurfaceRequestManager::ScopedSurfaceRequestManager() {}

ScopedSurfaceRequestManager::~ScopedSurfaceRequestManager() {}

}  // namespace host
