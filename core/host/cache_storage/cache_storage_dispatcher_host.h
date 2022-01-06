// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_BROWSER_CACHE_STORAGE_CACHE_STORAGE_DISPATCHER_HOST_H_
#define CONTENT_BROWSER_CACHE_STORAGE_CACHE_STORAGE_DISPATCHER_HOST_H_

#include <stdint.h>

#include <list>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "base/macros.h"
#include "core/host/cache_storage/cache_storage.h"
#include "core/host/cache_storage/cache_storage_index.h"
#include "core/host/host_thread.h"
#include "mojo/public/cpp/bindings/associated_binding_set.h"
#include "mojo/public/cpp/bindings/strong_associated_binding_set.h"
#include "mojo/public/cpp/bindings/strong_binding_set.h"

namespace url {
class Origin;
}

namespace host {

class CacheStorageContextImpl;

// Handles Cache Storage related messages sent to the browser process from
// child processes. One host instance exists per child process. All
// messages are processed on the IO thread.
class CONTENT_EXPORT CacheStorageDispatcherHost
    : public base::RefCountedThreadSafe<CacheStorageDispatcherHost,
                                        HostThread::DeleteOnIOThread>,
      public blink::mojom::CacheStorage {
 public:
  CacheStorageDispatcherHost();

  // Runs on UI thread.
  void Init(CacheStorageContextImpl* context);

  // Binds Mojo request to this instance, must be called on IO thread.
  // NOTE: The same CacheStorageDispatcherHost instance may be bound to
  // different clients on different origins. Each context is kept on
  // BindingSet's context. This guarantees that the browser process uses the
  // origin of the client known at the binding time, instead of relying on the
  // client to provide its origin at every method call.
  void AddBinding(blink::mojom::CacheStorageRequest request,
                  const url::Origin& origin);

  void AddAssociatedBinding(blink::mojom::CacheStorageAssociatedRequest request, const url::Origin& origin);

 private:
  // Friends to allow HostThread::DeleteOnIOThread delegation.
  friend struct HostThread::DeleteOnThread<HostThread::IO>;
  friend class base::DeleteHelper<CacheStorageDispatcherHost>;

  class CacheImpl;

  ~CacheStorageDispatcherHost() override;

  // Called by Init() on IO thread.
  void CreateCacheListener(CacheStorageContextImpl* context);

  // Mojo CacheStorage Interface implementation:
  void Keys(blink::mojom::CacheStorage::KeysCallback callback) override;
  void Delete(const base::string16& cache_name,
              blink::mojom::CacheStorage::DeleteCallback callback) override;
  void Has(const base::string16& cache_name,
           blink::mojom::CacheStorage::HasCallback callback) override;
  void Match(const common::ServiceWorkerFetchRequest& request,
             const common::CacheStorageCacheQueryParams& match_params,
             blink::mojom::CacheStorage::MatchCallback callback) override;
  void Open(const base::string16& cache_name,
            blink::mojom::CacheStorage::OpenCallback callback) override;

  // Callbacks used by Mojo implementation:
  void OnKeysCallback(KeysCallback callback,
                      const CacheStorageIndex& cache_index);
  void OnHasCallback(blink::mojom::CacheStorage::HasCallback callback,
                     bool has_cache,
                     blink::mojom::CacheStorageError error);
  void OnMatchCallback(blink::mojom::CacheStorage::MatchCallback callback,
                       blink::mojom::CacheStorageError error,
                       std::unique_ptr<common::ServiceWorkerResponse> response);
  void OnOpenCallback(url::Origin origin,
                      blink::mojom::CacheStorage::OpenCallback callback,
                      CacheStorageCacheHandle cache_handle,
                      blink::mojom::CacheStorageError error);

  // Validate the current state of required members, returns false if they
  // aren't valid and also close |bindings_|, so it's safe to not run
  // mojo callbacks.
  bool ValidState();

  scoped_refptr<CacheStorageContextImpl> context_;

  //mojo::BindingSet<blink::mojom::CacheStorage, url::Origin> bindings_;
  mojo::AssociatedBindingSet<blink::mojom::CacheStorage, url::Origin> bindings_;
  mojo::StrongAssociatedBindingSet<blink::mojom::CacheStorageCache> cache_bindings_;

  DISALLOW_COPY_AND_ASSIGN(CacheStorageDispatcherHost);
};

}  // namespace host

#endif  // CONTENT_BROWSER_CACHE_STORAGE_CACHE_STORAGE_DISPATCHER_HOST_H_
