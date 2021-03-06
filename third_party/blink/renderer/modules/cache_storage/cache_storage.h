// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef THIRD_PARTY_BLINK_RENDERER_MODULES_CACHE_STORAGE_CACHE_STORAGE_H_
#define THIRD_PARTY_BLINK_RENDERER_MODULES_CACHE_STORAGE_CACHE_STORAGE_H_

#include <memory>
#include "base/macros.h"
#include "third_party/blink/public/platform/modules/serviceworker/web_service_worker_cache_storage.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/core/fetch/global_fetch.h"
#include "third_party/blink/renderer/modules/cache_storage/cache.h"
#include "third_party/blink/renderer/modules/cache_storage/cache_query_options.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/bindings/script_wrappable.h"
#include "third_party/blink/renderer/platform/wtf/forward.h"
#include "third_party/blink/renderer/platform/wtf/hash_map.h"

namespace blink {

class WebServiceWorkerCacheStorage;

class CacheStorage final : public ScriptWrappable {
  DEFINE_WRAPPERTYPEINFO();

 public:
  static CacheStorage* Create(GlobalFetch::ScopedFetcher*,
                              std::unique_ptr<WebServiceWorkerCacheStorage>);
  ~CacheStorage() override;
  void Dispose();

  ScriptPromise open(ScriptState*, const String& cache_name);
  ScriptPromise has(ScriptState*, const String& cache_name);
  ScriptPromise Delete(ScriptState*, const String& cache_name);
  ScriptPromise keys(ScriptState*);
  ScriptPromise match(ScriptState*,
                      const RequestInfo&,
                      const CacheQueryOptions&,
                      ExceptionState&);

  void Trace(blink::Visitor*) override;

 private:
  class Callbacks;
  class WithCacheCallbacks;
  class DeleteCallbacks;
  class KeysCallbacks;
  class MatchCallbacks;

  friend class WithCacheCallbacks;
  friend class DeleteCallbacks;

  CacheStorage(GlobalFetch::ScopedFetcher*,
               std::unique_ptr<WebServiceWorkerCacheStorage>);
  ScriptPromise MatchImpl(ScriptState*,
                          const Request*,
                          const CacheQueryOptions&);

  Member<GlobalFetch::ScopedFetcher> scoped_fetcher_;
  std::unique_ptr<WebServiceWorkerCacheStorage> web_cache_storage_;

  DISALLOW_COPY_AND_ASSIGN(CacheStorage);
};

}  // namespace blink

#endif  // THIRD_PARTY_BLINK_RENDERER_MODULES_CACHE_STORAGE_CACHE_STORAGE_H_
