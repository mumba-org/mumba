// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_RENDERER_LOADER_CHILD_URL_LOADER_FACTORY_BUNDLE_H_
#define CONTENT_RENDERER_LOADER_CHILD_URL_LOADER_FACTORY_BUNDLE_H_

#include "base/callback.h"
#include "base/sequenced_task_runner.h"
#include "core/shared/common/content_export.h"
#include "core/shared/common/possibly_associated_interface_ptr.h"
#include "core/shared/common/url_loader_factory_bundle.h"
#include "core/shared/common/transferrable_url_loader.mojom.h"
#include "services/network/public/mojom/url_loader_factory.mojom.h"

namespace application {
class HostChildURLLoaderFactoryBundle;

// Holds the internal state of a ChildURLLoaderFactoryBundle in a form that is
// safe to pass across sequences.
class CONTENT_EXPORT ChildURLLoaderFactoryBundleInfo
    : public common::URLLoaderFactoryBundleInfo {
 public:
  using PossiblyAssociatedURLLoaderFactoryPtrInfo =
      common::PossiblyAssociatedInterfacePtrInfo<network::mojom::URLLoaderFactory>;

  ChildURLLoaderFactoryBundleInfo();
  explicit ChildURLLoaderFactoryBundleInfo(
      std::unique_ptr<URLLoaderFactoryBundleInfo> base_info);
  ChildURLLoaderFactoryBundleInfo(
      network::mojom::URLLoaderFactoryPtrInfo default_factory_info,
      std::map<std::string, network::mojom::URLLoaderFactoryPtrInfo>
          factories_info,
      PossiblyAssociatedURLLoaderFactoryPtrInfo direct_network_factory_info);
  ~ChildURLLoaderFactoryBundleInfo() override;

  PossiblyAssociatedURLLoaderFactoryPtrInfo& direct_network_factory_info() {
    return direct_network_factory_info_;
  }

 protected:
  // URLLoaderFactoryBundleInfo overrides.
  scoped_refptr<network::SharedURLLoaderFactory> CreateFactory() override;

  PossiblyAssociatedURLLoaderFactoryPtrInfo direct_network_factory_info_;

  DISALLOW_COPY_AND_ASSIGN(ChildURLLoaderFactoryBundleInfo);
};

// This class extends URLLoaderFactoryBundle to support a direct network loader
// factory, which bypasses custom overrides such as appcache or service worker.
// Besides, it also supports using callbacks to lazily initialize the blob and
// the direct network loader factories.
class CONTENT_EXPORT ChildURLLoaderFactoryBundle
    : public common::URLLoaderFactoryBundle {
 public:
  using PossiblyAssociatedURLLoaderFactoryPtr =
      common::PossiblyAssociatedInterfacePtr<network::mojom::URLLoaderFactory>;

  using FactoryGetterCallback =
      base::OnceCallback<network::mojom::URLLoaderFactoryPtr()>;
  using PossiblyAssociatedFactoryGetterCallback =
      base::OnceCallback<PossiblyAssociatedURLLoaderFactoryPtr()>;

  ChildURLLoaderFactoryBundle();

  explicit ChildURLLoaderFactoryBundle(
      std::unique_ptr<ChildURLLoaderFactoryBundleInfo> info);

  ChildURLLoaderFactoryBundle(
      PossiblyAssociatedFactoryGetterCallback direct_network_factory_getter,
      FactoryGetterCallback default_blob_factory_getter);

  // URLLoaderFactoryBundle overrides.
  network::mojom::URLLoaderFactory* GetFactoryForURL(const GURL& url) override;

  void CreateLoaderAndStart(network::mojom::URLLoaderRequest loader,
                            int32_t routing_id,
                            int32_t request_id,
                            uint32_t options,
                            const network::ResourceRequest& request,
                            network::mojom::URLLoaderClientPtr client,
                            const net::MutableNetworkTrafficAnnotationTag&
                                traffic_annotation) override;

  std::unique_ptr<network::SharedURLLoaderFactoryInfo> Clone() override;

  // Returns an info that omits this bundle's default factory, if any. This is
  // useful to make a clone that bypasses AppCache, for example.
  std::unique_ptr<network::SharedURLLoaderFactoryInfo>
  CloneWithoutDefaultFactory();

  std::unique_ptr<ChildURLLoaderFactoryBundleInfo> PassInterface();

  void Update(std::unique_ptr<ChildURLLoaderFactoryBundleInfo> info,
              base::Optional<std::vector<common::mojom::TransferrableURLLoaderPtr>>
                  subresource_overrides);

  virtual bool IsHostChildURLLoaderFactoryBundle() const;

 protected:
  ~ChildURLLoaderFactoryBundle() override;

 private:
  void InitDefaultBlobFactoryIfNecessary();
  void InitDirectNetworkFactoryIfNecessary();
  std::unique_ptr<network::SharedURLLoaderFactoryInfo> CloneInternal(
      bool include_default);

  PossiblyAssociatedFactoryGetterCallback direct_network_factory_getter_;
  PossiblyAssociatedURLLoaderFactoryPtr direct_network_factory_;

  std::map<GURL, common::mojom::TransferrableURLLoaderPtr> subresource_overrides_;

  FactoryGetterCallback default_blob_factory_getter_;
};

// Holds the internal state of a |TrackedChildURLLoaderFactoryBundle| in a form
// that is safe to pass across sequences.
class CONTENT_EXPORT TrackedChildURLLoaderFactoryBundleInfo
    : public ChildURLLoaderFactoryBundleInfo {
 public:
  using HostPtrAndTaskRunner =
      std::pair<base::WeakPtr<HostChildURLLoaderFactoryBundle>,
                scoped_refptr<base::SequencedTaskRunner>>;

  TrackedChildURLLoaderFactoryBundleInfo();
  TrackedChildURLLoaderFactoryBundleInfo(
      network::mojom::URLLoaderFactoryPtrInfo default_factory_info,
      std::map<std::string, network::mojom::URLLoaderFactoryPtrInfo>
          factories_info,
      PossiblyAssociatedURLLoaderFactoryPtrInfo direct_network_factory_info,
      std::unique_ptr<HostPtrAndTaskRunner> main_thread_host_bundle);
  ~TrackedChildURLLoaderFactoryBundleInfo() override;

  std::unique_ptr<HostPtrAndTaskRunner>& main_thread_host_bundle() {
    return main_thread_host_bundle_;
  }

 protected:
  // ChildURLLoaderFactoryBundleInfo overrides.
  scoped_refptr<network::SharedURLLoaderFactory> CreateFactory() override;

  std::unique_ptr<HostPtrAndTaskRunner> main_thread_host_bundle_;

  DISALLOW_COPY_AND_ASSIGN(TrackedChildURLLoaderFactoryBundleInfo);
};

// This class extends |ChildURLLoaderFactoryBundle| to support a host/observer
// tracking logic. There will be a single |HostChildURLLoaderFactoryBundle|
// owned by |RenderFrameImpl| which lives on the main thread, and multiple
// |TrackedChildURLLoaderFactoryBundle| on the worker thread (for Workers) or
// the main thread (for frames from 'window.open()').
// Both |Host/TrackedChildURLLoaderFactoryBundle::Clone()| can be used to create
// a tracked bundle to the original host bundle.
// These two classes are required to bring bundles back online in the event of
// Network Service crash.
class CONTENT_EXPORT TrackedChildURLLoaderFactoryBundle
    : public ChildURLLoaderFactoryBundle,
      public base::SupportsWeakPtr<TrackedChildURLLoaderFactoryBundle> {
 public:
  using HostPtrAndTaskRunner =
      std::pair<base::WeakPtr<HostChildURLLoaderFactoryBundle>,
                scoped_refptr<base::SequencedTaskRunner>>;

  // Posts a task to the host bundle on main thread to start tracking |this|.
  explicit TrackedChildURLLoaderFactoryBundle(
      std::unique_ptr<TrackedChildURLLoaderFactoryBundleInfo> info);

  // ChildURLLoaderFactoryBundle overrides.
  // Returns |std::unique_ptr<TrackedChildURLLoaderFactoryBundleInfo>|.
  std::unique_ptr<network::SharedURLLoaderFactoryInfo> Clone() override;

 private:
  friend class HostChildURLLoaderFactoryBundle;

  // Posts a task to the host bundle on main thread to stop tracking |this|.
  ~TrackedChildURLLoaderFactoryBundle() override;

  // Helper method to post a task to the host bundle on main thread to start
  // tracking |this|.
  void AddObserverOnMainThread();

  // Helper method to post a task to the host bundle on main thread to start
  // tracking |this|.
  void RemoveObserverOnMainThread();

  // Callback method to receive updates from the host bundle.
  void OnUpdate(std::unique_ptr<network::SharedURLLoaderFactoryInfo> info);

  // |WeakPtr| and |TaskRunner| of the host bundle. Can be copied and passed
  // across sequences.
  std::unique_ptr<HostPtrAndTaskRunner> main_thread_host_bundle_ = nullptr;

  DISALLOW_COPY_AND_ASSIGN(TrackedChildURLLoaderFactoryBundle);
};
// |HostChildURLLoaderFactoryBundle| lives entirely on the main thread, and all
// methods should be invoked on the main thread or through PostTask. See
// comments in |TrackedChildURLLoaderFactoryBundle| for details about the
// tracking logic.
class CONTENT_EXPORT HostChildURLLoaderFactoryBundle
    : public ChildURLLoaderFactoryBundle,
      public base::SupportsWeakPtr<HostChildURLLoaderFactoryBundle> {
 public:
  using ObserverPtrAndTaskRunner =
      std::pair<base::WeakPtr<TrackedChildURLLoaderFactoryBundle>,
                scoped_refptr<base::SequencedTaskRunner>>;
  using ObserverList =
      std::unordered_map<TrackedChildURLLoaderFactoryBundle*,
                         std::unique_ptr<ObserverPtrAndTaskRunner>>;

  explicit HostChildURLLoaderFactoryBundle(
      scoped_refptr<base::SequencedTaskRunner> task_runner);

  // ChildURLLoaderFactoryBundle overrides.
  // Returns |std::unique_ptr<TrackedChildURLLoaderFactoryBundleInfo>|.
  std::unique_ptr<network::SharedURLLoaderFactoryInfo> Clone() override;
  bool IsHostChildURLLoaderFactoryBundle() const override;

  // Update this bundle with |info|, and post cloned |info| to tracked bundles.
  // TODO(chongz): We should also update |direct_network_factory_| together with
  // the |URLLoaderFactoryBundleInfo| we got from browser.
  void UpdateThisAndAllClones(std::unique_ptr<common::URLLoaderFactoryBundleInfo> info);

 private:
  friend class TrackedChildURLLoaderFactoryBundle;

  ~HostChildURLLoaderFactoryBundle() override;

  // Must be called by the newly created |TrackedChildURLLoaderFactoryBundle|.
  // |TrackedChildURLLoaderFactoryBundle*| serves as the key and doesn't have to
  // remain valid.
  void AddObserver(TrackedChildURLLoaderFactoryBundle* observer,
                   std::unique_ptr<ObserverPtrAndTaskRunner> observer_info);

  // Must be called by the observer before it was destroyed.
  // |TrackedChildURLLoaderFactoryBundle*| serves as the key and doesn't have to
  // remain valid.
  void RemoveObserver(TrackedChildURLLoaderFactoryBundle* observer);

  // Post an update to the tracked bundle on the worker thread (for Workers) or
  // the main thread (for frames from 'window.open()'). Safe to use after the
  // tracked bundle has been destroyed.
  void NotifyUpdateOnMainOrWorkerThread(
      ObserverPtrAndTaskRunner* observer_bundle,
      std::unique_ptr<network::SharedURLLoaderFactoryInfo> update_info);

  // Contains |WeakPtr| and |TaskRunner| to tracked bundles.
  std::unique_ptr<ObserverList> observer_list_ = nullptr;

  scoped_refptr<base::SequencedTaskRunner> task_runner_;

  DISALLOW_COPY_AND_ASSIGN(HostChildURLLoaderFactoryBundle);
};

}  // namespace application

#endif  // CONTENT_RENDERER_LOADER_CHILD_URL_LOADER_FACTORY_BUNDLE_H_
