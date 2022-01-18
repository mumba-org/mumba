// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_WORKSPACE_WORKSPACE_OBSERVER_H_
#define MUMBA_HOST_WORKSPACE_WORKSPACE_OBSERVER_H_

namespace host {
class Domain;
class Graph;
class Device;
class Channel;
class Identity;
class Repo;
class RouteEntry;
class Schema;
class Volume;
class HostRpcService;
class Bundle;
class AppStoreEntry;

class WorkspaceObserver {
public:
  virtual ~WorkspaceObserver(){}
  virtual void OnApplicationsLoaded(size_t count) {}
  virtual void OnApplicationCreated(Domain* application) {}
  virtual void OnApplicationDestroyed(Domain* application) {}
  virtual void OnGraphsLoaded(size_t count) {}
  virtual void OnGraphCreated(Graph* graph) {}
  virtual void OnGraphDestroyed(Graph* graph) {}
  virtual void OnDevicesLoaded(size_t count) {}
  virtual void OnDeviceCreated(Device* device) {}
  virtual void OnDeviceDestroyed(Device* device) {}
  virtual void OnChannelsLoaded(size_t count) {}
  virtual void OnChannelCreated(Channel* channel) {}
  virtual void OnChannelDestroyed(Channel* channel) {}
  virtual void OnIdentitiesLoaded(size_t count) {}
  virtual void OnIdentityCreated(Identity* identity) {}
  virtual void OnIdentityDestroyed(Identity* identity) {}
  virtual void OnReposLoaded(size_t count) {}
  virtual void OnRepoCreated(Repo* repo) {}
  virtual void OnRepoDestroyed(Repo* repo) {}
  virtual void OnRoutesLoaded(size_t count) {}
  virtual void OnRouteCreated(RouteEntry* url) {}
  virtual void OnRouteDestroyed(RouteEntry* url) {}
  virtual void OnServicesLoaded(size_t count) {}
  virtual void OnServiceCreated(HostRpcService* service) {}
  virtual void OnServiceDestroyed(HostRpcService* service) {}
  virtual void OnSchemasLoaded(size_t count) {}
  virtual void OnSchemaCreated(Schema* schema) {}
  virtual void OnSchemaDestroyed(Schema* schema) {}
  virtual void OnVolumesLoaded(size_t count) {}
  virtual void OnVolumeCreated(Volume* volume) {}
  virtual void OnVolumeDestroyed(Volume* volume) {}
  virtual void OnBundlesLoaded(size_t count) {}
  virtual void OnBundleAdded(Bundle* bundle) {}
  virtual void OnBundleRemoved(Bundle* bundle) {}
  virtual void OnAppStoreEntriesLoaded(size_t count) {}
  virtual void OnAppStoreEntryAdded(AppStoreEntry* app_store_entry) {}
  virtual void OnAppStoreEntryemoved(AppStoreEntry* app_store_entry) {}
};

}

#endif