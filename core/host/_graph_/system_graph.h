// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_GRAPH_SYSTEM_GRAPH_H_
#define MUMBA_HOST_GRAPH_SYSTEM_GRAPH_H_

#include "core/host/graph/graph.h"
#include "core/host/workspace/workspace_observer.h"

namespace host {
class Workspace;

class SystemGraph : public Graph,
                    public WorkspaceObserver {
public:
  SystemGraph(Workspace* workspace, scoped_refptr<ShareDatabase> db, const std::string& name, base::UUID uuid);
  SystemGraph(Workspace* workspace, scoped_refptr<ShareDatabase> db, base::UUID uuid, protocol::Graph graph_proto);
  ~SystemGraph() override;

private:

  void OnApplicationsLoaded(size_t count) override;
  void OnApplicationCreated(Domain* application) override;
  void OnApplicationDestroyed(Domain* application) override;
  void OnGraphsLoaded(size_t count) override;
  void OnGraphCreated(Graph* graph) override;
  void OnGraphDestroyed(Graph* graph) override;
  void OnDevicesLoaded(size_t count) override;
  void OnDeviceCreated(Device* device) override;
  void OnDeviceDestroyed(Device* device) override;
  void OnChannelsLoaded(size_t count) override;
  void OnChannelCreated(Channel* channel) override;
  void OnChannelDestroyed(Channel* channel) override;
  void OnIdentitiesLoaded(size_t count) override;
  void OnIdentityCreated(Identity* identity) override;
  void OnIdentityDestroyed(Identity* identity) override;
  void OnReposLoaded(size_t count) override;
  void OnRepoCreated(Repo* repo) override;
  void OnRepoDestroyed(Repo* repo) override;
  void OnRoutesLoaded(size_t count) override;
  void OnRouteCreated(RouteEntry* url) override;
  void OnRouteDestroyed(RouteEntry* url) override;
  void OnServicesLoaded(size_t count) override;
  void OnServiceCreated(HostRpcService* service) override;
  void OnServiceDestroyed(HostRpcService* service) override;
  void OnSchemasLoaded(size_t count) override;
  void OnSchemaCreated(Schema* schema) override;
  void OnSchemaDestroyed(Schema* schema) override;
  void OnVolumesLoaded(size_t count) override;
  void OnVolumeCreated(Volume* volume) override;
  void OnVolumeDestroyed(Volume* volume) override;
 
 Workspace* workspace_;
};

}

#endif