// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/graph/system_graph.h"

#include "core/host/workspace/workspace.h"
#include "core/host/graph/graph_transaction.h"
#include "core/host/application/domain_manager.h"
#include "core/host/device/device_manager.h"
#include "core/host/volume/volume_manager.h"
#include "core/host/rpc/server/rpc_manager.h"
#include "core/host/route/route_registry.h"
#include "core/host/rpc/service_registry.h"
#include "core/host/schema/schema_registry.h"
#include "core/host/graph/graph_manager.h"
#include "core/host/channel/channel_manager.h"
#include "core/host/repo/repo_manager.h"
#include "core/host/identity/identity_manager.h"
#include "core/host/volume/volume_manager.h"

namespace host {

SystemGraph::SystemGraph(Workspace* workspace, scoped_refptr<ShareDatabase> db, const std::string& name, base::UUID uuid):
 Graph(db, name, std::move(uuid)),
 workspace_(workspace) {

}

SystemGraph::SystemGraph(Workspace* workspace, scoped_refptr<ShareDatabase> db, base::UUID uuid, protocol::Graph graph_proto):
 Graph(db, std::move(uuid), std::move(graph_proto)),
 workspace_(workspace) {

}

SystemGraph::~SystemGraph() {

}

void SystemGraph::OnApplicationsLoaded(size_t count) {

}

void SystemGraph::OnApplicationCreated(Domain* application) {
  auto tr = Begin(true);
  workspace_->domain_manager()->AddEntry(tr.get(), application);
  tr->Commit();
}

void SystemGraph::OnApplicationDestroyed(Domain* application) {
  auto tr = Begin(true);
  workspace_->domain_manager()->RemoveEntry(tr.get(), application);
  tr->Commit();
}

void SystemGraph::OnGraphsLoaded(size_t count) {

}

void SystemGraph::OnGraphCreated(Graph* graph) {

}

void SystemGraph::OnGraphDestroyed(Graph* graph) {

}

void SystemGraph::OnDevicesLoaded(size_t count) {
  if (count > 0) {
    auto tr = Begin(true);
    workspace_->device_manager()->AddEntries(tr.get());
    tr->Commit();
  }
}

void SystemGraph::OnDeviceCreated(Device* device) {
  auto tr = Begin(true);
  workspace_->device_manager()->AddEntry(tr.get(), device);
  tr->Commit();
}

void SystemGraph::OnDeviceDestroyed(Device* device) {
  auto tr = Begin(true);
  workspace_->device_manager()->RemoveEntry(tr.get(), device);
  tr->Commit();
}

void SystemGraph::OnChannelsLoaded(size_t count) {
  if (count > 0) {
    auto tr = Begin(true);
    workspace_->channel_manager()->AddEntries(tr.get());
    tr->Commit();
  }
}

void SystemGraph::OnChannelCreated(Channel* channel) {
  auto tr = Begin(true);
  workspace_->channel_manager()->AddEntry(tr.get(), channel);
  tr->Commit();
}

void SystemGraph::OnChannelDestroyed(Channel* channel) {
  auto tr = Begin(true);
  workspace_->channel_manager()->RemoveEntry(tr.get(), channel);
  tr->Commit();
}

void SystemGraph::OnIdentitiesLoaded(size_t count) {
  if (count > 0) {
    auto tr = Begin(true);
    workspace_->identity_manager()->AddEntries(tr.get());
    tr->Commit();
  }
}

void SystemGraph::OnIdentityCreated(Identity* identity) {
  auto tr = Begin(true);
  workspace_->identity_manager()->AddEntry(tr.get(), identity);
  tr->Commit();
}

void SystemGraph::OnIdentityDestroyed(Identity* identity) {
  auto tr = Begin(true);
  workspace_->identity_manager()->RemoveEntry(tr.get(), identity);
  tr->Commit();
}

void SystemGraph::OnReposLoaded(size_t count) {
  if (count > 0) {
    auto tr = Begin(true);
    workspace_->repo_manager()->AddEntries(tr.get());
    tr->Commit();
  }
}

void SystemGraph::OnRepoCreated(Repo* repo) {
  auto tr = Begin(true);
  workspace_->repo_manager()->AddEntry(tr.get(), repo);
  tr->Commit();
}

void SystemGraph::OnRepoDestroyed(Repo* repo) {
  auto tr = Begin(true);
  workspace_->repo_manager()->RemoveEntry(tr.get(), repo);
  tr->Commit();
}

void SystemGraph::OnRoutesLoaded(size_t count) {
  if (count > 0) {
    auto tr = Begin(true);
    workspace_->route_registry()->AddEntries(tr.get());
    tr->Commit();
  }
}

void SystemGraph::OnRouteCreated(RouteEntry* url) {
  auto tr = Begin(true);
  workspace_->route_registry()->AddEntry(tr.get(), url);
  tr->Commit();
}

void SystemGraph::OnRouteDestroyed(RouteEntry* url) {
  auto tr = Begin(true);
  workspace_->route_registry()->RemoveEntry(tr.get(), url);
  tr->Commit();
}

void SystemGraph::OnServicesLoaded(size_t count) {
  if (count > 0) {
    auto tr = Begin(true);
    workspace_->rpc_manager()->AddEntries(tr.get());
    tr->Commit();
  }
}

void SystemGraph::OnServiceCreated(HostRpcService* service) {
  auto tr = Begin(true);
  workspace_->rpc_manager()->AddEntry(tr.get(), service);
  tr->Commit();
}

void SystemGraph::OnServiceDestroyed(HostRpcService* service) {
  auto tr = Begin(true);
  workspace_->rpc_manager()->RemoveEntry(tr.get(), service);
  tr->Commit();
}

void SystemGraph::OnSchemasLoaded(size_t count) {
  if (count > 0) {
    auto tr = Begin(true);
    workspace_->schema_registry()->AddEntries(tr.get());
    tr->Commit();
  }
}

void SystemGraph::OnSchemaCreated(Schema* schema) {
  auto tr = Begin(true);
  workspace_->schema_registry()->AddEntry(tr.get(), schema);
  tr->Commit();
}

void SystemGraph::OnSchemaDestroyed(Schema* schema) {
  auto tr = Begin(true);
  workspace_->schema_registry()->RemoveEntry(tr.get(), schema);
  tr->Commit();
}

void SystemGraph::OnVolumesLoaded(size_t count) {
  if (count > 0) {
    auto tr = Begin(true);
    workspace_->volume_manager()->AddEntries(tr.get());
    tr->Commit();
  }
}

void SystemGraph::OnVolumeCreated(Volume* volume) {
  auto tr = Begin(true);
  workspace_->volume_manager()->AddEntry(tr.get(), volume);
  tr->Commit();
}

void SystemGraph::OnVolumeDestroyed(Volume* volume) {
  auto tr = Begin(true);
  workspace_->volume_manager()->RemoveEntry(tr.get(), volume);
  tr->Commit();
}

}
