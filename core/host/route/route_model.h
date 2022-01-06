// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_CORE_HOST_ROUTE_REGISTRY_ROUTE_MODEL_H_
#define MUMBA_CORE_HOST_ROUTE_REGISTRY_ROUTE_MODEL_H_

#include <string>
#include <unordered_map>
#include <vector>

#include "base/uuid.h"
#include "base/macros.h"
#include "base/synchronization/lock.h"
#include "core/shared/common/content_export.h"
#include "core/host/host_thread.h"
#include "core/host/route/route_entry.h"

namespace host {
class RouteScheme;
class RouteHandler;

class CONTENT_EXPORT RouteModel {
public:
  using OwnedEntry = std::unique_ptr<RouteEntry, HostThread::DeleteOnIOThread>;
  using OwnedHandler = std::unique_ptr<RouteHandler, HostThread::DeleteOnIOThread>;

  RouteModel();
  ~RouteModel();

  const std::map<int, OwnedEntry>& entries() const {
    return entries_;
  }

  std::map<int, OwnedEntry>& entries() {
    return entries_;
  }

  size_t entry_count();
  bool HaveEntry(const std::string& path);
  bool HaveEntry(const GURL& url);
  bool HaveEntry(const base::UUID& uuid);
  RouteEntry* GetEntry(const std::string& path);
  RouteEntry* GetEntry(const std::string& scheme, const std::string& path);
  RouteEntry* GetEntry(const GURL& url);
  RouteEntry* GetEntry(const base::UUID& uuid);
  void AddEntry(OwnedEntry entry);
  OwnedEntry RemoveEntry(const std::string& path, common::mojom::RouteEntryPtr* entry_ptr);
  OwnedEntry RemoveEntry(const GURL& url, common::mojom::RouteEntryPtr* entry_ptr);
  OwnedEntry RemoveEntry(const base::UUID& uuid, common::mojom::RouteEntryPtr* entry_ptr);
  std::vector<RouteEntry*> GetAllEntries();
  std::vector<RouteEntry*> GetEntriesForScheme(const std::string& scheme);
  std::vector<common::mojom::RouteEntryPtr> GetAllMojoEntries();
  std::vector<common::mojom::RouteEntryPtr> GetMojoEntriesForScheme(const std::string& scheme);

  void AddScheme(std::unique_ptr<RouteScheme> scheme);
  void RemoveScheme(const std::string& scheme_name);
  RouteScheme* GetScheme(const std::string& scheme_name);
  bool HasScheme(const std::string& scheme_name);
  std::vector<common::mojom::RouteEntryPtr> GetAllSchemes();
  size_t GetSchemeCount();

  // void AddHandler(OwnedHandler handler);
  // void RemoveHandler(const std::string& handler_name);
  // RouteHandler* GetHandler(const std::string& handler_name);
  // bool HasHandler(const std::string& handler_name);
  // std::vector<common::mojom::RouteHandlerPtr> GetMojoHandlers();

private:

  OwnedEntry RemoveEntryInternal(int id, common::mojom::RouteEntryPtr* entry_ptr);

  base::Lock entry_lock_;
  base::Lock scheme_lock_;
  base::Lock handler_lock_;
  std::unordered_map<base::UUID, int> entries_uuid_index_;
  std::unordered_map<std::string, int> entries_route_index_;
  std::unordered_map<std::string, int> entries_path_index_;
  std::map<int, OwnedEntry> entries_;
  std::unordered_map<std::string, std::unique_ptr<RouteScheme>> schemes_;
  
  // std::unordered_map<std::string, int> handlers_name_index_;
  // std::map<int, OwnedHandler> handlers_;

  int entry_next_index_ = 0;
  //int handler_next_index_ = 0;

  DISALLOW_COPY_AND_ASSIGN(RouteModel);
};

}

#endif