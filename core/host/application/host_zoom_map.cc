// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/application/host_zoom_map.h"

#include <algorithm>
#include <cmath>
#include <memory>
#include <utility>

#include "base/strings/string_piece.h"
#include "base/strings/utf_string_conversions.h"
#include "base/time/default_clock.h"
#include "base/values.h"
//#include "core/host/frame_host/navigation_entry_impl.h"
#include "core/host/application/application_process_host.h"
#include "core/host/application/application_window_host.h"
#include "core/host/application/application_contents.h"
//#include "core/shared/common/view_messages.h"
//#include "core/host/application_contents.h"
#include "core/host/host_thread.h"
//#include "core/host/resource_context.h"
//#include "core/host/site_instance.h"
//#include "core/host/storage_partition.h"
#include "core/shared/common/page_zoom.h"
//#include "core/shared/common/url_constants.h"
#include "net/base/url_util.h"

namespace host {

namespace {

// for now it will be here, but we need to plug this into a containing
// object that will manage its lifetime

base::LazyInstance<HostZoomMap>::Leaky g_host_zoom_map =
    LAZY_INSTANCE_INITIALIZER;

std::string GetHostFromProcessView(int render_process_id, int render_view_id) {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  //ApplicationWindowHost* render_view_host =
  //    ApplicationWindow::FromID(render_process_id, render_view_id);
  //if (!render_view_host)
  //  return std::string();

  //ApplicationContents* application_contents = ApplicationContents::FromApplicationWindowHost(render_view_host);

  //NavigationEntry* entry =
  //    application_contents->GetController().GetLastCommittedEntry();
  //if (!entry)
    return std::string();

  //return net::GetHostOrSpecFromURL(HostZoomMap::GetURLFromEntry(entry));
}

}  // namespace

// GURL HostZoomMap::GetURLFromEntry(const NavigationEntry* entry) {
//   DCHECK_CURRENTLY_ON(HostThread::UI);
//   switch (entry->GetPageType()) {
//     case PAGE_TYPE_ERROR:
//       return GURL(kUnreachableWebDataURL);
//     // TODO(wjmaclean): In future, give interstitial pages special treatment as
//     // well.
//     default:
//       return entry->GetURL();
//   }
// }

// HostZoomMap* HostZoomMap::GetDefaultForApplicationContents(ApplicationContents* context) {
//   DCHECK_CURRENTLY_ON(HostThread::UI);
//   StoragePartition* partition =
//       ApplicationContents::GetDefaultStoragePartition(context);
//   DCHECK(partition);
//   return partition->GetHostZoomMap();
// }

 HostZoomMap* HostZoomMap::Get() {//SiteInstance* instance) {
   DCHECK_CURRENTLY_ON(HostThread::UI);
   //StoragePartition* partition = ApplicationContents::GetStoragePartition(
   //    instance->GetApplicationContents(), instance);
   //DCHECK(partition);
   //return partition->GetHostZoomMap();
   return g_host_zoom_map.Pointer();
}

HostZoomMap* HostZoomMap::GetForApplicationContents(const ApplicationContents* contents) {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  // TODO(wjmaclean): Update this behaviour to work with OOPIF.
  // See crbug.com/528407.
  //StoragePartition* partition =
  //    ApplicationContents::GetStoragePartition(contents->GetApplicationContents(),
  //                                        contents->GetSiteInstance());
  //DCHECK(partition);
  //return partition->GetHostZoomMap();
  //CHECK(false);
  return HostZoomMap::Get();//nullptr;
}

// Helper function for setting/getting zoom levels for ApplicationContents without
// having to import HostZoomMap everywhere.
double HostZoomMap::GetZoomLevel(const ApplicationContents* application_contents) {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  HostZoomMap* host_zoom_map = HostZoomMap::GetForApplicationContents(application_contents);
  return host_zoom_map->GetZoomLevelForApplicationContents(*application_contents);
}

bool HostZoomMap::PageScaleFactorIsOne(const ApplicationContents* application_contents) {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  HostZoomMap* host_zoom_map = HostZoomMap::GetForApplicationContents(application_contents);
  return host_zoom_map->PageScaleFactorIsOneForApplicationContents(*application_contents);
}

void HostZoomMap::SetZoomLevel(const ApplicationContents* application_contents, double level) {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  HostZoomMap* host_zoom_map = HostZoomMap::GetForApplicationContents(application_contents);
  host_zoom_map->SetZoomLevelForApplicationContents(*application_contents, level);
}

void HostZoomMap::SendErrorPageZoomLevelRefresh(
    const ApplicationContents* application_contents) {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  //HostZoomMap* host_zoom_map = HostZoomMap::GetDefaultForApplicationContents(
  //        application_contents->GetApplicationContents());
  //host_zoom_map->SendErrorPageZoomLevelRefresh();
  CHECK(false);
}

HostZoomMap::HostZoomMap()
    : default_zoom_level_(0.0),
      clock_(base::DefaultClock::GetInstance()) {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  //g_host_zoom_map.Set(this);
}

void HostZoomMap::CopyFrom(HostZoomMap* copy_interface) {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  HostZoomMap* copy = copy_interface;
  host_zoom_levels_.insert(copy->host_zoom_levels_.begin(),
                           copy->host_zoom_levels_.end());
  for (const auto& it : copy->scheme_host_zoom_levels_) {
    const std::string& host = it.first;
    scheme_host_zoom_levels_[host] = HostZoomLevels();
    scheme_host_zoom_levels_[host].insert(it.second.begin(), it.second.end());
  }
  default_zoom_level_ = copy->default_zoom_level_;
}

double HostZoomMap::GetZoomLevelForHost(const std::string& host) const {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  const auto it = host_zoom_levels_.find(host);
  return it != host_zoom_levels_.end() ? it->second.level : default_zoom_level_;
}

bool HostZoomMap::HasZoomLevel(const std::string& scheme,
                               const std::string& host) const {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  SchemeHostZoomLevels::const_iterator scheme_iterator(
      scheme_host_zoom_levels_.find(scheme));

  const HostZoomLevels& zoom_levels =
      (scheme_iterator != scheme_host_zoom_levels_.end())
          ? scheme_iterator->second
          : host_zoom_levels_;

  return base::ContainsKey(zoom_levels, host);
}

double HostZoomMap::GetZoomLevelForHostAndScheme(
    const std::string& scheme,
    const std::string& host) const {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  SchemeHostZoomLevels::const_iterator scheme_iterator(
      scheme_host_zoom_levels_.find(scheme));
  if (scheme_iterator != scheme_host_zoom_levels_.end()) {
    HostZoomLevels::const_iterator i(scheme_iterator->second.find(host));
    if (i != scheme_iterator->second.end())
      return i->second.level;
  }

  return GetZoomLevelForHost(host);
}

HostZoomMap::ZoomLevelVector HostZoomMap::GetAllZoomLevels() const {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  HostZoomMap::ZoomLevelVector result;
  result.reserve(host_zoom_levels_.size() + scheme_host_zoom_levels_.size());
  for (const auto& entry : host_zoom_levels_) {
    ZoomLevelChange change = {
        HostZoomMap::ZOOM_CHANGED_FOR_HOST,
        entry.first,                // host
        std::string(),              // scheme
        entry.second.level,         // zoom level
        entry.second.last_modified  // last modified
    };
    result.push_back(change);
  }
  for (const auto& scheme_entry : scheme_host_zoom_levels_) {
    const std::string& scheme = scheme_entry.first;
    const HostZoomLevels& host_zoom_levels = scheme_entry.second;
    for (const auto& entry : host_zoom_levels) {
      ZoomLevelChange change = {
          HostZoomMap::ZOOM_CHANGED_FOR_SCHEME_AND_HOST,
          entry.first,                // host
          scheme,                     // scheme
          entry.second.level,         // zoom level
          entry.second.last_modified  // last modified
      };
      result.push_back(change);
    }
  }
  return result;
}

void HostZoomMap::SetZoomLevelForHost(const std::string& host,
                                          double level) {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  base::Time last_modified = clock_->Now();
  SetZoomLevelForHostInternal(host, level, last_modified);
}

void HostZoomMap::InitializeZoomLevelForHost(const std::string& host,
                                                 double level,
                                                 base::Time last_modified) {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  SetZoomLevelForHostInternal(host, level, last_modified);
}

void HostZoomMap::SetZoomLevelForHostInternal(const std::string& host,
                                              double level,
                                              base::Time last_modified) {
  DCHECK_CURRENTLY_ON(HostThread::UI);

  if (common::ZoomValuesEqual(level, default_zoom_level_)) {
    host_zoom_levels_.erase(host);
  } else {
    ZoomLevel& zoomLevel = host_zoom_levels_[host];
    zoomLevel.level = level;
    zoomLevel.last_modified = last_modified;
  }

  // TODO(wjmaclean) Should we use a GURL here? crbug.com/384486
  SendZoomLevelChange(std::string(), host, level);

  HostZoomMap::ZoomLevelChange change;
  change.mode = HostZoomMap::ZOOM_CHANGED_FOR_HOST;
  change.host = host;
  change.zoom_level = level;
  change.last_modified = last_modified;

  zoom_level_changed_callbacks_.Notify(change);
}

void HostZoomMap::SetZoomLevelForHostAndScheme(const std::string& scheme,
                                               const std::string& host,
                                               double level) {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  // No last_modified timestamp for scheme and host because they are
  // not persistet and are used for special cases only.
  scheme_host_zoom_levels_[scheme][host].level = level;

  SendZoomLevelChange(scheme, host, level);

  HostZoomMap::ZoomLevelChange change;
  change.mode = HostZoomMap::ZOOM_CHANGED_FOR_SCHEME_AND_HOST;
  change.host = host;
  change.scheme = scheme;
  change.zoom_level = level;
  change.last_modified = base::Time();

  zoom_level_changed_callbacks_.Notify(change);
}

double HostZoomMap::GetDefaultZoomLevel() const {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  return default_zoom_level_;
}

void HostZoomMap::SetDefaultZoomLevel(double level) {
  DCHECK_CURRENTLY_ON(HostThread::UI);

  if (common::ZoomValuesEqual(level, default_zoom_level_))
      return;

  default_zoom_level_ = level;

  // First, remove all entries that match the new default zoom level.
  for (auto it = host_zoom_levels_.begin(); it != host_zoom_levels_.end();) {
    if (common::ZoomValuesEqual(it->second.level, default_zoom_level_))
      it = host_zoom_levels_.erase(it);
    else
      it++;
  }

  // Second, update zoom levels for all pages that do not have an overriding
  // entry.
  for (auto* application_contents : ApplicationContents::GetAllApplicationContents()) {
    // Only change zoom for ApplicationContents tied to the StoragePartition this
    // HostZoomMap serves.
    if (GetForApplicationContents(application_contents) != this)
      continue;

    int render_process_id =
        application_contents->GetApplicationWindowHost()->GetProcess()->GetID();
    int render_view_id = application_contents->GetApplicationWindowHost()->GetRoutingID();

    // Get the url from the navigation controller directly, as calling
    // ApplicationContentsImpl::GetLastCommittedURL() may give us a virtual url that
    // is different than the one stored in the map.
    GURL url;
    std::string host;
    std::string scheme;

    //NavigationEntry* entry =
    //    application_contents->GetController().GetLastCommittedEntry();
    // It is possible for a WebContent's zoom level to be queried before
    // a navigation has occurred.
    //if (entry) {
    //  url = GetURLFromEntry(entry);
    //  scheme = url.scheme();
    //  host = net::GetHostOrSpecFromURL(url);
    //}

    bool uses_default_zoom =
        !HasZoomLevel(scheme, host) &&
        !UsesTemporaryZoomLevel(render_process_id, render_view_id);

    if (uses_default_zoom) {
      application_contents->UpdateZoom(level);

      HostZoomMap::ZoomLevelChange change;
      change.mode = HostZoomMap::ZOOM_CHANGED_FOR_HOST;
      change.host = host;
      change.zoom_level = level;

      zoom_level_changed_callbacks_.Notify(change);
    }
  }
}

std::unique_ptr<HostZoomMap::Subscription> HostZoomMap::AddZoomLevelChangedCallback(
    const ZoomLevelChangedCallback& callback) {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  return zoom_level_changed_callbacks_.Add(callback);
}

double HostZoomMap::GetZoomLevelForApplicationContents(const ApplicationContents& application_contents) {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  if (application_contents.GetApplicationProcessHost() && application_contents.GetApplicationWindowHost()) {
    int app_process_id =
        application_contents.GetApplicationProcessHost()->GetID();
    int routing_id = application_contents.GetApplicationWindowHost()->GetRoutingID();

    if (UsesTemporaryZoomLevel(app_process_id, routing_id))
      return GetTemporaryZoomLevel(app_process_id, routing_id);
  }

  // Get the url from the navigation controller directly, as calling
  // ApplicationContentsImpl::GetLastCommittedURL() may give us a virtual url that
  // is different than is stored in the map.
  GURL url;
  //NavigationEntry* entry =
  //    application_contents_impl.GetController().GetLastCommittedEntry();
  // It is possible for a WebContent's zoom level to be queried before
  // a navigation has occurred.
  //if (entry)
  //  url = GetURLFromEntry(entry);
  return GetZoomLevelForHostAndScheme(url.scheme(),
                                      net::GetHostOrSpecFromURL(url));
}

void HostZoomMap::SetZoomLevelForApplicationContents(
    const ApplicationContents& application_contents,
    double level) {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  int render_process_id =
      application_contents.GetApplicationWindowHost()->GetProcess()->GetID();
  int render_view_id = application_contents.GetApplicationWindowHost()->GetRoutingID();
  if (UsesTemporaryZoomLevel(render_process_id, render_view_id)) {
    SetTemporaryZoomLevel(render_process_id, render_view_id, level);
  } //else {
    // Get the url from the navigation controller directly, as calling
    // ApplicationContentsImpl::GetLastCommittedURL() may give us a virtual url that
    // is different than what the render view is using. If the two don't match,
    // the attempt to set the zoom will fail.
    //NavigationEntry* entry =
    //    application_contents_impl.GetController().GetLastCommittedEntry();
    // Tests may invoke this function with a null entry, but we don't
    // want to save zoom levels in this case.
    //if (!entry)
  //    return;

    //GURL url = GetURLFromEntry(entry);
    //SetZoomLevelForHost(net::GetHostOrSpecFromURL(url), level);
  //}
}

void HostZoomMap::SetZoomLevelForView(int render_process_id,
                                      int render_view_id,
                                      double level,
                                      const std::string& host) {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  if (UsesTemporaryZoomLevel(render_process_id, render_view_id))
    SetTemporaryZoomLevel(render_process_id, render_view_id, level);
  else
    SetZoomLevelForHost(host, level);
}

void HostZoomMap::SetPageScaleFactorIsOneForView(int render_process_id,
                                                 int render_view_id,
                                                 bool is_one) {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  view_page_scale_factors_are_one_[RenderViewKey(render_process_id,
                                                 render_view_id)] = is_one;
  HostZoomMap::ZoomLevelChange change;
  change.mode = HostZoomMap::PAGE_SCALE_IS_ONE_CHANGED;
  zoom_level_changed_callbacks_.Notify(change);
}

bool HostZoomMap::PageScaleFactorIsOneForApplicationContents(const ApplicationContents& application_contents) {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  if (!application_contents.GetApplicationWindowHost()->GetProcess())
    return true;

  const auto it = view_page_scale_factors_are_one_.find(RenderViewKey(
      application_contents.GetApplicationWindowHost()->GetProcess()->GetID(),
      application_contents.GetApplicationWindowHost()->GetRoutingID()));
  return it != view_page_scale_factors_are_one_.end() ? it->second : true;
}

void HostZoomMap::ClearPageScaleFactorIsOneForView(int render_process_id,
                                                   int render_view_id) {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  view_page_scale_factors_are_one_.erase(
      RenderViewKey(render_process_id, render_view_id));
}

bool HostZoomMap::UsesTemporaryZoomLevel(int render_process_id,
                                         int render_view_id) const {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  RenderViewKey key(render_process_id, render_view_id);
  return base::ContainsKey(temporary_zoom_levels_, key);
}

double HostZoomMap::GetTemporaryZoomLevel(int render_process_id,
                                          int render_view_id) const {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  RenderViewKey key(render_process_id, render_view_id);
  const auto it = temporary_zoom_levels_.find(key);
  return it != temporary_zoom_levels_.end() ? it->second : 0;
}

void HostZoomMap::SetTemporaryZoomLevel(int render_process_id,
                                        int render_view_id,
                                        double level) {
  DCHECK_CURRENTLY_ON(HostThread::UI);

  RenderViewKey key(render_process_id, render_view_id);
  temporary_zoom_levels_[key] = level;

  ApplicationContents* application_contents = ApplicationContents::FromApplicationWindowHost(
          ApplicationWindowHost::FromID(render_process_id, render_view_id));
  application_contents->SetTemporaryZoomLevel(level, true);

  HostZoomMap::ZoomLevelChange change;
  change.mode = HostZoomMap::ZOOM_CHANGED_TEMPORARY_ZOOM;
  change.host = GetHostFromProcessView(render_process_id, render_view_id);
  change.zoom_level = level;

  zoom_level_changed_callbacks_.Notify(change);
}

double HostZoomMap::GetZoomLevelForView(const GURL& url,
                                        int render_process_id,
                                        int render_view_id) const {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  RenderViewKey key(render_process_id, render_view_id);

  if (base::ContainsKey(temporary_zoom_levels_, key))
    return temporary_zoom_levels_.find(key)->second;

  return GetZoomLevelForHostAndScheme(url.scheme(),
                                      net::GetHostOrSpecFromURL(url));
}

void HostZoomMap::ClearZoomLevels(base::Time delete_begin,
                                  base::Time delete_end) {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  double default_zoom_level = GetDefaultZoomLevel();
  for (const auto& zoom_level : GetAllZoomLevels()) {
    if (zoom_level.scheme.empty() && delete_begin <= zoom_level.last_modified &&
        (delete_end.is_null() || zoom_level.last_modified < delete_end)) {
      SetZoomLevelForHost(zoom_level.host, default_zoom_level);
    }
  }
}

void HostZoomMap::ClearTemporaryZoomLevel(int render_process_id,
                                          int render_view_id) {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  RenderViewKey key(render_process_id, render_view_id);
  TemporaryZoomLevels::iterator it = temporary_zoom_levels_.find(key);
  if (it == temporary_zoom_levels_.end())
    return;

  temporary_zoom_levels_.erase(it);
  ApplicationContents* application_contents =ApplicationContents::FromApplicationWindowHost(
          ApplicationWindowHost::FromID(render_process_id, render_view_id));
  application_contents->SetTemporaryZoomLevel(GetZoomLevelForHost(
          GetHostFromProcessView(render_process_id, render_view_id)), false);
}

void HostZoomMap::SendZoomLevelChange(const std::string& scheme,
                                      const std::string& host,
                                      double level) {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  // We'll only send to ApplicationContents not using temporary zoom levels. The one
  // other case of interest is where the renderer is hosting a plugin document;
  // that should be reflected in our temporary zoom level map, but we will
  // double check on the renderer side to avoid the possibility of any races.
  for (auto* application_contents : ApplicationContents::GetAllApplicationContents()) {
    // Only send zoom level changes to ApplicationContents that are using this
    // HostZoomMap.
    if (GetForApplicationContents(application_contents) != this)
      continue;

    int render_process_id =
        application_contents->GetApplicationWindowHost()->GetProcess()->GetID();
    int render_view_id = application_contents->GetApplicationWindowHost()->GetRoutingID();

    if (!UsesTemporaryZoomLevel(render_process_id, render_view_id))
      application_contents->UpdateZoomIfNecessary(scheme, host, level);
  }
}

void HostZoomMap::SendErrorPageZoomLevelRefresh() {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  GURL error_url("data:text/html,chromewebdata");
  std::string host = net::GetHostOrSpecFromURL(error_url);
  double error_page_zoom_level = GetZoomLevelForHost(host);

  SendZoomLevelChange(std::string(), host, error_page_zoom_level);
}

void HostZoomMap::WillCloseApplicationWindow(int render_process_id,
                                             int render_view_id) {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  ClearTemporaryZoomLevel(render_process_id, render_view_id);
  ClearPageScaleFactorIsOneForView(render_process_id, render_view_id);
}

HostZoomMap::~HostZoomMap() {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  //g_host_zoom_map.Set(nullptr);
}

//void HostZoomMap::SetClockForTesting(base::Clock* clock) {
//  clock_ = clock;
//}

}  // namespace host
