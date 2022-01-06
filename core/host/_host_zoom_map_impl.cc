// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/host_zoom_map_impl.h"

#include <algorithm>
#include <cmath>
#include <memory>
#include <utility>

#include "base/strings/string_piece.h"
#include "base/strings/utf_string_conversions.h"
#include "base/time/default_clock.h"
#include "base/values.h"
#include "core/host/application/application_process_host.h"
#include "core/host/application/application_window_host.h"
#include "core/host/application/application_contents.h"
#include "core/host/host_thread.h"
#include "core/common/page_zoom.h"
//#include "core/common/url_constants.h"
#include "net/base/url_util.h"

namespace host {

namespace {

std::string GetHostFromProcessView(int render_process_id, int render_view_id) {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  // ApplicationWindowHost* render_view_host =
  //     ApplicationWindow::FromID(render_process_id, render_view_id);
  // if (!render_view_host)
  //   return std::string();

  // ApplicationContents* app_contents = ApplicationContents::FromApplicationWindowHost(render_view_host);

  // NavigationEntry* entry =
  //     app_contents->GetController().GetLastCommittedEntry();
  // if (!entry)
  //   return std::string();

  // return net::GetHostOrSpecFromURL(HostZoomMap::GetURLFromEntry(entry));
  return std::string();
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

// HostZoomMap* HostZoomMap::GetDefaultForBrowserContext(BrowserContext* context) {
//   DCHECK_CURRENTLY_ON(HostThread::UI);
//   StoragePartition* partition =
//       BrowserContext::GetDefaultStoragePartition(context);
//   DCHECK(partition);
//   return partition->GetHostZoomMap();
// }

// HostZoomMap* HostZoomMap::Get(SiteInstance* instance) {
//   DCHECK_CURRENTLY_ON(HostThread::UI);
//   StoragePartition* partition = BrowserContext::GetStoragePartition(
//       instance->GetBrowserContext(), instance);
//   DCHECK(partition);
//   return partition->GetHostZoomMap();
// }

HostZoomMap* HostZoomMap::GetForApplicationContents(const ApplicationContents* contents) {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  // TODO(wjmaclean): Update this behaviour to work with OOPIF.
  // See crbug.com/528407.
  //StoragePartition* partition =
  //    BrowserContext::GetStoragePartition(contents->GetBrowserContext(),
  //                                        contents->GetSiteInstance());
  //DCHECK(partition);
  //return partition->GetHostZoomMap();
  return contents->GetHostZoomMap();
}

// Helper function for setting/getting zoom levels for ApplicationContents without
// having to import HostZoomMapImpl everywhere.
double HostZoomMap::GetZoomLevel(const ApplicationContents* app_contents) {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  HostZoomMapImpl* host_zoom_map = static_cast<HostZoomMapImpl*>(
      HostZoomMap::GetForApplicationContents(app_contents));
  return host_zoom_map->GetZoomLevelForApplicationContents(
      *static_cast<const ApplicationContents*>(app_contents));
}

bool HostZoomMap::PageScaleFactorIsOne(const ApplicationContents* app_contents) {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  HostZoomMapImpl* host_zoom_map = static_cast<HostZoomMapImpl*>(
      HostZoomMap::GetForApplicationContents(app_contents));
  return host_zoom_map->PageScaleFactorIsOneForApplicationContents(
      *static_cast<const ApplicationContents*>(app_contents));
}

void HostZoomMap::SetZoomLevel(const ApplicationContents* app_contents, double level) {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  HostZoomMapImpl* host_zoom_map = static_cast<HostZoomMapImpl*>(
      HostZoomMap::GetForApplicationContents(app_contents));
  host_zoom_map->SetZoomLevelForApplicationContents(
      *static_cast<const ApplicationContents*>(app_contents), level);
}

void HostZoomMap::SendErrorPageZoomLevelRefresh(
    const ApplicationContents* app_contents) {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  HostZoomMapImpl* host_zoom_map =
      static_cast<HostZoomMapImpl*>(HostZoomMap::GetForApplicationContents(
          app_contents));
  host_zoom_map->SendErrorPageZoomLevelRefresh();
}

HostZoomMapImpl::HostZoomMapImpl()
    : default_zoom_level_(0.0),
      clock_(base::DefaultClock::GetInstance()) {
  DCHECK_CURRENTLY_ON(HostThread::UI);
}

void HostZoomMapImpl::CopyFrom(HostZoomMap* copy_interface) {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  HostZoomMapImpl* copy = static_cast<HostZoomMapImpl*>(copy_interface);
  host_zoom_levels_.insert(copy->host_zoom_levels_.begin(),
                           copy->host_zoom_levels_.end());
  for (const auto& it : copy->scheme_host_zoom_levels_) {
    const std::string& host = it.first;
    scheme_host_zoom_levels_[host] = HostZoomLevels();
    scheme_host_zoom_levels_[host].insert(it.second.begin(), it.second.end());
  }
  default_zoom_level_ = copy->default_zoom_level_;
}

double HostZoomMapImpl::GetZoomLevelForHost(const std::string& host) const {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  const auto it = host_zoom_levels_.find(host);
  return it != host_zoom_levels_.end() ? it->second.level : default_zoom_level_;
}

bool HostZoomMapImpl::HasZoomLevel(const std::string& scheme,
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

double HostZoomMapImpl::GetZoomLevelForHostAndScheme(
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

HostZoomMap::ZoomLevelVector HostZoomMapImpl::GetAllZoomLevels() const {
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

void HostZoomMapImpl::SetZoomLevelForHost(const std::string& host,
                                          double level) {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  base::Time last_modified = clock_->Now();
  SetZoomLevelForHostInternal(host, level, last_modified);
}

void HostZoomMapImpl::InitializeZoomLevelForHost(const std::string& host,
                                                 double level,
                                                 base::Time last_modified) {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  SetZoomLevelForHostInternal(host, level, last_modified);
}

void HostZoomMapImpl::SetZoomLevelForHostInternal(const std::string& host,
                                                  double level,
                                                  base::Time last_modified) {
  DCHECK_CURRENTLY_ON(HostThread::UI);

  if (ZoomValuesEqual(level, default_zoom_level_)) {
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

void HostZoomMapImpl::SetZoomLevelForHostAndScheme(const std::string& scheme,
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

double HostZoomMapImpl::GetDefaultZoomLevel() const {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  return default_zoom_level_;
}

void HostZoomMapImpl::SetDefaultZoomLevel(double level) {
  DCHECK_CURRENTLY_ON(HostThread::UI);

  if (ZoomValuesEqual(level, default_zoom_level_))
      return;

  default_zoom_level_ = level;

  // First, remove all entries that match the new default zoom level.
  for (auto it = host_zoom_levels_.begin(); it != host_zoom_levels_.end();) {
    if (ZoomValuesEqual(it->second.level, default_zoom_level_))
      it = host_zoom_levels_.erase(it);
    else
      it++;
  }

  // Second, update zoom levels for all pages that do not have an overriding
  // entry.
  for (auto* app_contents : ApplicationContents::GetAllApplicationContents()) {
    // Only change zoom for ApplicationContents tied to the StoragePartition this
    // HostZoomMap serves.
    if (GetForApplicationContents(app_contents) != this)
      continue;

    int render_process_id =
        app_contents->GetApplicationWindowHost()->GetProcess()->GetID();
    int render_view_id = app_contents->GetApplicationWindowHost()->GetRoutingID();

    // Get the url from the navigation controller directly, as calling
    // ApplicationContents::GetLastCommittedURL() may give us a virtual url that
    // is different than the one stored in the map.
    GURL url;
    std::string host;
    std::string scheme;

    //NavigationEntry* entry =
    //    app_contents->GetController().GetLastCommittedEntry();
    // It is possible for a WebContent's zoom level to be queried before
    // a navigation has occurred.
    //if (entry) {
//      url = GetURLFromEntry(entry);
      //scheme = url.scheme();
//      host = net::GetHostOrSpecFromURL(url);
    //}

    bool uses_default_zoom =
        !HasZoomLevel(scheme, host) &&
        !UsesTemporaryZoomLevel(render_process_id, render_view_id);

    if (uses_default_zoom) {
      app_contents->UpdateZoom(level);

      HostZoomMap::ZoomLevelChange change;
      change.mode = HostZoomMap::ZOOM_CHANGED_FOR_HOST;
      change.host = host;
      change.zoom_level = level;

      zoom_level_changed_callbacks_.Notify(change);
    }
  }
}

std::unique_ptr<HostZoomMap::Subscription>
HostZoomMapImpl::AddZoomLevelChangedCallback(
    const ZoomLevelChangedCallback& callback) {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  return zoom_level_changed_callbacks_.Add(callback);
}

double HostZoomMapImpl::GetZoomLevelForApplicationContents(
    const ApplicationContents& app_contents_impl) const {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  int render_process_id =
      app_contents_impl.GetApplicationWindowHostt()->GetProcess()->GetID();
  int routing_id = app_contents_impl.GetApplicationWindowHost()->GetRoutingID();

  if (UsesTemporaryZoomLevel(render_process_id, routing_id))
    return GetTemporaryZoomLevel(render_process_id, routing_id);

  // Get the url from the navigation controller directly, as calling
  // ApplicationContents::GetLastCommittedURL() may give us a virtual url that
  // is different than is stored in the map.
  GURL url;
  //NavigationEntry* entry =
  //    app_contents_impl.GetController().GetLastCommittedEntry();
  // It is possible for a WebContent's zoom level to be queried before
  // a navigation has occurred.
  //if (entry)
//    url = GetURLFromEntry(entry);
  return GetZoomLevelForHostAndScheme(url.scheme(),
                                      net::GetHostOrSpecFromURL(url));
}

void HostZoomMapImpl::SetZoomLevelForApplicationContents(
    const ApplicationContents& app_contents_impl,
    double level) {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  int render_process_id =
      app_contents_impl.GetApplicationWindowHost()->GetProcess()->GetID();
  int render_view_id = app_contents_impl.GetApplicationWindowHost()->GetRoutingID();
  if (UsesTemporaryZoomLevel(render_process_id, render_view_id)) {
    SetTemporaryZoomLevel(render_process_id, render_view_id, level);
  } else {
    // Get the url from the navigation controller directly, as calling
    // ApplicationContents::GetLastCommittedURL() may give us a virtual url that
    // is different than what the render view is using. If the two don't match,
    // the attempt to set the zoom will fail.
    //NavigationEntry* entry =
    //    app_contents_impl.GetController().GetLastCommittedEntry();
    // Tests may invoke this function with a null entry, but we don't
    // want to save zoom levels in this case.
    //if (!entry)
    //  return;

    GURL url;// = GetURLFromEntry(entry);
    SetZoomLevelForHost(net::GetHostOrSpecFromURL(url), level);
  }
}

void HostZoomMapImpl::SetZoomLevelForView(int render_process_id,
                                          int render_view_id,
                                          double level,
                                          const std::string& host) {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  if (UsesTemporaryZoomLevel(render_process_id, render_view_id))
    SetTemporaryZoomLevel(render_process_id, render_view_id, level);
  else
    SetZoomLevelForHost(host, level);
}

void HostZoomMapImpl::SetPageScaleFactorIsOneForView(int render_process_id,
                                                     int render_view_id,
                                                     bool is_one) {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  view_page_scale_factors_are_one_[RenderViewKey(render_process_id,
                                                 render_view_id)] = is_one;
  HostZoomMap::ZoomLevelChange change;
  change.mode = HostZoomMap::PAGE_SCALE_IS_ONE_CHANGED;
  zoom_level_changed_callbacks_.Notify(change);
}

bool HostZoomMapImpl::PageScaleFactorIsOneForApplicationContents(
    const ApplicationContents& app_contents_impl) const {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  if (!app_contents_impl.GetApplicationWindowHost()->GetProcess())
    return true;

  const auto it = view_page_scale_factors_are_one_.find(RenderViewKey(
      app_contents_impl.GetApplicationWindowHost()->GetProcess()->GetID(),
      app_contents_impl.GetApplicationWindowHost()->GetRoutingID()));
  return it != view_page_scale_factors_are_one_.end() ? it->second : true;
}

void HostZoomMapImpl::ClearPageScaleFactorIsOneForView(int render_process_id,
                                                       int render_view_id) {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  view_page_scale_factors_are_one_.erase(
      RenderViewKey(render_process_id, render_view_id));
}

bool HostZoomMapImpl::UsesTemporaryZoomLevel(int render_process_id,
                                             int render_view_id) const {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  RenderViewKey key(render_process_id, render_view_id);
  return base::ContainsKey(temporary_zoom_levels_, key);
}

double HostZoomMapImpl::GetTemporaryZoomLevel(int render_process_id,
                                              int render_view_id) const {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  RenderViewKey key(render_process_id, render_view_id);
  const auto it = temporary_zoom_levels_.find(key);
  return it != temporary_zoom_levels_.end() ? it->second : 0;
}

void HostZoomMapImpl::SetTemporaryZoomLevel(int render_process_id,
                                            int render_view_id,
                                            double level) {
  DCHECK_CURRENTLY_ON(HostThread::UI);

  RenderViewKey key(render_process_id, render_view_id);
  temporary_zoom_levels_[key] = level;

  ApplicationContents* app_contents =
      static_cast<ApplicationContents*>(ApplicationContents::FromApplicationWindowHost(
          ApplicationWindowHost::FromID(render_process_id, render_view_id)));
  app_contents->SetTemporaryZoomLevel(level, true);

  HostZoomMap::ZoomLevelChange change;
  change.mode = HostZoomMap::ZOOM_CHANGED_TEMPORARY_ZOOM;
  change.host = GetHostFromProcessView(render_process_id, render_view_id);
  change.zoom_level = level;

  zoom_level_changed_callbacks_.Notify(change);
}

double HostZoomMapImpl::GetZoomLevelForView(const GURL& url,
                                            int render_process_id,
                                            int render_view_id) const {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  RenderViewKey key(render_process_id, render_view_id);

  if (base::ContainsKey(temporary_zoom_levels_, key))
    return temporary_zoom_levels_.find(key)->second;

  return GetZoomLevelForHostAndScheme(url.scheme(),
                                      net::GetHostOrSpecFromURL(url));
}

void HostZoomMapImpl::ClearZoomLevels(base::Time delete_begin,
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

void HostZoomMapImpl::ClearTemporaryZoomLevel(int render_process_id,
                                              int render_view_id) {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  RenderViewKey key(render_process_id, render_view_id);
  TemporaryZoomLevels::iterator it = temporary_zoom_levels_.find(key);
  if (it == temporary_zoom_levels_.end())
    return;

  temporary_zoom_levels_.erase(it);
  ApplicationContents* app_contents =
      static_cast<ApplicationContents*>(ApplicationContents::FromApplicationWindowHost(
          ApplicationWindowHost::FromID(render_process_id, render_view_id)));
  app_contents->SetTemporaryZoomLevel(GetZoomLevelForHost(
          GetHostFromProcessView(render_process_id, render_view_id)), false);
}

void HostZoomMapImpl::SendZoomLevelChange(const std::string& scheme,
                                          const std::string& host,
                                          double level) {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  // We'll only send to ApplicationContents not using temporary zoom levels. The one
  // other case of interest is where the renderer is hosting a plugin document;
  // that should be reflected in our temporary zoom level map, but we will
  // double check on the renderer side to avoid the possibility of any races.
  for (auto* app_contents : ApplicationContents::GetAllApplicationContents()) {
    // Only send zoom level changes to ApplicationContents that are using this
    // HostZoomMap.
    if (GetForApplicationContents(app_contents) != this)
      continue;

    int render_process_id =
        app_contents->GetApplicationWindowHost()->GetProcess()->GetID();
    int render_view_id = app_contents->GetApplicationWindowHost()->GetRoutingID();

    if (!UsesTemporaryZoomLevel(render_process_id, render_view_id))
      app_contents->UpdateZoomIfNecessary(scheme, host, level);
  }
}

void HostZoomMapImpl::SendErrorPageZoomLevelRefresh() {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  GURL error_url(kUnreachableWebDataURL);
  std::string host = net::GetHostOrSpecFromURL(error_url);
  double error_page_zoom_level = GetZoomLevelForHost(host);

  SendZoomLevelChange(std::string(), host, error_page_zoom_level);
}

void HostZoomMapImpl::WillCloseRenderView(int render_process_id,
                                          int render_view_id) {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  ClearTemporaryZoomLevel(render_process_id, render_view_id);
  ClearPageScaleFactorIsOneForView(render_process_id, render_view_id);
}

HostZoomMapImpl::~HostZoomMapImpl() {
  DCHECK_CURRENTLY_ON(HostThread::UI);
}

void HostZoomMapImpl::SetClockForTesting(base::Clock* clock) {
  clock_ = clock;
}

}  // namespace host
