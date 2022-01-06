// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_HOST_ZOOM_MAP_H_
#define MUMBA_HOST_APPLICATION_HOST_ZOOM_MAP_H_

#include <map>
#include <string>
#include <tuple>
#include <vector>
#include <memory>

#include "base/callback.h"
#include "base/callback_list.h"
#include "base/compiler_specific.h"
#include "base/macros.h"
#include "base/sequenced_task_runner_helpers.h"
#include "base/time/time.h"
#include "core/shared/common/content_export.h"
#include "url/gurl.h"

namespace base {
class Clock;
}

namespace host {

class ApplicationContents;

// HostZoomMap lives on the UI thread.
class CONTENT_EXPORT HostZoomMap {
 public:
  enum ZoomLevelChangeMode {
    ZOOM_CHANGED_FOR_HOST,             // Zoom level changed for host.
    ZOOM_CHANGED_FOR_SCHEME_AND_HOST,  // Zoom level changed for scheme/host
                                       // pair.
    ZOOM_CHANGED_TEMPORARY_ZOOM,       // Temporary zoom change for specific
                                       // renderer, no scheme/host is specified.
    PAGE_SCALE_IS_ONE_CHANGED,         // Page scale factor equal to one changed
                                       // for a host.
  };

  // Structure used to notify about zoom changes. Host and/or scheme are empty
  // if not applicable to |mode|.
  struct ZoomLevelChange {
    ZoomLevelChangeMode mode;
    std::string host;
    std::string scheme;
    double zoom_level;
    base::Time last_modified;
  };

  typedef std::vector<ZoomLevelChange> ZoomLevelVector;
  typedef base::Callback<void(const ZoomLevelChange&)> ZoomLevelChangedCallback;
  typedef base::CallbackList<void(const ZoomLevelChange&)>::Subscription Subscription;

    // Extracts the URL from NavigationEntry, substituting the error page
  // URL in the event that the error page is showing.
  //CONTENT_EXPORT static GURL GetURLFromEntry(const NavigationEntry* entry);

  //CONTENT_EXPORT static HostZoomMap* GetDefaultForApplicationContents(
  //    ApplicationContents* application_contents);

  // Returns the HostZoomMap associated with this SiteInstance. The SiteInstance
  // may serve multiple WebContents, and the HostZoomMap is the same for all of
  // these WebContents.
  static HostZoomMap* Get();
  //CONTENT_EXPORT static HostZoomMap* Get();

  // Returns the HostZoomMap associated with this WebContent's main frame. If
  // multiple WebContents share the same SiteInstance, then they share a single
  // HostZoomMap.
  static HostZoomMap* GetForApplicationContents(
      const ApplicationContents* contents);
  //CONTENT_EXPORT static HostZoomMap* GetForApplicationContents(
  //    const ApplicationContents* contents);

  // Returns the current zoom level for the specified WebContents. May be
  // temporary or host-specific.
  static double GetZoomLevel(const ApplicationContents* contents);
  //CONTENT_EXPORT static double GetZoomLevel(const ApplicationContents* contents);

  // Returns true if the page scale factor for the WebContents is one.
  static bool PageScaleFactorIsOne(
      const ApplicationContents* contents);
  //CONTENT_EXPORT static bool PageScaleFactorIsOne(
  //    const ApplicationContents* contents);

  // Sets the current zoom level for the specified WebContents. The level may
  // be temporary or host-specific depending on the particular WebContents.
  static void SetZoomLevel(const ApplicationContents* contents,
                           double level);
  //CONTENT_EXPORT static void SetZoomLevel(const ApplicationContents* contents,
  //                                        double level);

  // Send an IPC to refresh any displayed error page's zoom levels. Needs to
  // be called since error pages don't get loaded via the normal channel.
  static void SendErrorPageZoomLevelRefresh(
      const ApplicationContents* contents);
  //CONTENT_EXPORT static void SendErrorPageZoomLevelRefresh(
  //    const ApplicationContents* contents);

  HostZoomMap();
  ~HostZoomMap();

  // HostZoomMap implementation:
  void SetPageScaleFactorIsOneForView(
      int render_process_id, int render_view_id, bool is_one);
  void ClearPageScaleFactorIsOneForView(
      int render_process_id, int render_view_id);
  void CopyFrom(HostZoomMap* copy);
  double GetZoomLevelForHostAndScheme(const std::string& scheme,
                                      const std::string& host) const;
  // TODO(wjmaclean) Should we use a GURL here? crbug.com/384486
  bool HasZoomLevel(const std::string& scheme,
                    const std::string& host) const;
  ZoomLevelVector GetAllZoomLevels() const;
  void SetZoomLevelForHost(const std::string& host, double level);
  void InitializeZoomLevelForHost(const std::string& host,
                                  double level,
                                  base::Time last_modified);
  void SetZoomLevelForHostAndScheme(const std::string& scheme,
                                    const std::string& host,
                                    double level);
  bool UsesTemporaryZoomLevel(int render_process_id,
                              int render_view_id) const;
  void SetTemporaryZoomLevel(int render_process_id,
                             int render_view_id,
                             double level);
  void ClearZoomLevels(base::Time delete_begin, base::Time delete_end);
  void ClearTemporaryZoomLevel(int render_process_id,
                               int render_view_id);
  double GetDefaultZoomLevel() const;
  void SetDefaultZoomLevel(double level);
  std::unique_ptr<Subscription> AddZoomLevelChangedCallback(
      const ZoomLevelChangedCallback& callback);

  // Returns the current zoom level for the specified ApplicationContents. This may
  // be a temporary zoom level, depending on UsesTemporaryZoomLevel().
  double GetZoomLevelForApplicationContents(
      const ApplicationContents& application_contents);

  bool PageScaleFactorIsOneForApplicationContents(
      const ApplicationContents& application_contents);

  // Sets the zoom level for this ApplicationContents. If this ApplicationContents is using
  // a temporary zoom level, then level is only applied to this ApplicationContents.
  // Otherwise, the level will be applied on a host level.
  void SetZoomLevelForApplicationContents(
    const ApplicationContents& application_contents,
    double level);

  // Sets the zoom level for the specified view. The level may be set for only
  // this view, or for the host, depending on UsesTemporaryZoomLevel().
  void SetZoomLevelForView(int render_process_id,
                           int render_view_id,
                           double level,
                           const std::string& host);

  // Returns the temporary zoom level that's only valid for the lifetime of
  // the given ApplicationContents (i.e. isn't saved and doesn't affect other
  // ApplicationContentses) if it exists, the default zoom level otherwise.
  double GetTemporaryZoomLevel(int render_process_id,
                               int render_view_id) const;

  // Returns the zoom level regardless of whether it's temporary, host-keyed or
  // scheme+host-keyed.
  double GetZoomLevelForView(const GURL& url,
                             int render_process_id,
                             int render_view_id) const;

  void SendErrorPageZoomLevelRefresh();

  void WillCloseApplicationWindow(int render_process_id, int render_view_id);

  //void SetClockForTesting(base::Clock* clock) override;

 private:
  struct ZoomLevel {
    double level;
    base::Time last_modified;
  };
  typedef std::map<std::string, ZoomLevel> HostZoomLevels;
  typedef std::map<std::string, HostZoomLevels> SchemeHostZoomLevels;

  struct RenderViewKey {
    int render_process_id;
    int render_view_id;
    RenderViewKey(int render_process_id, int render_view_id)
        : render_process_id(render_process_id),
          render_view_id(render_view_id) {}
    bool operator<(const RenderViewKey& other) const {
      return std::tie(render_process_id, render_view_id) <
             std::tie(other.render_process_id, other.render_view_id);
    }
  };

  typedef std::map<RenderViewKey, double> TemporaryZoomLevels;
  typedef std::map<RenderViewKey, bool> ViewPageScaleFactorsAreOne;

  double GetZoomLevelForHost(const std::string& host) const;

  // Set a zoom level for |host| and store the |last_modified| timestamp.
  // Use only to explicitly set a timestamp.
  void SetZoomLevelForHostInternal(const std::string& host,
                                   double level,
                                   base::Time last_modified);

  // Notifies the renderers from this browser context to change the zoom level
  // for the specified host and scheme.
  // TODO(wjmaclean) Should we use a GURL here? crbug.com/384486
  void SendZoomLevelChange(const std::string& scheme,
                           const std::string& host,
                           double level);

  // Callbacks called when zoom level changes.
  base::CallbackList<void(const ZoomLevelChange&)>
      zoom_level_changed_callbacks_;

  // Copy of the pref data.
  HostZoomLevels host_zoom_levels_;
  SchemeHostZoomLevels scheme_host_zoom_levels_;
  double default_zoom_level_;

  // Page scale factor data for each renderer.
  ViewPageScaleFactorsAreOne view_page_scale_factors_are_one_;

  TemporaryZoomLevels temporary_zoom_levels_;

  base::Clock* clock_;

  DISALLOW_COPY_AND_ASSIGN(HostZoomMap);
};

}  // namespace host

#endif  // CONTENT_BROWSER_HOST_ZOOM_MAP_IMPL_H_
