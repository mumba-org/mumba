// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef COMPONENTS_ZOOM_ZOOM_CONTROLLER_H_
#define COMPONENTS_ZOOM_ZOOM_CONTROLLER_H_

#include <memory>

#include "base/compiler_specific.h"
#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/observer_list.h"
#include "components/prefs/pref_member.h"
#include "core/host/application/host_zoom_map.h"
#include "core/host/application/application_contents.h"
#include "core/host/application/application_contents_observer.h"
#include "core/host/application/application_contents_user_data.h"

class ZoomControllerTest;

namespace host {
class ApplicationContents;
}

namespace zoom {
class ZoomObserver;

class ZoomRequestClient : public base::RefCounted<ZoomRequestClient> {
 public:
  ZoomRequestClient() {}
  virtual bool ShouldSuppressBubble() const = 0;

 protected:
  virtual ~ZoomRequestClient() {}

 private:
  friend class base::RefCounted<ZoomRequestClient>;

  DISALLOW_COPY_AND_ASSIGN(ZoomRequestClient);
};

// Per-tab class to manage zoom changes and the Omnibox zoom icon. Lives on the
// UI thread.
class ZoomController : public host::ApplicationContentsObserver,
                       public host::ApplicationContentsUserData<ZoomController> {
 public:
  // Defines how zoom changes are handled.
  enum ZoomMode {
    // Results in default zoom behavior, i.e. zoom changes are handled
    // automatically and on a per-origin basis, meaning that other tabs
    // navigated to the same origin will also zoom.
    ZOOM_MODE_DEFAULT,
    // Results in zoom changes being handled automatically, but on a per-tab
    // basis. Tabs in this zoom mode will not be affected by zoom changes in
    // other tabs, and vice versa.
    ZOOM_MODE_ISOLATED,
    // Overrides the automatic handling of zoom changes. The |onZoomChange|
    // event will still be dispatched, but the page will not actually be zoomed.
    // These zoom changes can be handled manually by listening for the
    // |onZoomChange| event. Zooming in this mode is also on a per-tab basis.
    ZOOM_MODE_MANUAL,
    // Disables all zooming in this tab. The tab will revert to the default
    // zoom level, and all attempted zoom changes will be ignored.
    ZOOM_MODE_DISABLED,
  };

  enum RelativeZoom {
    ZOOM_BELOW_DEFAULT_ZOOM,
    ZOOM_AT_DEFAULT_ZOOM,
    ZOOM_ABOVE_DEFAULT_ZOOM
  };

  struct ZoomChangedEventData {
    ZoomChangedEventData(host::ApplicationContents* app_contents,
                         double old_zoom_level,
                         double new_zoom_level,
                         ZoomController::ZoomMode zoom_mode,
                         bool can_show_bubble)
        : app_contents(app_contents),
          old_zoom_level(old_zoom_level),
          new_zoom_level(new_zoom_level),
          zoom_mode(zoom_mode),
          can_show_bubble(can_show_bubble) {}
    host::ApplicationContents* app_contents;
    double old_zoom_level;
    double new_zoom_level;
    ZoomController::ZoomMode zoom_mode;
    bool can_show_bubble;
  };

  // Since it's possible for a WebContents to not have a ZoomController, provide
  // a simple, safe and reliable method to find the current zoom level for a
  // given WebContents*.
  static double GetZoomLevelForApplicationContents(
      const host::ApplicationContents* app_contents);

  ~ZoomController() override;

  ZoomMode zoom_mode() const { return zoom_mode_; }

  // Convenience method to get default zoom level. Implemented here for
  // inlining.
  double GetDefaultZoomLevel() const {
    return host::HostZoomMap::GetForApplicationContents(application_contents())
        ->GetDefaultZoomLevel();
  }

  // Convenience method to quickly check if the tab's at default zoom.
  // Virtual for testing.
  virtual bool IsAtDefaultZoom() const;

  // Returns which image should be loaded for the current zoom level.
  RelativeZoom GetZoomRelativeToDefault() const;

  const ZoomRequestClient* last_client() const { return last_client_.get(); }

  void AddObserver(ZoomObserver* observer);
  void RemoveObserver(ZoomObserver* observer);

  // Used to set whether the zoom notification bubble can be shown when the
  // zoom level is changed for this controller. Default behavior is to show
  // the bubble.
  void SetShowsNotificationBubble(bool can_show_bubble) {
    can_show_bubble_ = can_show_bubble;
  }

  // Gets the current zoom level by querying HostZoomMap (if not in manual zoom
  // mode) or from the ZoomController local value otherwise.
  double GetZoomLevel() const;
  // Calls GetZoomLevel() then converts the returned value to a percentage
  // zoom factor.
  // Virtual for testing.
  virtual int GetZoomPercent() const;

  // Sets the zoom level through HostZoomMap.
  // Returns true on success.
  bool SetZoomLevel(double zoom_level);

  // Sets the zoom level via HostZoomMap (or stores it locally if in manual zoom
  // mode), and attributes the zoom to |client|. Returns true on success.
  bool SetZoomLevelByClient(
      double zoom_level,
      const scoped_refptr<const ZoomRequestClient>& client);

  // Sets the zoom mode, which defines zoom behavior (see enum ZoomMode).
  void SetZoomMode(ZoomMode zoom_mode);

  // Set and query whether or not the page scale factor is one.
  void SetPageScaleFactorIsOneForTesting(bool is_one);
  bool PageScaleFactorIsOne() const;

  // content::WebContentsObserver overrides:
  //void DidFinishNavigation(
//      content::NavigationHandle* navigation_handle) override;
  void ApplicationContentsDestroyed() override;
  void ApplicationWindowChanged(host::ApplicationWindowHost* old_host,
                                host::ApplicationWindowHost* new_host) override;

 protected:
  // Protected for testing.
  explicit ZoomController(host::ApplicationContents* app_contents);

 private:
  friend class host::ApplicationContentsUserData<ZoomController>;
  friend class ::ZoomControllerTest;

  void ResetZoomModeOnNavigationIfNeeded(const GURL& url);
  void OnZoomLevelChanged(const host::HostZoomMap::ZoomLevelChange& change);

  // Updates the zoom icon and zoom percentage based on current values and
  // notifies the observer if changes have occurred. |host| may be empty,
  // meaning the change should apply to ~all sites. If it is not empty, the
  // change only affects sites with the given host.
  void UpdateState(const std::string& host);

  // True if changes to zoom level can trigger the zoom notification bubble.
  bool can_show_bubble_;

  // The current zoom mode.
  ZoomMode zoom_mode_;

  // Current zoom level.
  double zoom_level_;

  std::unique_ptr<ZoomChangedEventData> event_data_;

  // Keeps track of the extension (if any) that initiated the last zoom change
  // that took effect.
  scoped_refptr<const ZoomRequestClient> last_client_;

  // Observer receiving notifications on state changes.
  base::ObserverList<ZoomObserver> observers_;

  //content::BrowserContext* browser_context_;
  // Keep track of the HostZoomMap we're currently subscribed to.
  host::HostZoomMap* host_zoom_map_;

  std::unique_ptr<host::HostZoomMap::Subscription> zoom_subscription_;

  DISALLOW_COPY_AND_ASSIGN(ZoomController);
};

}  // namespace zoom

#endif  // COMPONENTS_ZOOM_ZOOM_CONTROLLER_H_
