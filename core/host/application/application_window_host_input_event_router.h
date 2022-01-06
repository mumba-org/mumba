// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_RENDER_WIDGET_HOST_INPUT_EVENT_ROUTER_H_
#define MUMBA_HOST_APPLICATION_RENDER_WIDGET_HOST_INPUT_EVENT_ROUTER_H_

#include <stdint.h>

#include <map>
#include <unordered_map>
#include <vector>

#include "base/containers/hash_tables.h"
#include "base/gtest_prod_util.h"
#include "base/macros.h"
#include "base/memory/weak_ptr.h"
#include "components/viz/common/surfaces/surface_id.h"
#include "components/viz/host/hit_test/hit_test_query.h"
#include "components/viz/service/surfaces/surface_hittest_delegate.h"
#include "core/host/application/application_window_host_view_observer.h"
#include "core/host/application/application_window_targeter.h"
#include "core/shared/common/content_export.h"
#include "ui/gfx/geometry/vector2d_conversions.h"

namespace blink {
class WebGestureEvent;
class WebInputEvent;
class WebMouseEvent;
class WebMouseWheelEvent;
class WebTouchEvent;
}

namespace gfx {
class Point;
class PointF;
}

namespace ui {
class LatencyInfo;
}

namespace host {

class ApplicationWindowHost;
class ApplicationWindowHostView;
class ApplicationWindowHostView;
class RenderWidgetTargeter;

// Class owned by WebContentsImpl for the purpose of directing input events
// to the correct ApplicationWindowHost on pages with multiple ApplicationWindowHosts.
// It maintains a mapping of ApplicationWindowHostViews to Surface IDs that they
// own. When an input event requires routing based on window coordinates,
// this class requests a Surface hit test from the provided |root_view| and
// forwards the event to the owning RWHV of the returned Surface ID.
class CONTENT_EXPORT ApplicationWindowHostInputEventRouter final
    : public ApplicationWindowHostViewObserver,
      public RenderWidgetTargeter::Delegate {
 public:
  ApplicationWindowHostInputEventRouter();
  ~ApplicationWindowHostInputEventRouter() final;

  void OnApplicationWindowHostViewDestroyed(
      ApplicationWindowHostView* view) override;

  void RouteMouseEvent(ApplicationWindowHostView* root_view,
                       blink::WebMouseEvent* event,
                       const ui::LatencyInfo& latency);
  void RouteMouseWheelEvent(ApplicationWindowHostView* root_view,
                            blink::WebMouseWheelEvent* event,
                            const ui::LatencyInfo& latency);
  void RouteGestureEvent(ApplicationWindowHostView* root_view,
                         blink::WebGestureEvent* event,
                         const ui::LatencyInfo& latency);
  void OnHandledTouchStartOrFirstTouchMove(uint32_t unique_touch_event_id);
  void RouteTouchEvent(ApplicationWindowHostView* root_view,
                       blink::WebTouchEvent *event,
                       const ui::LatencyInfo& latency);

  // |event| is in root coordinates.
  void BubbleScrollEvent(ApplicationWindowHostView* target_view,
                         const blink::WebGestureEvent& event,
                         const ApplicationWindowHostView* resending_view);
  void CancelScrollBubbling(ApplicationWindowHostView* target_view);

  void AddFrameSinkIdOwner(const viz::FrameSinkId& id,
                           ApplicationWindowHostView* owner);
  void RemoveFrameSinkIdOwner(const viz::FrameSinkId& id);

  bool is_registered(const viz::FrameSinkId& id) {
    return owner_map_.find(id) != owner_map_.end();
  }

  void OnHittestData(const viz::SurfaceId& surface_id, bool ignored_for_hittest);

  // Returns the ApplicationWindowHost inside the |root_view| at |point| where
  // |point| is with respect to |root_view|'s coordinates. If a RWHI is found,
  // the value of |transformed_point| is the coordinate of the point with
  // respect to the RWHI's coordinates. If |root_view| is nullptr, this method
  // will return nullptr and will not modify |transformed_point|.
  ApplicationWindowHost* GetApplicationWindowHostAtPoint(
      ApplicationWindowHostView* root_view,
      const gfx::PointF& point,
      gfx::PointF* transformed_point);

  std::vector<ApplicationWindowHostView*> GetApplicationWindowHostViewsForTests() const;
  RenderWidgetTargeter* GetRenderWidgetTargeterForTests();

 private:
  struct HittestData {
    bool ignored_for_hittest;
  };

  class HittestDelegate : public viz::SurfaceHittestDelegate {
   public:
    HittestDelegate(const std::unordered_map<viz::SurfaceId,
                                             HittestData,
                                             viz::SurfaceIdHash>& hittest_data);
    bool RejectHitTarget(const viz::SurfaceDrawQuad* surface_quad,
                         const gfx::Point& point_in_quad_space) override;
    bool AcceptHitTarget(const viz::SurfaceDrawQuad* surface_quad,
                         const gfx::Point& point_in_quad_space) override;

    const std::unordered_map<viz::SurfaceId, HittestData, viz::SurfaceIdHash>&
        hittest_data_;
  };

  using FrameSinkIdOwnerMap = std::unordered_map<viz::FrameSinkId,
                                                 ApplicationWindowHostView*,
                                                 viz::FrameSinkIdHash>;
  struct TargetData {
    ApplicationWindowHostView* target;
    gfx::Vector2dF delta;

    TargetData() : target(nullptr) {}
  };
  using TargetMap = std::map<uint32_t, TargetData>;

  void ClearAllObserverRegistrations();
  RenderWidgetTargetResult FindViewAtLocation(
      ApplicationWindowHostView* root_view,
      const gfx::PointF& point,
      const gfx::PointF& point_in_screen,
      viz::EventSource source,
      gfx::PointF* transformed_point) const;

  bool IsViewInMap(const ApplicationWindowHostView* view) const;
  void RouteTouchscreenGestureEvent(ApplicationWindowHostView* root_view,
                                    blink::WebGestureEvent* event,
                                    const ui::LatencyInfo& latency);

  RenderWidgetTargetResult FindTouchpadGestureEventTarget(
      ApplicationWindowHostView* root_view,
      const blink::WebGestureEvent& event) const;
  void RouteTouchpadGestureEvent(ApplicationWindowHostView* root_view,
                                 blink::WebGestureEvent* event,
                                 const ui::LatencyInfo& latency);
  void DispatchTouchpadGestureEvent(
      ApplicationWindowHostView* root_view,
      ApplicationWindowHostView* target,
      const blink::WebGestureEvent& touchpad_gesture_event,
      const ui::LatencyInfo& latency,
      const base::Optional<gfx::PointF>& target_location);

  // MouseMove/Enter/Leave events might need to be processed by multiple frames
  // in different processes for MouseEnter and MouseLeave event handlers to
  // properly fire. This method determines which ApplicationWindowHostViews other
  // than the actual target require notification, and sends the appropriate
  // events to them. |event| should be in |root_view|'s coordinate space.
  void SendMouseEnterOrLeaveEvents(const blink::WebMouseEvent& event,
                                   ApplicationWindowHostView* target,
                                   ApplicationWindowHostView* root_view);

  // The following methods take a GestureScrollUpdate event and send a
  // GestureScrollBegin or GestureScrollEnd for wrapping it. This is needed
  // when GestureScrollUpdates are being forwarded for scroll bubbling.
  void SendGestureScrollBegin(ApplicationWindowHostView* view,
                              const blink::WebGestureEvent& event);
  void SendGestureScrollEnd(ApplicationWindowHostView* view,
                            const blink::WebGestureEvent& event);

  // Helper functions to implement RenderWidgetTargeter::Delegate functions.
  RenderWidgetTargetResult FindMouseEventTarget(
      ApplicationWindowHostView* root_view,
      const blink::WebMouseEvent& event) const;
  RenderWidgetTargetResult FindMouseWheelEventTarget(
      ApplicationWindowHostView* root_view,
      const blink::WebMouseWheelEvent& event) const;
  // Returns target for first TouchStart in a sequence, or a null target
  // otherwise.
  RenderWidgetTargetResult FindTouchEventTarget(
      ApplicationWindowHostView* root_view,
      const blink::WebTouchEvent& event);
  RenderWidgetTargetResult FindTouchscreenGestureEventTarget(
      ApplicationWindowHostView* root_view,
      const blink::WebGestureEvent& gesture_event);

  // |mouse_event| is in the coord-space of |root_view|.
  void DispatchMouseEvent(ApplicationWindowHostView* root_view,
                          ApplicationWindowHostView* target,
                          const blink::WebMouseEvent& mouse_event,
                          const ui::LatencyInfo& latency,
                          const base::Optional<gfx::PointF>& target_location);
  // |mouse_wheel_event| is in the coord-space of |root_view|.
  void DispatchMouseWheelEvent(
      ApplicationWindowHostView* root_view,
      ApplicationWindowHostView* target,
      const blink::WebMouseWheelEvent& mouse_wheel_event,
      const ui::LatencyInfo& latency,
      const base::Optional<gfx::PointF>& target_location);
  // Assumes |touch_event| has coordinates in the root view's coordinate space.
  void DispatchTouchEvent(ApplicationWindowHostView* root_view,
                          ApplicationWindowHostView* target,
                          const blink::WebTouchEvent& touch_event,
                          const ui::LatencyInfo& latency,
                          const base::Optional<gfx::PointF>& target_location);
  // Assumes |gesture_event| has coordinates in root view's coordinate space.
  void DispatchTouchscreenGestureEvent(
      ApplicationWindowHostView* root_view,
      ApplicationWindowHostView* target,
      const blink::WebGestureEvent& gesture_event,
      const ui::LatencyInfo& latency,
      const base::Optional<gfx::PointF>& target_location);

  // Transforms |point| from |root_view| coord space to |target| coord space.
  // Result is stored in |transformed_point|. Returns true if the transform
  // is successful, false otherwise.
  bool TransformPointToTargetCoordSpace(ApplicationWindowHostView* root_view,
                                        ApplicationWindowHostView* target,
                                        const gfx::PointF& point,
                                        gfx::PointF* transformed_point,
                                        viz::EventSource source) const;

  // TODO(828422): Remove once this issue no longer occurs.
  void ReportBubblingScrollToSameView(const blink::WebGestureEvent& event,
                                      const ApplicationWindowHostView* view);

  // RenderWidgetTargeter::Delegate:
  RenderWidgetTargetResult FindTargetSynchronously(
      ApplicationWindowHostView* root_view,
      const blink::WebInputEvent& event) override;
  void DispatchEventToTarget(
      ApplicationWindowHostView* root_view,
      ApplicationWindowHostView* target,
      const blink::WebInputEvent& event,
      const ui::LatencyInfo& latency,
      const base::Optional<gfx::PointF>& target_location) override;
  ApplicationWindowHostView* FindViewFromFrameSinkId(
      const viz::FrameSinkId& frame_sink_id) const override;

  FrameSinkIdOwnerMap owner_map_;
  TargetMap touchscreen_gesture_target_map_;
  TargetData touch_target_;
  TargetData touchscreen_gesture_target_;
  // The following variable is temporary, for diagnosis of
  // https://crbug.com/824774.
  bool touchscreen_gesture_target_in_map_;
  TargetData touchpad_gesture_target_;
  TargetData bubbling_gesture_scroll_target_;
  TargetData first_bubbling_scroll_target_;
  // Used to target wheel events for the duration of a scroll when wheel scroll
  // latching is enabled.
  TargetData wheel_target_;
  // Maintains the same target between mouse down and mouse up.
  TargetData mouse_capture_target_;

  // Tracked for the purpose of generating MouseEnter and MouseLeave events.
  ApplicationWindowHostView* last_mouse_move_target_;
  ApplicationWindowHostView* last_mouse_move_root_view_;

  int active_touches_;
  // Keep track of when we are between GesturePinchBegin and GesturePinchEnd
  // inclusive, as we need to route these events (and anything in between) to
  // the main frame.
  bool in_touchscreen_gesture_pinch_;
  bool gesture_pinch_did_send_scroll_begin_;
  std::unordered_map<viz::SurfaceId, HittestData, viz::SurfaceIdHash>
      hittest_data_;

  std::unique_ptr<RenderWidgetTargeter> event_targeter_;
  bool use_viz_hit_test_ = false;

  base::WeakPtrFactory<ApplicationWindowHostInputEventRouter> weak_ptr_factory_;

  DISALLOW_COPY_AND_ASSIGN(ApplicationWindowHostInputEventRouter);
  friend class ApplicationWindowHostInputEventRouterTest;
  FRIEND_TEST_ALL_PREFIXES(SitePerProcessHitTestBrowserTest,
                           HitTestStaleDataDeletedView);
  FRIEND_TEST_ALL_PREFIXES(SitePerProcessHitTestBrowserTest,
                           InputEventRouterGestureTargetMapTest);
  FRIEND_TEST_ALL_PREFIXES(SitePerProcessHitTestBrowserTest,
                           InputEventRouterGesturePreventDefaultTargetMapTest);
  FRIEND_TEST_ALL_PREFIXES(SitePerProcessHitTestBrowserTest,
                           InputEventRouterTouchpadGestureTargetTest);
  FRIEND_TEST_ALL_PREFIXES(SitePerProcessMouseWheelHitTestBrowserTest,
                           InputEventRouterWheelTargetTest);
  FRIEND_TEST_ALL_PREFIXES(SitePerProcessMacBrowserTest,
                           InputEventRouterTouchpadGestureTargetTest);
};

}  // namespace host

#endif  // MUMBA_HOST_APPLICATION_RENDER_WIDGET_HOST_INPUT_EVENT_ROUTER_H_
