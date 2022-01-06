// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_INPUT_GESTURE_EVENT_QUEUE_H_
#define MUMBA_HOST_APPLICATION_INPUT_GESTURE_EVENT_QUEUE_H_

#include <stddef.h>

#include <memory>

#include "base/containers/circular_deque.h"
#include "base/macros.h"
#include "base/timer/timer.h"
#include "core/host/application/event_with_latency_info.h"
#include "core/host/application/input/fling_controller.h"
#include "core/shared/common/content_export.h"
#include "core/shared/common/input_event_ack_source.h"
#include "core/shared/common/input_event_ack_state.h"
#include "third_party/blink/public/platform/web_input_event.h"

namespace host {
class GestureEventQueueTest;
class MockApplicationWindowHost;

// Interface with which the GestureEventQueue can forward gesture events, and
// dispatch gesture event responses.
class CONTENT_EXPORT GestureEventQueueClient {
 public:
  virtual ~GestureEventQueueClient() {}

  virtual void SendGestureEventImmediately(
      const common::GestureEventWithLatencyInfo& event) = 0;

  virtual void OnGestureEventAck(const common::GestureEventWithLatencyInfo& event,
                                 common::InputEventAckSource ack_source,
                                 common::InputEventAckState ack_result) = 0;
};

// Maintains WebGestureEvents in a queue before forwarding them to the renderer
// to apply a sequence of filters on them:
// 1. The sequence is filtered for bounces. A bounce is when the finger lifts
//    from the screen briefly during an in-progress scroll. Ifco this happens,
//    non-GestureScrollUpdate events are queued until the de-bounce interval
//    passes or another GestureScrollUpdate event occurs.
// 2. Unnecessary GestureFlingCancel events are filtered by fling controller.
//    These are GestureFlingCancels that have no corresponding GestureFlingStart
//    in the queue.
// 3. Taps immediately after a GestureFlingCancel (caused by the same tap) are
//    filtered by fling controller.
// 4. Whenever possible, events in the queue are coalesced to have as few events
//    as possible and therefore maximize the chance that the event stream can be
//    handled entirely by the compositor thread.
// Events in the queue are forwarded to the renderer one by one; i.e., each
// event is sent after receiving the ACK for previous one. The only exception is
// that if a GestureScrollUpdate is followed by a GesturePinchUpdate, they are
// sent together.
// TODO(rjkroege): Possibly refactor into a filter chain:
// http://crbug.com/148443.
class CONTENT_EXPORT GestureEventQueue {
 public:
  struct CONTENT_EXPORT Config {
    Config();

    FlingController::Config fling_config;

    // Determines whether non-scroll gesture events are "debounced" during an
    // active scroll sequence, suppressing brief scroll interruptions.
    // Zero by default (disabled).
    base::TimeDelta debounce_interval;
  };

  // Both |client| and |touchpad_client| must outlive the GestureEventQueue.
  GestureEventQueue(GestureEventQueueClient* client,
                    TouchpadTapSuppressionControllerClient* touchpad_client,
                    FlingControllerClient* fling_client,
                    const Config& config);
  ~GestureEventQueue();

  // Adds a gesture to the queue if it passes the relevant filters. If
  // there are no events currently queued, the event will be forwarded
  // immediately. Returns false if the event wasn't queued and was filtered.
  bool QueueEvent(const common::GestureEventWithLatencyInfo&);

  // Indicates that the caller has received an acknowledgement from the renderer
  // with state |ack_result| and event |type|. May send events if the queue is
  // not empty.
  void ProcessGestureAck(common::InputEventAckSource ack_source,
                         common::InputEventAckState ack_result,
                         blink::WebInputEvent::Type type,
                         const ui::LatencyInfo& latency);

  // Sets the state of the |fling_in_progress_| field to indicate that a fling
  // is definitely not in progress.
  void FlingHasBeenHalted();

  // Returns the |TouchpadTapSuppressionController| instance.
  TouchpadTapSuppressionController* GetTouchpadTapSuppressionController();

  void ForwardGestureEvent(const common::GestureEventWithLatencyInfo& gesture_event);

  bool empty() const {
    return coalesced_gesture_events_.empty() &&
           debouncing_deferral_queue_.empty();
  }

  // Returns |true| if the given GestureFlingCancel should be discarded
  // as unnecessary.
  bool ShouldDiscardFlingCancelEvent(
      const common::GestureEventWithLatencyInfo& gesture_event) const;

  // Calls |fling_controller_.ProgressFling| to advance an active fling on every
  // begin frame and returns the current fling velocity if a fling is active.
  gfx::Vector2dF ProgressFling(base::TimeTicks current_time);

  // Calls |fling_controller_.StopFling| to halt an active fling if such exists.
  void StopFling();

  bool FlingCancellationIsDeferred() const;

  bool TouchscreenFlingInProgress() const;

  void set_debounce_interval_time_ms_for_testing(int interval_ms) {
    debounce_interval_ = base::TimeDelta::FromMilliseconds(interval_ms);
  }

 private:
  friend class GestureEventQueueTest;
  friend class MockApplicationWindowHost;

  class GestureEventWithLatencyInfoAndAckState
      : public common::GestureEventWithLatencyInfo {
   public:
    GestureEventWithLatencyInfoAndAckState(const common::GestureEventWithLatencyInfo&);
    common::InputEventAckState ack_state() const { return ack_state_; }
    void set_ack_info(common::InputEventAckSource source, common::InputEventAckState state) {
      ack_source_ = source;
      ack_state_ = state;
    }
    common::InputEventAckSource ack_source() const { return ack_source_; }

   private:
    common::InputEventAckSource ack_source_ = common::InputEventAckSource::UNKNOWN;
    common::InputEventAckState ack_state_ = common::INPUT_EVENT_ACK_STATE_UNKNOWN;
  };

  bool OnScrollBegin(const common::GestureEventWithLatencyInfo& gesture_event);

  // Inovked on the expiration of the debounce interval to release
  // deferred events.
  void SendScrollEndingEventsNow();

  // Sub-filter for removing bounces from in-progress scrolls.
  bool ShouldForwardForBounceReduction(
      const common::GestureEventWithLatencyInfo& gesture_event);

  // Puts the events in a queue to forward them one by one; i.e., forward them
  // whenever ACK for previous event is received. This queue also tries to
  // coalesce events as much as possible.
  void QueueAndForwardIfNecessary(
      const common::GestureEventWithLatencyInfo& gesture_event);

  // Merge or append a GestureScrollUpdate or GesturePinchUpdate into
  // the coalescing queue, forwarding immediately if appropriate.
  void QueueScrollOrPinchAndForwardIfNecessary(
      const common::GestureEventWithLatencyInfo& gesture_event);

  // ACK completed events in order until we have reached an incomplete event.
  // Will preserve the FIFO order as events originally arrived.
  void AckCompletedEvents();
  void AckGestureEventToClient(const common::GestureEventWithLatencyInfo&,
                               common::InputEventAckSource,
                               common::InputEventAckState);

  // Used when |allow_multiple_inflight_events_| is false. Will only send next
  // event after receiving ACK for the previous one.
  void LegacyProcessGestureAck(common::InputEventAckSource,
                               common::InputEventAckState,
                               blink::WebInputEvent::Type,
                               const ui::LatencyInfo&);

  // The number of sent events for which we're awaiting an ack.  These events
  // remain at the head of the queue until ack'ed.
  size_t EventsInFlightCount() const;

  // The receiver of all forwarded gesture events.
  GestureEventQueueClient* client_;

  // True if a GestureFlingStart is in progress or queued without a subsequent
  // queued GestureFlingCancel event.
  bool fling_in_progress_;

  // True if a GestureScrollUpdate sequence is in progress.
  bool scrolling_in_progress_;

  // True if two related gesture events were sent before without waiting
  // for an ACK, so the next gesture ACK should be ignored.
  bool ignore_next_ack_;

  // True if compositor event queue is enabled. GestureEventQueue won't coalesce
  // events and will forward events immediately (instead of waiting for previous
  // ack).
  bool allow_multiple_inflight_events_;

  bool processing_acks_ = false;

  using GestureQueue = base::circular_deque<common::GestureEventWithLatencyInfo>;
  using GestureQueueWithAckState =
      base::circular_deque<GestureEventWithLatencyInfoAndAckState>;

  // If |allow_multiple_inflight_events_|, |coalesced_gesture_events_| stores
  // outstanding events that have been sent to the renderer but not yet been
  // ACKed.
  // Otherwise it stores coalesced gesture events not yet sent to the renderer.
  // If |ignore_next_ack_| is false, then the event at the front of the queue
  // has been sent and is awaiting an ACK, and all other events have yet to be
  // sent. If |ignore_next_ack_| is true, then the two events at the front of
  // the queue have been sent, and the second is awaiting an ACK. All other
  // events have yet to be sent.
  GestureQueueWithAckState coalesced_gesture_events_;

  // Timer to release a previously deferred gesture event.
  base::OneShotTimer debounce_deferring_timer_;

  // Queue of events that have been deferred for debounce.
  GestureQueue debouncing_deferral_queue_;

  // Time window in which to debounce scroll/fling ends. Note that an interval
  // of zero effectively disables debouncing.
  base::TimeDelta debounce_interval_;

  // An object for filtering unnecessary GFC events, as well as gestureTap/mouse
  // events that happen immediately after touchscreen/touchpad fling canceling
  // taps.
  FlingController fling_controller_;

  DISALLOW_COPY_AND_ASSIGN(GestureEventQueue);
};

}  // namespace host

#endif  // MUMBA_HOST_APPLICATION_INPUT_GESTURE_EVENT_QUEUE_H_
