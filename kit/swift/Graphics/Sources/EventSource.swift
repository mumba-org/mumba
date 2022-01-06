// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

open class EventSource {

  open var eventSink: EventSink? {
    return nil
  }

  public init() {}

  open func addEventRewriter(rewriter: EventRewriter) {

  }

  open func removeEventRewriter(rewriter: EventRewriter) {

  }

  open func sendEventToProcessor(event: Event) -> EventDispatchDetails {
    return EventDispatchDetails()
  }

  @discardableResult
  open func sendEventToSink(event: Event) -> EventDispatchDetails {
    // std::unique_ptr<ui::Event> event_for_rewriting_ptr;
    // Event* event_for_rewriting = event;
    // if (!rewriter_list_.empty() && IsLocatedEventWithDifferentLocations(*event)) {
    //   // EventRewriters don't expect an event with differing location and
    //   // root-location (because they don't honor the target). Provide such an
    //   // event for rewriters.
    //   event_for_rewriting_ptr = ui::Event::Clone(*event);
    //   event_for_rewriting_ptr->AsLocatedEvent()->set_location_f(
    //       event_for_rewriting_ptr->AsLocatedEvent()->root_location_f());
    //   event_for_rewriting = event_for_rewriting_ptr.get();
    // }
    // std::unique_ptr<Event> rewritten_event;
    // EventRewriteStatus status = EVENT_REWRITE_ONTINUE;
    // EventRewriterList::const_iterator it = rewriter_list_.begin(),
    //                                   end = rewriter_list_.end();
    // for (; it != end; ++it) {
    //   status = (*it)->RewriteEvent(*event_for_rewriting, &rewritten_event);
    //   if (status == EVENT_REWRITE_DISCARD) {
    //     CHECK(!rewritten_event);
    //     return EventDispatchDetails();
    //   }
    //   if (status == EVENT_REWRITE_ONTINUE) {
    //     CHECK(!rewritten_event);
    //     continue;
    //   }
    //   break;
    // }
    // CHECK((it == end && !rewritten_event) || rewritten_event);
    // EventDispatchDetails details =
    //     DeliverEventToSink(rewritten_event ? rewritten_event.get() : event);
    // if (details.dispatcher_destroyed)
    //   return details;

    // while (status == EVENT_REWRITE_DISPATCH_ANOTHER) {
    //   std::unique_ptr<Event> new_event;
    //   status = (*it)->NextDispatchEvent(*rewritten_event, &new_event);
    //   if (status == EVENT_REWRITE_DISCARD)
    //     return EventDispatchDetails();
    //   CHECK_NE(EVENT_REWRITE_ONTINUE, status);
    //   CHECK(new_event);
    //   details = DeliverEventToSink(new_event.get());
    //   if (details.dispatcher_destroyed)
    //     return details;
    //   rewritten_event = std::move(new_event);
    // }
    return EventDispatchDetails()
  }

  open func deliverEventToProcessor(event: Event) -> EventDispatchDetails {
    return EventDispatchDetails()
  }
}
