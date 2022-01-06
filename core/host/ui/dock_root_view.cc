// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/ui/dock_root_view.h"

#include <cmath>

#include "core/host/ui/dock.h"
#include "core/host/ui/dock_commands.h"
#include "core/host/ui/dock_frame.h"
#include "core/host/ui/dock_window.h"
#include "core/host/ui/tablist/tablist.h"
#include "ui/base/dragdrop/drag_drop_types.h"
#include "ui/base/dragdrop/os_exchange_data.h"
#include "ui/base/hit_test.h"

namespace host {

// static
const char DockRootView::kViewClassName[] =
    "core/host/ui/DockRootView";

DockRootView::DockRootView(
  DockWindow* dock_window,
  views::Widget* widget)
    : views::internal::RootView(widget),
      dock_window_(dock_window),
      scroll_remainder_x_(0),
      scroll_remainder_y_(0) {}

bool DockRootView::GetDropFormats(
      int* formats,
      std::set<ui::Clipboard::FormatType>* format_types) {
  if (tablist() && tablist()->visible()) {
    *formats = ui::OSExchangeData::URL | ui::OSExchangeData::STRING;
    return true;
  }
  return false;
}

bool DockRootView::AreDropTypesRequired() {
  return true;
}

bool DockRootView::CanDrop(const ui::OSExchangeData& data) {
  if (!tablist() || !tablist()->visible())
    return false;

  // If there is a URL, we'll allow the drop.
  if (data.HasURL(ui::OSExchangeData::CONVERT_FILENAMES))
    return true;

  // If there isn't a URL, see if we can 'paste and go'.
  return GetPasteAndGoURL(data, nullptr);
}

void DockRootView::OnDragEntered(const ui::DropTargetEvent& event) {
  if (ShouldForwardToTablist(event)) {
    forwarding_to_tablist_ = true;
    std::unique_ptr<ui::DropTargetEvent> mapped_event(
        MapEventToTablist(event, event.data()));
    tablist()->OnDragEntered(*mapped_event.get());
  }
}

int DockRootView::OnDragUpdated(const ui::DropTargetEvent& event) {
  if (ShouldForwardToTablist(event)) {
    std::unique_ptr<ui::DropTargetEvent> mapped_event(
        MapEventToTablist(event, event.data()));
    if (!forwarding_to_tablist_) {
      tablist()->OnDragEntered(*mapped_event.get());
      forwarding_to_tablist_ = true;
    }
    return tablist()->OnDragUpdated(*mapped_event.get());
  } else if (forwarding_to_tablist_) {
    forwarding_to_tablist_ = false;
    tablist()->OnDragExited();
  }
  return ui::DragDropTypes::DRAG_NONE;
}

void DockRootView::OnDragExited() {
  if (forwarding_to_tablist_) {
    forwarding_to_tablist_ = false;
    tablist()->OnDragExited();
  }
}

int DockRootView::OnPerformDrop(const ui::DropTargetEvent& event) {
  if (!forwarding_to_tablist_)
    return ui::DragDropTypes::DRAG_NONE;

  // Extract the URL and create a new ui::OSExchangeData containing the URL. We
  // do this as the Tablist doesn't know about the autocomplete edit and needs
  // to know about it to handle 'paste and go'.
  GURL url;
  base::string16 title;
  ui::OSExchangeData mapped_data;
  if (!event.data().GetURLAndTitle(
           ui::OSExchangeData::CONVERT_FILENAMES, &url, &title) ||
      !url.is_valid()) {
    // The url isn't valid. Use the paste and go url.
    if (GetPasteAndGoURL(event.data(), &url))
      mapped_data.SetURL(url, base::string16());
    // else case: couldn't extract a url or 'paste and go' url. This ends up
    // passing through an ui::OSExchangeData with nothing in it. We need to do
    // this so that the tab strip cleans up properly.
  } else {
    mapped_data.SetURL(url, base::string16());
  }
  forwarding_to_tablist_ = false;
  std::unique_ptr<ui::DropTargetEvent> mapped_event(
      MapEventToTablist(event, mapped_data));
  return tablist()->OnPerformDrop(*mapped_event);
}

const char* DockRootView::GetClassName() const {
  return kViewClassName;
}

bool DockRootView::OnMouseWheel(const ui::MouseWheelEvent& event) {
  // if (dock_defaults::kScrollEventChangesTab) {
  //   // Switch to the left/right tab if the wheel-scroll happens over the
  //   // tabstrip, or the empty space beside the tabstrip.
  //   views::View* hit_view = GetEventHandlerForPoint(event.location());
  //   int hittest =
  //       GetWidget()->non_client_view()->NonClientHitTest(event.location());
  //   if (tablist()->Contains(hit_view) ||
  //       hittest == HTCAPTION ||
  //       hittest == HTTOP) {
  //     scroll_remainder_x_ += event.x_offset();
  //     scroll_remainder_y_ += event.y_offset();

  //     // Number of integer scroll events that have passed in each direction.
  //     int whole_scroll_amount_x =
  //         std::lround(static_cast<double>(scroll_remainder_x_) /
  //                     ui::MouseWheelEvent::kWheelDelta);
  //     int whole_scroll_amount_y =
  //         std::lround(static_cast<double>(scroll_remainder_y_) /
  //                     ui::MouseWheelEvent::kWheelDelta);

  //     // Adjust the remainder such that any whole scrolls we have taken action
  //     // for don't count towards the scroll remainder.
  //     scroll_remainder_x_ -=
  //         whole_scroll_amount_x * ui::MouseWheelEvent::kWheelDelta;
  //     scroll_remainder_y_ -=
  //         whole_scroll_amount_y * ui::MouseWheelEvent::kWheelDelta;

  //     // Count a scroll in either axis - summing the axes works for this.
  //     int whole_scroll_offset = whole_scroll_amount_x + whole_scroll_amount_y;

  //     Dock* dock = dock_window_->dock();
  //     TablistModel* model = dock->tablist_model();
  //     // Switch to the next tab only if not at the end of the tab-strip.
  //     if (whole_scroll_offset < 0 &&
  //         model->active_index() + 1 < model->count()) {
  //       host::SelectNextTab(dock);
  //       return true;
  //     }

  //     // Switch to the previous tab only if not at the beginning of the
  //     // tab-strip.
  //     if (whole_scroll_offset > 0 && model->active_index() > 0) {
  //       host::SelectPreviousTab(dock);
  //       return true;
  //     }
  //   }
  // }
  return RootView::OnMouseWheel(event);
}

void DockRootView::OnMouseExited(const ui::MouseEvent& event) {
  // Reset the remainders so tab switches occur halfway through a smooth scroll.
  scroll_remainder_x_ = 0;
  scroll_remainder_y_ = 0;
  RootView::OnMouseExited(event);
}

void DockRootView::OnEventProcessingStarted(ui::Event* event) {
 // if (event->IsGestureEvent()) {
//    ui::GestureEvent* gesture_event = event->AsGestureEvent();
//    if (gesture_event->type() == ui::ET_GESTURE_TAP &&
//        gesture_event->location().y() <= 0 &&
//        gesture_event->location().x() <= dock_window_->GetBounds().width()) {
//      TouchUMA::RecordGestureAction(TouchUMA::GESTURE_ROOTVIEWTOP_TAP);
 //   }
  //}

  RootView::OnEventProcessingStarted(event);
}

bool DockRootView::ShouldForwardToTablist(
    const ui::DropTargetEvent& event) {
  if (!tablist()->visible())
    return false;

  // Allow the drop as long as the mouse is over the tabstrip or vertically
  // before it.
  gfx::Point app_loc_in_host;
  ConvertPointToTarget(tablist(), this, &app_loc_in_host);
  return event.y() < app_loc_in_host.y() + tablist()->height();
}

ui::DropTargetEvent* DockRootView::MapEventToTablist(
    const ui::DropTargetEvent& event,
    const ui::OSExchangeData& data) {
  gfx::Point tablist_loc(event.location());
  ConvertPointToTarget(this, tablist(), &tablist_loc);
  return new ui::DropTargetEvent(data, tablist_loc, tablist_loc,
                                 event.source_operations());
}

Tablist* DockRootView::tablist() const {
  return dock_window_->tablist();
}

bool DockRootView::GetPasteAndGoURL(const ui::OSExchangeData& data,
                                       GURL* url) {
  if (!data.HasString())
    return false;

  base::string16 text;
  if (!data.GetString(&text) || text.empty())
    return false;
  //text = AutocompleteMatch::SanitizeString(text);

  //AutocompleteMatch match;
  //AutocompleteClassifierFactory::GetForProfile(
      //browser_view_->browser()->profile())->Classify(
          //text, false, false, metrics::OmniboxEventProto::INVALID_SPEC, &match,
          //nullptr);
  //if (!match.destination_url.is_valid())
//    return false;

  if (url)
    *url = GURL(text);//match.destination_url;
  return true;
}


}