// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_UI_WINDOW_HOST_ROOT_VIEW_H_
#define MUMBA_HOST_UI_WINDOW_HOST_ROOT_VIEW_H_

#include "base/macros.h"
#include "ui/views/widget/root_view.h"

namespace ui {
class OSExchangeData;
}

namespace host {
class DockWindow;
class Tablist;

// BrowserRootView
class DockRootView : public views::internal::RootView {
public:
  // Internal class name.
  static const char kViewClassName[];

  // You must call set_tabstrip before this class will accept drops.
  DockRootView(DockWindow* dock_window, views::Widget* widget);

  // Overridden from views::View:
  bool GetDropFormats(
      int* formats,
      std::set<ui::Clipboard::FormatType>* format_types) override;
  bool AreDropTypesRequired() override;
  bool CanDrop(const ui::OSExchangeData& data) override;
  void OnDragEntered(const ui::DropTargetEvent& event) override;
  int OnDragUpdated(const ui::DropTargetEvent& event) override;
  void OnDragExited() override;
  int OnPerformDrop(const ui::DropTargetEvent& event) override;
  const char* GetClassName() const override;
  bool OnMouseWheel(const ui::MouseWheelEvent& event) override;
  void OnMouseExited(const ui::MouseEvent& event) override;

 private:
  // ui::EventProcessor:
  void OnEventProcessingStarted(ui::Event* event) override;

  // Returns true if the event should be forwarded to the tabstrip.
  bool ShouldForwardToTablist(const ui::DropTargetEvent& event);

  // Converts the event from the hosts coordinate system to the tabstrips
  // coordinate system.
  ui::DropTargetEvent* MapEventToTablist(
      const ui::DropTargetEvent& event,
      const ui::OSExchangeData& data);

  inline Tablist* tablist() const;

  // Returns true if |data| has string contents and the user can "paste and go".
  // If |url| is non-null and the user can "paste and go", |url| is set to the
  // desired destination.
  bool GetPasteAndGoURL(const ui::OSExchangeData& data, GURL* url);

  // The BrowserView.
  DockWindow* dock_window_;

  // If true, drag and drop events are being forwarded to the tab strip.
  // This is used to determine when to send OnDragEntered and OnDragExited
  // to the tab strip.
  bool forwarding_to_tablist_;

  // Used to calculate partial offsets in scrolls that occur for a smooth
  // scroll device.
  int scroll_remainder_x_;
  int scroll_remainder_y_;

  DISALLOW_COPY_AND_ASSIGN(DockRootView);
};


}

#endif