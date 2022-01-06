// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_APPLICATION_WINDOW_HOST_DELEGATE_VIEW_H_
#define MUMBA_HOST_APPLICATION_APPLICATION_WINDOW_HOST_DELEGATE_VIEW_H_

#include <vector>

#include "base/callback.h"
#include "build/build_config.h"
//#include "core/common/buildflags.h"
#include "core/shared/common/content_export.h"
#include "core/shared/common/drag_event_source_info.h"
#include "core/shared/common/input_event_ack_state.h"
#include "third_party/blink/public/platform/web_drag_operation.h"

namespace blink {
class WebGestureEvent;
}

namespace gfx {
class ImageSkia;
class Rect;
class Vector2d;
}

#if defined(OS_ANDROID)
namespace ui {
class OverscrollRefreshHandler;
}
#endif

namespace common {
struct ContextMenuParams;
struct DropData;
struct MenuItem;  
}

namespace host {
class ApplicationWindowHost;

// This class provides a way for the ApplicationWindowHost to reach out to its
// delegate's view.
class CONTENT_EXPORT ApplicationWindowHostDelegateView {
 public:
  // A context menu should be shown, to be built using the context information
  // provided in the supplied params.
  virtual void ShowContextMenu(ApplicationWindowHost* app_window_host,
                               const common::ContextMenuParams& params) {}

  // The user started dragging content of the specified type within the
  // ApplicationWindow. Contextual information about the dragged content is supplied
  // by DropData. If the delegate's view cannot start the drag for /any/
  // reason, it must inform the renderer that the drag has ended; otherwise,
  // this results in bugs like http://crbug.com/157134.
  virtual void StartDragging(const common::DropData& drop_data,
                             blink::WebDragOperationsMask allowed_ops,
                             const gfx::ImageSkia& image,
                             const gfx::Vector2d& image_offset,
                             const common::DragEventSourceInfo& event_info,
                             ApplicationWindowHost* source_rwh) {}

  // The page wants to update the mouse cursor during a drag & drop operation.
  // |operation| describes the current operation (none, move, copy, link.)
  virtual void UpdateDragCursor(blink::WebDragOperation operation) {}

  // Notification that view for this delegate got the focus.
  virtual void GotFocus(ApplicationWindowHost* application_window_host) {}

  // Notification that view for this delegate lost the focus.
  virtual void LostFocus(ApplicationWindowHost* application_window_host) {}

  // Callback to inform the browser that the page is returning the focus to
  // the browser's chrome. If reverse is true, it means the focus was
  // retrieved by doing a Shift-Tab.
  virtual void TakeFocus(bool reverse) {}

  // Returns the height of the top controls in DIP.
  virtual int GetTopControlsHeight() const;

  // Returns the height of the bottom controls in DIP.
  virtual int GetBottomControlsHeight() const;

  // Returns true if the browser controls resize Blink's view size.
  virtual bool DoBrowserControlsShrinkBlinkSize() const;

  // Do post-event tasks for gesture events.
  virtual void GestureEventAck(const blink::WebGestureEvent& event,
                               common::InputEventAckState ack_result);

//#if BUILDFLAG(USE_EXTERNAL_POPUP_MENU)
  // Shows a popup menu with the specified items.
  // This method should call RenderFrameHost::DidSelectPopupMenuItem[s]() or
  // RenderFrameHost::DidCancelPopupMenu() based on the user action.
  virtual void ShowPopupMenu(ApplicationWindowHost* app_window_host,
                             const gfx::Rect& bounds,
                             int item_height,
                             double item_font_size,
                             int selected_item,
                             const std::vector<common::MenuItem>& items,
                             bool right_aligned,
                             bool allow_multiple_selection) {};

  // Hides a popup menu opened by ShowPopupMenu().
  virtual void HidePopupMenu() {};
//#endif

#if defined(OS_ANDROID)
  virtual ui::OverscrollRefreshHandler* GetOverscrollRefreshHandler() const;
#endif

 protected:
  virtual ~ApplicationWindowHostDelegateView() {}
};

}  // namespace host

#endif  // MUMBA_HOST_APPLICATION_RENDER_VIEW_HOST_DELEGATE_VIEW_H_
