// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_UI_WINDOW_HOST_FRAME_H_
#define MUMBA_HOST_UI_WINDOW_HOST_FRAME_H_

#include <memory>

#include "base/macros.h"
#include "base/compiler_specific.h"
#include "base/logging.h"
#include "build/build_config.h"
#include "core/host/ui/dock_non_client_frame_view.h"
#include "ui/views/context_menu_controller.h"
#include "ui/views/widget/widget.h"


namespace gfx {
class FontList;
class Rect;
}

namespace ui {
class EventHandler;
class MenuModel;
}

namespace views {
class Button;
class MenuRunner;
class View;
}

namespace host {
class DockRootView;
class DockWindow;
class NativeDockFrame;
class NonClientFrameView;
class DockNonClientFrameView;
class SystemMenuModelBuilder;
struct NativeWebKeyboardEvent;

// BrowserFrame
class DockFrame : public views::Widget,
                  public views::ContextMenuController {
public:
  explicit DockFrame(DockWindow* dock_window);
  ~DockFrame() override;

  static const gfx::FontList& GetTitleFontList();

  // Initialize the frame (creates the underlying native window).
  void InitDockFrame();

  // Determine the distance of the left edge of the minimize button from the
  // left edge of the window. Used in our Non-Client View's Layout.
  int GetMinimizeButtonOffset() const;

  gfx::Rect GetBoundsForTablist(views::View* tablist) const;

  // Returns the inset of the topmost view in the client view from the top of
  // the non-client view. The topmost view depends on the window type. The
  // topmost view is the tab strip for tabbed browser windows, the toolbar for
  // popups, the web contents for app windows and varies for fullscreen windows.
  // If |restored| is true, this is calculated as if the window was restored,
  // regardless of its current state.
  int GetTopInset(bool restored) const;

  // Returns the amount that the theme background should be inset.
  int GetThemeBackgroundXInset() const;

  // Tells the frame to update the throbber.
  void UpdateThrobber(bool running);

  // Returns the NonClientFrameView of this frame.
  DockNonClientFrameView* GetFrameView() const;

  // Returns |true| if we should use the custom frame.
  bool UseCustomFrame() const;

  // Returns true when the window placement should be saved.
  bool ShouldSaveWindowPlacement() const;

  // Retrieves the window placement (show state and bounds) for restoring.
  void GetWindowPlacement(gfx::Rect* bounds,
                          ui::WindowShowState* show_state) const;

  // Returns true if the |event| was handled by the platform implementation
  // before sending it to the renderer. E.g., it may be swallowed by a native
  // menu bar.
  bool PreHandleKeyboardEvent(const NativeWebKeyboardEvent& event);

  // Returns true if the |event| was handled by the platform implementation,
  // if the renderer did not process it.
  bool HandleKeyboardEvent(const NativeWebKeyboardEvent& event);

  // Called when BrowserView creates all it's child views.
  void OnDockWindowInitViewsComplete();

  // Overridden from views::Widget:
  views::internal::RootView* CreateRootView() override;
  views::NonClientFrameView* CreateNonClientFrameView() override;
  bool GetAccelerator(int command_id,
                      ui::Accelerator* accelerator) const override;
  const ui::ThemeProvider* GetThemeProvider() const override;
  const ui::NativeTheme* GetNativeTheme() const override;
  void SchedulePaintInRect(const gfx::Rect& rect) override;
  void OnNativeWidgetWorkspaceChanged() override;
  void OnNativeThemeUpdated(ui::NativeTheme* observed_theme) override;

  // Overridden from views::ContextMenuController:
  void ShowContextMenuForView(views::View* source,
                              const gfx::Point& p,
                              ui::MenuSourceType source_type) override;

  // Returns the menu model. BrowserFrame owns the returned model.
  // Note that in multi user mode this will upon each call create a new model.
  ui::MenuModel* GetSystemMenuModel();

 private:
  // Callback for MenuRunner.
  void OnMenuClosed();

  NativeDockFrame* native_dock_frame_;

  // A weak reference to the root view associated with the window. We save a
  // copy as a BrowserRootView to avoid evil casting later, when we need to call
  // functions that only exist on BrowserRootView (versus RootView).
  DockRootView* root_view_;

  // A pointer to our NonClientFrameView as a BrowserNonClientFrameView.
  DockNonClientFrameView* dock_frame_view_;

  // The BrowserView is our ClientView. This is a pointer to it.
  DockWindow* dock_window_;

  std::unique_ptr<SystemMenuModelBuilder> menu_model_builder_;

  // Used to show the system menu. Only used if
  // NativeBrowserFrame::UsesNativeSystemMenu() returns false.
  std::unique_ptr<views::MenuRunner> menu_runner_;

  std::unique_ptr<ui::EventHandler> dock_command_handler_;

  DISALLOW_COPY_AND_ASSIGN(DockFrame);
};

}

#endif