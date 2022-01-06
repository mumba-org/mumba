// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/ui/dock_frame.h"

#include <utility>

#include "base/command_line.h"
#include "base/debug/leak_annotations.h"
#include "base/i18n/rtl.h"
#include "build/build_config.h"
#include "core/host/ui/dock_non_client_frame_view.h"
#include "core/host/ui/dock_root_view.h"
#include "core/host/ui/dock_window.h"
#include "core/host/ui/dock_list.h"
//#include "core/host/ui/immersive_mode_controller.h"
#include "core/host/ui/native_dock_frame.h"
#include "core/host/ui/native_dock_frame_factory.h"
#include "core/host/ui/system_menu_model_builder.h"
#include "core/host/ui/top_container_view.h"
#include "core/host/workspace/workspace.h"
#include "core/host/themes/theme_service.h"
#include "core/shared/common/switches.h"
#include "ui/base/hit_test.h"
#include "ui/events/event_handler.h"
#include "ui/gfx/font_list.h"
#include "ui/native_theme/native_theme_dark_aura.h"
#include "ui/views/controls/menu/menu_runner.h"
#include "ui/views/widget/native_widget.h"

#if defined(OS_CHROMEOS)
#include "components/user_manager/user_manager.h"
#endif

#if defined(OS_LINUX)
#include "core/host/ui/dock_command_handler_linux.h"
#endif

#if defined(USE_X11)
#include "ui/views/widget/desktop_aura/x11_desktop_handler.h"
#endif

namespace host {

DockFrame::DockFrame(DockWindow* dock_window): 
  native_dock_frame_(nullptr),
  root_view_(nullptr),
  dock_frame_view_(nullptr),
  dock_window_(dock_window) {
  
  dock_window_->set_frame(this);
  set_is_secondary_widget(false);
  set_focus_on_creation(false);
}

DockFrame::~DockFrame() {

}

const gfx::FontList& DockFrame::GetTitleFontList() {
  static const gfx::FontList* title_font_list = new gfx::FontList();
  ANNOTATE_LEAKING_OBJECT_PTR(title_font_list);
  return *title_font_list;
}

void DockFrame::InitDockFrame() {
  native_dock_frame_ =
      NativeDockFrameFactory::CreateNativeDockFrame(this, dock_window_);
  views::Widget::InitParams params = native_dock_frame_->GetWidgetParams();
  params.delegate = dock_window_;
  Init(params);
  if (!native_dock_frame_->UsesNativeSystemMenu()) {
    DCHECK(non_client_view());
    non_client_view()->set_context_menu_controller(this);
  }

#if defined(OS_LINUX)
  dock_command_handler_.reset(new DockCommandHandlerLinux(dock_window_));
#endif
}

int DockFrame::GetMinimizeButtonOffset() const {
  return native_dock_frame_->GetMinimizeButtonOffset();
}

gfx::Rect DockFrame::GetBoundsForTablist(views::View* tabstrip) const {
  // This can be invoked before |browser_frame_view_| has been set.
  gfx::Rect bounds = gfx::Rect();
  if (dock_frame_view_) {
    bounds = dock_frame_view_->GetBoundsForTablist(tabstrip);
  }
  return bounds;
}

int DockFrame::GetTopInset(bool restored) const {
  int top = dock_frame_view_->GetTopInset(restored);
  return top;
}

int DockFrame::GetThemeBackgroundXInset() const {
  return dock_frame_view_->GetThemeBackgroundXInset();
}

void DockFrame::UpdateThrobber(bool running) {
  dock_frame_view_->UpdateThrobber(running);
}

DockNonClientFrameView* DockFrame::GetFrameView() const {
  return dock_frame_view_;
}

bool DockFrame::UseCustomFrame() const {
  return native_dock_frame_->UseCustomFrame();
}

bool DockFrame::ShouldSaveWindowPlacement() const {
  return native_dock_frame_->ShouldSaveWindowPlacement();
}

void DockFrame::GetWindowPlacement(gfx::Rect* bounds,
                                  ui::WindowShowState* show_state) const {
  return native_dock_frame_->GetWindowPlacement(bounds, show_state);
}

bool DockFrame::PreHandleKeyboardEvent(const NativeWebKeyboardEvent& event) {
  DLOG(INFO) << "DockFrame::PreHandleKeyboardEvent";
  return native_dock_frame_->PreHandleKeyboardEvent(event);
}

bool DockFrame::HandleKeyboardEvent(const NativeWebKeyboardEvent& event) {
  return native_dock_frame_->HandleKeyboardEvent(event);
}

void DockFrame::OnDockWindowInitViewsComplete() {
  dock_frame_view_->OnDockWindowInitViewsComplete();
}

views::internal::RootView* DockFrame::CreateRootView() {
  root_view_ = new DockRootView(dock_window_, this);
  return root_view_;
}

views::NonClientFrameView* DockFrame::CreateNonClientFrameView() {
  dock_frame_view_ =
      host::CreateDockNonClientFrameView(this, dock_window_);
  return dock_frame_view_;
}

bool DockFrame::GetAccelerator(int command_id,
                               ui::Accelerator* accelerator) const {
  DLOG(INFO) << "DockFrame::GetAccelerator";
  return dock_window_->GetAccelerator(command_id, accelerator);
}

const ui::ThemeProvider* DockFrame::GetThemeProvider() const {
  return &ThemeService::GetThemeProviderForWorkspace(
      dock_window_->dock()->workspace());
}

const ui::NativeTheme* DockFrame::GetNativeTheme() const {
  return ui::NativeTheme::GetInstanceForNativeUi();
}

void DockFrame::SchedulePaintInRect(const gfx::Rect& rect) {
  views::Widget::SchedulePaintInRect(rect);

  // Paint the frame caption area and window controls during immersive reveal.
  //if (dock_window_ &&
  //    dock_window_->immersive_mode_controller()->IsRevealed()) {
    // This function should not be reentrant because the TopContainerView
    // paints to a layer for the duration of the immersive reveal.
  //  views::View* top_container = dock_window_->top_container();
  //  CHECK(top_container->layer());
  //  top_container->SchedulePaintInRect(rect);
  //}
}

void DockFrame::OnNativeWidgetWorkspaceChanged() {
  //chrome::SaveWindowWorkspace(dock_window_->browser(), GetWorkspace());
#if defined(USE_X11)
  DockList::MoveDocksInWorkspaceToFront(
      views::X11DesktopHandler::get()->GetWorkspace());
#endif
  Widget::OnNativeWidgetWorkspaceChanged();
}

void DockFrame::OnNativeThemeUpdated(ui::NativeTheme* observed_theme) {
  views::Widget::OnNativeThemeUpdated(observed_theme);
  dock_window_->NativeThemeUpdated(observed_theme);
}

void DockFrame::ShowContextMenuForView(
  views::View* source,
  const gfx::Point& p,
  ui::MenuSourceType source_type) {
   // Only show context menu if point is in unobscured parts of browser, i.e.
  // if NonClientHitTest returns :
  // - HTCAPTION: in title bar or unobscured part of tabstrip
  // - HTNOWHERE: as the name implies.
  gfx::Point point_in_view_coords(p);
  views::View::ConvertPointFromScreen(non_client_view(), &point_in_view_coords);
  int hit_test = non_client_view()->NonClientHitTest(point_in_view_coords);
  if (hit_test == HTCAPTION || hit_test == HTNOWHERE) {
    menu_runner_.reset(new views::MenuRunner(
        GetSystemMenuModel(),
        views::MenuRunner::HAS_MNEMONICS | views::MenuRunner::CONTEXT_MENU,
        base::Bind(&DockFrame::OnMenuClosed, base::Unretained(this))));
    menu_runner_->RunMenuAt(source->GetWidget(), nullptr,
                            gfx::Rect(p, gfx::Size(0, 0)),
                            views::MENU_ANCHOR_TOPLEFT, source_type);
  }
}

ui::MenuModel* DockFrame::GetSystemMenuModel() {
  if (!menu_model_builder_.get()) {
    menu_model_builder_.reset(
        new SystemMenuModelBuilder(dock_window_, dock_window_->dock()));
    menu_model_builder_->Init();
  }
  return menu_model_builder_->menu_model();
}

void DockFrame::OnMenuClosed() {
  menu_runner_.reset();
}


}
