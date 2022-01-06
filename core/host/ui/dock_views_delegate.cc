// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/ui/dock_views_delegate.h"

#include <memory>

#include "base/logging.h"
#include "build/build_config.h"
#include "core/host/ui/context_factory.h"
#include "ui/display/display.h"
#include "ui/display/screen.h"
#include "ui/gfx/geometry/rect.h"
#include "ui/views/widget/widget.h"
#include "components/keep_alive_registry/scoped_keep_alive.h"
#include "components/keep_alive_registry/keep_alive_registry.h"
#include "components/keep_alive_registry/keep_alive_state_observer.h"
#include "components/keep_alive_registry/keep_alive_types.h"

//#if defined(USE_AURA)
//#include "core/host/ui/aura/accessibility/automation_manager_aura.h"
//#endif

namespace host {

// DockViewsDelegate --------------------------------------------------------

DockViewsDelegate::DockViewsDelegate() {}

DockViewsDelegate::~DockViewsDelegate() {
  DCHECK_EQ(0u, ref_count_);
}

void DockViewsDelegate::SaveWindowPlacement(const views::Widget* window,
                                              const std::string& window_name,
                                              const gfx::Rect& bounds,
                                              ui::WindowShowState show_state) {
  // PrefService* prefs = GetPrefsForWindow(window);
  // if (!prefs)
  //   return;

  // std::unique_ptr<DictionaryPrefUpdate> pref_update =
  //     chrome::GetWindowPlacementDictionaryReadWrite(window_name, prefs);
  // base::DictionaryValue* window_preferences = pref_update->Get();
  // window_preferences->SetInteger("left", bounds.x());
  // window_preferences->SetInteger("top", bounds.y());
  // window_preferences->SetInteger("right", bounds.right());
  // window_preferences->SetInteger("bottom", bounds.bottom());
  // window_preferences->SetBoolean("maximized",
  //                                show_state == ui::SHOW_STATE_MAXIMIZED);

  // gfx::Rect work_area(display::Screen::GetScreen()
  //                         ->GetDisplayNearestView(window->GetNativeView())
  //                         .work_area());
  // window_preferences->SetInteger("work_area_left", work_area.x());
  // window_preferences->SetInteger("work_area_top", work_area.y());
  // window_preferences->SetInteger("work_area_right", work_area.right());
  // window_preferences->SetInteger("work_area_bottom", work_area.bottom());
}

bool DockViewsDelegate::GetSavedWindowPlacement(
    const views::Widget* widget,
    const std::string& window_name,
    gfx::Rect* bounds,
    ui::WindowShowState* show_state) const {
//   PrefService* prefs = g_browser_process->local_state();
//   if (!prefs)
//     return false;

//   DCHECK(prefs->FindPreference(window_name));
//   const base::DictionaryValue* dictionary = prefs->GetDictionary(window_name);
//   int left = 0;
//   int top = 0;
//   int right = 0;
//   int bottom = 0;
//   if (!dictionary || !dictionary->GetInteger("left", &left) ||
//       !dictionary->GetInteger("top", &top) ||
//       !dictionary->GetInteger("right", &right) ||
//       !dictionary->GetInteger("bottom", &bottom))
//     return false;

//   bounds->SetRect(left, top, right - left, bottom - top);

//   bool maximized = false;
//   if (dictionary)
//     dictionary->GetBoolean("maximized", &maximized);
//   *show_state = maximized ? ui::SHOW_STATE_MAXIMIZED : ui::SHOW_STATE_NORMAL;

// #if defined(OS_CHROMEOS)
//   AdjustSavedWindowPlacementWindowOS(widget, bounds);
// #endif
//   return true;
  return false;
}

void DockViewsDelegate::NotifyAccessibilityEvent(
    views::View* view,
    ax::mojom::Event event_type) {
// #if defined(USE_AURA)
//   AutomationManagerAura::GetInstance()->HandleEvent(
//       GetProfileForWindow(view->GetWidget()), view, event_type);
// #endif
}

void DockViewsDelegate::AddRef() {
  if (ref_count_ == 0u) {
    keep_alive_.reset(
        new ScopedKeepAlive(KeepAliveOrigin::CHROME_VIEWS_DELEGATE,
                            KeepAliveRestartOption::DISABLED));
  }

  ++ref_count_;
}

void DockViewsDelegate::ReleaseRef() {
  DCHECK_NE(0u, ref_count_);

  if (--ref_count_ == 0u)
    keep_alive_.reset();
}

void DockViewsDelegate::OnBeforeWidgetInit(
    views::Widget::InitParams* params,
    views::internal::NativeWidgetDelegate* delegate) {
  // We need to determine opacity if it's not already specified.
  if (params->opacity == views::Widget::InitParams::INFER_OPACITY)
    params->opacity = GetOpacityForInitParams(*params);

  // If we already have a native_widget, we don't have to try to come
  // up with one.
  //if (params->native_widget)
  //  return;

  //if (!native_widget_factory().is_null()) {
  //  params->native_widget = native_widget_factory().Run(*params, delegate);
  //  if (params->native_widget)
  //    return;
  //}

  //params->native_widget = CreateNativeWidget(params, delegate);
}

ui::ContextFactory* DockViewsDelegate::GetContextFactory() {
  return host::GetContextFactory();
}

ui::ContextFactoryPrivate* DockViewsDelegate::GetContextFactoryPrivate() {
  return host::GetContextFactoryPrivate();
}

std::string DockViewsDelegate::GetApplicationName() {
  return std::string("mumba");
  //return version_info::GetProductName();
}

#if !defined(OS_CHROMEOS)
views::Widget::InitParams::WindowOpacity
DockViewsDelegate::GetOpacityForInitParams(
    const views::Widget::InitParams& params) {
  return views::Widget::InitParams::OPAQUE_WINDOW;
}
#endif

}
