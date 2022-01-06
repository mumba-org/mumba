// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_UI_VIEWS_FRAME_SYSTEM_MENU_MODEL_BUILDER_H_
#define CHROME_BROWSER_UI_VIEWS_FRAME_SYSTEM_MENU_MODEL_BUILDER_H_

#include <memory>

#include "base/macros.h"
#include "core/host/ui/system_menu_model_delegate.h"

namespace ui {
class AcceleratorProvider;
class MenuModel;
class SimpleMenuModel;
}

namespace host {
class ZoomMenuModel;
class Dock;
// SystemMenuModelBuilder is responsible for building and owning the system menu
// model.
class SystemMenuModelBuilder {
 public:
  SystemMenuModelBuilder(ui::AcceleratorProvider* provider, Dock* dock);
  ~SystemMenuModelBuilder();

  // Populates the menu.
  void Init();

  // Returns the menu model. SystemMenuModelBuilder owns the returned model.
  ui::MenuModel* menu_model() { return menu_model_.get(); }

 private:
  Dock* dock() { return menu_delegate_.dock(); }

  // Populates |model| with the appropriate contents.
  void BuildMenu(ui::SimpleMenuModel* model);
  void BuildSystemMenuForBrowserWindow(ui::SimpleMenuModel* model);
  void BuildSystemMenuForAppOrPopupWindow(ui::SimpleMenuModel* model);

  // Adds items for toggling the frame type (if necessary).
  void AddFrameToggleItems(ui::SimpleMenuModel* model);

  // Add the items to allow the window to visit the desktop of another user.
  //void AppendTeleportMenu(ui::SimpleMenuModel* model);

  SystemMenuModelDelegate menu_delegate_;
  std::unique_ptr<ui::MenuModel> menu_model_;
  //std::unique_ptr<ZoomMenuModel> zoom_menu_contents_;

  DISALLOW_COPY_AND_ASSIGN(SystemMenuModelBuilder);
};

}

#endif  // CHROME_BROWSER_UI_VIEWS_FRAME_SYSTEM_MENU_MODEL_BUILDER_H_
