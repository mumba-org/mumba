// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_UI_GLOBAL_MENU_BAR_X11_H_
#define MUMBA_HOST_UI_GLOBAL_MENU_BAR_X11_H_

#include <map>
#include <string>

#include "base/compiler_specific.h"
#include "base/macros.h"
#include "base/memory/weak_ptr.h"
#include "base/scoped_observer.h"
#include "core/host/ui/dock_list_observer.h"
#include "core/host/ui/command_observer.h"
#include "ui/base/glib/glib_signal.h"
#include "ui/views/widget/desktop_aura/desktop_window_tree_host_observer_x11.h"

typedef struct _DbusmenuMenuitem DbusmenuMenuitem;
typedef struct _DbusmenuServer   DbusmenuServer;

namespace ui {
class Accelerator;
}

namespace host {
class Dock;
class DockWindow;
class Workspace;
class DockDesktopWindowTreeHostX11;
struct GlobalMenuBarCommand;

// Controls the Mac style menu bar on Unity.
//
// Unity has an Apple-like menu bar at the top of the screen that changes
// depending on the active window. In the GTK port, we had a hidden GtkMenuBar
// object in each GtkWindow which existed only to be scrapped by the
// libdbusmenu-gtk code. Since we don't have GtkWindows anymore, we need to
// interface directly with the lower level libdbusmenu-glib, which we
// opportunistically dlopen() since not everyone is running Ubuntu.
class GlobalMenuBarX11 : public DockListObserver,
                         public CommandObserver,
                         public views::DesktopWindowTreeHostObserverX11 {
 public:
  GlobalMenuBarX11(DockWindow* dock_window,
                   DockDesktopWindowTreeHostX11* host);
  ~GlobalMenuBarX11() override;

  // Creates the object path for DbusemenuServer which is attached to |xid|.
  static std::string GetPathForWindow(unsigned long xid);

 private:
  //struct HistoryItem;
  typedef std::map<int, DbusmenuMenuitem*> CommandIDMenuItemMap;

  // Builds a separator.
  DbusmenuMenuitem* BuildSeparator();

  // Creates an individual menu item from a title and command, and subscribes
  // to the activation signal.
  DbusmenuMenuitem* BuildMenuItem(const std::string& label, int tag_id);

  // Creates a DbusmenuServer, and attaches all the menu items.
  void InitServer(unsigned long xid);

  // Stops listening to enable state changed events.
  void Disable();

  // Creates a whole menu defined with |commands| and titled with the string
  // |menu_str_id|. Then appends it to |parent|.
  DbusmenuMenuitem* BuildStaticMenu(DbusmenuMenuitem* parent,
                                    int menu_str_id,
                                    GlobalMenuBarCommand* commands);

  // Sets the accelerator for |item|.
  void RegisterAccelerator(DbusmenuMenuitem* item,
                           const ui::Accelerator& accelerator);

    // Find the first index of the item in |menu| with the tag |tag_id|.
  int GetIndexOfMenuItemWithTag(DbusmenuMenuitem* menu, int tag_id);

  // This will remove all menu items in |menu| with |tag| as their tag. This
  // clears state about HistoryItems* that we keep to prevent that data from
  // going stale. That's why this method recurses into its child menus.
  void ClearMenuSection(DbusmenuMenuitem* menu, int tag_id);

  // Deleter function for HistoryItem implementation detail.
  //static void DeleteHistoryItem(void* void_item);

  // Overridden from DockListObserver:
  void OnDockSetLastActive(Dock* dock) override;

  // Overridden from CommandObserver:
  void EnabledStateChangedForCommand(int id, bool enabled) override;

  // Overridden from views::DesktopWindowTreeHostObserverX11:
  void OnWindowMapped(unsigned long xid) override;
  void OnWindowUnmapped(unsigned long xid) override;

  CHROMEG_CALLBACK_1(GlobalMenuBarX11, void, OnItemActivated, DbusmenuMenuitem*,
                     unsigned int);
  CHROMEG_CALLBACK_1(GlobalMenuBarX11, void, OnHistoryItemActivated,
                     DbusmenuMenuitem*, unsigned int);
  CHROMEG_CALLBACK_0(GlobalMenuBarX11, void, OnHistoryMenuAboutToShow,
                     DbusmenuMenuitem*);
  CHROMEG_CALLBACK_1(GlobalMenuBarX11, void, OnProfileItemActivated,
                     DbusmenuMenuitem*, unsigned int);
  CHROMEG_CALLBACK_1(GlobalMenuBarX11, void, OnEditProfileItemActivated,
                     DbusmenuMenuitem*, unsigned int);
  CHROMEG_CALLBACK_1(GlobalMenuBarX11, void, OnCreateProfileItemActivated,
                     DbusmenuMenuitem*, unsigned int);

  Dock* const dock_;
  scoped_refptr<Workspace> workspace_;
  DockWindow* dock_window_;
  DockDesktopWindowTreeHostX11* host_;

  // Maps command ids to DbusmenuMenuitems so we can modify their
  // enabled/checked state in response to state change notifications.
  CommandIDMenuItemMap id_to_menu_item_;

  DbusmenuServer* server_;
  DbusmenuMenuitem* root_item_;
  //DbusmenuMenuitem* history_menu_;
  //DbusmenuMenuitem* profiles_menu_;

    // For callbacks may be run after destruction.
  base::WeakPtrFactory<GlobalMenuBarX11> weak_ptr_factory_;

  DISALLOW_COPY_AND_ASSIGN(GlobalMenuBarX11);
};

}

#endif  // CHROME_BROWSER_UI_VIEWS_FRAME_GLOBAL_MENU_BAR_X11_H_
