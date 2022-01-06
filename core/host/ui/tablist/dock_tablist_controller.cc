// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/ui/tablist/dock_tablist_controller.h"

#include <utility>

#include "base/auto_reset.h"
#include "base/command_line.h"
#include "base/macros.h"
#include "base/metrics/user_metrics.h"
#include "base/task_scheduler/post_task.h"
#include "build/build_config.h"
#include "core/host/host.h"
#include "core/host/notification_types.h"
#include "core/host/favicon/favicon_utils.h"
#include "core/host/workspace/workspace.h"
#include "core/host/ui/dock.h"
#include "core/host/ui/dock_frame.h"
#include "core/host/host_thread.h"
#include "core/host/notification_service.h"
#include "core/host/application/application_contents.h"
#include "core/host/application/application_controller.h"
#include "core/host/ui/tab_ui_helper.h"
#include "core/host/ui/tablist/dock_tablist.h"
#include "core/host/ui/tablist/tab_menu_model.h"
#include "core/host/ui/tablist/tablist.h"
#include "core/host/ui/tablist/tablist_model.h"
#include "core/host/ui/tablist/tablist_model_delegate.h"
#include "core/host/ui/tablist/tab_network_state.h"
#include "core/host/ui/tablist/tab_utils.h"
#include "core/host/ui/tablist/tab.h"
#include "core/host/ui/tablist/tab_renderer_data.h"
#include "core/shared/common/switches.h"
#include "ipc/ipc_message.h"
#include "net/base/filename_util.h"
#include "net/base/mime_util.h"
#include "third_party/blink/public/common/mime_util/mime_util.h"
#include "third_party/metrics_proto/omnibox_event.pb.h"
#include "ui/base/material_design/material_design_controller.h"
#include "ui/base/models/list_selection_model.h"
#include "ui/gfx/image/image.h"
#include "ui/views/controls/menu/menu_runner.h"
#include "ui/views/widget/widget.h"
#include "url/origin.h"

using base::UserMetricsAction;

namespace host {

namespace {

bool DetermineTablistLayoutStacked(bool* adjust_layout) {
//  *adjust_layout = false;
  // For ash, always allow entering stacked mode.
//#if defined(OS_CHROMEOS)
//  *adjust_layout = true;
//  // Stacked layout is always enabled in touch optimized UI design.
//  return ui::MaterialDesignController::IsTouchOptimizedUiEnabled() ||
//         prefs->GetBoolean(prefs::kTablistStackedLayout);
//#else
//  return base::CommandLine::ForCurrentProcess()->HasSwitch(
//      switches::kForceStackedTablistLayout);
//#endif
  *adjust_layout = true;
  return false;
}

// Get the MIME type of the file pointed to by the url, based on the file's
// extension. Must be called on a thread that allows IO.
std::string FindURLMimeType(const GURL& url) {
  DCHECK(!HostThread::CurrentlyOn(HostThread::UI));
  base::FilePath full_path;
  net::FileURLToFilePath(url, &full_path);

  // Get the MIME type based on the filename.
  std::string mime_type;
  net::GetMimeTypeFromFile(full_path, &mime_type);

  return mime_type;
}

}  // namespace

class DockTablistController::TabContextMenuContents
    : public ui::SimpleMenuModel::Delegate {
 public:
  TabContextMenuContents(Tab* tab,
                         DockTablistController* controller)
      : tab_(tab),
        controller_(controller),
        last_command_(TablistModel::CommandFirst) {
    model_.reset(new TabMenuModel(
        this, controller->model_,
        controller->tablist_->GetModelIndexOfTab(tab)));
    menu_runner_.reset(new views::MenuRunner(
        model_.get(),
        views::MenuRunner::HAS_MNEMONICS | views::MenuRunner::CONTEXT_MENU));
  }

  ~TabContextMenuContents() override {
    if (controller_)
      controller_->tablist_->StopAllHighlighting();
  }

  void Cancel() {
    controller_ = NULL;
  }

  void RunMenuAt(const gfx::Point& point, ui::MenuSourceType source_type) {
    menu_runner_->RunMenuAt(tab_->GetWidget(), NULL,
                            gfx::Rect(point, gfx::Size()),
                            views::MENU_ANCHOR_TOPLEFT, source_type);
  }

  // Overridden from ui::SimpleMenuModel::Delegate:
  bool IsCommandIdChecked(int command_id) const override { return false; }
  bool IsCommandIdEnabled(int command_id) const override {
    return controller_->IsCommandEnabledForTab(
        static_cast<TablistModel::ContextMenuCommand>(command_id),
        tab_);
  }
  bool GetAcceleratorForCommandId(int command_id,
                                  ui::Accelerator* accelerator) const override {
    int browser_cmd;
    return TablistModel::ContextMenuCommandToDockCommand(command_id,
                                                             &browser_cmd) ?
        controller_->tablist_->GetWidget()->GetAccelerator(browser_cmd,
                                                            accelerator) :
        false;
  }
  void CommandIdHighlighted(int command_id) override {
    controller_->StopHighlightTabsForCommand(last_command_, tab_);
    last_command_ = static_cast<TablistModel::ContextMenuCommand>(command_id);
    controller_->StartHighlightTabsForCommand(last_command_, tab_);
  }
  void ExecuteCommand(int command_id, int event_flags) override {
    // Executing the command destroys |this|, and can also end up destroying
    // |controller_|. So stop the highlights before executing the command.
    controller_->tablist_->StopAllHighlighting();
    controller_->ExecuteCommandForTab(
        static_cast<TablistModel::ContextMenuCommand>(command_id),
        tab_);
  }

  void MenuClosed(ui::SimpleMenuModel* /*source*/) override {
    if (controller_)
      controller_->tablist_->StopAllHighlighting();
  }

 private:
  std::unique_ptr<TabMenuModel> model_;
  std::unique_ptr<views::MenuRunner> menu_runner_;

  // The tab we're showing a menu for.
  Tab* tab_;

  // A pointer back to our hosting controller, for command state information.
  DockTablistController* controller_;

  // The last command that was selected, so that we can start/stop highlighting
  // appropriately as the user moves through the menu.
  TablistModel::ContextMenuCommand last_command_;

  DISALLOW_COPY_AND_ASSIGN(TabContextMenuContents);
};

////////////////////////////////////////////////////////////////////////////////
// DockTablistController, public:

DockTablistController::DockTablistController(TablistModel* model,
                                                     DockWindow* browser_view)
    : model_(model),
      tablist_(NULL),
      dock_window_(browser_view),
      hover_tab_selector_(model),
      weak_ptr_factory_(this) {
  model_->AddObserver(this);

  //local_pref_registrar_.Init(g_browser_process->local_state());
  //local_pref_registrar_.Add(
      //prefs::kTablistStackedLayout,
     // base::Bind(&DockTablistController::UpdateStackedLayout,
                 //base::Unretained(this)));
}

DockTablistController::~DockTablistController() {
  // When we get here the Tablist is being deleted. We need to explicitly
  // cancel the menu, otherwise it may try to invoke something on the tablist
  // from its destructor.
  if (context_menu_contents_.get())
    context_menu_contents_->Cancel();

  model_->RemoveObserver(this);
}

void DockTablistController::InitFromModel(Tablist* tablist) {
  tablist_ = tablist;

  UpdateStackedLayout();

  // Walk the model, calling our insertion observer method for each item within
  // it.
  for (int i = 0; i < model_->count(); ++i)
    AddTab(model_->GetApplicationContentsAt(i), i, model_->active_index() == i);
}

bool DockTablistController::IsCommandEnabledForTab(
    TablistModel::ContextMenuCommand command_id,
    Tab* tab) const {
  int model_index = tablist_->GetModelIndexOfTab(tab);
  return model_->ContainsIndex(model_index) ?
      model_->IsContextMenuCommandEnabled(model_index, command_id) : false;
}

void DockTablistController::ExecuteCommandForTab(
    TablistModel::ContextMenuCommand command_id,
    Tab* tab) {
  int model_index = tablist_->GetModelIndexOfTab(tab);
  if (model_->ContainsIndex(model_index))
    model_->ExecuteContextMenuCommand(model_index, command_id);
}

bool DockTablistController::IsTabPinned(Tab* tab) const {
  return IsTabPinned(tablist_->GetModelIndexOfTab(tab));
}

const ui::ListSelectionModel&
DockTablistController::GetSelectionModel() const {
  return model_->selection_model();
}

int DockTablistController::GetCount() const {
  return model_->count();
}

bool DockTablistController::IsValidIndex(int index) const {
  return model_->ContainsIndex(index);
}

bool DockTablistController::IsActiveTab(int model_index) const {
  return model_->active_index() == model_index;
}

int DockTablistController::GetActiveIndex() const {
  return model_->active_index();
}

bool DockTablistController::IsTabSelected(int model_index) const {
  return model_->IsTabSelected(model_index);
}

bool DockTablistController::IsTabPinned(int model_index) const {
  return model_->ContainsIndex(model_index) && model_->IsTabPinned(model_index);
}

void DockTablistController::SelectTab(int model_index) {
  model_->ActivateTabAt(model_index, true);
}

void DockTablistController::ExtendSelectionTo(int model_index) {
  model_->ExtendSelectionTo(model_index);
}

void DockTablistController::ToggleSelected(int model_index) {
  model_->ToggleSelectionAt(model_index);
}

void DockTablistController::AddSelectionFromAnchorTo(int model_index) {
  model_->AddSelectionFromAnchorTo(model_index);
}

void DockTablistController::CloseTab(int model_index,
                                     CloseTabSource source) {
  // Cancel any pending tab transition.
  hover_tab_selector_.CancelTabTransition();

  tablist_->PrepareForCloseAt(model_index, source);
  model_->CloseApplicationContentsAt(model_index,
                             TablistModel::CLOSE_USER_GESTURE |
                             TablistModel::CLOSE_CREATE_HISTORICAL_TAB);
}

void DockTablistController::ToggleTabAudioMute(int model_index) {
  //ApplicationContents* const contents = model_->GetApplicationContentsAt(model_index);
  //host::SetTabAudioMuted(contents, !contents->IsAudioMuted(),
  //                       TabMutedReason::AUDIO_INDICATOR, std::string());
}

void DockTablistController::ShowContextMenuForTab(
    Tab* tab,
    const gfx::Point& p,
    ui::MenuSourceType source_type) {
  context_menu_contents_.reset(new TabContextMenuContents(tab, this));
  context_menu_contents_->RunMenuAt(p, source_type);
}

int DockTablistController::HasAvailableDragActions() const {
  return model_->delegate()->GetDragActions();
}

void DockTablistController::OnDropIndexUpdate(int index,
                                                  bool drop_before) {
  // Perform a delayed tab transition if hovering directly over a tab.
  // Otherwise, cancel the pending one.
  if (index != -1 && !drop_before) {
    hover_tab_selector_.StartTabTransition(index);
  } else {
    hover_tab_selector_.CancelTabTransition();
  }
}

void DockTablistController::PerformDrop(bool drop_before,
                                        int index,
                                        const GURL& url) {
  // NavigateParams params(dock_window_->dock(), url,
  //                       ui::PAGE_TRANSITION_LINK);
  // params.tablist_index = index;

  // if (drop_before) {
  //   base::RecordAction(UserMetricsAction("Tab_DropURLBetweenTabs"));
  //   params.disposition = WindowOpenDisposition::NEW_FOREGROUND_TAB;
  // } else {
  //   base::RecordAction(UserMetricsAction("Tab_DropURLOnTab"));
  //   params.disposition = WindowOpenDisposition::CURRENT_TAB;
  //   params.source_contents = model_->GetApplicationContentsAt(index);
  // }
  // params.window_action = NavigateParams::SHOW_WINDOW;
  // Navigate(&params);
  DCHECK(false);
}

bool DockTablistController::IsCompatibleWith(Tablist* other) const {
  scoped_refptr<Workspace> other_workspace = other->controller()->GetWorkspace();
  return other_workspace == GetWorkspace();
}

void DockTablistController::CreateNewTab() {
  //TabStyle style = TabStyle::kAPP;
  //model_->delegate()->AddTabAt(GURL("world://new"), nullptr, -1, true, style);
  ApplicationController* controller = dock()->workspace()->application_controller();
  controller->LaunchApplication(GURL("world://new"), LaunchOptions(), base::Callback<void(int)>());
}

void DockTablistController::CreateNewTabWithLocation(
    const base::string16& location) {
  DCHECK(false);
  TabStyle style = TabStyle::kAPP;
  // Use autocomplete to clean up the text, going so far as to turn it into
  // a search query if necessary.
  //AutocompleteMatch match;
  //AutocompleteClassifierFactory::GetForProfile(GetProfile())
  //    ->Classify(location, false, false, metrics::OmniboxEventProto::BLANK,
  //               &match, NULL);
  //if (match.destination_url.is_valid())
  //  model_->delegate()->AddTabAt(match.destination_url, -1, true);
  GURL dest_url(location);
  if (dest_url.is_valid())
    model_->delegate()->AddTabAt(dest_url, nullptr, -1, true, style);
}

bool DockTablistController::IsIncognito() {
  return false;//dock_window_->dock()->profile()->GetProfileType() ==
      //Profile::INCOGNITO_PROFILE;
}

void DockTablistController::StackedLayoutMaybeChanged() {
  //bool adjust_layout = false;
  //bool stacked_layout = DetermineTablistLayoutStacked(&adjust_layout);
  //if (!adjust_layout || stacked_layout == tablist_->stacked_layout())
  //  return;

  //g_browser_process->local_state()->SetBoolean(prefs::kTablistStackedLayout,
  //                                             tablist_->stacked_layout());
}

void DockTablistController::OnStartedDraggingTabs() {
  //if (!immersive_reveal_lock_.get()) {
    // The top-of-window views should be revealed while the user is dragging
    // tabs in immersive fullscreen. The top-of-window views may not be already
    // revealed if the user is attempting to attach a tab to a tablist
    // belonging to an immersive fullscreen window.
    //immersive_reveal_lock_.reset(
    //    dock_window_->immersive_mode_controller()->GetRevealedLock(
    //        ImmersiveModeController::ANIMATE_REVEAL_NO));
  //}
}

void DockTablistController::OnStoppedDraggingTabs() {
  //immersive_reveal_lock_.reset();
}

void DockTablistController::CheckFileSupported(const GURL& url) {
  base::PostTaskWithTraitsAndReplyWithResult(
      FROM_HERE, {base::MayBlock(), base::TaskPriority::USER_VISIBLE},
      base::Bind(&FindURLMimeType, url),
      base::Bind(&DockTablistController::OnFindURLMimeTypeCompleted,
                 weak_ptr_factory_.GetWeakPtr(), url));
}

SkColor DockTablistController::GetToolbarTopSeparatorColor() const {
  return dock_window_->frame()->GetFrameView()->GetToolbarTopSeparatorColor();
}

base::string16 DockTablistController::GetAccessibleTabName(
    const Tab* tab) const {
  return dock_window_->GetAccessibleWindowLabel(
      false /* include_app_name */, tablist_->GetModelIndexOfTab(tab));
}

scoped_refptr<Workspace> DockTablistController::GetWorkspace() const {
  return model_->workspace();
}

////////////////////////////////////////////////////////////////////////////////
// DockTablistController, TablistModelObserver implementation:

void DockTablistController::TabInsertedAt(TablistModel* tab_strip_model,
                                              ApplicationContents* contents,
                                              int model_index,
                                              bool is_active) {
  DCHECK(contents);
  DCHECK(model_->ContainsIndex(model_index));
  AddTab(contents, model_index, is_active);
}

void DockTablistController::TabDetachedAt(ApplicationContents* contents,
                                              int model_index) {
  // Cancel any pending tab transition.
  hover_tab_selector_.CancelTabTransition();

  tablist_->RemoveTabAt(contents, model_index);
}

void DockTablistController::ActiveTabChanged(
    ApplicationContents* old_contents,
    ApplicationContents* new_contents,
    int index,
    int reason) {
  // It's possible for |new_contents| to be null when the final tab in a tab
  // strip is closed.
  if (new_contents && index != TablistModel::kNoTab) {
    TabUIHelper::FromApplicationContents(new_contents)->set_was_active_at_least_once();
    SetTabDataAt(new_contents, index);
  }
}

void DockTablistController::TabSelectionChanged(
    TablistModel* tab_strip_model,
    const ui::ListSelectionModel& old_model) {
  tablist_->SetSelection(old_model, model_->selection_model());
}

void DockTablistController::TabMoved(ApplicationContents* contents,
                                         int from_model_index,
                                         int to_model_index) {
  // Cancel any pending tab transition.
  hover_tab_selector_.CancelTabTransition();

  // A move may have resulted in the pinned state changing, so pass in a
  // TabRendererData.
  tablist_->MoveTab(
      from_model_index, to_model_index,
      TabRendererDataFromModel(contents, to_model_index, EXISTING_TAB));
}

void DockTablistController::TabChangedAt(ApplicationContents* contents,
                                             int model_index,
                                             TabChangeType change_type) {
  if (change_type == TabChangeType::kTitleNotLoading) {
    tablist_->TabTitleChangedNotLoading(model_index);
    // We'll receive another notification of the change asynchronously.
    return;
  }

  SetTabDataAt(contents, model_index);
}

void DockTablistController::TabReplacedAt(TablistModel* tab_strip_model,
                                              ApplicationContents* old_contents,
                                              ApplicationContents* new_contents,
                                              int model_index) {
  SetTabDataAt(new_contents, model_index);
}

void DockTablistController::TabPinnedStateChanged(
    TablistModel* tab_strip_model,
    ApplicationContents* contents,
    int model_index) {
  SetTabDataAt(contents, model_index);
}

void DockTablistController::TabBlockedStateChanged(ApplicationContents* contents,
                                                       int model_index) {
  SetTabDataAt(contents, model_index);
}

void DockTablistController::SetTabNeedsAttentionAt(int index,
                                                       bool attention) {
  tablist_->SetTabNeedsAttention(index, attention);
}

TabRendererData DockTablistController::TabRendererDataFromModel(
    ApplicationContents* contents,
    int model_index,
    TabStatus tab_status) {
  TabRendererData data;
  TabUIHelper* tab_ui_helper = TabUIHelper::FromApplicationContents(contents);
  data.favicon = tab_ui_helper->GetFavicon().AsImageSkia();
  data.network_state = TabNetworkStateForApplicationContents(contents);
  data.title = tab_ui_helper->GetTitle();
  data.url = contents->GetURL();
  data.crashed_status = contents->GetCrashedStatus();
  data.incognito = false;//contents->GetDockContext()->IsOffTheRecord();
  data.pinned = model_->IsTabPinned(model_index);
  data.show_icon = true;//data.pinned || favicon::ShouldDisplayFavicon(contents);
  data.blocked = model_->IsTabBlocked(model_index);
  data.app = false;//extensions::TabHelper::FromApplicationContents(contents)->is_app();
  data.alert_state = GetTabAlertStateForContents(contents);
  data.should_hide_throbber = tab_ui_helper->ShouldHideThrobber();
  return data;
}

void DockTablistController::SetTabDataAt(ApplicationContents* web_contents,
                                             int model_index) {
  tablist_->SetTabData(
      model_index,
      TabRendererDataFromModel(web_contents, model_index, EXISTING_TAB));
}

void DockTablistController::StartHighlightTabsForCommand(
    TablistModel::ContextMenuCommand command_id,
    Tab* tab) {
  if (command_id == TablistModel::CommandCloseOtherTabs ||
      command_id == TablistModel::CommandCloseTabsToRight) {
    int model_index = tablist_->GetModelIndexOfTab(tab);
    if (IsValidIndex(model_index)) {
      std::vector<int> indices =
          model_->GetIndicesClosedByCommand(model_index, command_id);
      for (std::vector<int>::const_iterator i(indices.begin());
           i != indices.end(); ++i) {
        tablist_->StartHighlight(*i);
      }
    }
  }
}

void DockTablistController::StopHighlightTabsForCommand(
    TablistModel::ContextMenuCommand command_id,
    Tab* tab) {
  if (command_id == TablistModel::CommandCloseTabsToRight ||
      command_id == TablistModel::CommandCloseOtherTabs) {
    // Just tell all Tabs to stop pulsing - it's safe.
    tablist_->StopAllHighlighting();
  }
}

void DockTablistController::AddTab(ApplicationContents* contents,
                                       int index,
                                       bool is_active) {
  TabStyle style = TabStyle::kAPP;                                       
  // Cancel any pending tab transition.
  hover_tab_selector_.CancelTabTransition();

  tablist_->AddTabAt(index, TabRendererDataFromModel(contents, index, NEW_TAB),
                      is_active, style);
}

void DockTablistController::UpdateStackedLayout() {
  bool adjust_layout = false;
  bool stacked_layout = DetermineTablistLayoutStacked(&adjust_layout);
  tablist_->set_adjust_layout(adjust_layout);
  tablist_->SetStackedLayout(stacked_layout);
}

void DockTablistController::OnFindURLMimeTypeCompleted(
    const GURL& url,
    const std::string& mime_type) {
  // Check whether the mime type, if given, is known to be supported or whether
  // there is a plugin that supports the mime type (e.g. PDF).
  // TODO(bauerb): This possibly uses stale information, but it's guaranteed not
  // to do disk access.
  //content::WebPluginInfo plugin;
  tablist_->FileSupported(
      url,
      mime_type.empty() || blink::IsSupportedMimeType(mime_type));// ||
          //content::PluginService::GetInstance()->GetPluginInfo(
          //    -1,                // process ID
          //    MSG_ROUTING_NONE,  // routing ID
          //    model_->profile()->GetResourceContext(), url, url::Origin(),
          //    mime_type, false, NULL, &plugin, NULL));
}

}