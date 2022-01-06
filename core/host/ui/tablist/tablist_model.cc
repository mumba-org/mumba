// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/ui/tablist/tablist_model.h"

#include <algorithm>
#include <set>
#include <string>
#include <utility>

#include "base/containers/flat_map.h"
#include "base/macros.h"
#include "base/metrics/histogram_macros.h"
#include "base/metrics/user_metrics.h"
#include "build/build_config.h"
#include "mumba/app/mumba_command_ids.h"
//#include "chrome/browser/defaults.h"
//#include "chrome/browser/extensions/tab_helper.h"
#include "core/host/ui/tablist/core_tab_helper.h"
#include "core/host/ui/tablist/core_tab_helper_delegate.h"
#include "core/host/ui/tablist/tablist_model_delegate.h"
#include "core/host/ui/tablist/tablist_model_order_controller.h"
#include "core/host/ui/tablist/tab_utils.h"
#include "core/host/workspace/workspace.h"
#include "core/host/themes/theme_service_custom.h"
#include "core/host/application/application_contents.h"
#include "core/host/application/application_contents_observer.h"
#include "core/host/application/application_contents_sizer.h"
//#include "core/common/url_constants.h"
//#include "components/feature_engagement/buildflags.h"
//#include "components/web_modal/web_contents_modal_dialog_manager.h"

//#if BUILDFLAG(ENABLE_DESKTOP_IN_PRODUCT_HELP)
//#include "chrome/browser/feature_engagement/new_tab/new_tab_tracker.h"
//#include "chrome/browser/feature_engagement/new_tab/new_tab_tracker_factory.h"
//#endif

using base::UserMetricsAction;

namespace host {

namespace {

// Returns true if the specified transition is one of the types that cause the
// opener relationships for the tab in which the transition occurred to be
// forgotten. This is generally any navigation that isn't a link click (i.e.
// any navigation that can be considered to be the start of a new task distinct
// from what had previously occurred in that tab).
bool ShouldForgetOpenersForTransition(ui::PageTransition transition) {
  return ui::PageTransitionCoreTypeIs(transition, ui::PAGE_TRANSITION_TYPED) ||
         ui::PageTransitionCoreTypeIs(transition,
                                      ui::PAGE_TRANSITION_AUTO_BOOKMARK) ||
         ui::PageTransitionCoreTypeIs(transition,
                                      ui::PAGE_TRANSITION_GENERATED) ||
         ui::PageTransitionCoreTypeIs(transition,
                                      ui::PAGE_TRANSITION_KEYWORD) ||
         ui::PageTransitionCoreTypeIs(transition,
                                      ui::PAGE_TRANSITION_AUTO_TOPLEVEL);
}

}  // namespace

///////////////////////////////////////////////////////////////////////////////
// ApplicationContentsData

// An object to hold a reference to a ApplicationContents that is in a tabstrip, as
// well as other various properties it has.
class TablistModel::ApplicationContentsData : public ApplicationContentsObserver {
 public:
  ApplicationContentsData(TablistModel* tablist_model, ApplicationContents* a_contents);
  ~ApplicationContentsData() override;

  // Changes the ApplicationContents that this ApplicationContentsData tracks.
  void SetApplicationContents(ApplicationContents* contents);
  ApplicationContents* web_contents() { return contents_; }

  // Create a relationship between this ApplicationContentsData and other
  // ApplicationContentses. Used to identify which ApplicationContents to select next after
  // one is closed.
  ApplicationContents* group() const { return group_; }
  void set_group(ApplicationContents* value) { group_ = value; }
  ApplicationContents* opener() const { return opener_; }
  void set_opener(ApplicationContents* value) { opener_ = value; }

  SkColor color() const { return color_; }
  void set_color(SkColor color) { color_ = color; }

  CustomThemeService* theme_service() const {
    return theme_service_.get();
  }

  // Alters the properties of the ApplicationContents.
  bool reset_group_on_select() const { return reset_group_on_select_; }
  void set_reset_group_on_select(bool value) { reset_group_on_select_ = value; }
  bool pinned() const { return pinned_; }
  void set_pinned(bool value) { pinned_ = value; }
  bool blocked() const { return blocked_; }
  void set_blocked(bool value) { blocked_ = value; }

 private:
  // Make sure that if someone deletes this ApplicationContents out from under us, it
  // is properly removed from the tab strip.
  void ApplicationContentsDestroyed() override;

  // The ApplicationContents being tracked by this ApplicationContentsData. The
  // ApplicationContentsObserver does keep a reference, but when the ApplicationContents is
  // deleted, the ApplicationContentsObserver reference is NULLed and thus inaccessible.
  ApplicationContents* contents_;

  // The TablistModel containing this ApplicationContents.
  TablistModel* tablist_model_;

  // The group is used to model a set of tabs spawned from a single parent
  // tab. This value is preserved for a given tab as long as the tab remains
  // navigated to the link it was initially opened at or some navigation from
  // that page (i.e. if the user types or visits a bookmark or some other
  // navigation within that tab, the group relationship is lost). This
  // property can safely be used to implement features that depend on a
  // logical group of related tabs.
  ApplicationContents* group_ = nullptr;

  // The owner models the same relationship as group, except it is more
  // easily discarded, e.g. when the user switches to a tab not part of the
  // same group. This property is used to determine what tab to select next
  // when one is closed.
  ApplicationContents* opener_ = nullptr;

  // True if our group should be reset the moment selection moves away from
  // this tab. This is the case for tabs opened in the foreground at the end
  // of the TabStrip while viewing another Tab. If these tabs are closed
  // before selection moves elsewhere, their opener is selected. But if
  // selection shifts to _any_ tab (including their opener), the group
  // relationship is reset to avoid confusing close sequencing.
  bool reset_group_on_select_ = false;

  // Is the tab pinned?
  bool pinned_ = false;

  // Is the tab interaction blocked by a modal dialog?
  bool blocked_ = false;

  SkColor color_ = SK_ColorTRANSPARENT;

  std::unique_ptr<CustomThemeService> theme_service_;

  DISALLOW_COPY_AND_ASSIGN(ApplicationContentsData);
};

TablistModel::ApplicationContentsData::ApplicationContentsData(TablistModel* tablist_model,
                                                ApplicationContents* contents)
    : ApplicationContentsObserver(contents),
      contents_(contents),
      tablist_model_(tablist_model),
      theme_service_(new CustomThemeService()) {
  //DLOG(INFO) << "TablistModel::ApplicationContentsData: " << this; 
  theme_service_->Init(tablist_model->workspace());
}

TablistModel::ApplicationContentsData::~ApplicationContentsData() {
  //DLOG(INFO) << "~TablistModel::ApplicationContentsData: " << this; 
}

void TablistModel::ApplicationContentsData::SetApplicationContents(ApplicationContents* contents) {
  contents_ = contents;
  Observe(contents);
}

void TablistModel::ApplicationContentsData::ApplicationContentsDestroyed() {
  //DLOG(INFO) << "TablistModel::ApplicationContentsData::ApplicationContentsDestroyed: " << this;
  DCHECK_EQ(contents_, web_contents());

  // Note that we only detach the contents here, not close it - it's
  // already been closed. We just want to undo our bookkeeping.
  int index = tablist_model_->GetIndexOfApplicationContents(web_contents());
  DCHECK_NE(TablistModel::kNoTab, index);

  // TODO(erikchen): Clean up the internal ownership of TablistModel once we
  // move to a world where there's always explicit ownership of ApplicationContents.
  // https://crbug.com/832879.
  tablist_model_->DetachApplicationContentsAt(index).release();
}

///////////////////////////////////////////////////////////////////////////////
// TablistModel, public:

TablistModel::TablistModel(TablistModelDelegate* delegate, scoped_refptr<Workspace> workspace)
    : delegate_(delegate), workspace_(workspace), weak_factory_(this) {
  DCHECK(delegate_);
  order_controller_.reset(new TablistModelOrderController(this));
}

TablistModel::~TablistModel() {
  contents_data_.clear();
  order_controller_.reset();
}

scoped_refptr<Workspace> TablistModel::workspace() const { 
  return workspace_; 
}

void TablistModel::AddObserver(TablistModelObserver* observer) {
  observers_.AddObserver(observer);
}

void TablistModel::RemoveObserver(TablistModelObserver* observer) {
  observers_.RemoveObserver(observer);
}

bool TablistModel::ContainsIndex(int index) const {
  return index >= 0 && index < count();
}

void TablistModel::AppendApplicationContents(std::unique_ptr<ApplicationContents> contents,
                                      bool foreground) {
  InsertApplicationContentsAt(count(), std::move(contents),
                      foreground ? (ADD_INHERIT_GROUP | ADD_ACTIVE) : ADD_NONE);
}

CustomThemeService* TablistModel::GetThemeServiceForTab(int index) const {
  return contents_data_[index]->theme_service();
}

CustomThemeService* TablistModel::GetThemeServiceForActiveTab() const {
  int index = active_index();
  return contents_data_[index]->theme_service();
}

void TablistModel::InsertApplicationContentsAt(
  int index,
  std::unique_ptr<ApplicationContents> contents,
  int add_types) {
  
  delegate()->WillAddApplicationContents(contents.get());

  bool active = (add_types & ADD_ACTIVE) != 0;
  bool pin = (add_types & ADD_PINNED) != 0;
  index = ConstrainInsertionIndex(index, pin);

  // In tab dragging situations, if the last tab in the window was detached
  // then the user aborted the drag, we will have the |closing_all_| member
  // set (see DetachApplicationContentsAt) which will mess with our mojo here. We need
  // to clear this bit.
  closing_all_ = false;

  // Have to get the active contents before we monkey with the contents
  // otherwise we run into problems when we try to change the active contents
  // since the old contents and the new contents will be the same...
  ApplicationContents* active_contents = GetActiveApplicationContents();
  std::unique_ptr<ApplicationContentsData> data =
      std::make_unique<ApplicationContentsData>(this, contents.get());
  data->set_pinned(pin);
  if ((add_types & ADD_INHERIT_GROUP) && active_contents) {
    if (active) {
      // Forget any existing relationships, we don't want to make things too
      // confusing by having multiple groups active at the same time.
      ForgetAllOpeners();
    }
    // Anything opened by a link we deem to have an opener.
    data->set_group(active_contents);
    data->set_opener(active_contents);
  } else if ((add_types & ADD_INHERIT_OPENER) && active_contents) {
    if (active) {
      // Forget any existing relationships, we don't want to make things too
      // confusing by having multiple groups active at the same time.
      ForgetAllOpeners();
    }
    data->set_opener(active_contents);
  }

  // TODO(gbillock): Ask the modal dialog manager whether the ApplicationContents should
  // be blocked, or just let the modal dialog manager make the blocking call
  // directly and not use this at all.
  //const web_modal::ApplicationContentsModalDialogManager* manager =
  //    web_modal::ApplicationContentsModalDialogManager::FromApplicationContents(contents.get());
  //if (manager)
  //  data->set_blocked(manager->IsDialogActive());

  contents_data_.insert(contents_data_.begin() + index, std::move(data));

  selection_model_.IncrementFrom(index);

  for (auto& observer : observers_)
    observer.TabInsertedAt(this, contents.get(), index, active);

  if (active) {
    ui::ListSelectionModel new_model = selection_model_;
    new_model.SetSelectedIndex(index);
    SetSelection(std::move(new_model), Notify::kDefault);
  }

  // TODO(erikchen): Clean up the internal ownership of TablistModel once we
  // move to a world where there's always explicit ownership of ApplicationContents.
  // https://crbug.com/832879.
  contents.release();
}

std::unique_ptr<ApplicationContents> TablistModel::ReplaceApplicationContentsAt(
    int index,
    std::unique_ptr<ApplicationContents> new_contents) {
  delegate()->WillAddApplicationContents(new_contents.get());

  DCHECK(ContainsIndex(index));
  ApplicationContents* old_contents = GetApplicationContentsAtImpl(index);

  FixOpenersAndGroupsReferencing(index);

  contents_data_[index]->SetApplicationContents(new_contents.get());

  for (auto& observer : observers_)
    observer.TabReplacedAt(this, old_contents, new_contents.get(), index);

  // When the active ApplicationContents is replaced send out a selection notification
  // too. We do this as nearly all observers need to treat a replacement of the
  // selected contents as the selection changing.
  if (active_index() == index) {
    for (auto& observer : observers_) {
      observer.ActiveTabChanged(old_contents, new_contents.get(),
                                active_index(),
                                TablistModelObserver::CHANGE_REASON_REPLACED);
    }
  }

  // TODO(erikchen): Clean up the internal ownership of TablistModel once we
  // move to a world where there's always explicit ownership of ApplicationContents.
  // https://crbug.com/832879.
  new_contents.release();
  return base::WrapUnique(old_contents);
}

std::unique_ptr<ApplicationContents> TablistModel::DetachApplicationContentsAt(
    int index) {
  CHECK(!in_notify_);
  if (contents_data_.empty())
    return nullptr;
  DCHECK(ContainsIndex(index));

  FixOpenersAndGroupsReferencing(index);

  ApplicationContents* removed_contents = GetApplicationContentsAtImpl(index);
  bool was_selected = IsTabSelected(index);
  int next_selected_index = order_controller_->DetermineNewSelectedIndex(index);
  contents_data_.erase(contents_data_.begin() + index);
  if (empty())
    closing_all_ = true;
  for (auto& observer : observers_)
    observer.TabDetachedAt(removed_contents, index);
  if (empty()) {
    selection_model_.Clear();
    // TabDetachedAt() might unregister observers, so send |TabStripEmpty()| in
    // a second pass.
    for (auto& observer : observers_)
      observer.TablistEmpty();
  } else {
    int old_active = active_index();
    selection_model_.DecrementFrom(index);
    ui::ListSelectionModel old_model;
    old_model = selection_model_;
    if (index == old_active) {
      NotifyIfTabDeactivated(removed_contents);
      if (!selection_model_.empty()) {
        // The active tab was removed, but there is still something selected.
        // Move the active and anchor to the first selected index.
        selection_model_.set_active(selection_model_.selected_indices()[0]);
        selection_model_.set_anchor(selection_model_.active());
      } else {
        // The active tab was removed and nothing is selected. Reset the
        // selection and send out notification.
        selection_model_.SetSelectedIndex(next_selected_index);
      }
      NotifyIfActiveTabChanged(removed_contents, Notify::kDefault);
    }

    // Sending notification in case the detached tab was selected. Using
    // NotifyIfActiveOrSelectionChanged() here would not guarantee that a
    // notification is sent even though the tab selection has changed because
    // |old_model| is stored after calling DecrementFrom().
    if (was_selected) {
      for (auto& observer : observers_)
        observer.TabSelectionChanged(this, old_model);
    }
  }
  return base::WrapUnique(removed_contents);
}

void TablistModel::ActivateTabAt(int index, bool user_gesture) {
  DCHECK(ContainsIndex(index));
  ui::ListSelectionModel new_model = selection_model_;
  new_model.SetSelectedIndex(index);
  SetSelection(std::move(new_model),
               user_gesture ? Notify::kUserGesture : Notify::kDefault);
}

void TablistModel::AddTabAtToSelection(int index) {
  DCHECK(ContainsIndex(index));
  ui::ListSelectionModel new_model = selection_model_;
  new_model.AddIndexToSelection(index);
  SetSelection(std::move(new_model), Notify::kDefault);
}

void TablistModel::MoveApplicationContentsAt(int index,
                                      int to_position,
                                      bool select_after_move) {
  DCHECK(ContainsIndex(index));

  // Ensure pinned and non-pinned tabs do not mix.
  const int first_non_pinned_tab = IndexOfFirstNonPinnedTab();
  to_position = IsTabPinned(index)
                    ? std::min(first_non_pinned_tab - 1, to_position)
                    : std::max(first_non_pinned_tab, to_position);
  if (index == to_position)
    return;

  MoveApplicationContentsAtImpl(index, to_position, select_after_move);
}

void TablistModel::MoveSelectedTabsTo(int index) {
  int total_pinned_count = IndexOfFirstNonPinnedTab();
  int selected_pinned_count = 0;
  int selected_count =
      static_cast<int>(selection_model_.selected_indices().size());
  for (int i = 0; i < selected_count &&
                  IsTabPinned(selection_model_.selected_indices()[i]);
       ++i) {
    selected_pinned_count++;
  }

  // To maintain that all pinned tabs occur before non-pinned tabs we move them
  // first.
  if (selected_pinned_count > 0) {
    MoveSelectedTabsToImpl(
        std::min(total_pinned_count - selected_pinned_count, index), 0u,
        selected_pinned_count);
    if (index > total_pinned_count - selected_pinned_count) {
      // We're being told to drag pinned tabs to an invalid location. Adjust the
      // index such that non-pinned tabs end up at a location as though we could
      // move the pinned tabs to index. See description in header for more
      // details.
      index += selected_pinned_count;
    }
  }
  if (selected_pinned_count == selected_count)
    return;

  // Then move the non-pinned tabs.
  MoveSelectedTabsToImpl(std::max(index, total_pinned_count),
                         selected_pinned_count,
                         selected_count - selected_pinned_count);
}

ApplicationContents* TablistModel::GetActiveApplicationContents() const {
  return GetApplicationContentsAt(active_index());
}

ApplicationContents* TablistModel::GetApplicationContentsAt(int index) const {
  if (ContainsIndex(index))
    return GetApplicationContentsAtImpl(index);
  return nullptr;
}

int TablistModel::GetIndexOfApplicationContents(const ApplicationContents* contents) const {
  for (size_t i = 0; i < contents_data_.size(); ++i) {
    if (contents_data_[i]->web_contents() == contents)
      return i;
  }
  return kNoTab;
}

void TablistModel::UpdateApplicationContentsStateAt(int index,
                                             TabChangeType change_type) {
  DCHECK(ContainsIndex(index));

  for (auto& observer : observers_)
    observer.TabChangedAt(GetApplicationContentsAtImpl(index), index, change_type);
}

void TablistModel::SetTabNeedsAttentionAt(int index, bool attention) {
  DCHECK(ContainsIndex(index));

  for (auto& observer : observers_)
    observer.SetTabNeedsAttentionAt(index, attention);
}

void TablistModel::CloseAllTabs() {
  // Set state so that observers can adjust their behavior to suit this
  // specific condition when CloseApplicationContentsAt causes a flurry of
  // Close/Detach/Select notifications to be sent.
  closing_all_ = true;
  std::vector<ApplicationContents*> closing_tabs;
  closing_tabs.reserve(count());
  for (int i = count() - 1; i >= 0; --i)
    closing_tabs.push_back(GetApplicationContentsAt(i));
  InternalCloseTabs(closing_tabs, CLOSE_CREATE_HISTORICAL_TAB);
}

bool TablistModel::CloseApplicationContentsAt(int index, uint32_t close_types) {
  DCHECK(ContainsIndex(index));
  ApplicationContents* contents = GetApplicationContentsAt(index);
  return InternalCloseTabs(base::span<ApplicationContents* const>(&contents, 1),
                           close_types);
}

bool TablistModel::TabsAreLoading() const {
  for (const auto& data : contents_data_) {
    if (data->web_contents()->IsLoading())
      return true;
  }

  return false;
}

ApplicationContents* TablistModel::GetOpenerOfApplicationContentsAt(int index) {
  DCHECK(ContainsIndex(index));
  return contents_data_[index]->opener();
}

void TablistModel::SetOpenerOfApplicationContentsAt(int index, ApplicationContents* opener) {
  DCHECK(ContainsIndex(index));
  // The TablistModel only maintains the references to openers that it itself
  // owns; trying to set an opener to an external ApplicationContents can result in
  // the opener being used after its freed. See crbug.com/698681.
  DCHECK(!opener || GetIndexOfApplicationContents(opener) != kNoTab)
      << "Cannot set opener to a web contents not owned by this tab strip.";
  contents_data_[index]->set_opener(opener);
}

int TablistModel::GetIndexOfLastApplicationContentsOpenedBy(const ApplicationContents* opener,
                                                     int start_index) const {
  DCHECK(opener);
  DCHECK(ContainsIndex(start_index));

  std::set<const ApplicationContents*> opener_and_descendants;
  opener_and_descendants.insert(opener);
  int last_index = kNoTab;

  for (int i = start_index + 1; i < count(); ++i) {
    // Test opened by transitively, i.e. include tabs opened by tabs opened by
    // opener, etc. Stop when we find the first non-descendant.
    if (!opener_and_descendants.count(contents_data_[i]->opener())) {
      // Skip over pinned tabs as new tabs are added after pinned tabs.
      if (contents_data_[i]->pinned())
        continue;
      break;
    }
    opener_and_descendants.insert(contents_data_[i]->web_contents());
    last_index = i;
  }
  return last_index;
}

void TablistModel::TabNavigating(ApplicationContents* contents,
                                  ui::PageTransition transition) {
  if (ShouldForgetOpenersForTransition(transition)) {
    // Don't forget the openers if this tab is a New Tab page opened at the
    // end of the TabStrip (e.g. by pressing Ctrl+T). Give the user one
    // navigation of one of these transition types before resetting the
    // opener relationships (this allows for the use case of opening a new
    // tab to do a quick look-up of something while viewing a tab earlier in
    // the strip). We can make this heuristic more permissive if need be.
    if (!IsNewTabAtEndOfTablist(contents)) {
      // If the user navigates the current tab to another page in any way
      // other than by clicking a link, we want to pro-actively forget all
      // TabStrip opener relationships since we assume they're beginning a
      // different task by reusing the current tab.
      ForgetAllOpeners();
      // In this specific case we also want to reset the group relationship,
      // since it is now technically invalid.
      ForgetGroup(contents);
    }
  }
}

void TablistModel::SetTabBlocked(int index, bool blocked) {
  DCHECK(ContainsIndex(index));
  if (contents_data_[index]->blocked() == blocked)
    return;
  contents_data_[index]->set_blocked(blocked);
  for (auto& observer : observers_)
    observer.TabBlockedStateChanged(contents_data_[index]->web_contents(),
                                    index);
}

void TablistModel::SetTabPinned(int index, bool pinned) {
  DCHECK(ContainsIndex(index));
  if (contents_data_[index]->pinned() == pinned)
    return;

  // The tab's position may have to change as the pinned tab state is changing.
  int non_pinned_tab_index = IndexOfFirstNonPinnedTab();
  contents_data_[index]->set_pinned(pinned);
  if (pinned && index != non_pinned_tab_index) {
    MoveApplicationContentsAtImpl(index, non_pinned_tab_index, false);
    index = non_pinned_tab_index;
  } else if (!pinned && index + 1 != non_pinned_tab_index) {
    MoveApplicationContentsAtImpl(index, non_pinned_tab_index - 1, false);
    index = non_pinned_tab_index - 1;
  }

  for (auto& observer : observers_)
    observer.TabPinnedStateChanged(this, contents_data_[index]->web_contents(),
                                   index);
}

bool TablistModel::IsTabPinned(int index) const {
  DCHECK(ContainsIndex(index));
  return contents_data_[index]->pinned();
}

bool TablistModel::IsTabBlocked(int index) const {
  return contents_data_[index]->blocked();
}

int TablistModel::IndexOfFirstNonPinnedTab() const {
  for (size_t i = 0; i < contents_data_.size(); ++i) {
    if (!IsTabPinned(static_cast<int>(i)))
      return static_cast<int>(i);
  }
  // No pinned tabs.
  return count();
}

void TablistModel::ExtendSelectionTo(int index) {
  DCHECK(ContainsIndex(index));
  ui::ListSelectionModel new_model = selection_model_;
  new_model.SetSelectionFromAnchorTo(index);
  SetSelection(std::move(new_model), Notify::kDefault);
}

void TablistModel::ToggleSelectionAt(int index) {
  DCHECK(ContainsIndex(index));
  ui::ListSelectionModel new_model = selection_model();
  if (selection_model_.IsSelected(index)) {
    if (selection_model_.size() == 1) {
      // One tab must be selected and this tab is currently selected so we can't
      // unselect it.
      return;
    }
    new_model.RemoveIndexFromSelection(index);
    new_model.set_anchor(index);
    if (new_model.active() == index ||
        new_model.active() == ui::ListSelectionModel::kUnselectedIndex)
      new_model.set_active(new_model.selected_indices()[0]);
  } else {
    new_model.AddIndexToSelection(index);
    new_model.set_anchor(index);
    new_model.set_active(index);
  }
  SetSelection(std::move(new_model), Notify::kDefault);
}

void TablistModel::AddSelectionFromAnchorTo(int index) {
  ui::ListSelectionModel new_model = selection_model_;
  new_model.AddSelectionFromAnchorTo(index);
  SetSelection(std::move(new_model), Notify::kDefault);
}

bool TablistModel::IsTabSelected(int index) const {
  DCHECK(ContainsIndex(index));
  return selection_model_.IsSelected(index);
}

void TablistModel::SetSelectionFromModel(ui::ListSelectionModel source) {
  DCHECK_NE(ui::ListSelectionModel::kUnselectedIndex, source.active());
  SetSelection(std::move(source), Notify::kDefault);
}

const ui::ListSelectionModel& TablistModel::selection_model() const {
  return selection_model_;
}

void TablistModel::AddApplicationContents(std::unique_ptr<ApplicationContents> contents,
                                   int index,
                                   ui::PageTransition transition,
                                   int add_types) {
  //DLOG(INFO) << "TablistModel::AddApplicationContents";
  // If the newly-opened tab is part of the same task as the parent tab, we want
  // to inherit the parent's "group" attribute, so that if this tab is then
  // closed we'll jump back to the parent tab.
  bool inherit_group = (add_types & ADD_INHERIT_GROUP) == ADD_INHERIT_GROUP;

  if (ui::PageTransitionTypeIncludingQualifiersIs(transition,
                                                  ui::PAGE_TRANSITION_LINK) &&
      (add_types & ADD_FORCE_INDEX) == 0) {
    // We assume tabs opened via link clicks are part of the same task as their
    // parent.  Note that when |force_index| is true (e.g. when the user
    // drag-and-drops a link to the tab strip), callers aren't really handling
    // link clicks, they just want to score the navigation like a link click in
    // the history backend, so we don't inherit the group in this case.
    index = order_controller_->DetermineInsertionIndex(transition,
                                                       add_types & ADD_ACTIVE);
    inherit_group = true;
  } else {
    // For all other types, respect what was passed to us, normalizing -1s and
    // values that are too large.
    if (index < 0 || index > count())
      index = count();
  }

  if (ui::PageTransitionTypeIncludingQualifiersIs(transition,
                                                  ui::PAGE_TRANSITION_TYPED) &&
      index == count()) {
    // Also, any tab opened at the end of the TabStrip with a "TYPED"
    // transition inherit group as well. This covers the cases where the user
    // creates a New Tab (e.g. Ctrl+T, or clicks the New Tab button), or types
    // in the address bar and presses Alt+Enter. This allows for opening a new
    // Tab to quickly look up something. When this Tab is closed, the old one
    // is re-selected, not the next-adjacent.
    inherit_group = true;
  }
  ApplicationContents* raw_contents = contents.get();
  InsertApplicationContentsAt(index, std::move(contents),
                      add_types | (inherit_group ? ADD_INHERIT_GROUP : 0));
  // Reset the index, just in case insert ended up moving it on us.
  index = GetIndexOfApplicationContents(raw_contents);

  if (inherit_group && ui::PageTransitionTypeIncludingQualifiersIs(
                           transition, ui::PAGE_TRANSITION_TYPED))
    contents_data_[index]->set_reset_group_on_select(true);

  // TODO(sky): figure out why this is here and not in InsertApplicationContentsAt. When
  // here we seem to get failures in startup perf tests.
  // Ensure that the new ApplicationContentsView begins at the same size as the
  // previous ApplicationContentsView if it existed.  Otherwise, the initial WebKit
  // layout will be performed based on a width of 0 pixels, causing a
  // very long, narrow, inaccurate layout.  Because some scripts on pages (as
  // well as WebKit's anchor link location calculation) are run on the
  // initial layout and not recalculated later, we need to ensure the first
  // layout is performed with sane view dimensions even when we're opening a
  // new background tab.
  if (ApplicationContents* old_contents = GetActiveApplicationContents()) {
    if ((add_types & ADD_ACTIVE) == 0) {
      ResizeApplicationContents(raw_contents,
                        gfx::Rect(old_contents->GetContainerBounds().size()));
    }
  }
}

void TablistModel::CloseSelectedTabs() {
  InternalCloseTabs(
      GetApplicationContentsesByIndices(selection_model_.selected_indices()),
      CLOSE_CREATE_HISTORICAL_TAB | CLOSE_USER_GESTURE);
}

void TablistModel::SelectNextTab() {
  SelectRelativeTab(true);
}

void TablistModel::SelectPreviousTab() {
  SelectRelativeTab(false);
}

void TablistModel::SelectLastTab() {
  ActivateTabAt(count() - 1, true);
}

void TablistModel::MoveTabNext() {
  // TODO: this likely needs to be updated for multi-selection.
  int new_index = std::min(active_index() + 1, count() - 1);
  MoveApplicationContentsAt(active_index(), new_index, true);
}

void TablistModel::MoveTabPrevious() {
  // TODO: this likely needs to be updated for multi-selection.
  int new_index = std::max(active_index() - 1, 0);
  MoveApplicationContentsAt(active_index(), new_index, true);
}

// Context menu functions.
bool TablistModel::IsContextMenuCommandEnabled(
    int context_index,
    ContextMenuCommand command_id) const {
  DCHECK(command_id > CommandFirst && command_id < CommandLast);
  switch (command_id) {
    case CommandNewTab:
    case CommandCloseTab:
      return true;

    case CommandReload: {
      std::vector<int> indices = GetIndicesForCommand(context_index);
      for (size_t i = 0; i < indices.size(); ++i) {
        ApplicationContents* tab = GetApplicationContentsAt(indices[i]);
        if (tab) {
          CoreTabHelperDelegate* core_delegate =
              CoreTabHelper::FromApplicationContents(tab)->delegate();
          if (!core_delegate || core_delegate->CanReloadContents(tab))
            return true;
        }
      }
      return false;
    }

    case CommandCloseOtherTabs:
    case CommandCloseTabsToRight:
      return !GetIndicesClosedByCommand(context_index, command_id).empty();

    case CommandDuplicate: {
      std::vector<int> indices = GetIndicesForCommand(context_index);
      for (size_t i = 0; i < indices.size(); ++i) {
        if (delegate()->CanDuplicateContentsAt(indices[i]))
          return true;
      }
      return false;
    }

    case CommandRestoreTab:
      return delegate()->GetRestoreTabType() !=
             TablistModelDelegate::RESTORE_NONE;

    case CommandToggleTabAudioMuted:
    case CommandToggleSiteMuted: {
      //std::vector<int> indices = GetIndicesForCommand(context_index);
      //for (size_t i = 0; i < indices.size(); ++i) {
      //  if (!host::CanToggleAudioMute(GetApplicationContentsAt(indices[i])))
      //    return false;
      //}
      return true;
    }

    case CommandBookmarkAllTabs:
    case CommandTogglePinned:
    case CommandSelectByDomain:
    case CommandSelectByOpener:
      return true;

    default:
      NOTREACHED();
  }
  return false;
}

void TablistModel::ExecuteContextMenuCommand(int context_index,
                                             ContextMenuCommand command_id) {
  DCHECK(command_id > CommandFirst && command_id < CommandLast);
  switch (command_id) {
    case CommandNewTab: {
      base::RecordAction(UserMetricsAction("TabContextMenu_NewTab"));
      UMA_HISTOGRAM_ENUMERATION("Tab.NewTab",
                                TablistModel::NEW_TAB_CONTEXT_MENU,
                                TablistModel::NEW_TAB_ENUM_COUNT);
      delegate()->AddTabAt(GURL(), nullptr, context_index + 1, true, TabStyle::kAPP);
//#if BUILDFLAG(ENABLE_DESKTOP_IN_PRODUCT_HELP)
      //auto* new_tab_tracker =
      //    feature_engagement::NewTabTrackerFactory::GetInstance()
      //        ->GetForProfile(profile_);
      //new_tab_tracker->OnNewTabOpened();
      //new_tab_tracker->CloseBubble();
//#endif
      break;
    }

    case CommandReload: {
      //base::RecordAction(UserMetricsAction("TabContextMenu_Reload"));
      //std::vector<int> indices = GetIndicesForCommand(context_index);
      //for (size_t i = 0; i < indices.size(); ++i) {
      //  ApplicationContents* tab = GetApplicationContentsAt(indices[i]);
      //  if (tab) {
      //    CoreTabHelperDelegate* core_delegate =
      //        CoreTabHelper::FromApplicationContents(tab)->delegate();
      //    if (!core_delegate || core_delegate->CanReloadContents(tab))
      //      tab->GetController().Reload(content::ReloadType::NORMAL, true);
      //  }
      //}
      break;
    }

    case CommandDuplicate: {
      base::RecordAction(UserMetricsAction("TabContextMenu_Duplicate"));
      std::vector<int> indices = GetIndicesForCommand(context_index);
      // Copy the ApplicationContents off as the indices will change as tabs are
      // duplicated.
      std::vector<ApplicationContents*> tabs;
      for (size_t i = 0; i < indices.size(); ++i)
        tabs.push_back(GetApplicationContentsAt(indices[i]));
      for (size_t i = 0; i < tabs.size(); ++i) {
        int index = GetIndexOfApplicationContents(tabs[i]);
        if (index != -1 && delegate()->CanDuplicateContentsAt(index))
          delegate()->DuplicateContentsAt(index);
      }
      break;
    }

    case CommandCloseTab: {
      base::RecordAction(UserMetricsAction("TabContextMenu_CloseTab"));
      InternalCloseTabs(
          GetApplicationContentsesByIndices(GetIndicesForCommand(context_index)),
          CLOSE_CREATE_HISTORICAL_TAB | CLOSE_USER_GESTURE);
      break;
    }

    case CommandCloseOtherTabs: {
      base::RecordAction(UserMetricsAction("TabContextMenu_CloseOtherTabs"));
      InternalCloseTabs(GetApplicationContentsesByIndices(GetIndicesClosedByCommand(
                            context_index, command_id)),
                        CLOSE_CREATE_HISTORICAL_TAB);
      break;
    }

    case CommandCloseTabsToRight: {
      base::RecordAction(UserMetricsAction("TabContextMenu_CloseTabsToRight"));
      InternalCloseTabs(GetApplicationContentsesByIndices(GetIndicesClosedByCommand(
                            context_index, command_id)),
                        CLOSE_CREATE_HISTORICAL_TAB);
      break;
    }

    case CommandRestoreTab: {
      base::RecordAction(UserMetricsAction("TabContextMenu_RestoreTab"));
      delegate()->RestoreTab();
      break;
    }

    case CommandTogglePinned: {
      base::RecordAction(UserMetricsAction("TabContextMenu_TogglePinned"));
      std::vector<int> indices = GetIndicesForCommand(context_index);
      bool pin = WillContextMenuPin(context_index);
      if (pin) {
        for (size_t i = 0; i < indices.size(); ++i)
          SetTabPinned(indices[i], true);
      } else {
        // Unpin from the back so that the order is maintained (unpinning can
        // trigger moving a tab).
        for (size_t i = indices.size(); i > 0; --i)
          SetTabPinned(indices[i - 1], false);
      }
      break;
    }

    case CommandToggleTabAudioMuted: {
      //const std::vector<int>& indices = GetIndicesForCommand(context_index);
      //const bool mute = WillContextMenuMute(context_index);
      //if (mute)
      //  base::RecordAction(UserMetricsAction("TabContextMenu_MuteTabs"));
      //else
      //  base::RecordAction(UserMetricsAction("TabContextMenu_UnmuteTabs"));
      //for (std::vector<int>::const_iterator i = indices.begin();
      //     i != indices.end(); ++i) {
      //  host::SetTabAudioMuted(GetApplicationContentsAt(*i), mute,
      //                         TabMutedReason::CONTEXT_MENU, std::string());
      //}
      break;
    }

    case CommandToggleSiteMuted: {
      //const std::vector<int>& indices = GetIndicesForCommand(context_index);
      //const bool mute = WillContextMenuMuteSites(context_index);
      //if (mute) {
      //  base::RecordAction(
      //      UserMetricsAction("SoundContentSetting.MuteBy.TabStrip"));
      //} else {
      //  base::RecordAction(
      //      UserMetricsAction("SoundContentSetting.UnmuteBy.TabStrip"));
      //}
      //host::SetSitesMuted(*this, indices, mute);
      break;
    }

    case CommandBookmarkAllTabs: {
      //base::RecordAction(UserMetricsAction("TabContextMenu_BookmarkAllTabs"));

      //delegate()->BookmarkAllTabs();
      break;
    }

    case CommandSelectByDomain:
    case CommandSelectByOpener: {
      std::vector<int> indices;
      if (command_id == CommandSelectByDomain)
        GetIndicesWithSameDomain(context_index, &indices);
      else
        GetIndicesWithSameOpener(context_index, &indices);
      ui::ListSelectionModel selection_model;
      selection_model.SetSelectedIndex(context_index);
      for (size_t i = 0; i < indices.size(); ++i)
        selection_model.AddIndexToSelection(indices[i]);
      SetSelectionFromModel(std::move(selection_model));
      break;
    }

    default:
      NOTREACHED();
  }
}

std::vector<int> TablistModel::GetIndicesClosedByCommand(
    int index,
    ContextMenuCommand id) const {
  DCHECK(ContainsIndex(index));
  DCHECK(id == CommandCloseTabsToRight || id == CommandCloseOtherTabs);
  bool is_selected = IsTabSelected(index);
  int last_unclosed_tab = -1;
  if (id == CommandCloseTabsToRight) {
    last_unclosed_tab =
        is_selected ? selection_model_.selected_indices().back() : index;
  }

  // NOTE: callers expect the vector to be sorted in descending order.
  std::vector<int> indices;
  for (int i = count() - 1; i > last_unclosed_tab; --i) {
    if (i != index && !IsTabPinned(i) && (!is_selected || !IsTabSelected(i)))
      indices.push_back(i);
  }
  return indices;
}

bool TablistModel::WillContextMenuMute(int index) {
  //std::vector<int> indices = GetIndicesForCommand(index);
  return false;//!chrome::AreAllTabsMuted(*this, indices);
}

bool TablistModel::WillContextMenuMuteSites(int index) {
  return false;//!chrome::AreAllSitesMuted(*this, GetIndicesForCommand(index));
}

bool TablistModel::WillContextMenuPin(int index) {
  std::vector<int> indices = GetIndicesForCommand(index);
  // If all tabs are pinned, then we unpin, otherwise we pin.
  bool all_pinned = true;
  for (size_t i = 0; i < indices.size() && all_pinned; ++i)
    all_pinned = IsTabPinned(indices[i]);
  return !all_pinned;
}

// static
bool TablistModel::ContextMenuCommandToDockCommand(int cmd_id,
                                                  int* browser_cmd) {
  switch (cmd_id) {
    case CommandNewTab:
      *browser_cmd = IDC_NEW_TAB;
      break;
    case CommandReload:
      *browser_cmd = IDC_RELOAD;
      break;
    case CommandDuplicate:
      *browser_cmd = IDC_DUPLICATE_TAB;
      break;
    case CommandCloseTab:
      *browser_cmd = IDC_CLOSE_TAB;
      break;
    case CommandRestoreTab:
      *browser_cmd = IDC_RESTORE_TAB;
      break;
    case CommandBookmarkAllTabs:
      *browser_cmd = IDC_BOOKMARK_ALL_TABS;
      break;
    default:
      *browser_cmd = 0;
      return false;
  }

  return true;
}

int TablistModel::GetIndexOfNextApplicationContentsOpenedBy(const ApplicationContents* opener,
                                                     int start_index,
                                                     bool use_group) const {
  DCHECK(opener);
  DCHECK(ContainsIndex(start_index));

  // Check tabs after start_index first.
  for (int i = start_index + 1; i < count(); ++i) {
    if (OpenerMatches(contents_data_[i], opener, use_group))
      return i;
  }
  // Then check tabs before start_index, iterating backwards.
  for (int i = start_index - 1; i >= 0; --i) {
    if (OpenerMatches(contents_data_[i], opener, use_group))
      return i;
  }
  return kNoTab;
}

void TablistModel::ForgetAllOpeners() {
  // Forget all opener memories so we don't do anything weird with tab
  // re-selection ordering.
  for (const auto& data : contents_data_)
    data->set_opener(nullptr);
}

void TablistModel::ForgetGroup(ApplicationContents* contents) {
  int index = GetIndexOfApplicationContents(contents);
  DCHECK(ContainsIndex(index));
  contents_data_[index]->set_group(nullptr);
  contents_data_[index]->set_opener(nullptr);
}

bool TablistModel::ShouldResetGroupOnSelect(ApplicationContents* contents) const {
  int index = GetIndexOfApplicationContents(contents);
  DCHECK(ContainsIndex(index));
  return contents_data_[index]->reset_group_on_select();
}

///////////////////////////////////////////////////////////////////////////////
// TablistModel, private:

bool TablistModel::ContainsApplicationContents(ApplicationContents* contents) {
  return GetIndexOfApplicationContents(contents) != kNoTab;
}

void TablistModel::OnWillDeleteApplicationContents(ApplicationContents* contents,
                                            uint32_t close_types) {
  //DLOG(INFO) << "TablistModel::OnWillDeleteApplicationContents";
  const int index = GetIndexOfApplicationContents(contents);
  DCHECK_NE(kNoTab, index);

  for (auto& observer : observers_)
    observer.TabClosingAt(this, contents, index);

  // Ask the delegate to save an entry for this tab in the historical tab
  // database if applicable.
  //if ((close_types & CLOSE_CREATE_HISTORICAL_TAB) != 0)
  //  delegate_->CreateHistoricalTab(contents);
}

bool TablistModel::RunUnloadListenerBeforeClosing(
    ApplicationContents* contents) {
  return delegate_->RunUnloadListenerBeforeClosing(contents);
}

bool TablistModel::ShouldRunUnloadListenerBeforeClosing(
    ApplicationContents* contents) {
  return delegate_->ShouldRunUnloadListenerBeforeClosing(contents);
}

int TablistModel::ConstrainInsertionIndex(int index, bool pinned_tab) {
  return pinned_tab
             ? std::min(std::max(0, index), IndexOfFirstNonPinnedTab())
             : std::min(count(), std::max(index, IndexOfFirstNonPinnedTab()));
}

std::vector<ApplicationContents*> TablistModel::GetApplicationContentsFromIndices(
    const std::vector<int>& indices) const {
  std::vector<ApplicationContents*> contents;
  for (size_t i = 0; i < indices.size(); ++i)
    contents.push_back(GetApplicationContentsAtImpl(indices[i]));
  return contents;
}

void TablistModel::GetIndicesWithSameDomain(int index,
                                             std::vector<int>* indices) {
  std::string domain = GetApplicationContentsAt(index)->GetURL().host();
  if (domain.empty())
    return;
  for (int i = 0; i < count(); ++i) {
    if (i == index)
      continue;
    if (GetApplicationContentsAt(i)->GetURL().host_piece() == domain)
      indices->push_back(i);
  }
}

void TablistModel::GetIndicesWithSameOpener(int index,
                                             std::vector<int>* indices) {
  ApplicationContents* opener = contents_data_[index]->group();
  if (!opener) {
    // If there is no group, find all tabs with the selected tab as the opener.
    opener = GetApplicationContentsAt(index);
    if (!opener)
      return;
  }
  for (int i = 0; i < count(); ++i) {
    if (i == index)
      continue;
    if (contents_data_[i]->group() == opener ||
        GetApplicationContentsAtImpl(i) == opener) {
      indices->push_back(i);
    }
  }
}

std::vector<int> TablistModel::GetIndicesForCommand(int index) const {
  if (!IsTabSelected(index)) {
    std::vector<int> indices;
    indices.push_back(index);
    return indices;
  }
  return selection_model_.selected_indices();
}

bool TablistModel::IsNewTabAtEndOfTablist(ApplicationContents* contents) const {
  //const GURL& url = contents->GetURL();
  return false;//url.SchemeIs(content::kChromeUIScheme) &&
         //url.host_piece() == chrome::kChromeUINewTabHost &&
         //contents == GetApplicationContentsAtImpl(count() - 1) &&
         //contents->GetController().GetEntryCount() == 1;
}

std::vector<ApplicationContents*> TablistModel::GetApplicationContentsesByIndices(
    const std::vector<int>& indices) {
  std::vector<ApplicationContents*> items;
  items.reserve(indices.size());
  for (int index : indices)
    items.push_back(GetApplicationContentsAtImpl(index));
  return items;
}

bool TablistModel::InternalCloseTabs(
    base::span<ApplicationContents* const> items,
    uint32_t close_types) {
    
  if (items.empty()) {
    return true;
  }

  const bool closing_all = static_cast<int>(items.size()) == count();
  base::WeakPtr<TablistModel> ref = weak_factory_.GetWeakPtr();
  if (closing_all) {
    for (auto& observer : observers_) {
      observer.WillCloseAllTabs();
    }
  }
  const bool closed_all = CloseApplicationContentses(this, items, close_types);
  if (!ref) {
    return closed_all;
  }
  if (closing_all && !closed_all) {
    for (auto& observer : observers_) {
      observer.CloseAllTabsCanceled();
    }
  }

  return closed_all;
}

ApplicationContents* TablistModel::GetApplicationContentsAtImpl(int index) const {
  CHECK(ContainsIndex(index))
      << "Failed to find: " << index << " in: " << count() << " entries.";
  return contents_data_[index]->web_contents();
}

void TablistModel::NotifyIfTabDeactivated(ApplicationContents* contents) {
  if (contents) {
    for (auto& observer : observers_)
      observer.TabDeactivated(contents);
  }
}

void TablistModel::NotifyIfActiveTabChanged(ApplicationContents* old_contents,
                                             Notify notify_types) {
  ApplicationContents* new_contents = GetApplicationContentsAtImpl(active_index());
  if (old_contents == new_contents)
    return;

  int reason = notify_types == Notify::kUserGesture
                   ? TablistModelObserver::CHANGE_REASON_USER_GESTURE
                   : TablistModelObserver::CHANGE_REASON_NONE;
  CHECK(!in_notify_);
  in_notify_ = true;
  for (auto& observer : observers_) {
    observer.ActiveTabChanged(old_contents, new_contents, active_index(),
                              reason);
  }
  in_notify_ = false;
}

void TablistModel::NotifyIfActiveOrSelectionChanged(
    ApplicationContents* old_contents,
    Notify notify_types,
    const ui::ListSelectionModel& old_model) {
  NotifyIfActiveTabChanged(old_contents, notify_types);

  if (selection_model() != old_model) {
    for (auto& observer : observers_)
      observer.TabSelectionChanged(this, old_model);
  }
}

void TablistModel::NotifyTablistColorChanged(SkColor color, int tab_index) {
  for (auto& observer : observers_) {
    observer.TablistColorChanged(this, color, tab_index);
  }
}

void TablistModel::SetSelection(ui::ListSelectionModel new_model,
                                 Notify notify_types) {
  ApplicationContents* old_contents = GetActiveApplicationContents();
  ui::ListSelectionModel old_model;
  old_model = selection_model_;
  if (new_model.active() != selection_model_.active())
    NotifyIfTabDeactivated(old_contents);
  selection_model_ = new_model;
  NotifyIfActiveOrSelectionChanged(old_contents, notify_types, old_model);
}

void TablistModel::SelectRelativeTab(bool next) {
  // This may happen during automated testing or if a user somehow buffers
  // many key accelerators.
  if (contents_data_.empty())
    return;

  int index = active_index();
  int delta = next ? 1 : -1;
  index = (index + count() + delta) % count();
  ActivateTabAt(index, true);
}

void TablistModel::MoveApplicationContentsAtImpl(int index,
                                          int to_position,
                                          bool select_after_move) {
  FixOpenersAndGroupsReferencing(index);

  std::unique_ptr<ApplicationContentsData> moved_data =
      std::move(contents_data_[index]);
  ApplicationContents* web_contents = moved_data->web_contents();
  contents_data_.erase(contents_data_.begin() + index);
  contents_data_.insert(contents_data_.begin() + to_position,
                        std::move(moved_data));

  selection_model_.Move(index, to_position, 1);
  if (!selection_model_.IsSelected(to_position) && select_after_move) {
    // TODO(sky): why doesn't this code notify observers?
    selection_model_.SetSelectedIndex(to_position);
  }

  for (auto& observer : observers_)
    observer.TabMoved(web_contents, index, to_position);
}

SkColor TablistModel::tablist_color() const {
  int index = active_index();
  return contents_data_[index]->color();
}

SkColor TablistModel::tab_color(int index) const {
  return contents_data_[index]->color();
}

void TablistModel::SetTablistThemeColor(SkColor color, int tab_index) {
  contents_data_[tab_index]->set_color(color);
  NotifyTablistColorChanged(color, tab_index);
}

void TablistModel::MoveSelectedTabsToImpl(int index,
                                           size_t start,
                                           size_t length) {
  DCHECK(start < selection_model_.selected_indices().size() &&
         start + length <= selection_model_.selected_indices().size());
  size_t end = start + length;
  int count_before_index = 0;
  for (size_t i = start; i < end && selection_model_.selected_indices()[i] <
                                        index + count_before_index;
       ++i) {
    count_before_index++;
  }

  // First move those before index. Any tabs before index end up moving in the
  // selection model so we use start each time through.
  int target_index = index + count_before_index;
  size_t tab_index = start;
  while (tab_index < end &&
         selection_model_.selected_indices()[start] < index) {
    MoveApplicationContentsAt(selection_model_.selected_indices()[start],
                      target_index - 1, false);
    tab_index++;
  }

  // Then move those after the index. These don't result in reordering the
  // selection.
  while (tab_index < end) {
    if (selection_model_.selected_indices()[tab_index] != target_index) {
      MoveApplicationContentsAt(selection_model_.selected_indices()[tab_index],
                        target_index, false);
    }
    tab_index++;
    target_index++;
  }
}

// static
bool TablistModel::OpenerMatches(const std::unique_ptr<ApplicationContentsData>& data,
                                  const ApplicationContents* opener,
                                  bool use_group) {
  return data->opener() == opener || (use_group && data->group() == opener);
}

void TablistModel::FixOpenersAndGroupsReferencing(int index) {
  ApplicationContents* old_contents = GetApplicationContentsAtImpl(index);
  for (auto& data : contents_data_) {
    if (data->group() == old_contents)
      data->set_group(contents_data_[index]->group());
    if (data->opener() == old_contents)
      data->set_opener(contents_data_[index]->opener());
  }
}

}
