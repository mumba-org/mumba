// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/ui/dock.h"

#include "core/host/application/application_contents_observer.h"
#include "core/host/application/application_contents.h"
#include "core/host/ui/picture_in_picture_window_controller.h"
#include "core/host/ui/tablist/dock_tablist.h"
#include "core/host/ui/tablist/dock_tablist_model_delegate.h"
#include "core/host/ui/tablist/core_tab_helper.h"
#include "core/host/ui/tablist/sad_tab_helper.h"
#include "core/host/ui/exclusive_access/fullscreen_controller.h"
#include "core/host/ui/exclusive_access/mouse_lock_controller.h"
#include "core/host/ui/dock_command_controller.h"
#include "core/host/ui/dock_commands.h"
#include "core/host/ui/dock_window.h"
#include "core/host/ui/dock_list.h"
#include "core/host/ui/dock_finder.h"
#include "core/host/workspace/workspace.h"
#include "core/host/application/domain.h"
#include "core/host/application/application.h"
#include "core/host/favicon/favicon_utils.h"
#include "core/host/media/webrtc/media_capture_devices_dispatcher.h"
#include "core/host/ui/tab_ui_helper.h"
#include "core/host/notification_service.h"
#include "core/host/notification_types.h"
#include "core/host/notification_service_impl.h"
#include "components/zoom/zoom_controller.h"

#if defined(OS_WIN)
#ifdef CreateWindow
#undef CreateWindow
#endif
#endif

namespace host {

namespace {

const int kUIUpdateCoalescingTimeMS = 200;

class ScopedDockShower {
 public:
  explicit ScopedDockShower(NavigateParams* params) : params_(params) {}
  ~ScopedDockShower() {
    if (params_->window_action == NavigateParams::SHOW_WINDOW_INACTIVE) {
      params_->dock->window()->ShowInactive();
    } else if (params_->window_action == NavigateParams::SHOW_WINDOW) {
      DockWindow* window = params_->dock->window();
      window->Show();
      // If a user gesture opened a popup window, focus the contents.
      if (params_->user_gesture &&
          params_->disposition == WindowOpenDisposition::NEW_POPUP &&
          params_->target_contents) {
        params_->target_contents->Focus();
        window->Activate();
      }
      // NOTE: i've changed here.. 
      //window->Activate();
    }
  }

 private:
  NavigateParams* params_;
  DISALLOW_COPY_AND_ASSIGN(ScopedDockShower);
};

class ScopedTargetContentsOwner {
 public:
  explicit ScopedTargetContentsOwner(NavigateParams* params)
      : params_(params) {}
  ~ScopedTargetContentsOwner() {
    if (target_contents_owner_.get())
      params_->target_contents = NULL;
  }

  // Assumes ownership of |params_|' target_contents until ReleaseOwnership
  // is called.
  void TakeOwnership() {
    target_contents_owner_.reset(params_->target_contents);
  }

  // Relinquishes ownership of |params_|' target_contents.
  ApplicationContents* ReleaseOwnership() {
    return target_contents_owner_.release();
  }

 private:
  NavigateParams* params_;
  std::unique_ptr<ApplicationContents> target_contents_owner_;
  DISALLOW_COPY_AND_ASSIGN(ScopedTargetContentsOwner);
};

void ParseApplicationAndPageName(const GURL& url, std::string* app_name, std::string* page_name) {
  std::string full_url = url.spec();
  const url::Parsed& parsed = url.parsed_for_possibly_invalid_spec();
  int query_pos = parsed.CountCharactersBefore(url::Parsed::QUERY, true);
  full_url = query_pos > 0 ? full_url.substr(0, query_pos) : full_url;
  size_t resource_start = full_url.find("://");
  full_url = full_url.substr(resource_start + 3);
  // try to find the first "/"
  size_t resource_end = full_url.find("/");
  *app_name = url.scheme();
  *page_name = resource_end == std::string::npos ? full_url : full_url.substr(0, resource_end);
}

DockWindow* CreateWindow(Dock* dock, bool user_gesture, bool tabs_hidden) {
  return DockWindow::CreateDockWindow(dock, user_gesture, tabs_hidden);
}

Dock* GetOrCreateDock(
  const GURL& url, 
  const Dock::CreateParams& params) {
  Dock* dock = host::FindTabbedDock(params.workspace, url, false);
  return dock ? dock
                 : new Dock(params);
}

int GetIndexOfExistingTab(Dock* dock, const NavigateParams& params) {
  if (params.disposition != WindowOpenDisposition::SINGLETON_TAB &&
      params.disposition != WindowOpenDisposition::SWITCH_TO_TAB)
    return -1;

  // If there are several matches: prefer the active tab by starting there.
  int start_index = std::max(0, dock->tablist_model()->active_index());
  int tab_count = dock->tablist_model()->count();
  for (int i = 0; i < tab_count; ++i) {
    int tab_index = (start_index + i) % tab_count;
    ApplicationContents* tab =
        dock->tablist_model()->GetApplicationContentsAt(tab_index);
    GURL tab_url = tab->GetVisibleURL();
    // does this works as its supposed to?
    if (tab_url == params.url) {
      return tab_index;
    }
  }

  return -1;
}

std::pair<Dock*, int> GetDockAndTabForDisposition(
    const NavigateParams& params) {
  scoped_refptr<Workspace> workspace = params.initiating_workspace;
  switch (params.disposition) {
    case WindowOpenDisposition::SWITCH_TO_TAB: {
      for (auto dock_it = DockList::GetInstance()->begin_last_active();
           dock_it != DockList::GetInstance()->end_last_active();
           ++dock_it) {
        Dock* dock = *dock_it;
        int index = GetIndexOfExistingTab(params.dock, params);
        if (index >= 0)
          return {dock, index};
        
      }
    }
      break;
    case WindowOpenDisposition::CURRENT_TAB:
      return {params.dock, -1};
      break;
    case WindowOpenDisposition::SINGLETON_TAB: {
      int index = GetIndexOfExistingTab(params.dock, params);
      if (index >= 0)
        return {params.dock, index};
      }
      FALLTHROUGH;
    case WindowOpenDisposition::NEW_FOREGROUND_TAB:
    case WindowOpenDisposition::NEW_BACKGROUND_TAB:
      if (params.dock)
        return {params.dock, -1};
      // Find a compatible window and re-execute this command in it. Otherwise
      // re-run with NEW_WINDOW.
      return {GetOrCreateDock(params.url, Dock::CreateParams(Dock::TYPE_POPUP, workspace, params.url, gfx::Rect(800, 600), ui::SHOW_STATE_MAXIMIZED, params.user_gesture)), -1};
    case WindowOpenDisposition::NEW_POPUP: {
      std::string app_name;
      std::string page_name;
      ParseApplicationAndPageName(params.url, &app_name, &page_name);
      return {new Dock(Dock::CreateParams::CreateForApp(
                  app_name, page_name, params.trusted_source, params.window_bounds,
                  workspace, params.user_gesture)),
              -1};
    }
      break;
    case WindowOpenDisposition::NEW_WINDOW:
      return {new Dock(Dock::CreateParams(workspace, params.url, params.user_gesture)),
              -1};
      break;
    case WindowOpenDisposition::SAVE_TO_DISK:
    case WindowOpenDisposition::IGNORE_ACTION:
      return {nullptr, -1};
     break;
    default:
      NOTREACHED();
  }
  return {nullptr, -1};
}

bool SwapInPrerender(const GURL& url, NavigateParams* params) {
  DLOG(INFO) << "SwapInPrerender: not implemented";
  return false;
}

ApplicationContents* CreateTargetContents(Application* app,
                                          const std::string& page_name,
                                          const NavigateParams& params,
                                          const GURL& url) {
  // Always create the new WebContents in a new SiteInstance (and therefore a
  // new BrowsingInstance), *unless* there's a |params.opener|.
  //
  // Note that the SiteInstance below is only for the "initial" placement of the
  // new WebContents (i.e. if subsequent navigation [including the initial
  // navigation] triggers a cross-process transfer, then the opener and new
  // contents can end up in separate processes).  This is fine, because even if
  // subsequent navigation is cross-process (i.e. cross-SiteInstance), then it
  // will stay in the same BrowsingInstance (creating frame proxies as needed)
  // preserving the requested opener relationship along the way.
  
  ApplicationContents::CreateParams create_params;
  scoped_refptr<Workspace> workspace = params.dock->workspace();
  create_params.workspace = workspace;
  create_params.initialize_application = true;
  create_params.url = url;
  create_params.application = app;
  create_params.page_name = page_name;
  create_params.url_resolver = workspace->route_resolver();
  create_params.parent = app ? app->domain() : nullptr;
  DCHECK(create_params.parent);
  if (params.opener) {
    //create_params.opener_render_frame_id = params.opener->GetRoutingID();
    create_params.opener_application_process_id =
        params.opener->GetProcess()->GetID();
  }
  if (params.source_contents) {
    create_params.initial_size =
        params.source_contents->GetContainerBounds().size();
    create_params.created_with_opener = params.created_with_opener;
  }
  if (params.disposition == WindowOpenDisposition::NEW_BACKGROUND_TAB)
    create_params.initially_hidden = true;

#if defined(USE_AURA)
  if (params.dock->window() &&
      params.dock->window()->GetNativeWindow()) {
    create_params.context =
        params.dock->window()->GetNativeWindow();
  }
#endif

  ApplicationContents* target_contents = ApplicationContents::Create(create_params);
  return target_contents;
}


}

Dock::CreateParams::CreateParams(scoped_refptr<Workspace> workspace, const GURL& url, bool user_gesture)
    : CreateParams(TYPE_POPUP, workspace, url, user_gesture) {}

Dock::CreateParams::CreateParams(Type type,
                                 scoped_refptr<Workspace> workspace,
                                 const GURL& url,
                                 bool user_gesture)
    : type(type), workspace(workspace), scheme(url.scheme()), user_gesture(user_gesture) {
      ParseApplicationAndPageName(url, &app_name, &page_name);
    }

Dock::CreateParams::CreateParams(Type type, scoped_refptr<Workspace> workspace, const GURL& url, const gfx::Rect& window_bounds, ui::WindowShowState show_state, bool user_gesture):
  type(type), workspace(workspace), trusted_source(true), is_grouped_by_app(type == TYPE_POPUP ? false : true), initial_bounds(window_bounds), scheme(url.scheme()),  initial_show_state(show_state), tabs_hidden(type == TYPE_POPUP ? true : false), user_gesture(user_gesture) {
    ParseApplicationAndPageName(url, &app_name, &page_name);
  }


Dock::CreateParams::CreateParams(const CreateParams& other) = default;


// static 
Dock* Dock::GetOrCreate(
  const GURL& url, 
  const CreateParams& params) {
    return GetOrCreateDock(url, params);
}

// static
Dock::CreateParams Dock::CreateParams::CreateForApp(
    const std::string& app_name,
    const std::string& page_name,
    bool trusted_source,
    const gfx::Rect& window_bounds,
    scoped_refptr<Workspace> workspace,
    bool user_gesture) {
  DCHECK(!app_name.empty());

  CreateParams params(TYPE_POPUP, workspace, GURL(), user_gesture);
  //CreateParams params(TYPE_TABBED, workspace, GURL(), user_gesture);
  params.app_name = app_name;
  params.scheme = app_name;
  params.page_name = page_name;
  params.is_grouped_by_app = true;
  params.trusted_source = trusted_source;
  params.initial_bounds = window_bounds;

  return params;
}

////////////////////////////////////////////////////////////////////////////////
// Dock, InterstitialObserver:

class Dock::InterstitialObserver : public ApplicationContentsObserver {
 public:
  InterstitialObserver(Dock* app, ApplicationContents* app_contents)
      : ApplicationContentsObserver(app_contents) {//,
        //app_(app) {
   
  }

  ~InterstitialObserver() override {
    //DLOG(INFO) << "~DockCommandController::InterstitialObserver: " << this;
  }

  void DidAttachInterstitialPage() override {
    //app_->UpdateBookmarkBarState(BOOKMARK_BAR_STATE_CHANGE_TAB_STATE);
  }

  void DidDetachInterstitialPage() override {
    //app_->UpdateBookmarkBarState(BOOKMARK_BAR_STATE_CHANGE_TAB_STATE);
  }

 private:
  //Dock* app_;

  DISALLOW_COPY_AND_ASSIGN(InterstitialObserver);
};

Dock::Dock(const Dock::CreateParams& params):
  workspace_(params.workspace),
  window_(params.window),
  id_(base::UUID::generate()),
  app_name_(params.app_name),
  page_name_(params.page_name),
  override_bounds_(params.initial_bounds),
  initial_show_state_(params.initial_show_state),
  initial_workspace_(params.initial_workspace),
  tablist_model_delegate_(new DockTablistModelDelegate(this)),
  tablist_model_(
      std::make_unique<TablistModel>(tablist_model_delegate_.get(),
                                     params.workspace)),
  type_(params.type),
  window_has_shown_(false),
  is_grouped_by_app_(params.is_grouped_by_app),
  scheme_(params.scheme),
  command_controller_(new DockCommandController(this)),
  dock_updater_factory_(this),
  weak_factory_(this)
  {

  Init(params);
}

Dock::~Dock() {
  registrar_.RemoveAll();
  
  // The tablist should not have any tabs at this point.
  DCHECK(tablist_model_->empty());
  tablist_model_->RemoveObserver(this);
  
  command_controller_.reset();
  DockList::RemoveDock(this);
}

void Dock::Init(const Dock::CreateParams& params) {
  //registrar_.Add(this, NOTIFICATION_APPLICATION_CONTENT_SETTINGS_CHANGED,
  //               NotificationService::AllSources());

  tablist_model_->AddObserver(this);

  window_ = params.window ? params.window
                          : CreateWindow(this, params.user_gesture, params.tabs_hidden);

  // we should already be added to the ApplicationManager
  // so this shouldnt be needed
  exclusive_access_manager_.reset(
    new ExclusiveAccessManager(window_->GetExclusiveAccessContext()));

  DockList::AddDock(this);
}

scoped_refptr<Workspace> Dock::workspace() const {
  return workspace_;
}

scoped_refptr<net::IOBufferWithSize> Dock::Serialize() const {
  return scoped_refptr<net::IOBufferWithSize>();
}

void Dock::OnWindowClosing() {
  //if (!ShouldCloseWindow())
  //  return;

  // Application should shutdown on last window close if the user is explicitly
  // trying to quit, or if there is nothing keeping the browser alive (such as
  // AppController on the Mac, or BackgroundContentsService for background
  // pages).
  //bool should_quit_if_last_browser =
  //    browser_shutdown::IsTryingToQuit() ||
  //    KeepAliveRegistry::GetInstance()->IsKeepingAliveOnlyByBrowserOrigin();

  //if (should_quit_if_last_browser && ShouldStartShutdown())
  //  browser_shutdown::OnShutdownStarting(browser_shutdown::WINDOW_CLOSE);
  
  DockList::NotifyDockCloseStarted(this);
  tablist_model_->CloseAllTabs();
}

void Dock::TabInsertedAt(TablistModel* tablist_model,
                         ApplicationContents* contents,
                         int index,
                         bool foreground) {
  SetAsDelegate(contents, true);

  //SessionTabHelper::FromWebContents(contents)->SetWindowID(session_id());

  NotificationService::current()->Notify(
      NOTIFICATION_TAB_PARENTED,
      Source<ApplicationContents>(contents),
      NotificationService::NoDetails());

  //SyncHistoryWithTabs(index);

  // Make sure the loading state is updated correctly, otherwise the throbber
  // won't start if the page is loading. Note that we don't want to
  // ScheduleUIUpdate() because the tab may not have been inserted in the UI
  // yet if this function is called before TabStripModel::TabInsertedAt().
  UpdateWindowForLoadingStateChanged(contents, true);

  interstitial_observers_.push_back(new InterstitialObserver(this, contents));

  // SessionService* session_service =
  //     SessionServiceFactory::GetForProfile(profile_);
  // if (session_service) {
  //   session_service->TabInserted(contents);
  //   int new_active_index = tab_strip_model_->active_index();
  //   if (index < new_active_index)
  //     session_service->SetSelectedTabInWindow(session_id(),
  //                                             new_active_index);
  // }
}

void Dock::TabClosingAt(TablistModel* tablist_model,
                        ApplicationContents* contents,
                        int index) {
  exclusive_access_manager_->OnTabClosing(contents);
  //SessionService* session_service =
  //    SessionServiceFactory::GetForProfile(profile_);
  //if (session_service)
  //  session_service->TabClosing(contents);
  NotificationService::current()->Notify(
      NOTIFICATION_TAB_CLOSING,
      //Source<NavigationController>(&contents->GetController()),
      Source<ApplicationContents>(contents),
      NotificationService::NoDetails());

  // Sever the WebContents' connection back to us.
  SetAsDelegate(contents, false);
}

void Dock::TabDetachedAt(ApplicationContents* contents, int index) {
  //int old_active_index = tablist_model_->active_index();
  //if (index < old_active_index && !tablist_model_->closing_all()) {
  //  SessionService* session_service =
  //      SessionServiceFactory::GetForProfileIfExisting(profile_);
  //  if (session_service)
  //    session_service->SetSelectedTabInWindow(session_id(),
  //                                            old_active_index - 1);
  //}
  TabDetachedAtImpl(contents, index, DETACH_TYPE_DETACH);
}

void Dock::TabDeactivated(ApplicationContents* contents) {
  exclusive_access_manager_->OnTabDeactivated(contents);
  //SearchTabHelper::FromWebContents(contents)->OnTabDeactivated();

  // Save what the user's currently typing, so it can be restored when we
  // switch back to this tab.
  //window_->GetLocationBar()->SaveStateToContents(contents);
}

void Dock::ActiveTabChanged(ApplicationContents* old_contents,
                            ApplicationContents* new_contents,
                            int index,
                            int reason) {
  //SadTabHelper* old_tab_helper = nullptr;
  SadTabHelper* new_tab_helper = nullptr;
  // Mac correctly sets the initial background color of new tabs to the theme
  // background color, so it does not need this block of code. Aura should
  // implement this as well.
  // https://crbug.com/719230
//#if !defined(OS_MACOSX)
  // Copies the background color from an old WebContents to a new one that
  // replaces it on the screen. This allows the new WebContents to use the
  // old one's background color as the starting background color, before having
  // loaded any contents. As a result, we avoid flashing white when moving to
  // a new tab. (There is also code in RenderFrameHostManager to do something
  // similar for intra-tab navigations.)
  // if (old_contents && new_contents) {
  //   // While GetMainFrame() is guaranteed to return non-null, GetView() is not,
  //   // e.g. between WebContents creation and creation of the
  //   // RenderWidgetHostView.
  //   //ApplicationWindowHostView* old_view = old_contents->GetMainFrame()->GetView();
  //   //ApplicationWindowHostView* new_view = new_contents->GetMainFrame()->GetView();
  //   ApplicationWindowHostView* old_view = nullptr;
  //   ApplicationWindowHostView* new_view = nullptr;
  //   old_tab_helper = SadTabHelper::FromApplicationContents(old_contents);
  //   new_tab_helper = SadTabHelper::FromApplicationContents(new_contents);
  //   if (old_tab_helper && old_tab_helper->sad_tab() == nullptr) { 
  //     old_view = old_contents->GetApplicationWindowHostView();//window()->GetView();
  //   }
  //   if (new_tab_helper && new_tab_helper->sad_tab() == nullptr) { 
  //     new_view = new_contents->GetApplicationWindowHostView();//window()->GetView();
  //   }
  //   if (old_view && new_view)
  //     new_view->SetBackgroundColor(*old_view->GetBackgroundColor());
  // }
//#endif

  //base::RecordAction(UserMetricsAction("ActiveTabChanged"));

  // Update the bookmark state, since the BrowserWindow may query it during
  // OnActiveTabChanged() below.
  //UpdateBookmarkBarState(BOOKMARK_BAR_STATE_CHANGE_TAB_SWITCH);

  // Let the BrowserWindow do its handling.  On e.g. views this changes the
  // focused object, which should happen before we update the toolbar below,
  // since the omnibox expects the correct element to already be focused when it
  // is updated.
  window_->OnActiveTabChanged(old_contents, new_contents, index, reason);

  exclusive_access_manager_->OnTabDetachedFromView(old_contents);

  // If we have any update pending, do it now.
  if (dock_updater_factory_.HasWeakPtrs() && old_contents)
    ProcessPendingUIUpdates();

  // Propagate the profile to the location bar.
  //UpdateToolbar((reason & CHANGE_REASON_REPLACED) == 0);

  // Update reload/stop state.
  command_controller_->LoadingStateChanged(new_contents->IsLoading(), true);

  // Update commands to reflect current state.
  if (new_tab_helper && new_tab_helper->sad_tab() == nullptr) {
    command_controller_->TabStateChanged();
  }

  // Reset the status bubble.
  //StatusBubble* status_bubble = GetStatusBubble();
  //if (status_bubble) {
  //  status_bubble->Hide();
  //
  //  Show the loading state (if any).
  //  status_bubble->SetStatus(CoreTabHelper::FromWebContents(
  //      tab_strip_model_->GetActiveWebContents())->GetStatusText());
  //}

  // Update sessions (selected tab index and last active time). Don't force
  // creation of sessions. If sessions doesn't exist, the change will be picked
  // up by sessions when created.
  //SessionService* session_service =
  //    SessionServiceFactory::GetForProfileIfExisting(profile_);
  //if (session_service && !tab_strip_model_->closing_all()) {
  //  session_service->SetSelectedTabInWindow(session_id(),
  //                                          tab_strip_model_->active_index());
  //  SessionTabHelper* session_tab_helper =
  //      SessionTabHelper::FromWebContents(new_contents);
  //  session_service->SetLastActiveTime(session_id(),
  //                                     session_tab_helper->session_id(),
  //                                     base::TimeTicks::Now());
  //}

  //SearchTabHelper::FromWebContents(new_contents)->OnTabActivated();
}

void Dock::TabMoved(ApplicationContents* contents,
                    int from_index,
                    int to_index) {
  DCHECK(from_index >= 0 && to_index >= 0);
  // Notify the history service.
  //SyncHistoryWithTabs(std::min(from_index, to_index));
}

void Dock::TabReplacedAt(TablistModel* tablist_model,
                         ApplicationContents* old_contents,
                         ApplicationContents* new_contents,
                         int index) {
  TabDetachedAtImpl(old_contents, index, DETACH_TYPE_REPLACE);
  exclusive_access_manager_->OnTabClosing(old_contents);
  //SessionService* session_service =
  //    SessionServiceFactory::GetForProfile(profile_);
  //if (session_service)
  //  session_service->TabClosing(old_contents);
  TabInsertedAt(tablist_model, new_contents, index,
                (index == tablist_model_->active_index()));

  //if (!new_contents->GetController().IsInitialBlankNavigation()) {
  //  Send out notification so that observers are updated appropriately.
  //  int entry_count = new_contents->GetController().GetEntryCount();
  //  new_contents->GetController().NotifyEntryChanged(
  //      new_contents->GetController().GetEntryAtIndex(entry_count - 1));
  //}

  //if (session_service) {
  //   The new_contents may end up with a different navigation stack. Force
  //   the session service to update itself.
  //  session_service->TabRestored(new_contents,
  //                               tab_strip_model_->IsTabPinned(index));
  //}
}

void Dock::TabPinnedStateChanged(TablistModel* tablist_model,
                                 ApplicationContents* contents,
                                 int index) {
  DLOG(INFO) << "Dock::TabPinnedStateChanged: tab was pinned, but we did not implement it.. fix";
  //SessionService* session_service =
  //    SessionServiceFactory::GetForProfileIfExisting(profile());
  //if (session_service) {
  //  SessionTabHelper* session_tab_helper =
  //      SessionTabHelper::FromWebContents(contents);
  //  session_service->SetPinnedState(session_id(),
  //                                  session_tab_helper->session_id(),
  //                                  tab_strip_model_->IsTabPinned(index));
  //}
}

void Dock::TablistEmpty() {
  // Close the frame after we return to the message loop (not immediately,
  // otherwise it will destroy this object before the stack has a chance to
  // cleanly unwind.)
  // Note: This will be called several times if TabStripEmpty is called several
  //       times. This is because it does not close the window if tabs are
  //       still present.
  base::ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE,
      base::BindOnce(&Dock::CloseFrame, weak_factory_.GetWeakPtr()));

  // Instant may have visible WebContents that need to be detached before the
  // window system closes.
  //instant_controller_.reset();
}

void Dock::TablistColorChanged(TablistModel* tablist_model, SkColor color, int tab_index) {
  
}

void Dock::SetAsDelegate(ApplicationContents* app_contents, bool set_delegate) {
  Dock* delegate = set_delegate ? this : nullptr;

  // AppContents...
  app_contents->SetDelegate(delegate);

  // ...and all the helpers.
 // ApplicationContentsModalDialogManager::FromApplicationContents(app_contents)->
 //     SetDelegate(delegate);
  CoreTabHelper::FromApplicationContents(app_contents)->set_delegate(delegate);
  if (delegate) {
    zoom::ZoomController::FromApplicationContents(app_contents)->AddObserver(this);
  } else {
    zoom::ZoomController::FromApplicationContents(app_contents)->RemoveObserver(this);
  }
}

void Dock::CloseFrame() {
  window_->Close();
}

void Dock::TabDetachedAtImpl(ApplicationContents* contents,
                             int index,
                             DetachType type) {
  // if (type == DETACH_TYPE_DETACH) {
  //   // Save the current location bar state, but only if the tab being detached
  //   // is the selected tab.  Because saving state can conditionally revert the
  //   // location bar, saving the current tab's location bar state to a
  //   // non-selected tab can corrupt both tabs.
  //   if (contents == tab_strip_model_->GetActiveWebContents()) {
  //     LocationBar* location_bar = window()->GetLocationBar();
  //     if (location_bar)
  //       location_bar->SaveStateToContents(contents);
  //   }
  // }

  SetAsDelegate(contents, false);
  RemoveScheduledUpdatesFor(contents);

  // if (find_bar_controller_.get() && index == tab_strip_model_->active_index()) {
  //   find_bar_controller_->ChangeWebContents(NULL);
  // }

  for (size_t i = 0; i < interstitial_observers_.size(); i++) {
    if (interstitial_observers_[i]->application_contents() != contents)
      continue;

    delete interstitial_observers_[i];
    interstitial_observers_.erase(interstitial_observers_.begin() + i);
    return;
  }
}

// static
void Dock::FormatTitleForDisplay(base::string16* title) {
  size_t current_index = 0;
  size_t match_index;
  while ((match_index = title->find(L'\n', current_index)) !=
         base::string16::npos) {
    title->replace(match_index, 1, base::string16());
    current_index = match_index;
  }
}


bool Dock::CanOverscrollContent() const {
  return false;
}

KeyboardEventProcessingResult Dock::PreHandleKeyboardEvent(
  ApplicationContents* source,
  const NativeWebKeyboardEvent& event) {
  DLOG(INFO) << "Dock::PreHandleKeyboardEvent";
  if (exclusive_access_manager_->HandleUserKeyEvent(event))
    return KeyboardEventProcessingResult::HANDLED;

  return window()->PreHandleKeyboardEvent(event);
}

void Dock::HandleKeyboardEvent(
    ApplicationContents* source,
    const NativeWebKeyboardEvent& event) {
  window()->HandleKeyboardEvent(event);
}

bool Dock::PreHandleGestureEvent(
  ApplicationContents* source,
  const blink::WebGestureEvent& event) {
  return false;
}

bool Dock::CanDragEnter(ApplicationContents* source,
                               const common::DropData& data,
                               blink::WebDragOperationsMask operations_allowed) {
  return true;
}

void Dock::OnAudioStateChanged(ApplicationContents* app_contents, bool is_audible) {
 //SoundContentSettingObserver* sound_content_setting_observer =
 //     SoundContentSettingObserver::FromApplicationContents(app_contents);
 // if (sound_content_setting_observer)
 //   sound_content_setting_observer->OnAudioStateChanged(is_audible);
}

void Dock::UpdatePictureInPictureSurfaceId(const viz::SurfaceId& surface_id,
                                                  const gfx::Size& natural_size) {
  if (!pip_window_controller_)
    pip_window_controller_.reset(
        PictureInPictureWindowController::GetOrCreateForApplicationContents(
          tablist_model_->GetActiveApplicationContents()));
  pip_window_controller_->EmbedSurface(surface_id, natural_size);
  pip_window_controller_->Show();
}

void Dock::ExitPictureInPicture() {
  if (pip_window_controller_)
    pip_window_controller_->Close();
}

ApplicationContents* Dock::OpenURL(
  ApplicationContents* source,
  const OpenURLParams& params) {
  return nullptr;
}

void Dock::NavigationStateChanged(ApplicationContents* source,
                                  InvalidateTypes changed_flags) {
  // Only update the UI when something visible has changed.
  if (changed_flags)
    ScheduleUIUpdate(source, changed_flags);

  // We can synchronously update commands since they will only change once per
  // navigation, so we don't have to worry about flickering. We do, however,
  // need to update the command state early on load to always present usable
  // actions in the face of slow-to-commit pages.
  if (changed_flags & (INVALIDATE_TYPE_URL |
                       INVALIDATE_TYPE_LOAD |
                       INVALIDATE_TYPE_TAB))
    command_controller_->TabStateChanged();
}

void Dock::VisibleSecurityStateChanged(ApplicationContents* source) {

}

void Dock::AddNewContents(const std::string& app_name,
                          ApplicationContents* source,
                          ApplicationContents* new_contents,
                          WindowOpenDisposition disposition,
                          const gfx::Rect& initial_rect,
                          bool user_gesture,
                          bool* was_blocked) {
  // from dock_tablist.h
  AddApplicationContents(this, source, new_contents, disposition, initial_rect,
                         user_gesture);
  // int view_index = tablist_model_->GetNextViewIndex();
  // tablist_model_->AddApplicationContents(
  //       base::WrapUnique(new_contents), 
  //       view_index,
  //       disposition, 
  //       initial_rect);
  // //contents_model_.ActivateViewAt(view_index, false);
  ActivateContents(new_contents);
  new_contents->Focus();
  // NotificationService::current()->Notify(
  //       chrome::NOTIFICATION_TAB_ADDED,
  //       Source<ApplicationContentsDelegate>(this),
  //       Details<ApplicationContents>(new_contents))
}

void Dock::ActivateContents(ApplicationContents* contents) {
  tablist_model_->ActivateTabAt(
      tablist_model_->GetIndexOfApplicationContents(contents), false);
  window_->Activate();
}

void Dock::LoadingStateChanged(ApplicationContents* source,
                                      bool to_different_document) {
  ScheduleUIUpdate(source, INVALIDATE_TYPE_LOAD);
  UpdateWindowForLoadingStateChanged(source, to_different_document);
}

void Dock::CloseContents(ApplicationContents* source) {
  //DLOG(INFO) << "Dock::CloseContents";
  bool can_close_contents;
  can_close_contents = true;//unload_controller_->CanCloseContents(source);
  if (can_close_contents) { 
    int index = tablist_model_->GetIndexOfApplicationContents(source);
    if (index == TablistModel::kNoTab) {
      NOTREACHED() << "CloseWebContents called for tab not in our strip";
      return;
    }
    //DLOG(INFO) << "calling tablist_model_->CloseApplicationContentsAt() ..";
    tablist_model_->CloseApplicationContentsAt(index, TablistModel::CLOSE_NONE);
  }
}

void Dock::MoveContents(ApplicationContents* source,
                               const gfx::Rect& pos) {
  window_->SetBounds(pos);
}

bool Dock::IsPopupOrPanel(const ApplicationContents* source) const {
  return is_type_popup();
}

void Dock::UpdateTargetURL(ApplicationContents* source, const GURL& url) {
  
}

void Dock::ContentsMouseEvent(ApplicationContents* source,
                                     bool motion,
                                     bool exited) {
  exclusive_access_manager_->OnUserInput();
}

void Dock::ContentsZoomChange(bool zoom_in) {
  DLOG(INFO) << "Dock::ContentsZoomChange: Not implemented";
  //host::ExecuteCommand(this, zoom_in ? IDC_ZOOM_PLUS : IDC_ZOOM_MINUS);
}

bool Dock::TakeFocus(ApplicationContents* source, bool reverse) {
  NotificationService::current()->Notify(
      NOTIFICATION_FOCUS_RETURNED_TO_BROWSER,
      Source<Dock>(this),
      NotificationService::NoDetails());
  return false;
}

void Dock::BeforeUnloadFired(ApplicationContents* source,
                             bool proceed,
                             bool* proceed_to_fire_unload) {
  *proceed_to_fire_unload = true;
        //unload_controller_->BeforeUnloadFired(web_contents, proceed);
}

bool Dock::ShouldFocusLocationBarByDefault(ApplicationContents* source) {
  return false;
}

bool Dock::ShouldCreateApplicationContents(
    ApplicationContents* application_contents,
    ApplicationWindowHost* opener,
    int32_t route_id,
    int32_t main_frame_route_id,
    int32_t main_frame_widget_route_id,
    common::mojom::WindowContainerType window_container_type,
    const GURL& opener_url,
    const std::string& frame_name,
    const GURL& target_url) {
  return true;
}

void Dock::ApplicationContentsCreated(ApplicationContents* source_contents,
    int opener_render_process_id,
    int opener_render_frame_id,
    const std::string& frame_name,
    const GURL& target_url,
    ApplicationContents* new_contents) {
  Dock::AttachTabHelpers(new_contents);  
}

void Dock::ApplicationUnresponsive(
  ApplicationContents* source,
  ApplicationWindowHost* application_host_window) {  
  DLOG(INFO) << "Dock::ApplicationUnresponsive: should implement ShowHungApplicationDialog()";
 // TabDialogs::FromApplicationContents(source)->ShowHungApplicationDialog(
 //     application_host_window);
}

void Dock::ApplicationResponsive(
  ApplicationContents* source,
  ApplicationWindowHost* application_host_window) {
 DLOG(INFO) << "Dock::ApplicattionResponsive: should implement HideHungApplicationDialog()";
 //TabDialogs::FromApplicationContents(source)->HideHungApplicationDialog(
 //     application_host_window);
}

void Dock::DidNavigateMainFramePostCommit(
    ApplicationContents* app_contents) {
  //DLOG(INFO) << "DidNavigateMainFramePostCommit: theres nothing here";
}

bool Dock::EmbedsFullscreenWindow() const {
  //return true;
  return false;
}

void Dock::EnterFullscreenMode(ApplicationContents* app_contents) {
  exclusive_access_manager_->fullscreen_controller()->EnterFullscreenModeForTab(
      app_contents);
}

void Dock::ExitFullscreenMode(ApplicationContents* app_contents) {
  exclusive_access_manager_->fullscreen_controller()->ExitFullscreenModeForTab(
     app_contents);
}

bool Dock::IsFullscreenOrPending(
    const ApplicationContents* app_contents) const {
  return exclusive_access_manager_->fullscreen_controller()
      ->IsFullscreenForTabOrPending(app_contents);
}

blink::WebDisplayMode Dock::GetDisplayMode(
    const ApplicationContents* app_contents) const {
  if (window_->IsFullscreen())
    return blink::kWebDisplayModeFullscreen;

  if (is_type_popup())
    return blink::kWebDisplayModeStandalone;

  return blink::kWebDisplayModeBrowser;
}

void Dock::RegisterProtocolHandler(ApplicationContents* app_contents,
                                          const std::string& protocol,
                                          const GURL& url,
                                          bool user_gesture) {}

void Dock::UnregisterProtocolHandler(ApplicationContents* app_contents,
                                            const std::string& protocol,
                                            const GURL& url,
                                            bool user_gesture) {}

void Dock::FindReply(ApplicationContents* app_contents,
               int request_id,
               int number_of_matches,
               const gfx::Rect& selection_rect,
               int active_match_ordinal,
               bool final_update) {}

void Dock::RequestToLockMouse(ApplicationContents* app_contents,
                              bool user_gesture,
                              bool last_unlocked_by_target) {
  exclusive_access_manager_->mouse_lock_controller()->RequestToLockMouse(
      app_contents, user_gesture, last_unlocked_by_target);
}

void Dock::LostMouseLock() {
  exclusive_access_manager_->mouse_lock_controller()->LostMouseLock();
}

bool Dock::IsMouseLocked() const {
  return exclusive_access_manager_->mouse_lock_controller()->IsMouseLocked();
}

void Dock::RequestKeyboardLock(ApplicationContents* app_contents,
                                      bool esc_key_locked) {
  exclusive_access_manager_->keyboard_lock_controller()->RequestKeyboardLock(
      app_contents, esc_key_locked);
}

void Dock::CancelKeyboardLockRequest(ApplicationContents* app_contents) {
  exclusive_access_manager_->keyboard_lock_controller()
      ->CancelKeyboardLockRequest(app_contents);
}

void Dock::RequestMediaAccessPermission(
    ApplicationContents* app_contents,
    const common::MediaStreamRequest& request,
    const common::MediaResponseCallback& callback) {
  MediaCaptureDevicesDispatcher::GetInstance()->ProcessMediaAccessRequest(
      app_contents, request, callback);
}

bool Dock::CheckMediaAccessPermission(ApplicationWindowHost* app_dock_window,
                                const GURL& security_origin,
                                common::MediaStreamType type) {
  return MediaCaptureDevicesDispatcher::GetInstance()
      ->CheckMediaAccessPermission(app_dock_window, security_origin, type);
}

std::string Dock::GetDefaultMediaDeviceID(ApplicationContents* app_contents,
                                          common::MediaStreamType type) {
  return MediaCaptureDevicesDispatcher::GetInstance()->GetDefaultDeviceIDForProfile(workspace_, type);
}

gfx::Size Dock::GetSizeForNewApplicationWindow(
    ApplicationContents* app_contents) const {
  gfx::Size size = app_contents->GetContainerBounds().size();
  return size;
}

gfx::Image Dock::GetCurrentPageIcon() const {
  ApplicationContents* app_contents = tablist_model_->GetActiveApplicationContents();
  // |web_contents| can be NULL since GetCurrentPageIcon() is called by the
  // window during the window's creation (before tabs have been added).
  favicon::FaviconDriver* favicon_driver =
      app_contents
          ? favicon::ContentFaviconDriver::FromApplicationContents(app_contents)
          : nullptr;
  return favicon_driver ? favicon_driver->GetFavicon() : gfx::Image();
}

void Dock::UpdateWindowForLoadingStateChanged(ApplicationContents* source,
                                              bool to_different_document) {
  window_->UpdateLoadingAnimations(tablist_model_->TabsAreLoading());
  window_->UpdateTitleBar();

  ApplicationContents* selected_contents = tablist_model_->GetActiveApplicationContents();
  if (source == selected_contents) {
    bool is_loading = source->IsLoading() && to_different_document;
    command_controller_->LoadingStateChanged(is_loading, false);
    //if (GetStatusBubble()) {
    //  GetStatusBubble()->SetStatus(CoreTabHelper::FromApplicationContents(
    //                               tab_strip_model_->GetActiveApplicationContents())
    //                                ->GetStatusText());
    //}
  }
}

void Dock::Observe(int type,
             const NotificationSource& source,
             const NotificationDetails& details) {
//     switch (type) {
// #if !defined(OS_ANDROID)
//     case chrome::NOTIFICATION_BROWSER_THEME_CHANGED:
//       window()->UserChangedTheme();
//       break;
// #endif

//     case chrome::NOTIFICATION_WEB_CONTENT_SETTINGS_CHANGED: {
//       WebContents* web_contents = content::Source<WebContents>(source).ptr();
//       if (web_contents == tablist_model_->GetActiveWebContents()) {
//         LocationBar* location_bar = window()->GetLocationBar();
//         if (location_bar)
//           location_bar->UpdateContentSettingsIcons();
//       }
//       break;
//     }

//     default:
//       NOTREACHED() << "Got a notification we didn't register for.";
//   }
}

void Dock::WindowFullscreenStateWillChange() {
  exclusive_access_manager_->fullscreen_controller()
      ->WindowFullscreenStateWillChange();
}

void Dock::WindowFullscreenStateChanged() {
  exclusive_access_manager_->fullscreen_controller()
      ->WindowFullscreenStateChanged();
  command_controller_->FullscreenStateChanged();
  //UpdateBookmarkBarState(BOOKMARK_BAR_STATE_CHANGE_TOGGLE_FULLSCREEN);
}

void Navigate(NavigateParams* params) {
  std::string app_name, page_name;
  if (!params->url.is_empty()) {
    ParseApplicationAndPageName(params->url, &app_name, &page_name);
  }
  
  Dock* source_dock = params->dock;
  
  // The browser window may want to adjust the disposition.
  if (params->disposition == WindowOpenDisposition::NEW_POPUP &&
      source_dock && source_dock->window()) {
    params->disposition =
        source_dock->window()->GetDispositionForPopupBounds(
            params->window_bounds);
  }
  
  // If no source WebContents was specified, we use the selected one from
  // the target browser. This must happen first, before
  // GetBrowserForDisposition() has a chance to replace |params->browser| with
  // another one.
  if (!params->source_contents && params->dock) {
    params->source_contents =
        params->dock->tablist_model()->GetActiveApplicationContents();
  }
  int singleton_index;
  std::tie(params->dock, singleton_index) =
      GetDockAndTabForDisposition(*params);
  if (!params->dock)
    return;
  if (singleton_index != -1) {
    params->target_contents =
        params->dock->tablist_model()->GetApplicationContentsAt(singleton_index);
  }

  // Make sure the Browser is shown if params call for it.
  ScopedDockShower shower(params);

  // Makes sure any WebContents created by this function is destroyed if
  // not properly added to a tab strip.
  ScopedTargetContentsOwner target_contents_owner(params);

  // Some dispositions need coercion to base types.
  //NormalizeDisposition(params);

  // If a new window has been created, it needs to be shown.
  if (params->window_action == NavigateParams::NO_ACTION &&
      source_dock != params->dock &&
      params->dock->tablist_model()->empty()) {
    params->window_action = NavigateParams::SHOW_WINDOW;
  }

  // If we create a popup window from a non user-gesture, don't activate it.
  if (params->window_action == NavigateParams::SHOW_WINDOW &&
      params->disposition == WindowOpenDisposition::NEW_POPUP &&
      params->user_gesture == false) {
    params->window_action = NavigateParams::SHOW_WINDOW_INACTIVE;
  }

  // Determine if the navigation was user initiated. If it was, we need to
  // inform the target WebContents, and we may need to update the UI.
  bool user_initiated =
      params->transition & ui::PAGE_TRANSITION_FROM_ADDRESS_BAR ||
      ui::PageTransitionCoreTypeIs(params->transition,
                                   ui::PAGE_TRANSITION_TYPED) ||
      ui::PageTransitionCoreTypeIs(params->transition,
                                   ui::PAGE_TRANSITION_AUTO_BOOKMARK) ||
      ui::PageTransitionCoreTypeIs(params->transition,
                                   ui::PAGE_TRANSITION_GENERATED) ||
      ui::PageTransitionCoreTypeIs(params->transition,
                                   ui::PAGE_TRANSITION_AUTO_TOPLEVEL) ||
      ui::PageTransitionCoreTypeIs(params->transition,
                                   ui::PAGE_TRANSITION_RELOAD) ||
      ui::PageTransitionCoreTypeIs(params->transition,
                                   ui::PAGE_TRANSITION_KEYWORD);

  // Did we use a prerender?
  bool swapped_in_prerender = false;

  // If no target WebContents was specified (and we didn't seek and find a
  // singleton), we need to construct one if we are supposed to target a new
  // tab.
  if (!params->target_contents) {
    DCHECK(!params->url.is_empty());
    if (params->disposition != WindowOpenDisposition::CURRENT_TAB) {
      params->target_contents = CreateTargetContents(params->application, page_name, *params, params->url);

      // This function takes ownership of |params->target_contents| until it
      // is added to a TabStripModel.
      target_contents_owner.TakeOwnership();
    } else {
      // ... otherwise if we're loading in the current tab, the target is the
      // same as the source.
      DCHECK(params->source_contents);
      params->target_contents = params->source_contents;

      // Prerender can only swap in CURRENT_TAB navigations; others have
      // different sessionStorage namespaces.
      swapped_in_prerender = SwapInPrerender(params->url, params);
    }

    if (user_initiated)
      params->target_contents->NavigatedByUser();

    if (!swapped_in_prerender) {
      // Try to handle non-navigational URLs that popup dialogs and such, these
      // should not actually navigate.
      //if (!HandleNonNavigationAboutURL(params->url)) {
        // Perform the actual navigation, tracking whether it came from the
        // renderer.

        LoadURLInContents(params->target_contents, params->url, *params);
      //}
    }
  } //else {
    // |target_contents| was specified non-NULL, and so we assume it has already
    // been navigated appropriately. We need to do nothing more other than
    // add it to the appropriate tabstrip.
  //}

  // If the user navigated from the omnibox, and the selected tab is going to
  // lose focus, then make sure the focus for the source tab goes away from the
  // omnibox.
  if (params->source_contents &&
      (params->disposition == WindowOpenDisposition::NEW_FOREGROUND_TAB ||
       params->disposition == WindowOpenDisposition::NEW_WINDOW) &&
      (params->tablist_add_types & TablistModel::ADD_INHERIT_OPENER))
    params->source_contents->Focus();

  if (params->source_contents == params->target_contents ||
      (swapped_in_prerender &&
       params->disposition == WindowOpenDisposition::CURRENT_TAB)) {
    // The navigation occurred in the source tab.
    params->dock->UpdateUIForNavigationInTab(
        params->target_contents, params->transition, params->window_action,
        user_initiated);
  } else if (singleton_index == -1 && params->tab_style != TabStyle::kEMBED) {
    // If some non-default value is set for the index, we should tell the
    // TabStripModel to respect it.
    if (params->tablist_index != -1)
      params->tablist_add_types |= TablistModel::ADD_FORCE_INDEX;

    // The navigation should insert a new tab into the target Browser.
    params->dock->tablist_model()->AddApplicationContents(
        base::WrapUnique(params->target_contents), params->tablist_index,
        params->transition, params->tablist_add_types);

    // TODO(erikchen): Fix ownership semantics here. https://crbug.com/832879.
    // Now that the |params->target_contents| is safely owned by the target
    // Browser's TabStripModel, we can release ownership.
    target_contents_owner.ReleaseOwnership();
  }

  if (singleton_index >= 0) {
    // If switching browsers, make sure it is shown.
    if (params->disposition == WindowOpenDisposition::SWITCH_TO_TAB &&
        params->dock != source_dock)
      params->window_action = NavigateParams::SHOW_WINDOW;

    // if (params->target_contents->IsCrashed()) {
    //   params->target_contents->GetController().Reload(
    //       ReloadType::NORMAL, true);
    // } else if (params->path_behavior == NavigateParams::IGNORE_AND_NAVIGATE &&
    //            params->target_contents->GetURL() != params->url) {
    //   LoadURLInContents(params->target_contents, params->url, *params);
    // }

    if (params->path_behavior == NavigateParams::IGNORE_AND_NAVIGATE &&
        params->target_contents->GetURL() != params->url) {
      LoadURLInContents(params->target_contents, params->url, *params);
    }

    // If the singleton tab isn't already selected, select it.
    if (params->source_contents != params->target_contents && params->tab_style != TabStyle::kEMBED) {
      // Use the index before the potential close below, because it could
      // make the index refer to a different tab.
      params->dock->tablist_model()->ActivateTabAt(singleton_index,
                                                   user_initiated);
      if (params->disposition == WindowOpenDisposition::SWITCH_TO_TAB) {
        // Close orphaned NTP (and the like) with no history when the user
        // switches away from them.
        //if (params->source_contents->GetController().CanGoBack() ||
        //    (params->source_contents->GetLastCommittedURL().spec() !=
        //         chrome::kChromeUINewTabURL &&
        //     params->source_contents->GetLastCommittedURL().spec() !=
       //          chrome::kChromeSearchLocalNtpUrl &&
       //      params->source_contents->GetLastCommittedURL().spec() !=
       //          url::kAboutBlankURL))
          params->source_contents->Focus();
       // else
       //   params->source_contents->Close();
      }
    }
  }

  if (params->disposition != WindowOpenDisposition::CURRENT_TAB) {
    NotificationService::current()->Notify(
        NOTIFICATION_TAB_ADDED,
        Source<ApplicationContentsDelegate>(params->dock),
        Details<ApplicationContents>(params->target_contents));
  }
  // embedded tab should control the ownership of the created application contents
  if (params->tab_style == TabStyle::kEMBED) {
    target_contents_owner.ReleaseOwnership();
  }
}

void LoadURLInContents(ApplicationContents* target_contents,
                       const GURL& url,
                       const NavigateParams& params) {
  target_contents->LoadURL(url, params);
}

void Dock::UpdateToolbar(bool should_restore_state) {
  //window_->UpdateToolbar(should_restore_state ?
  //    tablist_model_->GetActiveApplicationContents() : NULL);
}

void Dock::ScheduleUIUpdate(ApplicationContents* source,
                            unsigned changed_flags) {
  DCHECK(source);
  int index = tablist_model_->GetIndexOfApplicationContents(source);
  DCHECK_NE(TablistModel::kNoTab, index);

  // Do some synchronous updates.
  if (changed_flags & INVALIDATE_TYPE_URL) {
  //  if (source == tablist_model_->GetActiveApplicationContents()) {
  //     // Only update the URL for the current tab. Note that we do not update
  //     // the navigation commands since those would have already been updated
  //     // synchronously by NavigationStateChanged.
       //UpdateToolbar(false);
  //   } else {
  //     // Clear the saved tab state for the tab that navigated, so that we don't
  //     // restore any user text after the old URL has been invalidated (e.g.,
  //     // after a new navigation commits in that tab while unfocused).
       //window_->ResetToolbarTabState(source);
  //   }
     changed_flags &= ~INVALIDATE_TYPE_URL;
   }

  if (changed_flags & INVALIDATE_TYPE_LOAD) {
    // Update the loading state synchronously. This is so the throbber will
    // immediately start/stop, which gives a more snappy feel. We want to do
    // this for any tab so they start & stop quickly.
    tablist_model_->UpdateApplicationContentsStateAt(
        tablist_model_->GetIndexOfApplicationContents(source),
        TabChangeType::kLoadingOnly);
    // The status bubble needs to be updated during INVALIDATE_TYPE_LOAD too,
    // but we do that asynchronously by not stripping INVALIDATE_TYPE_LOAD from
    // changed_flags.
  }

  if (changed_flags & INVALIDATE_TYPE_TITLE && !source->IsLoading()) {
    // To correctly calculate whether the title changed while not loading
    // we need to process the update synchronously. This state only matters for
    // the TabStripModel, so we notify the TabStripModel now and notify others
    // asynchronously.
    tablist_model_->UpdateApplicationContentsStateAt(
        tablist_model_->GetIndexOfApplicationContents(source),
        TabChangeType::kTitleNotLoading);
  }

  // If the only updates were synchronously handled above, we're done.
  if (changed_flags == 0)
    return;

  // Save the dirty bits.
  scheduled_updates_[source] |= changed_flags;

  if (!dock_updater_factory_.HasWeakPtrs()) {
    // No task currently scheduled, start another.
    base::ThreadTaskRunnerHandle::Get()->PostDelayedTask(
        FROM_HERE,
        base::BindOnce(&Dock::ProcessPendingUIUpdates,
                       dock_updater_factory_.GetWeakPtr()),
        base::TimeDelta::FromMilliseconds(kUIUpdateCoalescingTimeMS));
  }
}

void Dock::ProcessPendingUIUpdates() {
#ifndef NDEBUG
  // Validate that all tabs we have pending updates for exist. This is scary
  // because the pending list must be kept in sync with any detached or
  // deleted tabs.
  for (UpdateMap::const_iterator i = scheduled_updates_.begin();
       i != scheduled_updates_.end(); ++i) {
    bool found = false;
    for (int tab = 0; tab < tablist_model_->count(); tab++) {
      if (tablist_model_->GetApplicationContentsAt(tab) == i->first) {
        found = true;
        break;
      }
    }
    DCHECK(found);
  }
#endif

  dock_updater_factory_.InvalidateWeakPtrs();

  for (UpdateMap::const_iterator i = scheduled_updates_.begin();
       i != scheduled_updates_.end(); ++i) {
    // Do not dereference |contents|, it may be out-of-date!
    const ApplicationContents* contents = i->first;
    unsigned flags = i->second;

    if (contents == tablist_model_->GetActiveApplicationContents()) {
      // Updates that only matter when the tab is selected go here.

      // Updating the URL happens synchronously in ScheduleUIUpdate.
      //if (flags & content::INVALIDATE_TYPE_LOAD && GetStatusBubble()) {
      //  GetStatusBubble()->SetStatus(CoreTabHelper::FromApplicationContents(
      //      tab_strip_model_->GetActiveApplicationContents())->GetStatusText());
      //}

      if (flags & (INVALIDATE_TYPE_TAB |
                   INVALIDATE_TYPE_TITLE)) {
        window_->UpdateTitleBar();
      }
    }

    // Updates that don't depend upon the selected state go here.
    if (flags &
        (INVALIDATE_TYPE_TAB | INVALIDATE_TYPE_TITLE)) {
      tablist_model_->UpdateApplicationContentsStateAt(
          tablist_model_->GetIndexOfApplicationContents(contents),
          TabChangeType::kAll);
    }

    // Update the bookmark bar. It may happen that the tab is crashed, and if
    // so, the bookmark bar should be hidden.
    //if (flags & content::INVALIDATE_TYPE_TAB)
     // UpdateBookmarkBarState(BOOKMARK_BAR_STATE_CHANGE_TAB_STATE);

    // We don't need to process INVALIDATE_STATE, since that's not visible.
  }

  scheduled_updates_.clear();
}

void Dock::RemoveScheduledUpdatesFor(ApplicationContents* contents) {
  if (!contents)
    return;

  UpdateMap::iterator i = scheduled_updates_.find(contents);
  if (i != scheduled_updates_.end())
    scheduled_updates_.erase(i);
}

// static
void Dock::AttachTabHelpers(ApplicationContents* contents) {
#if !defined(OS_ANDROID)
  // ZoomController comes before common tab helpers since ChromeAutofillClient
  // may want to register as a ZoomObserver with it.
  zoom::ZoomController::CreateForApplicationContents(contents);
#endif
  CoreTabHelper::CreateForApplicationContents(contents);
  favicon::CreateContentFaviconDriverForApplicationContents(contents);
  TabUIHelper::CreateForApplicationContents(contents);
  SadTabHelper::CreateForApplicationContents(contents);
}

void Dock::OnZoomChanged(const zoom::ZoomController::ZoomChangedEventData& data) {
  if (data.app_contents == tablist_model_->GetActiveApplicationContents()) {
    window_->ZoomChangedForActiveTab(data.can_show_bubble);
    // Change the zoom commands state based on the zoom state
    command_controller_->ZoomStateChanged();
  } 
}

void Dock::UpdateUIForNavigationInTab(ApplicationContents* contents,
                                      ui::PageTransition transition,
                                      NavigateParams::WindowAction action,
                                      bool user_initiated) {
  tablist_model_->TabNavigating(contents, transition);

  bool contents_is_selected =
      contents == tablist_model_->GetActiveApplicationContents();
  //if (user_initiated && contents_is_selected && window()->GetLocationBar()) {
    // Forcibly reset the location bar if the url is going to change in the
    // current tab, since otherwise it won't discard any ongoing user edits,
    // since it doesn't realize this is a user-initiated action.
  //  window()->GetLocationBar()->Revert();
  //}

  //if (GetStatusBubble())
 //   GetStatusBubble()->Hide();

  // Update the location bar. This is synchronous. We specifically don't
  // update the load state since the load hasn't started yet and updating it
  // will put it out of sync with the actual state like whether we're
  // displaying a favicon, which controls the throbber. If we updated it here,
  // the throbber will show the default favicon for a split second when
  // navigating away from the new tab page.
  ScheduleUIUpdate(contents, INVALIDATE_TYPE_URL);

  if (contents_is_selected &&
      (window()->IsActive() || action == NavigateParams::SHOW_WINDOW)) {
    contents->SetInitialFocus();
  }
}

bool Dock::TryToCloseWindow(
    bool skip_beforeunload,
    const base::Callback<void(bool)>& on_close_confirmed) {
  //cancel_download_confirmation_state_ = RESPONSE_RECEIVED;
  //if (IsFastTabUnloadEnabled()) {
//    return fast_unload_controller_->TryToCloseWindow(skip_beforeunload,
                                                     //on_close_confirmed);
  //}
  //return unload_controller_->TryToCloseWindow(skip_beforeunload,
  //                                            on_close_confirmed);
  OnWindowClosing();
  return true;
}

void Dock::ResetTryToCloseWindow() {

}

void Dock::OnWindowDidShow() {
  if (window_has_shown_)
    return;
  window_has_shown_ = true;
}

}
