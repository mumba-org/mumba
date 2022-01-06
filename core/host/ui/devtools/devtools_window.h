// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_DEVTOOLS_DEVTOOLS_WINDOW_H_
#define CHROME_BROWSER_DEVTOOLS_DEVTOOLS_WINDOW_H_

#include <memory>
#include <string>

#include "base/macros.h"
#include "core/host/ui/devtools/devtools_contents_resizing_strategy.h"
#include "core/host/ui/devtools/devtools_toggle_action.h"
#include "core/host/application/domain.h"
//#include "core/host/ui/devtools/devtools_ui_bindings.h"
#include "core/host/application/application_contents_delegate.h"
#include "core/host/application/application_contents_observer.h"


namespace host {
struct NativeWebKeyboardEvent;
class NavigationHandle;
class NavigationThrottle;
class ApplicationWindowHost;
class Dock;
class DockWindow;
class DevToolsEventForwarder;
class Workspace;
//class DevToolsEyeDropper;


// Values that represent different actions to open DevTools window.
// These values are written to logs. New enum values can be added, but existing
// enums must never be renumbered or deleted and reused.
enum class DevToolsOpenedByAction {
  kUnknown = 0,
  // Main menu -> More Tools -> Developer Tools
  // or Ctrl+Shift+I shortcut
  kMainMenuOrMainShortcut = 1,
  // Ctrl+Shift+J shortcut to jump to Console
  kConsoleShortcut = 2,
  // Context menu -> Inspect
  kContextMenuInspect = 3,
  // Ctrl+Shift+C shortcut to turn on inspect mode
  kInspectorModeShortcut = 4,
  // Toggle-open via F12
  kToggleShortcut = 5,
  // Add values above this line with a corresponding label in
  // tools/metrics/histograms/enums.xml
  kMaxValue = kToggleShortcut,
};

class DevToolsWindow : //public DevToolsUIBindings::Delegate,
                       public ApplicationContentsDelegate,
                       public Domain::Observer {
 public:
  class ObserverWithAccessor : public ApplicationContentsObserver {
   public:
    explicit ObserverWithAccessor(ApplicationContents* app_contents);
    ~ObserverWithAccessor() override;

   private:
    DISALLOW_COPY_AND_ASSIGN(ObserverWithAccessor);
  };

  static const char kDevToolsApp[];

  ~DevToolsWindow() override;

  // Return the docked DevTools ApplicationContents for the given inspected ApplicationContents
  // if one exists and should be shown in browser window, otherwise nullptr.
  // This method will return only fully initialized window ready to be
  // presented in UI.
  // If |out_strategy| is not nullptr, it will contain resizing strategy.
  // For immediately-ready-to-use but maybe not yet fully initialized DevTools
  // use |GetInstanceForInspectedRenderViewHost| instead.
  static void GetInTabApplicationContents(
    ApplicationContents* inspected_tab,
    base::OnceCallback<void(ApplicationContents*, DevToolsContentsResizingStrategy, bool)> result);

  static DevToolsWindow* GetInstanceForInspectedApplicationContents(
    ApplicationContents* inspected_app_contents);

  static bool IsDevToolsWindow(ApplicationContents* app_contents);
  static DevToolsWindow* AsDevToolsWindow(ApplicationContents* app_contents);
  static DevToolsWindow* AsDevToolsWindow(Dock* dock);
  //static DevToolsWindow* FindDevToolsWindow(content::DevToolsAgentHost*);

  // Open or reveal DevTools window, and perform the specified action.
  // How to get pointer to the created window see comments for
  // ToggleDevToolsWindow().
  static void OpenDevToolsWindow(ApplicationContents* inspected_app_contents,
                                 const DevToolsToggleAction& action);

  // Open or reveal DevTools window, with no special action.
  // How to get pointer to the created window see comments for
  // ToggleDevToolsWindow().
  static void OpenDevToolsWindow(ApplicationContents* inspected_app_contents);

  // Open or reveal DevTools window, with no special action. Use |profile| to
  // open client window in, default to |host|'s profile if none given.
  //static void OpenDevToolsWindow(
  //    scoped_refptr<content::DevToolsAgentHost> host);

  // Perform specified action for current ApplicationContents inside a |browser|.
  // This may close currently open DevTools window.
  // If DeveloperToolsAvailability policy disallows developer tools for the
  // current ApplicationContents, no DevTools window created. In case if needed pointer
  // to the created window one should use DevToolsAgentHost and
  // DevToolsWindow::FindDevToolsWindow(). E.g.:
  //
  // scoped_refptr<content::DevToolsAgentHost> agent(
  //   content::DevToolsAgentHost::GetOrCreateFor(inspected_app_contents));
  // DevToolsWindow::ToggleDevToolsWindow(
  //   inspected_app_contents, DevToolsToggleAction::Show());
  // DevToolsWindow* window = DevToolsWindow::FindDevToolsWindow(agent.get());
  //
  static void ToggleDevToolsWindow(
      Dock* dock,
      const DevToolsToggleAction& action,
      DevToolsOpenedByAction opened_by = DevToolsOpenedByAction::kUnknown);

//   static void InspectElement(content::RenderFrameHost* inspected_frame_host,
//                              int x,
//                              int y);

//   static void LogDevToolsOpenedByAction(DevToolsOpenedByAction opened_by);

 // static std::unique_ptr<content::NavigationThrottle>
 // MaybeCreateNavigationThrottle(content::NavigationHandle* handle);

  // Updates the ApplicationContents inspected by the DevToolsWindow by reattaching
  // the binding to |new_app_contents|. Called when swapping an outer
  // ApplicationContents with its inner ApplicationContents.
  void UpdateInspectedApplicationContents(ApplicationContents* new_app_contents,
                                  base::OnceCallback<void()> callback);

  // Sets closure to be called after load is done. If already loaded, calls
  // closure immediately.
  void SetLoadCompletedCallback(base::OnceClosure closure);

  // Forwards an unhandled keyboard event to the DevTools frontend.
  bool ForwardKeyboardEvent(const NativeWebKeyboardEvent& event);

  // Reloads inspected web contents as if it was triggered from DevTools.
  // Returns true if it has successfully handled reload, false if the caller
  // is to proceed reload without DevTools interception.
  bool ReloadInspectedApplicationContents(bool bypass_cache);

  ApplicationContents* OpenURLFromTab(
      ApplicationContents* source,
      const GURL& url);

  ApplicationContents* OpenURLFromInspectedTab(
      const GURL& url);

  // BeforeUnload interception ////////////////////////////////////////////////

  // In order to preserve any edits the user may have made in devtools, the
  // beforeunload event of the inspected page is hooked - devtools gets the
  // first shot at handling beforeunload and presents a dialog to the user. If
  // the user accepts the dialog then the script is given a chance to handle
  // it. This way 2 dialogs may be displayed: one from the devtools asking the
  // user to confirm that they're ok with their devtools edits going away and
  // another from the webpage as the result of its beforeunload handler.
  // The following set of methods handle beforeunload event flow through
  // devtools window. When the |contents| with devtools opened on them are
  // getting closed, the following sequence of calls takes place:
  // 1. |DevToolsWindow::InterceptPageBeforeUnload| is called and indicates
  //    whether devtools intercept the beforeunload event.
  //    If InterceptPageBeforeUnload() returns true then the following steps
  //    will take place; otherwise only step 4 will be reached and none of the
  //    corresponding functions in steps 2 & 3 will get called.
  // 2. |DevToolsWindow::InterceptPageBeforeUnload| fires beforeunload event
  //    for devtools frontend, which will asynchronously call
  //    |ApplicationContentsDelegate::BeforeUnloadFired| method.
  //    In case of docked devtools window, devtools are set as a delegate for
  //    its frontend, so method |DevToolsWindow::BeforeUnloadFired| will be
  //    called directly.
  //    If devtools window is undocked it's not set as the delegate so the call
  //    to BeforeUnloadFired is proxied through HandleBeforeUnload() rather
  //    than getting called directly.
  // 3a. If |DevToolsWindow::BeforeUnloadFired| is called with |proceed|=false
  //     it calls throught to the content's BeforeUnloadFired(), which from the
  //     ApplicationContents perspective looks the same as the |content|'s own
  //     beforeunload dialog having had it's 'stay on this page' button clicked.
  // 3b. If |proceed| = true, then it fires beforeunload event on |contents|
  //     and everything proceeds as it normally would without the Devtools
  //     interception.
  // 4. If the user cancels the dialog put up by either the ApplicationContents or
  //    devtools frontend, then |contents|'s |BeforeUnloadFired| callback is
  //    called with the proceed argument set to false, this causes
  //    |DevToolsWindow::OnPageCloseCancelled| to be called.

  // Devtools window in undocked state is not set as a delegate of
  // its frontend. Instead, an instance of browser is set as the delegate, and
  // thus beforeunload event callback from devtools frontend is not delivered
  // to the instance of devtools window, which is solely responsible for
  // managing custom beforeunload event flow.
  // This is a helper method to route callback from
  // |Browser::BeforeUnloadFired| back to |DevToolsWindow::BeforeUnloadFired|.
  // * |proceed| - true if the user clicked 'ok' in the beforeunload dialog,
  //   false otherwise.
  // * |proceed_to_fire_unload| - output parameter, whether we should continue
  //   to fire the unload event or stop things here.
  // Returns true if devtools window is in a state of intercepting beforeunload
  // event and if it will manage unload process on its own.
  static bool HandleBeforeUnload(ApplicationContents* contents,
                                 bool proceed,
                                 bool* proceed_to_fire_unload);

  // Returns true if this contents beforeunload event was intercepted by
  // devtools and false otherwise. If the event was intercepted, caller should
  // not fire beforeunlaod event on |contents| itself as devtools window will
  // take care of it, otherwise caller should continue handling the event as
  // usual.
  static bool InterceptPageBeforeUnload(ApplicationContents* contents);

  // Returns true if devtools browser has already fired its beforeunload event
  // as a result of beforeunload event interception.
  static bool HasFiredBeforeUnloadEventForDevToolsDock(Dock* browser);

  // Returns true if devtools window would like to hook beforeunload event
  // of this |contents|.
  static bool NeedsToInterceptBeforeUnload(ApplicationContents* contents);

  // Notify devtools window that closing of |contents| was cancelled
  // by user.
  static void OnPageCloseCanceled(ApplicationContents* contents);

  static bool HaveAnyInstance();

  ApplicationContents* GetInspectedApplicationContents();

 private:

  using CreationCallback = base::RepeatingCallback<void(DevToolsWindow*)>;

//   static void OpenDevToolsWindowForFrame(
//       Profile* profile,
//       const scoped_refptr<content::DevToolsAgentHost>& agent_host);
//   static void OpenDevToolsWindowForWorker(
//       Profile* profile,
//       const scoped_refptr<content::DevToolsAgentHost>& worker_agent);

  // DevTools lifecycle typically follows this way:
  // - Toggle/Open: client call;
  // - Create;
  // - ScheduleShow: setup window to be functional, but not yet show;
  // - DocumentOnLoadCompletedInMainFrame: frontend loaded;
  // - SetIsDocked: frontend decided on docking state;
  // - OnLoadCompleted: ready to present frontend;
  // - Show: actually placing frontend ApplicationContents to a Browser or docked place;
  // - DoAction: perform action passed in Toggle/Open;
  // - ...;
  // - CloseWindow: initiates before unload handling;
  // - CloseContents: destroys frontend;
  // - DevToolsWindow is dead once it's main_app_contents dies.
  enum LifeStage {
    kNotLoaded,
    kOnLoadFired, // Implies SetIsDocked was not yet called.
    kIsDockedSet, // Implies DocumentOnLoadCompleted was not yet called.
    kLoadCompleted,
    kClosing
  };

  enum FrontendType {
    kFrontendDefault,
    kFrontendWorker,
    kFrontendV8,
    kFrontendRemote,
    kFrontendRemoteWorker,
  };

  DevToolsWindow(FrontendType frontend_type,
                 scoped_refptr<Workspace> workspace,
                 Domain* domain,
                 //ApplicationContents* main_app_contents,
                 //DevToolsUIBindings* bindings,
                 ApplicationContents* inspected_app_contents,
                 bool can_dock);

  // External frontend is always undocked.
//   static void OpenExternalFrontend(
//       Workspace* workspace,
//       const std::string& frontend_uri,
//       const scoped_refptr<content::DevToolsAgentHost>& agent_host,
//       bool use_bundled_frontend);
//   static void OpenDevToolsWindow(scoped_refptr<content::DevToolsAgentHost> host,
//                                  Profile* profile,
//                                  bool use_bundled_frontend);

  static DevToolsWindow* Create(scoped_refptr<Workspace> workspace,
                                ApplicationContents* inspected_app_contents,
                                FrontendType frontend_type,
                                const std::string& frontend_url,
                                bool can_dock,
                                const std::string& settings,
                                const std::string& panel,
                                bool has_other_clients);
  static GURL GetDevToolsURL(scoped_refptr<Workspace> workspace,
                             FrontendType frontend_type,
                             const std::string& frontend_url,
                             bool can_dock,
                             const std::string& panel,
                             bool has_other_clients);

  static void ToggleDevToolsWindow(
      ApplicationContents* app_contents,
      bool force_open,
      const DevToolsToggleAction& action,
      const std::string& settings,
      DevToolsOpenedByAction opened_by = DevToolsOpenedByAction::kUnknown);

  // content::ApplicationContentsDelegate:
  void ActivateContents(ApplicationContents* contents) override;
  void AddNewContents(const std::string& app_name,
                      ApplicationContents* source,
                      ApplicationContents* new_contents,
                      WindowOpenDisposition disposition,
                      const gfx::Rect& initial_rect,
                      bool user_gesture,
                      bool* was_blocked) override;
  void ApplicationContentsCreated(ApplicationContents* source_contents,
                                  int opener_render_process_id,
                                  int opener_render_frame_id,
                                  const std::string& frame_name,
                                  const GURL& target_url,
                                  ApplicationContents* new_contents) override;
  void CloseContents(ApplicationContents* source) override;
  void ContentsZoomChange(bool zoom_in) override;
  void BeforeUnloadFired(ApplicationContents* tab,
                         bool proceed,
                         bool* proceed_to_fire_unload) override;
  KeyboardEventProcessingResult PreHandleKeyboardEvent(
      ApplicationContents* source,
      const NativeWebKeyboardEvent& event) override;
  void HandleKeyboardEvent(
      ApplicationContents* source,
      const NativeWebKeyboardEvent& event) override;
  bool PreHandleGestureEvent(ApplicationContents* source,
                             const blink::WebGestureEvent& event) override;

  // content::DevToolsUIBindings::Delegate overrides
  // void ActivateWindow() override;
  // void CloseWindow() override;
  // //void Inspect(scoped_refptr<content::DevToolsAgentHost> host) override;
  // void SetInspectedPageBounds(const gfx::Rect& rect) override;
  // void InspectElementCompleted() override;
  // void SetIsDocked(bool is_docked) override;
  // void OpenInNewTab(const std::string& url) override;
  // void InspectedContentsClosing() override;
  // void OnLoadCompleted() override;
  // void ConnectionReady() override;
  // void SetOpenNewWindowForPopups(bool value) override;
  // void DomainProcessGone(bool crashed) override;
  // void ShowCertificateViewer(const std::string& cert_viewer) override;

  void ActivateWindow();
  void CloseWindow();
  //void Inspect(scoped_refptr<content::DevToolsAgentHost> host) override;
  void SetInspectedPageBounds(const gfx::Rect& rect);
  void InspectElementCompleted();
  void SetIsDocked(bool is_docked);
  void OpenInNewTab(const std::string& url);
  void InspectedContentsClosing();
  void OnLoadCompleted();
  void ConnectionReady();
  void SetOpenNewWindowForPopups(bool value);
  void ApplicationProcessGone(bool crashed);
  //void ShowCertificateViewer(const std::string& cert_viewer);

  // This method creates a new Browser object (if possible), and passes
  // ownership of owned_main_app_contents_ to the tab strip of the Browser.
  void CreateDevToolsDock();
  DockWindow* GetInspectedDockWindow();
  void ScheduleShow(const DevToolsToggleAction& action);
  void Show(const DevToolsToggleAction& action);
  void DoAction(const DevToolsToggleAction& action);
  void LoadCompleted();
  void UpdateDockToolbar();
  void UpdateDockWindow();

  // Registers a ApplicationContentsModalDialogManager for our ApplicationContents in order to
  // display web modal dialogs triggered by it.
  void RegisterModalDialogManager(Dock* dock);

  void OnReattachMainTargetComplete(base::Value);

  // Called when the accepted language changes. |navigator.language| of the
  // DevTools window should match the application language. When the user
  // changes the accepted language then this listener flips the language back
  // to the application language for the DevTools renderer process.
  // Please note that |navigator.language| will have the wrong language for
  // a very short period of time (until this handler has reset it again).
  void OnLocaleChanged();

  // Domain::Observer
  void OnApplicationLaunched(Domain* domain, Application* application) override;
  void OnApplicationInitialized(Domain* domain, Application* application) override;
  void OnApplicationShutdown(Domain* domain, Application* application) override;

 
  std::unique_ptr<ObserverWithAccessor> inspected_contents_observer_;

  FrontendType frontend_type_;
  scoped_refptr<Workspace> workspace_;
  Domain* domain_;
  ApplicationContents* main_app_contents_;
  gfx::Size main_app_contents_size_;

  // DevToolsWindow is informed of the creation of the |toolbox_app_contents_|
  // in ApplicationContentsCreated right before ownership is passed to to DevToolsWindow
  // in AddNewContents(). The former call has information not available in the
  // latter, so it's easiest to record a raw pointer first in
  // |toolbox_app_contents_|, and then update ownership immediately afterwards.
  // TODO(erikchen): If we updated AddNewContents() to also pass back the
  // target url, then we wouldn't need to listen to ApplicationContentsCreated at all.
  ApplicationContents* toolbox_app_contents_;
  std::unique_ptr<ApplicationContents> owned_toolbox_app_contents_;

  //DevToolsUIBindings* bindings_;
  Dock* dock_;

  // When DevToolsWindow is docked, it owns main_app_contents_. When it isn't
  // docked, the tab strip model owns the main_app_contents_.
  bool is_docked_;
  class OwnedMainApplicationContents;
  std::unique_ptr<OwnedMainApplicationContents> owned_main_app_contents_;

  const bool can_dock_;
  bool close_on_detach_;
  LifeStage life_stage_;
  DevToolsToggleAction action_on_load_;
  DevToolsContentsResizingStrategy contents_resizing_strategy_;
  // True if we're in the process of handling a beforeunload event originating
  // from the inspected webcontents, see InterceptPageBeforeUnload for details.
  bool intercepted_page_beforeunload_;
  base::OnceClosure load_completed_callback_;
  base::OnceClosure close_callback_;
  bool ready_for_test_;
  base::OnceClosure ready_for_test_callback_;

  base::TimeTicks inspect_element_start_time_;
  std::unique_ptr<DevToolsEventForwarder> event_forwarder_;

  //class Throttle;
  //Throttle* throttle_ = nullptr;
  bool open_new_window_for_popups_ = false;

  base::OnceCallback<void()> reattach_complete_callback_;
  base::OnceCallback<void(ApplicationContents*, DevToolsContentsResizingStrategy, bool)> contents_complete_callback_;

  friend class DevToolsEventForwarder;
  DISALLOW_COPY_AND_ASSIGN(DevToolsWindow);
};

}

#endif  // CHROME_BROWSER_DEVTOOLS_DEVTOOLS_WINDOW_H_
