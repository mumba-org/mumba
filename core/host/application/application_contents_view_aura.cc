// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/application/application_contents_view_aura.h"

#include <stddef.h>
#include <stdint.h>

#include "base/auto_reset.h"
#include "base/command_line.h"
#include "base/files/file_util.h"
#include "base/macros.h"
#include "base/message_loop/message_loop_current.h"
#include "base/strings/utf_string_conversions.h"
#include "build/build_config.h"
#include "components/viz/common/features.h"
//#include "core/host/download/drag_download_util.h"
//#include "core/host/frame_host/navigation_entry_impl.h"
#include "core/host/application/dip_util.h"
#include "core/host/application/display_util.h"
#include "core/host/application/interstitial_page_impl.h"
#include "core/host/application/input/touch_selection_controller_client_aura.h"
#include "core/host/application/overscroll_controller.h"
#include "core/host/application/application_window_host.h"
#include "core/host/application/application_window_host_view.h"
#include "core/host/application/application_window_host_factory.h"
#include "core/host/application/application_window_host_input_event_router.h"
#include "core/host/application/application_window_host_view_aura.h"
#include "core/host/application/application_contents.h"
#include "core/host/application/application_contents_delegate.h"
#include "core/host/application/application_contents_observer.h"
#include "core/host/application/application_contents_view_delegate.h"
#include "core/host/application/application_drag_dest_delegate.h"
//#include "core/host/application/aura/gesture_nav_simple.h"
//#include "core/host/application/aura/overscroll_navigation_overlay.h"
#include "core/host/host_client.h"
#include "core/host/notification_observer.h"
#include "core/host/notification_registrar.h"
#include "core/host/notification_source.h"
#include "core/host/notification_types.h"
#include "core/host/ui/tablist/sad_tab_helper.h"
#include "core/host/application/overscroll_configuration.h"
#include "core/shared/common/child_process_host.h"
#include "core/shared/common/client.h"
#include "core/shared/common/switches.h"
#include "core/shared/common/drop_data.h"
#include "net/base/filename_util.h"
#include "third_party/blink/public/platform/web_input_event.h"
#include "ui/aura/client/aura_constants.h"
#include "ui/aura/client/drag_drop_client.h"
#include "ui/aura/client/drag_drop_delegate.h"
#include "ui/aura/client/screen_position_client.h"
#include "ui/aura/client/window_parenting_client.h"
#include "ui/aura/env.h"
#include "ui/aura/window.h"
#include "ui/aura/window_observer.h"
#include "ui/aura/window_occlusion_tracker.h"
#include "ui/aura/window_tree_host.h"
#include "ui/aura/window_tree_host_observer.h"
#include "ui/base/clipboard/clipboard.h"
#include "ui/base/clipboard/custom_data_helper.h"
#include "ui/base/dragdrop/drag_drop_types.h"
#include "ui/base/dragdrop/drop_target_event.h"
#include "ui/base/dragdrop/os_exchange_data.h"
#include "ui/base/dragdrop/os_exchange_data_provider_factory.h"
#include "ui/base/hit_test.h"
#include "ui/base/ui_base_features.h"
#include "ui/base/ui_base_switches_util.h"
#include "ui/compositor/layer.h"
#include "ui/display/display.h"
#include "ui/display/screen.h"
#include "ui/events/blink/web_input_event.h"
#include "ui/events/event.h"
#include "ui/events/event_utils.h"
#include "ui/gfx/canvas.h"
#include "ui/gfx/image/image.h"
#include "ui/gfx/image/image_png_rep.h"
#include "ui/gfx/image/image_skia.h"
#include "ui/touch_selection/touch_selection_controller.h"

namespace host {

namespace {

ApplicationContentsViewAura::ApplicationWindowHostViewCreateFunction
    g_create_application_window_host_view = nullptr;

ApplicationWindowHostViewAura* ToApplicationWindowHostViewAura(
    ApplicationWindowHostView* view) {
  if (!view || (ApplicationWindowHostFactory::has_factory() &&
      !ApplicationWindowHostFactory::is_real_application_window_host())) {
    return nullptr;  // Can't cast to ApplicationWindowHostViewAura in unit tests.
  }

  //ApplicationWindowHost* rvh = view->GetApplicationWindowHost();
  //ApplicationContents* app_contents = 
  //    rvh ? ApplicationContents::FromApplicationWindowHost(rvh) : nullptr;
  //if (BrowserPluginGuest::IsGuest(app_contents))
  //  return nullptr;
  return static_cast<ApplicationWindowHostViewAura*>(view);
}

// Listens to all mouse drag events during a drag and drop and sends them to
// the renderer.
class WebDragSourceAura : public NotificationObserver {
 public:
  WebDragSourceAura(aura::Window* window, ApplicationContents* contents)
      : window_(window),
        contents_(contents) {
    registrar_.Add(this,
                   NOTIFICATION_WEB_CONTENTS_DISCONNECTED,
                   Source<ApplicationContents>(contents));
  }

  ~WebDragSourceAura() override {}

  // NotificationObserver:
  void Observe(int type,
               const NotificationSource& source,
               const NotificationDetails& details) override {
    if (type != NOTIFICATION_WEB_CONTENTS_DISCONNECTED)
      return;

    // Cancel the drag if it is still in progress.
    aura::client::DragDropClient* dnd_client =
        aura::client::GetDragDropClient(window_->GetRootWindow());
    if (dnd_client && dnd_client->IsDragDropInProgress())
      dnd_client->DragCancel();

    window_ = nullptr;
    contents_ = nullptr;
  }

  aura::Window* window() const { return window_; }

 private:
  aura::Window* window_;
  ApplicationContents* contents_;
  NotificationRegistrar registrar_;

  DISALLOW_COPY_AND_ASSIGN(WebDragSourceAura);
};

#if defined(USE_X11) || defined(OS_WIN)
// Fill out the OSExchangeData with a file contents, synthesizing a name if
// necessary.
void PrepareDragForFileContents(const common::DropData& drop_data,
                                ui::OSExchangeData::Provider* provider) {
  base::Optional<base::FilePath> filename =
      drop_data.GetSafeFilenameForImageFileContents();
  if (filename)
    provider->SetFileContents(*filename, drop_data.file_contents);
}
#endif

// #if defined(OS_WIN)
// void PrepareDragForDownload(
//     const common::DropData& drop_data,
//     ui::OSExchangeData::Provider* provider,
//     ApplicationContents* app_contents) {
//   const GURL& page_url = app_contents->GetLastCommittedURL();
//   const std::string& page_encoding = app_contents->GetEncoding();

//   // Parse the download metadata.
//   base::string16 mime_type;
//   base::FilePath file_name;
//   GURL download_url;
//   if (!ParseDownloadMetadata(drop_data.download_metadata,
//                              &mime_type,
//                              &file_name,
//                              &download_url))
//     return;

//   // Generate the file name based on both mime type and proposed file name.
//   std::string default_name =
//       common::GetClient()->host()->GetDefaultDownloadName();
//   base::FilePath generated_download_file_name =
//       net::GenerateFileName(download_url,
//                             std::string(),
//                             std::string(),
//                             base::UTF16ToUTF8(file_name.value()),
//                             base::UTF16ToUTF8(mime_type),
//                             default_name);

//   // http://crbug.com/332579
//   base::ThreadRestrictions::ScopedAllowIO allow_file_operations;

//   base::FilePath temp_dir_path;
//   if (!base::CreateNewTempDirectory(FILE_PATH_LITERAL("chrome_drag"),
//                                     &temp_dir_path))
//     return;

//   base::FilePath download_path =
//       temp_dir_path.Append(generated_download_file_name);

//   // We cannot know when the target application will be done using the temporary
//   // file, so schedule it to be deleted after rebooting.
//   base::DeleteFileAfterReboot(download_path);
//   base::DeleteFileAfterReboot(temp_dir_path);

//   // Provide the data as file (CF_HDROP). A temporary download file with the
//   // Zone.Identifier ADS (Alternate Data Stream) attached will be created.
//   scoped_refptr<DragDownloadFile> download_file =
//       new DragDownloadFile(
//           download_path,
//           base::File(),
//           download_url,
//           Referrer(page_url, drop_data.referrer_policy),
//           page_encoding,
//           app_contents);
//   ui::OSExchangeData::DownloadFileInfo file_download(base::FilePath(),
//                                                      download_file.get());
//   provider->SetDownloadFileInfo(file_download);
// }
// #endif  // defined(OS_WIN)

// Returns the FormatType to store file system files.
const ui::Clipboard::FormatType& GetFileSystemFileFormatType() {
  static const char kFormatString[] = "chromium/x-file-system-files";
  CR_DEFINE_STATIC_LOCAL(ui::Clipboard::FormatType,
                         format,
                         (ui::Clipboard::GetFormatType(kFormatString)));
  return format;
}


// Utility to fill a ui::OSExchangeDataProvider object from DropData.
void PrepareDragData(const common::DropData& drop_data,
                     ui::OSExchangeData::Provider* provider,
                     ApplicationContents* app_contents) {
  provider->MarkOriginatedFromRenderer();
// #if defined(OS_WIN)
//   // Put download before file contents to prefer the download of a image over
//   // its thumbnail link.
//   if (!drop_data.download_metadata.empty())
//     PrepareDragForDownload(drop_data, provider, app_contents);
// #endif
#if defined(USE_X11) || defined(OS_WIN)
  // We set the file contents before the URL because the URL also sets file
  // contents (to a .URL shortcut).  We want to prefer file content data over
  // a shortcut so we add it first.
  if (!drop_data.file_contents.empty())
    PrepareDragForFileContents(drop_data, provider);
#endif
  // Call SetString() before SetURL() when we actually have a custom string.
  // SetURL() will itself do SetString() when a string hasn't been set yet,
  // but we want to prefer drop_data.text.string() over the URL string if it
  // exists.
  if (!drop_data.text.string().empty())
    provider->SetString(drop_data.text.string());
  if (drop_data.url.is_valid())
    provider->SetURL(drop_data.url, drop_data.url_title);
  if (!drop_data.html.string().empty())
    provider->SetHtml(drop_data.html.string(), drop_data.html_base_url);
  if (!drop_data.filenames.empty())
    provider->SetFilenames(drop_data.filenames);
  if (!drop_data.file_system_files.empty()) {
    base::Pickle pickle;
    common::DropData::FileSystemFileInfo::WriteFileSystemFilesToPickle(
        drop_data.file_system_files, &pickle);
    provider->SetPickledData(GetFileSystemFileFormatType(), pickle);
  }
  if (!drop_data.custom_data.empty()) {
    base::Pickle pickle;
    ui::WriteCustomDataToPickle(drop_data.custom_data, &pickle);
    provider->SetPickledData(ui::Clipboard::GetWebCustomDataFormatType(),
                             pickle);
  }
}

// Utility to fill a DropData object from ui::OSExchangeData.
void PrepareDropData(common::DropData* drop_data, const ui::OSExchangeData& data) {
  drop_data->did_originate_from_renderer = data.DidOriginateFromRenderer();

  base::string16 plain_text;
  data.GetString(&plain_text);
  if (!plain_text.empty())
    drop_data->text = base::NullableString16(plain_text, false);

  GURL url;
  base::string16 url_title;
  data.GetURLAndTitle(
      ui::OSExchangeData::DO_NOT_CONVERT_FILENAMES, &url, &url_title);
  if (url.is_valid()) {
    drop_data->url = url;
    drop_data->url_title = url_title;
  }

  base::string16 html;
  GURL html_base_url;
  data.GetHtml(&html, &html_base_url);
  if (!html.empty())
    drop_data->html = base::NullableString16(html, false);
  if (html_base_url.is_valid())
    drop_data->html_base_url = html_base_url;

  data.GetFilenames(&drop_data->filenames);

  base::Pickle pickle;
  std::vector<common::DropData::FileSystemFileInfo> file_system_files;
  if (data.GetPickledData(GetFileSystemFileFormatType(), &pickle) &&
      common::DropData::FileSystemFileInfo::ReadFileSystemFilesFromPickle(
          pickle, &file_system_files))
    drop_data->file_system_files = file_system_files;

  if (data.GetPickledData(ui::Clipboard::GetWebCustomDataFormatType(), &pickle))
    ui::ReadCustomDataIntoMap(
        pickle.data(), pickle.size(), &drop_data->custom_data);
}

// Utilities to convert between blink::WebDragOperationsMask and
// ui::DragDropTypes.
int ConvertFromWeb(blink::WebDragOperationsMask ops) {
  int drag_op = ui::DragDropTypes::DRAG_NONE;
  if (ops & blink::kWebDragOperationCopy)
    drag_op |= ui::DragDropTypes::DRAG_COPY;
  if (ops & blink::kWebDragOperationMove)
    drag_op |= ui::DragDropTypes::DRAG_MOVE;
  if (ops & blink::kWebDragOperationLink)
    drag_op |= ui::DragDropTypes::DRAG_LINK;
  return drag_op;
}

blink::WebDragOperationsMask ConvertToWeb(int drag_op) {
  int web_drag_op = blink::kWebDragOperationNone;
  if (drag_op & ui::DragDropTypes::DRAG_COPY)
    web_drag_op |= blink::kWebDragOperationCopy;
  if (drag_op & ui::DragDropTypes::DRAG_MOVE)
    web_drag_op |= blink::kWebDragOperationMove;
  if (drag_op & ui::DragDropTypes::DRAG_LINK)
    web_drag_op |= blink::kWebDragOperationLink;
  return (blink::WebDragOperationsMask) web_drag_op;
}

GlobalRoutingID GetApplicationWindowHostID(ApplicationWindowHost* rvh) {
  return GlobalRoutingID(rvh->GetProcess()->GetID(), rvh->GetRoutingID());
}

}  // namespace

class ApplicationContentsViewAura::WindowObserver
    : public aura::WindowObserver, public aura::WindowTreeHostObserver {
 public:
  explicit WindowObserver(ApplicationContentsViewAura* view)
      : view_(view), host_window_(nullptr) {
    view_->window_->AddObserver(this);
  }

  ~WindowObserver() override {
    view_->window_->RemoveObserver(this);
    if (view_->window_->GetHost())
      view_->window_->GetHost()->RemoveObserver(this);
    if (host_window_)
      host_window_->RemoveObserver(this);
  }

  void OnWindowParentChanged(aura::Window* window,
                             aura::Window* parent) override {
    if (window != view_->window_.get())
      return;

    aura::Window* host_window =
      window->GetProperty(aura::client::kHostWindowKey);

    if (!host_window) {
      host_window = parent;
    }

    if (host_window_)
      host_window_->RemoveObserver(this);

    host_window_ = host_window;
    if (host_window)
      host_window->AddObserver(this);
  }

  void OnWindowBoundsChanged(aura::Window* window,
                             const gfx::Rect& old_bounds,
                             const gfx::Rect& new_bounds,
                             ui::PropertyChangeReason reason) override {
    if (window == host_window_ || window == view_->window_.get()) {
      SendScreenRects();
      if (old_bounds.origin() != new_bounds.origin()) {
        TouchSelectionControllerClientAura* selection_controller_client =
            view_->GetSelectionControllerClient();
        if (selection_controller_client)
          selection_controller_client->OnWindowMoved();
      }
    }
  }

  void OnWindowDestroying(aura::Window* window) override {
    if (window == host_window_) {
      host_window_->RemoveObserver(this);
      host_window_ = nullptr;
    }
  }

  void OnWindowAddedToRootWindow(aura::Window* window) override {
    if (window == view_->window_.get())
      window->GetHost()->AddObserver(this);
  }

  void OnWindowRemovingFromRootWindow(aura::Window* window,
                                      aura::Window* new_root) override {
    if (window == view_->window_.get())
      window->GetHost()->RemoveObserver(this);
  }

  void OnWindowPropertyChanged(aura::Window* window,
                               const void* key,
                               intptr_t old) override {
    if (key != aura::client::kMirroringEnabledKey)
      return;
    if (window->GetProperty(aura::client::kMirroringEnabledKey))
      view_->app_contents_->IncrementCapturerCount(gfx::Size());
    else
      view_->app_contents_->DecrementCapturerCount();
  }

  // Overridden WindowTreeHostObserver:
  void OnHostMovedInPixels(aura::WindowTreeHost* host,
                           const gfx::Point& new_origin_in_pixels) override {
    TRACE_EVENT1("ui",
                 "ApplicationContentsViewAura::WindowObserver::OnHostMovedInPixels",
                 "new_origin_in_pixels", new_origin_in_pixels.ToString());

    // This is for the desktop case (i.e. Aura desktop).
    SendScreenRects();
  }

 private:
  void SendScreenRects() { view_->app_contents_->SendScreenRects(); }

  ApplicationContentsViewAura* view_;

  // The parent window that hosts the constrained windows. We cache the old host
  // view so that we can unregister when it's not the parent anymore.
  aura::Window* host_window_;

  DISALLOW_COPY_AND_ASSIGN(WindowObserver);
};

ApplicationContentsView* CreateApplicationContentsView(
    ApplicationContents* app_contents,
    ApplicationContentsViewDelegate* delegate,
    ApplicationWindowHostDelegateView** app_window_host_delegate_view) {
  ApplicationContentsViewAura* av = new ApplicationContentsViewAura(app_contents, delegate);
  *app_window_host_delegate_view = av;
  return av;
}

// static
void ApplicationContentsViewAura::InstallCreateHookForTests(
    ApplicationWindowHostViewCreateFunction create_application_window_host_view) {
  CHECK_EQ(nullptr, g_create_application_window_host_view);
  g_create_application_window_host_view = create_application_window_host_view;
}

////////////////////////////////////////////////////////////////////////////////
// ApplicationContentsViewAura, public:

ApplicationContentsViewAura::ApplicationContentsViewAura(
  ApplicationContents* app_contents,
  ApplicationContentsViewDelegate* delegate)
    : app_contents_(app_contents),
      delegate_(delegate),
      current_drag_op_(blink::kWebDragOperationNone),
      drag_dest_delegate_(nullptr),
      current_rvh_for_drag_(common::ChildProcessHost::kInvalidUniqueID,
                            MSG_ROUTING_NONE),
      drag_start_process_id_(common::ChildProcessHost::kInvalidUniqueID),
      drag_start_view_id_(common::ChildProcessHost::kInvalidUniqueID, MSG_ROUTING_NONE),
      current_overscroll_gesture_(OVERSCROLL_NONE),
      completed_overscroll_gesture_(OVERSCROLL_NONE)
//      navigation_overlay_(nullptr)
     {}

void ApplicationContentsViewAura::SetDelegateForTesting(
    ApplicationContentsViewDelegate* delegate) {
  delegate_.reset(delegate);
}

////////////////////////////////////////////////////////////////////////////////
// ApplicationContentsViewAura, private:

ApplicationContentsViewAura::~ApplicationContentsViewAura() {
  if (!window_)
    return;

  window_observer_.reset();

  // Window needs a valid delegate during its destructor, so we explicitly
  // delete it here.
  window_.reset();
}

void ApplicationContentsViewAura::SizeChangedCommon(const gfx::Size& size) {
  if (app_contents_->GetInterstitialPage())
    app_contents_->GetInterstitialPage()->SetSize(size);

  ApplicationWindowHostView* rwhv =
      app_contents_->GetApplicationWindowHostView();
  if (rwhv)
    rwhv->SetSize(size);
}

void ApplicationContentsViewAura::EndDrag(ApplicationWindowHost* source_rwh,
                                          blink::WebDragOperationsMask ops) {
  drag_start_process_id_ = common::ChildProcessHost::kInvalidUniqueID;
  drag_start_view_id_ = GlobalRoutingID(common::ChildProcessHost::kInvalidUniqueID,
                                        MSG_ROUTING_NONE);

  if (!app_contents_)
    return;

  aura::Window* window = GetContentNativeView();
  gfx::PointF screen_loc =
      gfx::PointF(display::Screen::GetScreen()->GetCursorScreenPoint());
  gfx::PointF client_loc = screen_loc;
  aura::client::ScreenPositionClient* screen_position_client =
      aura::client::GetScreenPositionClient(window->GetRootWindow());
  if (screen_position_client)
    screen_position_client->ConvertPointFromScreen(window, &client_loc);

  // |client_loc| and |screen_loc| are in the root coordinate space, for
  // non-root ApplicationWindowHosts they need to be transformed.
  gfx::PointF transformed_point = client_loc;
  gfx::PointF transformed_screen_point = screen_loc;
  if (source_rwh && app_contents_->GetApplicationWindowHostView()) {
    static_cast<ApplicationWindowHostView*>(
        app_contents_->GetApplicationWindowHostView())
        ->TransformPointToCoordSpaceForView(
            client_loc,
            static_cast<ApplicationWindowHostView*>(source_rwh->GetView()),
            &transformed_point);
    static_cast<ApplicationWindowHostView*>(
        app_contents_->GetApplicationWindowHostView())
        ->TransformPointToCoordSpaceForView(
            screen_loc,
            static_cast<ApplicationWindowHostView*>(source_rwh->GetView()),
            &transformed_screen_point);
  }

  app_contents_->DragSourceEndedAt(transformed_point.x(), transformed_point.y(),
                                   transformed_screen_point.x(),
                                   transformed_screen_point.y(), ops,
                                   source_rwh);

  app_contents_->SystemDragEnded(source_rwh);
}

void ApplicationContentsViewAura::InstallOverscrollControllerDelegate(
    ApplicationWindowHostViewAura* view) {
  const OverscrollConfig::HistoryNavigationMode mode =
      OverscrollConfig::GetHistoryNavigationMode();
  switch (mode) {
    case OverscrollConfig::HistoryNavigationMode::kDisabled:
   //   navigation_overlay_.reset();
      break;
    case OverscrollConfig::HistoryNavigationMode::kParallaxUi:
      view->overscroll_controller()->set_delegate(this);
//      if (!navigation_overlay_) {
//        navigation_overlay_.reset(
//            new OverscrollNavigationOverlay(app_contents_, window_.get()));
//      }
      break;
    case OverscrollConfig::HistoryNavigationMode::kSimpleUi:
  //    navigation_overlay_.reset();
  //    if (!gesture_nav_simple_)
  //      gesture_nav_simple_.reset(new GestureNavSimple(app_contents_));
 //     view->overscroll_controller()->set_delegate(gesture_nav_simple_.get());
      break;
  }
}

void ApplicationContentsViewAura::CompleteOverscrollNavigation(OverscrollMode mode) {
  if (!app_contents_->GetApplicationWindowHostView())
    return;
  //navigation_overlay_->relay_delegate()->OnOverscrollComplete(mode);
  ui::TouchSelectionController* selection_controller = GetSelectionController();
  if (selection_controller)
    selection_controller->HideAndDisallowShowingAutomatically();
}

ui::TouchSelectionController* ApplicationContentsViewAura::GetSelectionController()
    const {
  ApplicationWindowHostViewAura* view =
      ToApplicationWindowHostViewAura(app_contents_->GetApplicationWindowHostView());
  return view ? view->selection_controller() : nullptr;
}

TouchSelectionControllerClientAura*
ApplicationContentsViewAura::GetSelectionControllerClient() const {
  SadTabHelper* sad_tab_helper =
          SadTabHelper::FromApplicationContents(app_contents_);
  if (sad_tab_helper && sad_tab_helper->sad_tab()) {
    return nullptr;
  }
  ApplicationWindowHostViewAura* view =
      ToApplicationWindowHostViewAura(app_contents_->GetApplicationWindowHostView());
  return view ? view->selection_controller_client() : nullptr;
}

gfx::NativeView ApplicationContentsViewAura::GetApplicationWindowHostViewParent() const {
  //if (init_rwhv_with_null_parent_for_testing_)
  //  return nullptr;
  return window_.get();
}

bool ApplicationContentsViewAura::IsValidDragTarget(
    ApplicationWindowHost* target_rwh) const {
  return target_rwh->GetProcess()->GetID() == drag_start_process_id_ ||
      GetApplicationWindowHostID(app_contents_->GetApplicationWindowHost()) !=
      drag_start_view_id_;
}

////////////////////////////////////////////////////////////////////////////////
// ApplicationContentsViewAura, ApplicationContentsView implementation:

gfx::NativeView ApplicationContentsViewAura::GetNativeView() const {
  //if (!is_mus_browser_plugin_guest_)
  return window_.get();
  //DCHECK(app_contents_->GetOuterApplicationContents());
  //return app_contents_->GetOuterApplicationContents()->GetView()->GetNativeView();
}

gfx::NativeView ApplicationContentsViewAura::GetContentNativeView() const {
  //if (!is_mus_browser_plugin_guest_) {
   ApplicationWindowHostView* awhv = app_contents_->GetApplicationWindowHostView();
   DCHECK(awhv);
   return awhv->GetNativeView();
  //}
  //DCHECK(app_contents_->GetOuterApplicationContents());
  //return app_contents_->GetOuterApplicationContents()
  //    ->GetView()
  //    ->GetContentNativeView();
}

gfx::NativeWindow ApplicationContentsViewAura::GetTopLevelNativeWindow() const {
  //if (!is_mus_browser_plugin_guest_) {
    gfx::NativeWindow window = window_->GetToplevelWindow();
    return window ? window : window_.get();//delegate_->GetNativeWindow();
  //}
 // DCHECK(app_contents_->GetOuterApplicationContents());
  //return app_contents_->GetOuterApplicationContents()
 //     ->GetView()
 //     ->GetTopLevelNativeWindow();
}

void ApplicationContentsViewAura::GetContainerBounds(gfx::Rect* out) const {
  *out = GetNativeView()->GetBoundsInScreen();
}

void ApplicationContentsViewAura::SizeContents(const gfx::Size& size) {
  gfx::Rect bounds = window_->bounds();
  if (bounds.size() != size) {
    bounds.set_size(size);
    window_->SetBounds(bounds);
  } else {
    // Our size matches what we want but the renderers size may not match.
    // Pretend we were resized so that the renderers size is updated too.
    SizeChangedCommon(size);
  }
}

void ApplicationContentsViewAura::Focus() {
  if (delegate_)
    delegate_->ResetStoredFocus();

  if (app_contents_->GetInterstitialPage()) {
    app_contents_->GetInterstitialPage()->Focus();
    return;
  }

  if (delegate_ && delegate_->Focus())
    return;

  SadTabHelper* sad_tab_helper =
          SadTabHelper::FromApplicationContents(app_contents_);
  if (sad_tab_helper && sad_tab_helper->sad_tab()) {
    return;
  }  

  ApplicationWindowHostView* rwhv =
      app_contents_->GetFullscreenApplicationWindowHostView();
  if (!rwhv)
    rwhv = app_contents_->GetApplicationWindowHostView();
  if (rwhv)
    rwhv->Focus();
}

void ApplicationContentsViewAura::SetInitialFocus() {
  if (delegate_)
    delegate_->ResetStoredFocus();

  //if (app_contents_->FocusLocationBarByDefault())
  //  app_contents_->SetFocusToLocationBar(false);
  //else
    Focus();
}

void ApplicationContentsViewAura::StoreFocus() {
  if (delegate_)
    delegate_->StoreFocus();
}

void ApplicationContentsViewAura::RestoreFocus() {
  if (delegate_ && delegate_->RestoreFocus())
    return;
  SetInitialFocus();
}

void ApplicationContentsViewAura::FocusThroughWindowTraversal(bool reverse) {
  if (delegate_)
    delegate_->ResetStoredFocus();

  if (app_contents_->ShowingInterstitialPage()) {
    app_contents_->GetInterstitialPage()->FocusThroughTabTraversal(reverse);
    return;
  }
  ApplicationWindowHostView* fullscreen_view =
      app_contents_->GetFullscreenApplicationWindowHostView();
  if (fullscreen_view) {
    fullscreen_view->Focus();
    return;
  }
  app_contents_->GetApplicationWindowHost()->SetInitialFocus(reverse);
}

common::DropData* ApplicationContentsViewAura::GetDropData() const {
  return current_drop_data_.get();
}

gfx::Rect ApplicationContentsViewAura::GetViewBounds() const {
  return GetNativeView()->GetBoundsInScreen();
}

void ApplicationContentsViewAura::CreateAuraWindow(aura::Window* context) {
  DCHECK(aura::Env::GetInstanceDontCreate());
  DCHECK(!window_);
  window_ = std::make_unique<aura::Window>(this);
  window_->set_owned_by_parent(false);
  window_->SetType(aura::client::WINDOW_TYPE_CONTROL);
  window_->SetName("ApplicationContentsViewAura");
  window_->Init(ui::LAYER_NOT_DRAWN);
  aura::Window* root_window = context ? context->GetRootWindow() : nullptr;
  if (root_window) {
  
    // There are places where there is no context currently because object
    // hierarchies are built before they're attached to a Widget. (See
    // views::WebView as an example; GetWidget() returns NULL at the point
    // where we are created.)
    //
    // It should be OK to not set a default parent since such users will
    // explicitly add this ApplicationContentsViewAura to their tree after they create
    // us.
    aura::client::ParentWindowWithContext(window_.get(), root_window,
                                          root_window->GetBoundsInScreen());
  }

  window_->layer()->SetMasksToBounds(true);
  aura::WindowOcclusionTracker::Track(window_.get());

  // WindowObserver is not interesting and is problematic for Browser Plugin
  // guests.
  // The use cases for WindowObserver do not apply to Browser Plugins:
  // 1) guests do not support NPAPI plugins.
  // 2) guests' window bounds are supposed to come from its embedder.
//  if (!BrowserPluginGuest::IsGuest(app_contents_))
  window_observer_.reset(new WindowObserver(this));
}

////////////////////////////////////////////////////////////////////////////////
// ApplicationContentsViewAura, ApplicationContentsView implementation:

void ApplicationContentsViewAura::CreateView(const gfx::Size& initial_size,
                                             gfx::NativeView context) {
  // NOTE: we ignore |initial_size| since in some cases it's wrong (such as
  // if the bookmark bar is not shown and you create a new tab). The right
  // value is set shortly after this, so its safe to ignore.

  //if (!is_mus_browser_plugin_guest_)
  CreateAuraWindow(context);

  // note added here
  gfx::Rect bounds = window_->bounds();
  bounds.set_size(initial_size);
  window_->SetBounds(bounds);
  
  // delegate_->GetDragDestDelegate() creates a new delegate on every call.
  // Hence, we save a reference to it locally. Similar model is used on other
  // platforms as well.
  if (delegate_)
    drag_dest_delegate_ = delegate_->GetDragDestDelegate();
}

ApplicationWindowHostView* ApplicationContentsViewAura::CreateViewForWindow(
    ApplicationWindowHost* application_window_host) {
  if (application_window_host->GetView()) {
    // During testing, the view will already be set up in most cases to the
    // test view, so we don't want to clobber it with a real one. To verify that
    // this actually is happening (and somebody isn't accidentally creating the
    // view twice), we check for the RVH Factory, which will be set when we're
    // making special ones (which go along with the special views).
    DCHECK(ApplicationWindowHostFactory::has_factory());
    return application_window_host->GetView();
  }

  ApplicationWindowHostViewAura* view = new ApplicationWindowHostViewAura(application_window_host);
      //g_create_application_window_host_view
      //    ? g_create_application_window_host_view(application_window_host, false)
      //    : new ApplicationWindowHostViewAura(application_window_host);
  view->InitAsChild(window_.get());//GetApplicationWindowHostViewParent());

  //ApplicationWindowHost* host_impl =
  //    ApplicationWindowHost::From(application_window_host);

  if (!application_window_host->is_hidden()) {
    view->Show();
  }

  // We listen to drag drop events in the newly created view's window.
  aura::client::SetDragDropDelegate(view->GetNativeView(), this);

  if (view->overscroll_controller() &&
      (!app_contents_->GetDelegate() ||
       app_contents_->GetDelegate()->CanOverscrollContent())) {
    InstallOverscrollControllerDelegate(view);
  }

  return view;
}

ApplicationWindowHostView* ApplicationContentsViewAura::CreateViewForPopupWindow(
    ApplicationWindowHost* application_window_host) {
  // Popups are not created as embedded windows in mus, so
  // |is_mus_browser_plugin_guest| is always false for them.
  return new ApplicationWindowHostViewAura(application_window_host);
}

void ApplicationContentsViewAura::SetPageTitle(const base::string16& title) {
  //if (!is_mus_browser_plugin_guest_) {
  window_->SetTitle(title);
  aura::Window* child_window = GetContentNativeView();
  if (child_window)
    child_window->SetTitle(title);
  //}
}

void ApplicationContentsViewAura::ApplicationWindowCreated(ApplicationWindowHost* host) {
  //DLOG(INFO) << "ApplicationContentsViewAura::ApplicationWindowCreated";
}

void ApplicationContentsViewAura::ApplicationWindowSwappedIn(ApplicationWindowHost* host) {
  //DLOG(INFO) << "ApplicationContentsViewAura::ApplicationWindowSwappedIn";
}

void ApplicationContentsViewAura::SetOverscrollControllerEnabled(bool enabled) {
  ApplicationWindowHostViewAura* view =
      ToApplicationWindowHostViewAura(app_contents_->GetApplicationWindowHostView());
  if (view) {
    view->SetOverscrollControllerEnabled(enabled);
    if (enabled)
      InstallOverscrollControllerDelegate(view);
  }

  //if (!enabled) {
  //  navigation_overlay_.reset();
  //} else if (!navigation_overlay_) {
    //if (is_mus_browser_plugin_guest_) {
      // |is_mus_browser_plugin_guest_| implies this ApplicationContentsViewAura is
      // held inside a ApplicationContentsViewGuest, which does not forward this call.
    //  NOTREACHED();
   // } else {
  //    navigation_overlay_.reset(
  //        new OverscrollNavigationOverlay(app_contents_, window_.get()));
    //}
  //}
}

////////////////////////////////////////////////////////////////////////////////
// ApplicationContentsViewAura, ApplicationWindowHostDelegateView implementation:

void ApplicationContentsViewAura::ShowContextMenu(ApplicationWindowHost* app_window_host,
                                                  const common::ContextMenuParams& params) {
  TouchSelectionControllerClientAura* selection_controller_client =
      GetSelectionControllerClient();
  if (selection_controller_client &&
      selection_controller_client->HandleContextMenu(params)) {
    return;
  }

  if (delegate_) {
    delegate_->ShowContextMenu(app_window_host, params);
    // WARNING: we may have been deleted during the call to ShowContextMenu().
  }
}

void ApplicationContentsViewAura::StartDragging(
    const common::DropData& drop_data,
    blink::WebDragOperationsMask operations,
    const gfx::ImageSkia& image,
    const gfx::Vector2d& image_offset,
    const common::DragEventSourceInfo& event_info,
    ApplicationWindowHost* source_rwh) {
  aura::Window* root_window = GetNativeView()->GetRootWindow();
  if (!aura::client::GetDragDropClient(root_window)) {
    app_contents_->SystemDragEnded(source_rwh);
    return;
  }

  // Grab a weak pointer to the ApplicationWindowHost, since it can be destroyed
  // during the drag and drop nested run loop in StartDragAndDrop.
  // For example, the ApplicationWindowHost can be deleted if a cross-process
  // transfer happens while dragging, since the ApplicationWindowHost is deleted in
  // that case.
  base::WeakPtr<ApplicationWindowHost> source_rwh_weak_ptr =
      source_rwh->GetWeakPtr();

  drag_start_process_id_ = source_rwh->GetProcess()->GetID();
  drag_start_view_id_ = GetApplicationWindowHostID(app_contents_->GetApplicationWindowHost());

  ui::TouchSelectionController* selection_controller = GetSelectionController();
  if (selection_controller)
    selection_controller->HideAndDisallowShowingAutomatically();
  std::unique_ptr<ui::OSExchangeData::Provider> provider =
      ui::OSExchangeDataProviderFactory::CreateProvider();
  PrepareDragData(drop_data, provider.get(), app_contents_);

  ui::OSExchangeData data(
      std::move(provider));  // takes ownership of |provider|.

  if (!image.isNull())
    data.provider().SetDragImage(image, image_offset);

  std::unique_ptr<WebDragSourceAura> drag_source(
      new WebDragSourceAura(GetNativeView(), app_contents_));

  // We need to enable recursive tasks on the message loop so we can get
  // updates while in the system DoDragDrop loop.
  int result_op = 0;
  {
    gfx::NativeView content_native_view = GetContentNativeView();
    base::MessageLoopCurrent::ScopedNestableTaskAllower allow;
    result_op = aura::client::GetDragDropClient(root_window)
        ->StartDragAndDrop(data,
                           root_window,
                           content_native_view,
                           event_info.event_location,
                           ConvertFromWeb(operations),
                           event_info.event_source);
  }

  // Bail out immediately if the contents view window is gone. Note that it is
  // not safe to access any class members in this case since |this| may already
  // be destroyed. The local variable |drag_source| will still be valid though,
  // so we can use it to determine if the window is gone.
  if (!drag_source->window()) {
    // Note that in this case, we don't need to call SystemDragEnded() since the
    // renderer is going away.
    return;
  }

  EndDrag(source_rwh_weak_ptr.get(), ConvertToWeb(result_op));
}

void ApplicationContentsViewAura::UpdateDragCursor(blink::WebDragOperation operation) {
  current_drag_op_ = operation;
}

void ApplicationContentsViewAura::GotFocus(ApplicationWindowHost* application_window_host) {
  app_contents_->NotifyApplicationContentsFocused(application_window_host);
}

void ApplicationContentsViewAura::LostFocus(ApplicationWindowHost* application_window_host) {
  app_contents_->NotifyApplicationContentsLostFocus(application_window_host);
}

void ApplicationContentsViewAura::TakeFocus(bool reverse) {
  if (app_contents_->GetDelegate() &&
      !app_contents_->GetDelegate()->TakeFocus(app_contents_, reverse) &&
      delegate_.get()) {
    delegate_->TakeFocus(reverse);
  }
}

////////////////////////////////////////////////////////////////////////////////
// ApplicationContentsViewAura, OverscrollControllerDelegate implementation:

gfx::Size ApplicationContentsViewAura::GetDisplaySize() const {
  ApplicationWindowHostView* rwhv = app_contents_->GetApplicationWindowHostView();
  if (!rwhv)
    return gfx::Size();

  return display::Screen::GetScreen()
      ->GetDisplayNearestView(rwhv->GetNativeView())
      .size();
}

bool ApplicationContentsViewAura::OnOverscrollUpdate(float delta_x, float delta_y) {
  //if (current_overscroll_gesture_ != OVERSCROLL_EAST &&
  //    current_overscroll_gesture_ != OVERSCROLL_WEST) {
    return false;
  //}

  //return navigation_overlay_->relay_delegate()->OnOverscrollUpdate(delta_x,
  //                                                                 delta_y);
}

void ApplicationContentsViewAura::OnOverscrollComplete(OverscrollMode mode) {
  CompleteOverscrollNavigation(mode);
}

void ApplicationContentsViewAura::OnOverscrollModeChange(
    OverscrollMode old_mode,
    OverscrollMode new_mode,
    OverscrollSource source,
    cc::OverscrollBehavior behavior) {
  current_overscroll_gesture_ = new_mode;
  //navigation_overlay_->relay_delegate()->OnOverscrollModeChange(
  //    old_mode, new_mode, source, behavior);
  completed_overscroll_gesture_ = OVERSCROLL_NONE;
}

base::Optional<float> ApplicationContentsViewAura::GetMaxOverscrollDelta() const {
  //return navigation_overlay_->relay_delegate()->GetMaxOverscrollDelta();
  return base::Optional<float>();
}

////////////////////////////////////////////////////////////////////////////////
// ApplicationContentsViewAura, aura::WindowDelegate implementation:

gfx::Size ApplicationContentsViewAura::GetMinimumSize() const {
  return gfx::Size();
}

gfx::Size ApplicationContentsViewAura::GetMaximumSize() const {
  return gfx::Size();
}

void ApplicationContentsViewAura::OnBoundsChanged(
  const gfx::Rect& old_bounds,
  const gfx::Rect& new_bounds) {

  SadTabHelper* sad_tab_helper =
          SadTabHelper::FromApplicationContents(app_contents_);
  if (sad_tab_helper && sad_tab_helper->sad_tab()) {
    return;
  }  
  
  SizeChangedCommon(new_bounds.size());

  // Constrained web dialogs, need to be kept centered over our content area.
  for (size_t i = 0; i < window_->children().size(); i++) {
    if (window_->children()[i]->GetProperty(
            aura::client::kConstrainedWindowKey)) {
      gfx::Rect bounds = window_->children()[i]->bounds();
      bounds.set_origin(
          gfx::Point((new_bounds.width() - bounds.width()) / 2,
                     (new_bounds.height() - bounds.height()) / 2));
      window_->children()[i]->SetBounds(bounds);
    }
  }
}

gfx::NativeCursor ApplicationContentsViewAura::GetCursor(const gfx::Point& point) {
  return gfx::kNullCursor;
}

int ApplicationContentsViewAura::GetNonClientComponent(const gfx::Point& point) const {
  return HTCLIENT;
}

bool ApplicationContentsViewAura::ShouldDescendIntoChildForEventHandling(
    aura::Window* child,
    const gfx::Point& location) {
  return true;
}

bool ApplicationContentsViewAura::CanFocus() {
  // Do not take the focus if the render widget host view aura is gone or
  // is in the process of shutting down because neither the view window nor
  // this window can handle key events.
  ApplicationWindowHostViewAura* view = ToApplicationWindowHostViewAura(
      app_contents_->GetApplicationWindowHostView());
  if (view != nullptr && !view->IsClosing())
    return true;

  return false;
}

void ApplicationContentsViewAura::OnCaptureLost() {
}

void ApplicationContentsViewAura::OnPaint(const ui::PaintContext& context) {
}

void ApplicationContentsViewAura::OnDeviceScaleFactorChanged(
    float old_device_scale_factor,
    float new_device_scale_factor) {}

void ApplicationContentsViewAura::OnWindowDestroying(aura::Window* window) {
  // This means the destructor is going to be called soon. If there is an
  // overscroll gesture in progress (i.e. |overscroll_window_| is not NULL),
  // then destroying it in the ApplicationContentsViewAura destructor can trigger other
  // virtual functions to be called (e.g. OnImplicitAnimationsCompleted()). So
  // destroy the overscroll window here.
//  navigation_overlay_.reset();
}

void ApplicationContentsViewAura::OnWindowDestroyed(aura::Window* window) {
}

void ApplicationContentsViewAura::OnWindowTargetVisibilityChanged(bool visible) {
}

void ApplicationContentsViewAura::OnWindowOcclusionChanged(
    aura::Window::OcclusionState occlusion_state) {
  app_contents_->UpdateApplicationContentsVisibility(
      occlusion_state == aura::Window::OcclusionState::VISIBLE
          ? Visibility::VISIBLE
          : (occlusion_state == aura::Window::OcclusionState::OCCLUDED
                 ? Visibility::OCCLUDED
                 : Visibility::HIDDEN));
}

bool ApplicationContentsViewAura::HasHitTestMask() const {
  return false;
}

void ApplicationContentsViewAura::GetHitTestMask(gfx::Path* mask) const {
}

////////////////////////////////////////////////////////////////////////////////
// ApplicationContentsViewAura, ui::EventHandler implementation:

void ApplicationContentsViewAura::OnKeyEvent(ui::KeyEvent* event) {
}

void ApplicationContentsViewAura::OnMouseEvent(ui::MouseEvent* event) {
  if (!app_contents_->GetDelegate())
    return;

  ui::EventType type = event->type();
  if (type == ui::ET_MOUSE_PRESSED) {
    // Linux window managers like to handle raise-on-click themselves.  If we
    // raise-on-click manually, this may override user settings that prevent
    // focus-stealing.
#if !defined(USE_X11)
    app_contents_->GetDelegate()->ActivateContents(app_contents_);
#endif
  }

  app_contents_->GetDelegate()->ContentsMouseEvent(
      app_contents_, type == ui::ET_MOUSE_MOVED, type == ui::ET_MOUSE_EXITED);
}

////////////////////////////////////////////////////////////////////////////////
// ApplicationContentsViewAura, aura::client::DragDropDelegate implementation:

void ApplicationContentsViewAura::OnDragEntered(const ui::DropTargetEvent& event) {
  gfx::PointF transformed_pt;
  ApplicationWindowHost* target_rwh =
      app_contents_->GetInputEventRouter()->GetApplicationWindowHostAtPoint(
          app_contents_->GetApplicationWindowHost()->GetView(),
          event.location_f(), &transformed_pt);

  if (!IsValidDragTarget(target_rwh))
    return;

  current_rwh_for_drag_ = target_rwh->GetWeakPtr();
  current_rvh_for_drag_ =
      GetApplicationWindowHostID(app_contents_->GetApplicationWindowHost());
  current_drop_data_.reset(new common::DropData());
  PrepareDropData(current_drop_data_.get(), event.data());
  current_rwh_for_drag_->FilterDropData(current_drop_data_.get());

  blink::WebDragOperationsMask op = ConvertToWeb(event.source_operations());

  // Give the delegate an opportunity to cancel the drag.
  if (app_contents_->GetDelegate() &&
      !app_contents_->GetDelegate()->CanDragEnter(
          app_contents_, *current_drop_data_.get(), op)) {
    current_drop_data_.reset(nullptr);
    return;
  }

  if (drag_dest_delegate_)
    drag_dest_delegate_->DragInitialize(app_contents_);

  gfx::PointF screen_pt(display::Screen::GetScreen()->GetCursorScreenPoint());
  current_rwh_for_drag_->DragTargetDragEnter(
      *current_drop_data_, transformed_pt, screen_pt, op,
      ui::EventFlagsToWebEventModifiers(event.flags()));

  if (drag_dest_delegate_) {
    drag_dest_delegate_->OnReceiveDragData(event.data());
    drag_dest_delegate_->OnDragEnter();
  }
}

int ApplicationContentsViewAura::OnDragUpdated(const ui::DropTargetEvent& event) {
  gfx::PointF transformed_pt;
  ApplicationWindowHost* target_rwh =
      app_contents_->GetInputEventRouter()->GetApplicationWindowHostAtPoint(
          app_contents_->GetApplicationWindowHost()->GetView(),
          event.location_f(), &transformed_pt);

  if (!IsValidDragTarget(target_rwh))
    return ui::DragDropTypes::DRAG_NONE;

  gfx::PointF screen_pt = event.root_location_f();
  if (target_rwh != current_rwh_for_drag_.get()) {
    if (current_rwh_for_drag_) {
      gfx::PointF transformed_leave_point = event.location_f();
      gfx::PointF transformed_screen_point = screen_pt;
      static_cast<ApplicationWindowHostView*>(
          app_contents_->GetApplicationWindowHostView())
          ->TransformPointToCoordSpaceForView(
              event.location_f(),
              static_cast<ApplicationWindowHostView*>(
                  current_rwh_for_drag_->GetView()),
              &transformed_leave_point);
      static_cast<ApplicationWindowHostView*>(
          app_contents_->GetApplicationWindowHostView())
          ->TransformPointToCoordSpaceForView(
              screen_pt, static_cast<ApplicationWindowHostView*>(
                             current_rwh_for_drag_->GetView()),
              &transformed_screen_point);
      current_rwh_for_drag_->DragTargetDragLeave(transformed_leave_point,
                                                 transformed_screen_point);
    }
    OnDragEntered(event);
  }

  if (!current_drop_data_)
    return ui::DragDropTypes::DRAG_NONE;

  blink::WebDragOperationsMask op = ConvertToWeb(event.source_operations());
  target_rwh->DragTargetDragOver(
      transformed_pt, screen_pt, op,
      ui::EventFlagsToWebEventModifiers(event.flags()));

  if (drag_dest_delegate_)
    drag_dest_delegate_->OnDragOver();

  return ConvertFromWeb(current_drag_op_);
}

void ApplicationContentsViewAura::OnDragExited() {
  if (current_rvh_for_drag_ !=
      GetApplicationWindowHostID(app_contents_->GetApplicationWindowHost()) ||
      !current_drop_data_) {
    return;
  }

  if (current_rwh_for_drag_) {
    current_rwh_for_drag_->DragTargetDragLeave(gfx::PointF(), gfx::PointF());
    current_rwh_for_drag_.reset();
  }

  if (drag_dest_delegate_)
    drag_dest_delegate_->OnDragLeave();

  current_drop_data_.reset();
}

int ApplicationContentsViewAura::OnPerformDrop(const ui::DropTargetEvent& event) {
  gfx::PointF transformed_pt;
  ApplicationWindowHost* target_rwh =
      app_contents_->GetInputEventRouter()->GetApplicationWindowHostAtPoint(
          app_contents_->GetApplicationWindowHost()->GetView(),
          event.location_f(), &transformed_pt);

  if (!IsValidDragTarget(target_rwh))
    return ui::DragDropTypes::DRAG_NONE;

  gfx::PointF screen_pt(display::Screen::GetScreen()->GetCursorScreenPoint());
  if (target_rwh != current_rwh_for_drag_.get()) {
    if (current_rwh_for_drag_)
      current_rwh_for_drag_->DragTargetDragLeave(transformed_pt, screen_pt);
    OnDragEntered(event);
  }

  if (!current_drop_data_)
    return ui::DragDropTypes::DRAG_NONE;

  target_rwh->DragTargetDrop(
      *current_drop_data_, transformed_pt,
      gfx::PointF(display::Screen::GetScreen()->GetCursorScreenPoint()),
      ui::EventFlagsToWebEventModifiers(event.flags()));
  if (drag_dest_delegate_)
    drag_dest_delegate_->OnDrop();
  current_drop_data_.reset();
  return ConvertFromWeb(current_drag_op_);
}

//#if BUILDFLAG(USE_EXTERNAL_POPUP_MENU)
void ApplicationContentsViewAura::ShowPopupMenu(
  ApplicationWindowHost* app_window_host,
  const gfx::Rect& bounds,
  int item_height,
  double item_font_size,
  int selected_item,
  const std::vector<common::MenuItem>& items,
  bool right_aligned,
  bool allow_multiple_selection) {
  NOTIMPLEMENTED() << " show " << items.size() << " menu items";
}

void ApplicationContentsViewAura::HidePopupMenu() {
  NOTIMPLEMENTED();
}
//#endif

}  // namespace host
