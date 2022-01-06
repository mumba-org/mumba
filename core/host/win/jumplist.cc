// Copyright 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/win/jumplist.h"

#include "base/base_paths.h"
#include "base/bind.h"
#include "base/bind_helpers.h"
#include "base/command_line.h"
#include "base/containers/flat_set.h"
#include "base/files/file_util.h"
#include "base/metrics/histogram_macros.h"
#include "base/path_service.h"
#include "base/sequenced_task_runner.h"
#include "base/single_thread_task_runner.h"
#include "base/strings/string_piece.h"
#include "base/strings/string_util.h"
#include "base/strings/utf_string_conversions.h"
#include "base/task_scheduler/post_task.h"
#include "base/task_scheduler/task_traits.h"
#include "base/threading/thread.h"
#include "base/timer/elapsed_timer.h"
#include "base/trace_event/trace_event.h"
#include "core/host/notification_types.h"
#include "core/host/favicon/favicon_service_factory.h"
#include "core/host/shell_integration_win.h"
#include "core/host/workspace/workspace.h"
#include "core/host/win/jumplist_file_util.h"
//#include "core/host/win/jumplist_update_util.h"
#include "core/common/constants.h"
//#include "core/common/chrome_icon_resources_win.h"
#include "core/shared/common/switches.h"
#include "mumba/grit/generated_resources.h"
#include "mumba/install_static/install_util.h"
#include "components/favicon/core/favicon_service.h"
#include "components/strings/grit/components_strings.h"
#include "ui/base/l10n/l10n_util.h"
#include "ui/gfx/codec/png_codec.h"
#include "ui/gfx/favicon_size.h"
#include "ui/gfx/icon_util.h"
#include "ui/gfx/image/image.h"
#include "ui/gfx/image/image_family.h"
#include "ui/gfx/image/image_skia.h"
#include "ui/gfx/image/image_skia_rep.h"
#include "url/gurl.h"

namespace host {

namespace {

// The default maximum number of items to display in JumpList is 10.
// https://msdn.microsoft.com/library/windows/desktop/dd378398.aspx
// The "Most visited" and "Recently closed" category titles always take 2 slots.
// For the remaining 8 slots, we allocate 5 slots to "most-visited" items and 3
// slots to "recently-closed" items, respectively.
constexpr size_t kMostVisitedItems = 5;
constexpr size_t kRecentlyClosedItems = 3;

// The number of update notifications to skip to alleviate the machine when a
// previous update was too slow.
constexpr int kNotificationsToSkipUnderHeavyLoad = 2;

// The delay before updating the JumpList for users who haven't used it in a
// session. A delay of 2000 ms is chosen to coalesce more updates when tabs are
// closed rapidly.
constexpr base::TimeDelta kLongDelayForUpdate =
    base::TimeDelta::FromMilliseconds(2000);

// The delay before updating the JumpList for users who have used it in a
// session. A delay of 500 ms is used to not only make the update happen almost
// immediately, but also prevent update storms when tabs are closed rapidly via
// Ctrl-W.
constexpr base::TimeDelta kShortDelayForUpdate =
    base::TimeDelta::FromMilliseconds(500);

// The maximum allowed time for JumpListUpdater::BeginUpdate. Updates taking
// longer than this are discarded to prevent bogging down slow machines.
constexpr base::TimeDelta kTimeOutForBeginUpdate =
    base::TimeDelta::FromMilliseconds(500);

// The maximum allowed time for adding most visited pages custom category via
// JumpListUpdater::AddCustomCategory.
constexpr base::TimeDelta kTimeOutForAddCustomCategory =
    base::TimeDelta::FromMilliseconds(320);

// The maximum allowed time for JumpListUpdater::CommitUpdate.
constexpr base::TimeDelta kTimeOutForCommitUpdate =
    base::TimeDelta::FromMilliseconds(1000);

// Appends the common switches to each shell link.
void AppendCommonSwitches(ShellLinkItem* shell_link) {
  //const char* kSwitchNames[] = { switches::kUserDataDir };
  //const base::CommandLine& command_line =
  //    *base::CommandLine::ForCurrentProcess();
  //shell_link->GetCommandLine()->CopySwitchesFrom(command_line,
  //                                               kSwitchNames,
  //                                               arraysize(kSwitchNames));
}

// Creates a ShellLinkItem preloaded with common switches.
scoped_refptr<ShellLinkItem> CreateShellLink() {
  auto link = base::MakeRefCounted<ShellLinkItem>();
  AppendCommonSwitches(link.get());
  return link;
}

// Creates a temporary icon file to be shown in JumpList.
bool CreateIconFile(const gfx::ImageSkia& image_skia,
                    const base::FilePath& icon_dir,
                    base::FilePath* icon_path) {
  // Retrieve the path to a temporary file.
  // We don't have to care about the extension of this temporary file because
  // JumpList does not care about it.
  base::FilePath path;
  if (!base::CreateTemporaryFileInDir(icon_dir, &path))
    return false;

  // Create an icon file from the favicon attached to the given |page|, and
  // save it as the temporary file.
  gfx::ImageFamily image_family;
  if (!image_skia.isNull()) {
    std::vector<float> supported_scales = image_skia.GetSupportedScales();
    for (auto& scale : supported_scales) {
      gfx::ImageSkiaRep image_skia_rep = image_skia.GetRepresentation(scale);
      if (!image_skia_rep.is_null()) {
        image_family.Add(
            gfx::Image::CreateFrom1xBitmap(image_skia_rep.sk_bitmap()));
      }
    }
  }

  if (!IconUtil::CreateIconFileFromImageFamily(image_family, path,
                                               IconUtil::NORMAL_WRITE)) {
    // Delete the file created by CreateTemporaryFileInDir as it won't be used.
    base::DeleteFile(path, false);
    return false;
  }

  // Add this icon file to the list and return its absolute path.
  // The IShellLink::SetIcon() function needs the absolute path to an icon.
  *icon_path = path;
  return true;
}

// Updates the "Tasks" category of the JumpList.
bool UpdateTaskCategory(
    JumpListUpdater* jumplist_updater) {
  base::FilePath chrome_path;
  if (!base::PathService::Get(base::FILE_EXE, &chrome_path))
    return false;

  int icon_index = install_static::GetIconResourceIndex();

  ShellLinkItemList items;

  // Create an IShellLink object which launches Chrome, and add it to the
  // collection. We use our application icon as the icon for this item.
  // We remove '&' characters from this string so we can share it with our
  // system menu.
  //if (incognito_availability != IncognitoModePrefs::FORCED) {
    scoped_refptr<ShellLinkItem> chrome = CreateShellLink();
    base::string16 chrome_title = l10n_util::GetStringUTF16(IDS_NEW_WINDOW);
    base::ReplaceSubstringsAfterOffset(
        &chrome_title, 0, L"&", base::StringPiece16());
    chrome->set_title(chrome_title);
    chrome->set_icon(chrome_path.value(), icon_index);
    items.push_back(chrome);
  //}

  // Create an IShellLink object which launches Chrome in incognito mode, and
  // add it to the collection.
  //if (incognito_availability != IncognitoModePrefs::DISABLED) {
  //  scoped_refptr<ShellLinkItem> incognito = CreateShellLink();
  //  incognito->GetCommandLine()->AppendSwitch(switches::kIncognito);
  //  base::string16 incognito_title =
  //      l10n_util::GetStringUTF16(IDS_NEW_INCOGNITO_WINDOW);
  //  base::ReplaceSubstringsAfterOffset(
  //      &incognito_title, 0, L"&", base::StringPiece16());
  //  incognito->set_title(incognito_title);
  //  incognito->set_icon(chrome_path.value(), icon_resources::kIncognitoIndex);
  //  items.push_back(incognito);
  //}

  return jumplist_updater->AddTasks(items);
}

// Returns the full path of the JumpListIcons[|suffix|] directory in
// |profile_dir|.
base::FilePath GenerateJumplistIconDirName(
    const base::FilePath& profile_dir,
    const base::FilePath::StringPieceType& suffix) {
  //base::FilePath::StringType dir_name(chrome::kJumpListIconDirname);
  //suffix.AppendToString(&dir_name);
  //return profile_dir.Append(dir_name);
  return profile_dir;
}

}  // namespace

JumpList::UpdateTransaction::UpdateTransaction() {}

JumpList::UpdateTransaction::~UpdateTransaction() {}

// static
bool JumpList::Enabled() {
  return JumpListUpdater::IsEnabled();
}

void JumpList::Shutdown() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  Terminate();
}

JumpList::JumpList()
    : update_jumplist_task_runner_(base::CreateCOMSTATaskRunnerWithTraits(
          {base::MayBlock(), base::TaskPriority::USER_VISIBLE,
           base::TaskShutdownBehavior::CONTINUE_ON_SHUTDOWN})),
      delete_jumplisticons_task_runner_(
          base::CreateSequencedTaskRunnerWithTraits(
              {base::MayBlock(), base::TaskPriority::BACKGROUND,
               base::TaskShutdownBehavior::CONTINUE_ON_SHUTDOWN})),
      weak_ptr_factory_(this) {
  DCHECK(Enabled());
  // To update JumpList when a tab is added or removed, we add this object to
  // the observer list of the TabRestoreService class.
  // When we add this object to the observer list, we save the pointer to this
  // TabRestoreService object. This pointer is used when we remove this object
  // from the observer list.
  // sessions::TabRestoreService* tab_restore_service =
  //     TabRestoreServiceFactory::GetForProfile(profile_);
  // if (!tab_restore_service)
  //   return;

  // app_id_ =
  //     shell_integration::win::GetChromiumModelIdForProfile(profile_->GetPath());

  // // Register as TopSitesObserver so that we can update ourselves when the
  // // TopSites changes. TopSites updates itself after a delay. This is especially
  // // noticable when your profile is empty.
  // scoped_refptr<history::TopSites> top_sites =
  //     TopSitesFactory::GetForProfile(profile_);
  // if (top_sites)
  //   top_sites->AddObserver(this);

  // // Register as TabRestoreServiceObserver so that we can update ourselves when
  // // recently closed tabs have changes.
  // tab_restore_service->AddObserver(this);

  // // kIncognitoModeAvailability is monitored for changes on Incognito mode.
  // pref_change_registrar_.reset(new PrefChangeRegistrar);
  // pref_change_registrar_->Init(profile_->GetPrefs());
  // // base::Unretained is safe since |this| is guaranteed to outlive
  // // pref_change_registrar_.
  // pref_change_registrar_->Add(
  //     prefs::kIncognitoModeAvailability,
  //     base::Bind(&JumpList::OnIncognitoAvailabilityChanged,
  //                base::Unretained(this)));
}

JumpList::~JumpList() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  Terminate();
}

void JumpList::InitializeTimerForUpdate() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  if (timer_.IsRunning()) {
    timer_.Reset();
  } else {
    // base::Unretained is safe since |this| is guaranteed to outlive timer_.
    timer_.Start(
        FROM_HERE,
        //profile_->GetUserData(chrome::kJumpListIconDirname)
        kShortDelayForUpdate,
        //kLongDelayForUpdate,
        base::Bind(&JumpList::ProcessNotifications, base::Unretained(this)));
  }
}

void JumpList::ProcessNotifications() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  if (updates_to_skip_ > 0) {
    --updates_to_skip_;
    return;
  }

  // If TopSites has updates, retrieve the URLs asynchronously, and on its
  // completion, trigger favicon loading.
  // Otherwise, call StartLoadingFavicon directly to start favicon loading.
  StartLoadingFavicon();
}

void JumpList::StartLoadingFavicon() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  if (icon_urls_.empty()) {
    // No more favicons are needed by the application JumpList. Schedule a
    // RunUpdateJumpList call.
    PostRunUpdate();
    return;
  }

  scoped_refptr<Workspace> workspace = Workspace::GetCurrent();
  // Ask FaviconService if it has a favicon of a URL.
  // When FaviconService has one, it will call OnFaviconDataAvailable().
  favicon::FaviconService* favicon_service =
      FaviconServiceFactory::GetForWorkspace(workspace, ServiceAccessType::EXPLICIT_ACCESS);
  // base::Unretained is safe since |this| is guaranteed to outlive
  // cancelable_task_tracker_.
  task_id_ = favicon_service->GetFaviconImageForPageURL(
      GURL(icon_urls_.front().first),
      base::Bind(&JumpList::OnFaviconDataAvailable, base::Unretained(this)),
      &cancelable_task_tracker_);
}

void JumpList::OnFaviconDataAvailable(
    const favicon_base::FaviconImageResult& image_result) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  // If there is currently a favicon request in progress, it is now outdated,
  // as we have received another, so nullify the handle from the old request.
  task_id_ = base::CancelableTaskTracker::kBadTaskId;

  // Attach the received data to the ShellLinkItem object. This data will be
  // decoded by the RunUpdateJumpList method.
  if (!icon_urls_.empty()) {
    if (!image_result.image.IsEmpty() && icon_urls_.front().second.get()) {
      gfx::ImageSkia image_skia = image_result.image.AsImageSkia();
      image_skia.EnsureRepsForSupportedScales();
      std::unique_ptr<gfx::ImageSkia> deep_copy(image_skia.DeepCopy());
      icon_urls_.front().second->set_icon_image(*deep_copy);
    }
    icon_urls_.pop_front();
  }

  // Check whether we need to load more favicons.
  StartLoadingFavicon();
}

void JumpList::PostRunUpdate() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  TRACE_EVENT0("browser", "JumpList::PostRunUpdate");

  update_in_progress_ = true;

  scoped_refptr<Workspace> workspace = Workspace::GetCurrent();
  base::FilePath profile_dir = workspace->root_path();
  
  auto update_transaction = std::make_unique<UpdateTransaction>();
  
  // Parameter evaluation order is unspecified in C++. Do the first bind and
  // then move it into PostTaskAndReply to ensure the pointer value is obtained
  // before base::Passed() is called.
  auto run_update =
      base::Bind(&JumpList::RunUpdateJumpList, app_id_, profile_dir,
                 most_visited_pages_, recently_closed_pages_,
                 most_visited_should_update_, recently_closed_should_update_,
                 update_transaction.get());

  // Post a task to update the JumpList, which consists of 1) create new icons,
  // 2) notify the OS, 3) delete old icons.
  if (!update_jumplist_task_runner_->PostTaskAndReply(
          FROM_HERE, std::move(run_update),
          base::Bind(&JumpList::OnRunUpdateCompletion,
                     weak_ptr_factory_.GetWeakPtr(),
                     base::Passed(std::move(update_transaction))))) {
    OnRunUpdateCompletion(std::make_unique<UpdateTransaction>());
  }
}

void JumpList::OnRunUpdateCompletion(
    std::unique_ptr<UpdateTransaction> update_transaction) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  // Update JumpList member variables based on the results from the update run
  // just finished.
  if (update_transaction->update_timeout)
    updates_to_skip_ = kNotificationsToSkipUnderHeavyLoad;

  if (update_transaction->update_success) {
    if (most_visited_should_update_) {
      most_visited_icons_ = std::move(update_transaction->most_visited_icons);
      most_visited_should_update_ = false;
    }
    if (recently_closed_should_update_) {
      recently_closed_icons_ =
          std::move(update_transaction->recently_closed_icons);
      recently_closed_should_update_ = false;
    }
  }

  update_in_progress_ = false;

  // If there is any new notification during the update run just finished, start
  // another JumpList update.
  // Otherwise, post tasks to delete the JumpListIcons and JumpListIconsOld
  // folders as they are no longer needed. Now we have the
  // JumpListIcons{MostVisited, RecentClosed} folders instead.
  scoped_refptr<Workspace> workspace = Workspace::GetCurrent();
  base::FilePath profile_dir = workspace->root_path();
   
    base::FilePath icon_dir =
        GenerateJumplistIconDirName(profile_dir, FILE_PATH_LITERAL(""));
    delete_jumplisticons_task_runner_->PostTask(
        FROM_HERE,
        base::Bind(&DeleteDirectory, std::move(icon_dir), kFileDeleteLimit));

    base::FilePath icon_dir_old =
        GenerateJumplistIconDirName(profile_dir, FILE_PATH_LITERAL("Old"));
    delete_jumplisticons_task_runner_->PostTask(
        FROM_HERE, base::Bind(&DeleteDirectory, std::move(icon_dir_old),
                              kFileDeleteLimit));
  
}

void JumpList::CancelPendingUpdate() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  // Cancel a pending most-visited URL fetch by invalidating the weak pointer.
  weak_ptr_factory_.InvalidateWeakPtrs();

  // Cancel a pending favicon loading by invalidating its task id.
  if (task_id_ != base::CancelableTaskTracker::kBadTaskId) {
    cancelable_task_tracker_.TryCancel(task_id_);
    task_id_ = base::CancelableTaskTracker::kBadTaskId;
  }
}

void JumpList::Terminate() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  timer_.Stop();
  CancelPendingUpdate();
  update_in_progress_ = false;
}

// static
void JumpList::RunUpdateJumpList(
    const base::string16& app_id,
    const base::FilePath& profile_dir,
    const ShellLinkItemList& most_visited_pages,
    const ShellLinkItemList& recently_closed_pages,
    bool most_visited_should_update,
    bool recently_closed_should_update,
    UpdateTransaction* update_transaction) {
  DCHECK(update_transaction);

  base::FilePath most_visited_icon_dir = GenerateJumplistIconDirName(
      profile_dir, FILE_PATH_LITERAL("MostVisited"));
  base::FilePath recently_closed_icon_dir = GenerateJumplistIconDirName(
      profile_dir, FILE_PATH_LITERAL("RecentClosed"));

  CreateNewJumpListAndNotifyOS(
      app_id, most_visited_icon_dir, recently_closed_icon_dir,
      most_visited_pages, recently_closed_pages, most_visited_should_update,
      recently_closed_should_update,
      update_transaction);

  // Delete any obsolete icon files.
  if (most_visited_should_update) {
    DeleteIconFiles(most_visited_icon_dir,
                    update_transaction->most_visited_icons);
  }
  if (recently_closed_should_update) {
    DeleteIconFiles(recently_closed_icon_dir,
                    update_transaction->recently_closed_icons);
  }
}

// static
void JumpList::CreateNewJumpListAndNotifyOS(
    const base::string16& app_id,
    const base::FilePath& most_visited_icon_dir,
    const base::FilePath& recently_closed_icon_dir,
    const ShellLinkItemList& most_visited_pages,
    const ShellLinkItemList& recently_closed_pages,
    bool most_visited_should_update,
    bool recently_closed_should_update,
    UpdateTransaction* update_transaction) {
  DCHECK(update_transaction);

  JumpListUpdater jumplist_updater(app_id);

  base::ElapsedTimer begin_update_timer;

  bool begin_success = jumplist_updater.BeginUpdate();

  // If JumpListUpdater::BeginUpdate takes longer than the maximum allowed time,
  // abort the current update as it's very likely the following steps will also
  // take a long time, and skip the next |kNotificationsToSkipUnderHeavyLoad|
  // update notifications.
  if (begin_update_timer.Elapsed() >= kTimeOutForBeginUpdate) {
    update_transaction->update_timeout = true;
    return;
  }

  if (!begin_success)
    return;

  // Record the desired number of icons created in this JumpList update.
  int icons_created = 0;

  URLIconCache most_visited_icons_next;
  URLIconCache recently_closed_icons_next;

  base::ElapsedTimer add_custom_category_timer;

  // Update the "Most Visited" category of the JumpList if it exists.
  // This update request is applied into the JumpList when we commit this
  // transaction.
  bool add_category_success = jumplist_updater.AddCustomCategory(
      l10n_util::GetStringUTF16(IDS_NEW_TAB_MOST_VISITED), most_visited_pages,
      kMostVisitedItems);

  // If AddCustomCategory takes longer than the maximum allowed time, abort the
  // current update and skip the next |kNotificationsToSkipUnderHeavyLoad|
  // update notifications.
  //
  // We only time adding custom category for most visited pages because
  // 1. If processing the first category times out or fails, there is no need to
  //    process the second category. In this case, we are not able to time both
  //    categories. Then we need to select one category from the two.
  // 2. Most visited category is selected because it always has 5 items except
  //    for a new Chrome user who has not closed 5 distinct websites yet. In
  //    comparison, the number of items in recently closed category is much less
  //    stable. It has 3 items only after an user closes 3 websites in one
  //    session. This means the runtime of AddCustomCategory API should be fixed
  //    for most visited category, but not for recently closed category. So a
  //    fixed timeout threshold is only valid for most visited category.
  if (add_custom_category_timer.Elapsed() >= kTimeOutForAddCustomCategory) {
    update_transaction->update_timeout = true;
    return;
  }

  if (!add_category_success)
    return;

  // Update the "Recently Closed" category of the JumpList.
  if (!jumplist_updater.AddCustomCategory(
          l10n_util::GetStringUTF16(IDS_RECENTLY_CLOSED), recently_closed_pages,
          kRecentlyClosedItems)) {
    return;
  }

  // Update the "Tasks" category of the JumpList.
  if (!UpdateTaskCategory(&jumplist_updater))
    return;

  base::ElapsedTimer commit_update_timer;

  // Commit this transaction and send the updated JumpList to Windows.
  bool commit_success = jumplist_updater.CommitUpdate();

  // If CommitUpdate call takes longer than the maximum allowed time, skip the
  // next |kNotificationsToSkipUnderHeavyLoad| update notifications.
  if (commit_update_timer.Elapsed() >= kTimeOutForCommitUpdate)
    update_transaction->update_timeout = true;

  if (commit_success) {
    update_transaction->update_success = true;

    // The move assignments below ensure update_transaction always has the icons
    // to keep.
  }
}

// static
int JumpList::UpdateIconFiles(const base::FilePath& icon_dir,
                              const ShellLinkItemList& item_list,
                              size_t max_items,
                              URLIconCache* icon_cur,
                              URLIconCache* icon_next) {
  DCHECK(icon_cur);
  DCHECK(icon_next);

  // Clear the JumpList icon folder at |icon_dir| and the caches when
  // 1) |icon_cur| is empty. This happens when "Most visited" or "Recently
  //    closed" category updates for the 1st time after Chrome is launched.
  // 2) The number of icons in |icon_dir| has exceeded the limit.
  if (icon_cur->empty() || FilesExceedLimitInDir(icon_dir, max_items * 2)) {
    DeleteDirectoryContent(icon_dir, kFileDeleteLimit);
    icon_cur->clear();
    icon_next->clear();
    // Create new icons only when the directory exists and is empty.
    if (!base::CreateDirectory(icon_dir) || !base::IsDirectoryEmpty(icon_dir))
      return 0;
  } else if (!base::CreateDirectory(icon_dir)) {
    return 0;
  }

  return CreateIconFiles(icon_dir, item_list, max_items, *icon_cur, icon_next);
}

// static
int JumpList::CreateIconFiles(const base::FilePath& icon_dir,
                              const ShellLinkItemList& item_list,
                              size_t max_items,
                              const URLIconCache& icon_cur,
                              URLIconCache* icon_next) {
  DCHECK(icon_next);

  int icons_created = 0;

  // Reuse icons for urls that already present in the current JumpList.
  for (ShellLinkItemList::const_iterator iter = item_list.begin();
       iter != item_list.end() && max_items > 0; ++iter, --max_items) {
    ShellLinkItem* item = iter->get();
    auto cache_iter = icon_cur.find(item->url());
    if (cache_iter != icon_cur.end()) {
      item->set_icon(cache_iter->second.value(), 0);
      (*icon_next)[item->url()] = cache_iter->second;
    } else {
      base::FilePath icon_path;
      if (CreateIconFile(item->icon_image(), icon_dir, &icon_path)) {
        ++icons_created;
        item->set_icon(icon_path.value(), 0);
        (*icon_next)[item->url()] = icon_path;
      }
    }
  }

  return icons_created;
}

// static
void JumpList::DeleteIconFiles(const base::FilePath& icon_dir,
                               const URLIconCache& icons_cache) {
  // Put all cached icon file paths into a set.
  base::flat_set<base::FilePath> cached_files;
  cached_files.reserve(icons_cache.size());

  for (const auto& url_path_pair : icons_cache)
    cached_files.insert(url_path_pair.second);

  DeleteNonCachedFiles(icon_dir, cached_files);
}

}