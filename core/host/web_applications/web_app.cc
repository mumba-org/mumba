// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/web_applications/web_app.h"

#include <stddef.h>
#include <utility>

#include "base/bind.h"
#include "base/bind_helpers.h"
#include "base/command_line.h"
#include "base/files/file_util.h"
#include "base/i18n/file_util_icu.h"
#include "base/macros.h"
#include "base/strings/string_util.h"
#include "base/strings/utf_string_conversions.h"
#include "base/task_scheduler/post_task.h"
#include "base/threading/thread.h"
#include "base/threading/thread_restrictions.h"
#include "build/build_config.h"
#include "core/host/host.h"
//#include "core/host/extensions/extension_ui_util.h"
//#include "core/host/workspaces/workspace.h"
//#include "core/host/workspaces/workspace_manager.h"
#include "core/common/constants.h"
#include "core/shared/common/switches.h"
//#include "chrome/common/extensions/manifest_handlers/app_launch_info.h"
//#include "chrome/common/pref_names.h"
//#include "components/prefs/pref_service.h"
#include "core/host/host_thread.h"
//#include "extensions/browser/extension_registry.h"
//#include "extensions/browser/image_loader.h"
//#include "extensions/common/constants.h"
//#include "extensions/common/extension.h"
//#include "extensions/common/extension_set.h"
//#include "extensions/common/manifest_handlers/icons_handler.h"
//#include "extensions/grit/extensions_browser_resources.h"
#include "skia/ext/image_operations.h"
#include "third_party/skia/include/core/SkBitmap.h"
#include "ui/base/resource/resource_bundle.h"
#include "ui/gfx/image/image.h"
#include "ui/gfx/image/image_family.h"
#include "ui/gfx/image/image_skia.h"
#include "url/url_constants.h"

#if defined(OS_WIN)
#include "ui/gfx/icon_util.h"
#endif

using host::HostThread;

namespace {

#if defined(OS_MACOSX)
const int kDesiredSizes[] = {16, 32, 128, 256, 512};
const size_t kNumDesiredSizes = arraysize(kDesiredSizes);
#elif defined(OS_LINUX)
// Linux supports icons of any size. FreeDesktop Icon Theme Specification states
// that "Minimally you should install a 48x48 icon in the hicolor theme."
//const int kDesiredSizes[] = {16, 32, 48, 128, 256, 512};
//const size_t kNumDesiredSizes = arraysize(kDesiredSizes);
#elif defined(OS_WIN)
const int* kDesiredSizes = IconUtil::kIconDimensions;
const size_t kNumDesiredSizes = IconUtil::kNumIconDimensions;
#else
const int kDesiredSizes[] = {32};
const size_t kNumDesiredSizes = arraysize(kDesiredSizes);
#endif

}  // namespace

namespace web_app {

// The following string is used to build the directory name for
// shortcuts to chrome applications (the kind which are installed
// from a CRX).  Application shortcuts to URLs use the {host}_{path}
// for the name of this directory.  Hosts can't include an underscore.
// By starting this string with an underscore, we ensure that there
// are no naming conflicts.
static const char kCrxAppPrefix[] = "_crx_";

ShortcutInfo::ShortcutInfo() {}

ShortcutInfo::~ShortcutInfo() {
  //DCHECK_CURRENTLY_ON(HostThread::UI);
}

// static
void ShortcutInfo::PostIOTask(
    base::OnceCallback<void(const ShortcutInfo&)> task,
    std::unique_ptr<ShortcutInfo> shortcut_info) {
  PostIOTaskAndReply(std::move(task), std::move(shortcut_info),
                     base::Closure());
}

// static
void ShortcutInfo::PostIOTaskAndReply(
    base::OnceCallback<void(const ShortcutInfo&)> task,
    std::unique_ptr<ShortcutInfo> shortcut_info,
    const base::Closure& reply) {
  // DCHECK_CURRENTLY_ON(HostThread::UI);

  // // Ownership of |shortcut_info| moves to the Reply, which is guaranteed to
  // // outlive the const reference.
  // const web_app::ShortcutInfo& shortcut_info_ref = *shortcut_info;
  // GetTaskRunner()->PostTaskAndReply(
  //     FROM_HERE,
  //     base::BindOnce(std::move(task), base::ConstRef(shortcut_info_ref)),
  //     base::BindOnce(&DeleteShortcutInfoOnUIThread, std::move(shortcut_info),
  //                    reply));
}

// static
scoped_refptr<base::TaskRunner> ShortcutInfo::GetTaskRunner() {
//   constexpr base::TaskTraits traits = {
//       base::MayBlock(), base::TaskPriority::BACKGROUND,
//       base::TaskShutdownBehavior::BLOCK_SHUTDOWN};

// #if defined(OS_WIN)
//   return base::TaskScheduler::GetInstance()->CreateCOMSTATaskRunnerWithTraits(
//       traits, base::SingleThreadTaskRunnerThreadMode::SHARED);
// #else
//   return base::TaskScheduler::GetInstance()->CreateTaskRunnerWithTraits(traits);
// #endif
  return {};
}

ShortcutLocations::ShortcutLocations()
    : on_desktop(false),
      applications_menu_location(APP_MENU_LOCATION_NONE),
      in_quick_launch_bar(false) {
}


std::string GenerateApplicationNameFromURL(const GURL& url) {
  std::string t;
  t.append(url.host());
  t.append("_");
  t.append(url.path());
  return t;
}

std::string GenerateApplicationNameFromApplicationId(const std::string& id) {
  std::string t(kCrxAppPrefix);
  t.append(id);
  return t;
}

std::string GenerateApplicationNameFromInfo(const ShortcutInfo& shortcut_info) {
  if (!shortcut_info.extension_id.empty())
    return GenerateApplicationNameFromApplicationId(shortcut_info.extension_id);
  else
    return GenerateApplicationNameFromURL(shortcut_info.url);
}


#if defined(OS_LINUX)
std::string GetWMClassFromAppName(std::string app_name) {
  base::i18n::ReplaceIllegalCharactersInPath(&app_name, '_');
  base::TrimString(app_name, "_", &app_name);
  return app_name;
}
#endif

}  // namespace web_app
