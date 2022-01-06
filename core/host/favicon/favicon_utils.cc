// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/favicon/favicon_utils.h"

#include "core/host/favicon/favicon_service_factory.h"
//#include "chrome/browser/history/history_service_factory.h"
#include "core/host/workspace/workspace.h"
//#include "chrome/browser/search/search.h"
//#include "chrome/common/url_constants.h"
#include "components/favicon/content/content_favicon_driver.h"
//#include "core/host/navigation_controller.h"
//#include "core/host/navigation_entry.h"
#include "core/shared/common/favicon_url.h"
#include "ui/gfx/image/image.h"
#include "ui/gfx/image/image_skia.h"
#include "ui/gfx/image/image_skia_operations.h"

namespace favicon {

// namespace {

// // Desaturate favicon HSL shift values.
// const double kDesaturateHue = -1.0;
// const double kDesaturateSaturation = 0.0;
// const double kDesaturateLightness = 0.6;
// }

void CreateContentFaviconDriverForApplicationContents(
    host::ApplicationContents* app_contents) {
  DCHECK(app_contents);
  if (ContentFaviconDriver::FromApplicationContents(app_contents))
    return;
  scoped_refptr<host::Workspace> workspace = host::Workspace::GetCurrent();
  //Profile* original_profile =
   //   Profile::FromBrowserContext(app_contents->GetBrowserContext())
   //       ->GetOriginalProfile();
  return ContentFaviconDriver::CreateForApplicationContents(
      app_contents,
      host::FaviconServiceFactory::GetForWorkspace(workspace,//original_profile,
                                                   ServiceAccessType::IMPLICIT_ACCESS));//,
      //HistoryServiceFactory::GetForProfile(workspace,//original_profile,
      //                                     ServiceAccessType::IMPLICIT_ACCESS));
}

bool ShouldDisplayFavicon(host::ApplicationContents* app_contents) {
  // No favicon on interstitials. This check must be done first since
  // interstitial navigations don't commit and always have a pending entry.
  if (app_contents->ShowingInterstitialPage())
    return false;

  // Always display a throbber during pending loads.
  //const content::NavigationController& controller =
  //    app_contents->GetController();
  //if (controller.GetLastCommittedEntry() && controller.GetPendingEntry())
  //  return true;

  //GURL url = app_contents->GetURL();
  //if (url.SchemeIs(content::kChromeUIScheme) &&
  //    url.host_piece() == chrome::kChromeUINewTabHost) {
  //  return false;
 // }

  // No favicon on Instant New Tab Pages.
  //if (search::IsInstantNTP(app_contents))
  //  return false;

  return true;
}

gfx::Image TabFaviconFromApplicationContents(host::ApplicationContents* contents) {
  DCHECK(contents);

  favicon::FaviconDriver* favicon_driver =
      favicon::ContentFaviconDriver::FromApplicationContents(contents);
  gfx::Image favicon = favicon_driver->GetFavicon();

  // Desaturate the favicon if the navigation entry contains a network error.
  // if (!contents->IsLoadingToDifferentDocument()) {
  //   const content::NavigationController& controller = contents->GetController();

  //   content::NavigationEntry* entry = controller.GetLastCommittedEntry();
  //   if (entry && (entry->GetPageType() == content::PAGE_TYPE_ERROR)) {
  //     color_utils::HSL shift = {kDesaturateHue, kDesaturateSaturation,
  //                               kDesaturateLightness};
  //     return gfx::Image(gfx::ImageSkiaOperations::CreateHSLShiftedImage(
  //         *favicon.ToImageSkia(), shift));
  //   }
  // }

  return favicon;
}

}  // namespace favicon
