// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/application/blink_platform_impl.h"

#include <math.h>

#include <memory>
#include <vector>

#include "base/bind.h"
#include "base/files/file_path.h"
#include "base/location.h"
#include "base/macros.h"
#include "base/memory/singleton.h"
#include "base/metrics/user_metrics_action.h"
#include "base/rand_util.h"
#include "base/run_loop.h"
#include "base/sequence_checker.h"
#include "base/single_thread_task_runner.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "base/strings/utf_string_conversions.h"
#include "base/synchronization/lock.h"
#include "base/synchronization/waitable_event.h"
#include "base/sys_info.h"
#include "base/threading/platform_thread.h"
#include "base/threading/thread.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/time/time.h"
#include "base/trace_event/memory_allocator_dump_guid.h"
#include "base/trace_event/memory_dump_manager.h"
#include "base/trace_event/trace_event.h"
#include "build/build_config.h"
#include "mumba/app/resources/grit/content_resources.h"
#include "mumba/app/strings/grit/content_strings.h"
#include "core/shared/common/child_thread_impl.h"
#include "core/shared/common/client.h"
#include "core/shared/common/content_features.h"
#include "core/shared/common/switches.h"
#include "core/shared/common/service_manager_connection.h"
#include "core/shared/common/service_names.mojom.h"
#include "core/shared/common/gpu_stream_constants.h"
#include "core/shared/application/application_thread.h"
#include "core/shared/application/resource_dispatcher.h"
#include "core/shared/application/child_url_loader_factory_bundle.h"
#include "core/shared/application/application_url_loader.h"
#include "core/shared/application/thread_safe_sender.h"
#include "core/shared/application/web_blob_registry_impl.h"
#include "core/shared/application/webgraphicscontext3d_provider_impl.h"
#include "core/shared/application/mojo/blink_interface_provider_impl.h"
#include "core/shared/application/worker_thread_registry.h"
#include "core/shared/application/cache_storage/webserviceworkercachestorage_impl.h"
#include "net/base/net_errors.h"
#include "services/network/public/cpp/features.h"
#include "services/ui/public/cpp/gpu/context_provider_command_buffer.h"
#include "services/device/public/cpp/generic_sensor/motion_data.h"
#include "services/network/public/cpp/features.h"
#include "services/network/public/cpp/shared_url_loader_factory.h"
//#include "services/network/public/cpp/wrapper_shared_url_loader_factory.h"
#include "third_party/blink/public/platform/scheduler/child/webthread_base.h"
#include "third_party/blink/public/platform/web_data.h"
#include "third_party/blink/public/platform/web_float_point.h"
#include "third_party/blink/public/platform/web_gesture_curve.h"
#include "third_party/blink/public/platform/web_security_origin.h"
#include "third_party/blink/public/platform/web_string.h"
#include "third_party/blink/public/platform/web_url.h"
#include "third_party/blink/renderer/platform/wtf/allocator/partitions.h"
#include "third_party/blink/public/resources/grit/blink_image_resources.h"
#include "third_party/blink/public/resources/grit/blink_resources.h"
#include "third_party/blink/public/resources/grit/media_controls_resources.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/zlib/google/compression_utils.h"
#include "cc/layers/texture_layer.h"
#include "ui/base/layout.h"
#include "ui/events/gestures/blink/web_gesture_curve_impl.h"
#include "ui/events/keycodes/dom/keycode_converter.h"
#include "runtime/MumbaShims/CompositorStructsPrivate.h"


using blink::WebData;
using blink::WebFallbackThemeEngine;
using blink::WebLocalizedString;
using blink::WebString;
using blink::WebThemeEngine;
using blink::WebURL;
using blink::WebURLError;

namespace application {

namespace {

WebData loadAudioSpatializationResource(const char* name) {
#ifdef IDR_AUDIO_SPATIALIZATION_COMPOSITE
  if (!strcmp(name, "Composite")) {
    base::StringPiece resource = common::GetClient()->GetDataResource(
        IDR_AUDIO_SPATIALIZATION_COMPOSITE, ui::SCALE_FACTOR_NONE);
    return WebData(resource.data(), resource.size());
  }
#endif

#ifdef IDR_AUDIO_SPATIALIZATION_T000_P000
  const size_t kExpectedSpatializationNameLength = 31;
  if (strlen(name) != kExpectedSpatializationNameLength) {
    return WebData();
  }

  // Extract the azimuth and elevation from the resource name.
  int azimuth = 0;
  int elevation = 0;
  int values_parsed =
      sscanf(name, "IRC_Composite_C_R0195_T%3d_P%3d", &azimuth, &elevation);
  if (values_parsed != 2) {
    return WebData();
  }

  // The resource index values go through the elevations first, then azimuths.
  const int kAngleSpacing = 15;

  // 0 <= elevation <= 90 (or 315 <= elevation <= 345)
  // in increments of 15 degrees.
  int elevation_index =
      elevation <= 90 ? elevation / kAngleSpacing :
      7 + (elevation - 315) / kAngleSpacing;
  bool is_elevation_index_good = 0 <= elevation_index && elevation_index < 10;

  // 0 <= azimuth < 360 in increments of 15 degrees.
  int azimuth_index = azimuth / kAngleSpacing;
  bool is_azimuth_index_good = 0 <= azimuth_index && azimuth_index < 24;

  const int kNumberOfElevations = 10;
  const int kNumberOfAudioResources = 240;
  int resource_index = kNumberOfElevations * azimuth_index + elevation_index;
  bool is_resource_index_good = 0 <= resource_index &&
      resource_index < kNumberOfAudioResources;

  if (is_azimuth_index_good && is_elevation_index_good &&
      is_resource_index_good) {
    const int kFirstAudioResourceIndex = IDR_AUDIO_SPATIALIZATION_T000_P000;
    base::StringPiece resource = common::GetClient()->GetDataResource(
        kFirstAudioResourceIndex + resource_index, ui::SCALE_FACTOR_NONE);
    return WebData(resource.data(), resource.size());
  }
#endif  // IDR_AUDIO_SPATIALIZATION_T000_P000

  NOTREACHED();
  return WebData();
}

// This must match third_party/WebKit/public/blink_resources.grd.
// In particular, |is_gzipped| corresponds to compress="gzip".
struct DataResource {
  const char* name;
  int id;
  ui::ScaleFactor scale_factor;
  bool is_gzipped;
};

const DataResource kDataResources[] = {
    {"missingImage", IDR_BROKENIMAGE, ui::SCALE_FACTOR_100P, false},
    {"missingImage@2x", IDR_BROKENIMAGE, ui::SCALE_FACTOR_200P, false},
    {"searchCancel", IDR_SEARCH_CANCEL, ui::SCALE_FACTOR_100P, false},
    {"searchCancelPressed", IDR_SEARCH_CANCEL_PRESSED, ui::SCALE_FACTOR_100P,
     false},
    {"generatePassword", IDR_PASSWORD_GENERATION_ICON, ui::SCALE_FACTOR_100P,
     false},
    {"generatePasswordHover", IDR_PASSWORD_GENERATION_ICON_HOVER,
     ui::SCALE_FACTOR_100P, false},
    {"html.css", IDR_UASTYLE_HTML_CSS, ui::SCALE_FACTOR_NONE, false},
    {"quirks.css", IDR_UASTYLE_QUIRKS_CSS, ui::SCALE_FACTOR_NONE, false},
    {"view-source.css", IDR_UASTYLE_VIEW_SOURCE_CSS, ui::SCALE_FACTOR_NONE,
     false},
    // Not limited to Android since it's used for mobile layouts in inspector.
    {"themeChromiumAndroid.css", IDR_UASTYLE_THEME_CHROMIUM_ANDROID_CSS,
     ui::SCALE_FACTOR_NONE, false},
    // Not limited to Android since it's used for mobile layouts in inspector.
    {"fullscreenAndroid.css", IDR_UASTYLE_FULLSCREEN_ANDROID_CSS,
     ui::SCALE_FACTOR_NONE, false},
    // Not limited to Linux since it's used for mobile layouts in inspector.
    {"themeChromiumLinux.css", IDR_UASTYLE_THEME_CHROMIUM_LINUX_CSS,
     ui::SCALE_FACTOR_NONE, false},
    {"themeInputMultipleFields.css",
     IDR_UASTYLE_THEME_INPUT_MULTIPLE_FIELDS_CSS, ui::SCALE_FACTOR_NONE, false},
#if defined(OS_MACOSX)
    {"themeMac.css", IDR_UASTYLE_THEME_MAC_CSS, ui::SCALE_FACTOR_NONE, false},
#endif
    {"themeWin.css", IDR_UASTYLE_THEME_WIN_CSS, ui::SCALE_FACTOR_NONE, false},
    {"themeWinQuirks.css", IDR_UASTYLE_THEME_WIN_QUIRKS_CSS,
     ui::SCALE_FACTOR_NONE, false},
    {"svg.css", IDR_UASTYLE_SVG_CSS, ui::SCALE_FACTOR_NONE, false},
    {"mathml.css", IDR_UASTYLE_MATHML_CSS, ui::SCALE_FACTOR_NONE, false},
    {"fullscreen.css", IDR_UASTYLE_FULLSCREEN_CSS, ui::SCALE_FACTOR_NONE, false},
    {"xhtmlmp.css", IDR_UASTYLE_XHTMLMP_CSS, ui::SCALE_FACTOR_NONE, false},
    {"viewportAndroid.css", IDR_UASTYLE_VIEWPORT_ANDROID_CSS,
     ui::SCALE_FACTOR_NONE, false},
    {"viewportTelevision.css", IDR_UASTYLE_VIEWPORT_TELEVISION_CSS,
     ui::SCALE_FACTOR_NONE, false},
    {"InspectorOverlayPage.html", IDR_INSPECTOR_OVERLAY_PAGE_HTML,
     ui::SCALE_FACTOR_NONE, false},
    {"DocumentXMLTreeViewer.css", IDR_DOCUMENTXMLTREEVIEWER_CSS,
     ui::SCALE_FACTOR_NONE, false},
    {"DocumentXMLTreeViewer.js", IDR_DOCUMENTXMLTREEVIEWER_JS,
     ui::SCALE_FACTOR_NONE, false},
#ifdef IDR_PICKER_COMMON_JS
    {"pickerCommon.js", IDR_PICKER_COMMON_JS, ui::SCALE_FACTOR_NONE, false},
    {"pickerCommon.css", IDR_PICKER_COMMON_CSS, ui::SCALE_FACTOR_NONE, false},
    {"calendarPicker.js", IDR_CALENDAR_PICKER_JS, ui::SCALE_FACTOR_NONE, false},
    {"calendarPicker.css", IDR_CALENDAR_PICKER_CSS, ui::SCALE_FACTOR_NONE,
     false},
    {"listPicker.js", IDR_LIST_PICKER_JS, ui::SCALE_FACTOR_NONE, false},
    {"listPicker.css", IDR_LIST_PICKER_CSS, ui::SCALE_FACTOR_NONE, false},
    {"pickerButton.css", IDR_PICKER_BUTTON_CSS, ui::SCALE_FACTOR_NONE, false},
    {"suggestionPicker.js", IDR_SUGGESTION_PICKER_JS, ui::SCALE_FACTOR_NONE,
     false},
    {"suggestionPicker.css", IDR_SUGGESTION_PICKER_CSS, ui::SCALE_FACTOR_NONE,
     false},
    {"colorSuggestionPicker.js", IDR_COLOR_SUGGESTION_PICKER_JS,
     ui::SCALE_FACTOR_NONE, false},
    {"colorSuggestionPicker.css", IDR_COLOR_SUGGESTION_PICKER_CSS,
     ui::SCALE_FACTOR_NONE, false},
#endif
    {"input_alert.svg", IDR_VALIDATION_BUBBLE_ICON, ui::SCALE_FACTOR_NONE,
     false},
    {"validation_bubble.css", IDR_VALIDATION_BUBBLE_CSS, ui::SCALE_FACTOR_NONE,
     false},
    {"placeholderIcon", IDR_PLACEHOLDER_ICON, ui::SCALE_FACTOR_100P, false},
    {"brokenCanvas", IDR_BROKENCANVAS, ui::SCALE_FACTOR_100P, false},
    {"brokenCanvas@2x", IDR_BROKENCANVAS, ui::SCALE_FACTOR_200P, false},
};

class NestedMessageLoopRunnerImpl
    : public blink::Platform::NestedMessageLoopRunner {
 public:
  NestedMessageLoopRunnerImpl() = default;

  ~NestedMessageLoopRunnerImpl() override {
    DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  }

  void Run() override {
    DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
    base::RunLoop* const previous_run_loop = run_loop_;
    base::RunLoop run_loop(base::RunLoop::Type::kNestableTasksAllowed);
    run_loop_ = &run_loop;
    run_loop.Run();
    run_loop_ = previous_run_loop;
  }

  void QuitNow() override {
    DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
    DCHECK(run_loop_);
    run_loop_->Quit();
  }

 private:
  base::RunLoop* run_loop_ = nullptr;

  SEQUENCE_CHECKER(sequence_checker_);
};

gpu::ContextType ToGpuContextType(blink::Platform::ContextType type) {
  switch (type) {
    case blink::Platform::kWebGL1ContextType:
      return gpu::CONTEXT_TYPE_WEBGL1;
    case blink::Platform::kWebGL2ContextType:
      return gpu::CONTEXT_TYPE_WEBGL2;
    case blink::Platform::kGLES2ContextType:
      return gpu::CONTEXT_TYPE_OPENGLES2;
    case blink::Platform::kGLES3ContextType:
      return gpu::CONTEXT_TYPE_OPENGLES3;
  }
  NOTREACHED();
  return gpu::CONTEXT_TYPE_OPENGLES2;
}

void MaxObservedSizeFunction(size_t size_in_mb) {}

// static void URLLoaderLoadAsynchronously(void* state) {}
// static void URLLoaderLoadSynchronously(void* state) {}
// static void URLLoaderCancel(void* state) {}
// static void URLLoaderSetDefersLoading(void* state, int defers)  {}
// static void URLLoaderDidChangePriority(void* state) {}

}  // namespace


static int ToMessageID(WebLocalizedString::Name name) {
  switch (name) {
    case WebLocalizedString::kAXAMPMFieldText:
      return IDS_AX_AM_PM_FIELD_TEXT;
    case WebLocalizedString::kAXCalendarShowMonthSelector:
      return IDS_AX_CALENDAR_SHOW_MONTH_SELECTOR;
    case WebLocalizedString::kAXCalendarShowNextMonth:
      return IDS_AX_CALENDAR_SHOW_NEXT_MONTH;
    case WebLocalizedString::kAXCalendarShowPreviousMonth:
      return IDS_AX_CALENDAR_SHOW_PREVIOUS_MONTH;
    case WebLocalizedString::kAXCalendarWeekDescription:
      return IDS_AX_CALENDAR_WEEK_DESCRIPTION;
    case WebLocalizedString::kAXDayOfMonthFieldText:
      return IDS_AX_DAY_OF_MONTH_FIELD_TEXT;
    case WebLocalizedString::kAXHourFieldText:
      return IDS_AX_HOUR_FIELD_TEXT;
    case WebLocalizedString::kAXMediaDefault:
      return IDS_AX_MEDIA_DEFAULT;
    case WebLocalizedString::kAXMediaAudioElement:
      return IDS_AX_MEDIA_AUDIO_ELEMENT;
    case WebLocalizedString::kAXMediaVideoElement:
      return IDS_AX_MEDIA_VIDEO_ELEMENT;
    case WebLocalizedString::kAXMediaMuteButton:
      return IDS_AX_MEDIA_MUTE_BUTTON;
    case WebLocalizedString::kAXMediaUnMuteButton:
      return IDS_AX_MEDIA_UNMUTE_BUTTON;
    case WebLocalizedString::kAXMediaPlayButton:
      return IDS_AX_MEDIA_PLAY_BUTTON;
    case WebLocalizedString::kAXMediaPauseButton:
      return IDS_AX_MEDIA_PAUSE_BUTTON;
    case WebLocalizedString::kAXMediaCurrentTimeDisplay:
      return IDS_AX_MEDIA_CURRENT_TIME_DISPLAY;
    case WebLocalizedString::kAXMediaTimeRemainingDisplay:
      return IDS_AX_MEDIA_TIME_REMAINING_DISPLAY;
    case WebLocalizedString::kAXMediaEnterFullscreenButton:
      return IDS_AX_MEDIA_ENTER_FULL_SCREEN_BUTTON;
    case WebLocalizedString::kAXMediaExitFullscreenButton:
      return IDS_AX_MEDIA_EXIT_FULL_SCREEN_BUTTON;
    case WebLocalizedString::kAXMediaShowClosedCaptionsButton:
      return IDS_AX_MEDIA_SHOW_CLOSED_CAPTIONS_BUTTON;
    case WebLocalizedString::kAXMediaHideClosedCaptionsButton:
      return IDS_AX_MEDIA_HIDE_CLOSED_CAPTIONS_BUTTON;
    case WebLocalizedString::kAXMediaCastOffButton:
      return IDS_AX_MEDIA_CAST_OFF_BUTTON;
    case WebLocalizedString::kAXMediaCastOnButton:
      return IDS_AX_MEDIA_CAST_ON_BUTTON;
    case WebLocalizedString::kAXMediaDownloadButton:
      return IDS_AX_MEDIA_DOWNLOAD_BUTTON;
    case WebLocalizedString::kAXMediaOverflowButton:
      return IDS_AX_MEDIA_OVERFLOW_BUTTON;
    case WebLocalizedString::kAXMediaAudioElementHelp:
      return IDS_AX_MEDIA_AUDIO_ELEMENT_HELP;
    case WebLocalizedString::kAXMediaVideoElementHelp:
      return IDS_AX_MEDIA_VIDEO_ELEMENT_HELP;
    case WebLocalizedString::kAXMediaMuteButtonHelp:
      return IDS_AX_MEDIA_MUTE_BUTTON_HELP;
    case WebLocalizedString::kAXMediaUnMuteButtonHelp:
      return IDS_AX_MEDIA_UNMUTE_BUTTON_HELP;
    case WebLocalizedString::kAXMediaPlayButtonHelp:
      return IDS_AX_MEDIA_PLAY_BUTTON_HELP;
    case WebLocalizedString::kAXMediaPauseButtonHelp:
      return IDS_AX_MEDIA_PAUSE_BUTTON_HELP;
    case WebLocalizedString::kAXMediaAudioSliderHelp:
      return IDS_AX_MEDIA_AUDIO_SLIDER_HELP;
    case WebLocalizedString::kAXMediaVideoSliderHelp:
      return IDS_AX_MEDIA_VIDEO_SLIDER_HELP;
    case WebLocalizedString::kAXMediaCurrentTimeDisplayHelp:
      return IDS_AX_MEDIA_CURRENT_TIME_DISPLAY_HELP;
    case WebLocalizedString::kAXMediaTimeRemainingDisplayHelp:
      return IDS_AX_MEDIA_TIME_REMAINING_DISPLAY_HELP;
    case WebLocalizedString::kAXMediaEnterFullscreenButtonHelp:
      return IDS_AX_MEDIA_ENTER_FULL_SCREEN_BUTTON_HELP;
    case WebLocalizedString::kAXMediaExitFullscreenButtonHelp:
      return IDS_AX_MEDIA_EXIT_FULL_SCREEN_BUTTON_HELP;
    case WebLocalizedString::kAXMediaShowClosedCaptionsButtonHelp:
      return IDS_AX_MEDIA_SHOW_CLOSED_CAPTIONS_BUTTON_HELP;
    case WebLocalizedString::kAXMediaHideClosedCaptionsButtonHelp:
      return IDS_AX_MEDIA_HIDE_CLOSED_CAPTIONS_BUTTON_HELP;
    case WebLocalizedString::kAXMediaCastOffButtonHelp:
      return IDS_AX_MEDIA_CAST_OFF_BUTTON_HELP;
    case WebLocalizedString::kAXMediaCastOnButtonHelp:
      return IDS_AX_MEDIA_CAST_ON_BUTTON_HELP;
    case WebLocalizedString::kAXMediaOverflowButtonHelp:
      return IDS_AX_MEDIA_OVERFLOW_BUTTON_HELP;
    case WebLocalizedString::kAXMillisecondFieldText:
      return IDS_AX_MILLISECOND_FIELD_TEXT;
    case WebLocalizedString::kAXMinuteFieldText:
      return IDS_AX_MINUTE_FIELD_TEXT;
    case WebLocalizedString::kAXMonthFieldText:
      return IDS_AX_MONTH_FIELD_TEXT;
    case WebLocalizedString::kAXSecondFieldText:
      return IDS_AX_SECOND_FIELD_TEXT;
    case WebLocalizedString::kAXWeekOfYearFieldText:
      return IDS_AX_WEEK_OF_YEAR_FIELD_TEXT;
    case WebLocalizedString::kAXYearFieldText:
      return IDS_AX_YEAR_FIELD_TEXT;
    case WebLocalizedString::kCalendarClear:
      return IDS_FORM_CALENDAR_CLEAR;
    case WebLocalizedString::kCalendarToday:
      return IDS_FORM_CALENDAR_TODAY;
    case WebLocalizedString::kDetailsLabel:
      return IDS_DETAILS_WITHOUT_SUMMARY_LABEL;
    case WebLocalizedString::kFileButtonChooseFileLabel:
      return IDS_FORM_FILE_BUTTON_LABEL;
    case WebLocalizedString::kFileButtonChooseMultipleFilesLabel:
      return IDS_FORM_MULTIPLE_FILES_BUTTON_LABEL;
    case WebLocalizedString::kFileButtonNoFileSelectedLabel:
      return IDS_FORM_FILE_NO_FILE_LABEL;
    case WebLocalizedString::kInputElementAltText:
      return IDS_FORM_INPUT_ALT;
    case WebLocalizedString::kMissingPluginText:
      return IDS_PLUGIN_INITIALIZATION_ERROR;
    case WebLocalizedString::kMediaRemotingCastText:
      return IDS_MEDIA_REMOTING_CAST_TEXT;
    case WebLocalizedString::kMediaRemotingCastToUnknownDeviceText:
      return IDS_MEDIA_REMOTING_CAST_TO_UNKNOWN_DEVICE_TEXT;
    case WebLocalizedString::kMediaRemotingStopByErrorText:
      return IDS_MEDIA_REMOTING_STOP_BY_ERROR_TEXT;
    case WebLocalizedString::kMediaRemotingStopByPlaybackQualityText:
      return IDS_MEDIA_REMOTING_STOP_BY_PLAYBACK_QUALITY_TEXT;
    case WebLocalizedString::kMediaRemotingStopNoText:
      return -1;  // This string name is used only to indicate an empty string.
    case WebLocalizedString::kMediaRemotingStopText:
      return IDS_MEDIA_REMOTING_STOP_TEXT;
    case WebLocalizedString::kMediaScrubbingMessageText:
      return IDS_MEDIA_SCRUBBING_MESSAGE_TEXT;
    case WebLocalizedString::kMultipleFileUploadText:
      return IDS_FORM_FILE_MULTIPLE_UPLOAD;
    case WebLocalizedString::kOtherColorLabel:
      return IDS_FORM_OTHER_COLOR_LABEL;
    case WebLocalizedString::kOtherDateLabel:
      return IDS_FORM_OTHER_DATE_LABEL;
    case WebLocalizedString::kOtherMonthLabel:
      return IDS_FORM_OTHER_MONTH_LABEL;
    case WebLocalizedString::kOtherWeekLabel:
      return IDS_FORM_OTHER_WEEK_LABEL;
    case WebLocalizedString::kOverflowMenuCaptions:
      return IDS_MEDIA_OVERFLOW_MENU_CLOSED_CAPTIONS;
    case WebLocalizedString::kOverflowMenuCaptionsSubmenuTitle:
      return IDS_MEDIA_OVERFLOW_MENU_CLOSED_CAPTIONS_SUBMENU_TITLE;
    case WebLocalizedString::kOverflowMenuCast:
      return IDS_MEDIA_OVERFLOW_MENU_CAST;
    case WebLocalizedString::kOverflowMenuEnterFullscreen:
      return IDS_MEDIA_OVERFLOW_MENU_ENTER_FULLSCREEN;
    case WebLocalizedString::kOverflowMenuExitFullscreen:
      return IDS_MEDIA_OVERFLOW_MENU_EXIT_FULLSCREEN;
    case WebLocalizedString::kOverflowMenuMute:
      return IDS_MEDIA_OVERFLOW_MENU_MUTE;
    case WebLocalizedString::kOverflowMenuUnmute:
      return IDS_MEDIA_OVERFLOW_MENU_UNMUTE;
    case WebLocalizedString::kOverflowMenuPlay:
      return IDS_MEDIA_OVERFLOW_MENU_PLAY;
    case WebLocalizedString::kOverflowMenuPause:
      return IDS_MEDIA_OVERFLOW_MENU_PAUSE;
    case WebLocalizedString::kOverflowMenuDownload:
      return IDS_MEDIA_OVERFLOW_MENU_DOWNLOAD;
    case WebLocalizedString::kOverflowMenuPictureInPicture:
      return IDS_MEDIA_OVERFLOW_MENU_PICTURE_IN_PICTURE;
    case WebLocalizedString::kPictureInPictureInterstitialText:
      return IDS_MEDIA_PICTURE_IN_PICTURE_INTERSTITIAL_TEXT;
    case WebLocalizedString::kPlaceholderForDayOfMonthField:
      return IDS_FORM_PLACEHOLDER_FOR_DAY_OF_MONTH_FIELD;
    case WebLocalizedString::kPlaceholderForMonthField:
      return IDS_FORM_PLACEHOLDER_FOR_MONTH_FIELD;
    case WebLocalizedString::kPlaceholderForYearField:
      return IDS_FORM_PLACEHOLDER_FOR_YEAR_FIELD;
    case WebLocalizedString::kResetButtonDefaultLabel:
      return IDS_FORM_RESET_LABEL;
    case WebLocalizedString::kSelectMenuListText:
      return IDS_FORM_SELECT_MENU_LIST_TEXT;
    case WebLocalizedString::kSubmitButtonDefaultLabel:
      return IDS_FORM_SUBMIT_LABEL;
    case WebLocalizedString::kThisMonthButtonLabel:
      return IDS_FORM_THIS_MONTH_LABEL;
    case WebLocalizedString::kThisWeekButtonLabel:
      return IDS_FORM_THIS_WEEK_LABEL;
    case WebLocalizedString::kValidationBadInputForDateTime:
      return IDS_FORM_VALIDATION_BAD_INPUT_DATETIME;
    case WebLocalizedString::kValidationBadInputForNumber:
      return IDS_FORM_VALIDATION_BAD_INPUT_NUMBER;
    case WebLocalizedString::kValidationPatternMismatch:
      return IDS_FORM_VALIDATION_PATTERN_MISMATCH;
    case WebLocalizedString::kValidationRangeOverflow:
      return IDS_FORM_VALIDATION_RANGE_OVERFLOW;
    case WebLocalizedString::kValidationRangeOverflowDateTime:
      return IDS_FORM_VALIDATION_RANGE_OVERFLOW_DATETIME;
    case WebLocalizedString::kValidationRangeUnderflow:
      return IDS_FORM_VALIDATION_RANGE_UNDERFLOW;
    case WebLocalizedString::kValidationRangeUnderflowDateTime:
      return IDS_FORM_VALIDATION_RANGE_UNDERFLOW_DATETIME;
    case WebLocalizedString::kValidationStepMismatch:
      return IDS_FORM_VALIDATION_STEP_MISMATCH;
    case WebLocalizedString::kValidationStepMismatchCloseToLimit:
      return IDS_FORM_VALIDATION_STEP_MISMATCH_CLOSE_TO_LIMIT;
    case WebLocalizedString::kValidationTooLong:
      return IDS_FORM_VALIDATION_TOO_LONG;
    case WebLocalizedString::kValidationTooShort:
      return IDS_FORM_VALIDATION_TOO_SHORT;
    case WebLocalizedString::kValidationTooShortPlural:
      return IDS_FORM_VALIDATION_TOO_SHORT_PLURAL;
    case WebLocalizedString::kValidationTypeMismatch:
      return IDS_FORM_VALIDATION_TYPE_MISMATCH;
    case WebLocalizedString::kValidationTypeMismatchForEmail:
      return IDS_FORM_VALIDATION_TYPE_MISMATCH_EMAIL;
    case WebLocalizedString::kValidationTypeMismatchForEmailEmpty:
      return IDS_FORM_VALIDATION_TYPE_MISMATCH_EMAIL_EMPTY;
    case WebLocalizedString::kValidationTypeMismatchForEmailEmptyDomain:
      return IDS_FORM_VALIDATION_TYPE_MISMATCH_EMAIL_EMPTY_DOMAIN;
    case WebLocalizedString::kValidationTypeMismatchForEmailEmptyLocal:
      return IDS_FORM_VALIDATION_TYPE_MISMATCH_EMAIL_EMPTY_LOCAL;
    case WebLocalizedString::kValidationTypeMismatchForEmailInvalidDomain:
      return IDS_FORM_VALIDATION_TYPE_MISMATCH_EMAIL_INVALID_DOMAIN;
    case WebLocalizedString::kValidationTypeMismatchForEmailInvalidDots:
      return IDS_FORM_VALIDATION_TYPE_MISMATCH_EMAIL_INVALID_DOTS;
    case WebLocalizedString::kValidationTypeMismatchForEmailInvalidLocal:
      return IDS_FORM_VALIDATION_TYPE_MISMATCH_EMAIL_INVALID_LOCAL;
    case WebLocalizedString::kValidationTypeMismatchForEmailNoAtSign:
      return IDS_FORM_VALIDATION_TYPE_MISMATCH_EMAIL_NO_AT_SIGN;
    case WebLocalizedString::kValidationTypeMismatchForMultipleEmail:
      return IDS_FORM_VALIDATION_TYPE_MISMATCH_MULTIPLE_EMAIL;
    case WebLocalizedString::kValidationTypeMismatchForURL:
      return IDS_FORM_VALIDATION_TYPE_MISMATCH_URL;
    case WebLocalizedString::kValidationValueMissing:
      return IDS_FORM_VALIDATION_VALUE_MISSING;
    case WebLocalizedString::kValidationValueMissingForCheckbox:
      return IDS_FORM_VALIDATION_VALUE_MISSING_CHECKBOX;
    case WebLocalizedString::kValidationValueMissingForFile:
      return IDS_FORM_VALIDATION_VALUE_MISSING_FILE;
    case WebLocalizedString::kValidationValueMissingForMultipleFile:
      return IDS_FORM_VALIDATION_VALUE_MISSING_MULTIPLE_FILE;
    case WebLocalizedString::kValidationValueMissingForRadio:
      return IDS_FORM_VALIDATION_VALUE_MISSING_RADIO;
    case WebLocalizedString::kValidationValueMissingForSelect:
      return IDS_FORM_VALIDATION_VALUE_MISSING_SELECT;
    case WebLocalizedString::kWeekFormatTemplate:
      return IDS_FORM_INPUT_WEEK_TEMPLATE;
    case WebLocalizedString::kWeekNumberLabel:
      return IDS_FORM_WEEK_NUMBER_LABEL;
    case WebLocalizedString::kTextTracksNoLabel:
      return IDS_MEDIA_TRACKS_NO_LABEL;
    case WebLocalizedString::kTextTracksOff:
      return IDS_MEDIA_TRACKS_OFF;
    case WebLocalizedString::kUnitsKibibytes:
      return IDS_UNITS_KIBIBYTES;
    case WebLocalizedString::kUnitsMebibytes:
      return IDS_UNITS_MEBIBYTES;
    case WebLocalizedString::kUnitsGibibytes:
      return IDS_UNITS_GIBIBYTES;
    case WebLocalizedString::kUnitsTebibytes:
      return IDS_UNITS_TEBIBYTES;
    case WebLocalizedString::kUnitsPebibytes:
      return IDS_UNITS_PEBIBYTES;
    // This "default:" line exists to avoid compile warnings about enum
    // coverage when we add a new symbol to WebLocalizedString.h in WebKit.
    // After a planned WebKit patch is landed, we need to add a case statement
    // for the added symbol here.
    default:
      break;
  }
  return -1;
}

BlinkPlatformImpl::BlinkPlatformImpl(
    ApplicationThread* thread,
    blink::scheduler::WebMainThreadScheduler* main_thread_scheduler,
    CApplicationCallbacks callbacks,
    void* state)
    : thread_(thread),
      main_thread_task_runner_(main_thread_scheduler->DefaultTaskRunner()),
      io_thread_task_runner_(thread->GetIOTaskRunner()),
      compositor_thread_(nullptr),
      main_thread_(main_thread_scheduler->CreateMainThread()),
      main_thread_scheduler_(main_thread_scheduler),
      callbacks_(callbacks),
      state_(state) {

  WTF::Partitions::Initialize(MaxObservedSizeFunction);
  
  common::ServiceManagerConnection* service_conn = thread_->GetServiceManagerConnection();
  if (service_conn) {
    connector_ = service_conn->GetConnector()->Clone();
  }
  sync_message_filter_ = thread_->sync_message_filter();
  thread_safe_sender_ = thread_->thread_safe_sender();
  blob_registry_.reset(new WebBlobRegistryImpl(thread_safe_sender_.get()));
  //web_idb_factory_.reset(new WebIDBFactoryImpl(
  //    sync_message_filter_,
  //    ApplicationThread::current()->GetIOTaskRunner().get()));
  //notification_dispatcher_ =
  //    ApplicationThread::current()->notification_dispatcher();

  if (connector_) {
    blink_interface_provider_.reset(
      new BlinkInterfaceProviderImpl(connector_.get()));
  }

  DCHECK(blink_interface_provider_);

  top_level_blame_context_.Initialize();
  main_thread_scheduler_->SetTopLevelBlameContext(&top_level_blame_context_);

  //GetInterfaceProvider()->GetInterface(
  //    mojo::MakeRequest(&web_database_host_info_))

  blink::RuntimeEnabledFeatures::SetSlimmingPaintV2Enabled(true);
  blink::RuntimeEnabledFeatures::SetConstructableStylesheetsEnabled(true);
}

BlinkPlatformImpl::~BlinkPlatformImpl() {
  main_thread_scheduler_->SetTopLevelBlameContext(nullptr);
}

void BlinkPlatformImpl::SetCompositorThread(
    blink::scheduler::WebThreadBase* compositor_thread) {
  compositor_thread_ = compositor_thread;
  if (compositor_thread_)
    WaitUntilWebThreadTLSUpdate(compositor_thread_);
}

scoped_refptr<cc::TextureLayer> BlinkPlatformImpl::GetExternalTextureLayerForCanvas(cc::TextureLayerClient* canvas_client) {
  callbacks_.OnExternalTextureLayerRequested(state_);
  base::AutoLock lock(texture_vector_lock_);
  if (texture_layers_.size() == 0) {
    return nullptr;
  }
  // for now we will just return the first we encounter
  for (auto it = texture_layers_.begin(); it != texture_layers_.end(); ++it) {
    // bind the texture client
    (*it)->canvas_client = canvas_client;
    // this hack will make the layer client associated with the layer to route
    // back the calls to the canvas client instead
    static_cast<_LayerClientImpl*>((*it)->application_client)->set_texture_client(canvas_client);
    return (*it)->texture_layer;
  }
  return nullptr;
}

void BlinkPlatformImpl::SetExternalTextureLayerForCanvas(const blink::WebString& target, scoped_refptr<cc::TextureLayer> layer) {
  DCHECK(false);
}

blink::WebBlobRegistry* BlinkPlatformImpl::GetBlobRegistry() {
  return blob_registry_.get();
}

void BlinkPlatformImpl::SetExternalTextureLayerForCanvas(const blink::WebString& target, scoped_refptr<cc::TextureLayer> layer, cc::TextureLayerClient* application_client) {
  base::AutoLock lock(texture_vector_lock_);
  std::unique_ptr<TextureItem> item = std::make_unique<TextureItem>();
  item->target_name = target.Ascii();
  item->texture_layer = std::move(layer);
  item->application_client = application_client;
  texture_layers_.push_back(std::move(item));
}

void BlinkPlatformImpl::OnExternalTextureLayerForCanvasInjected(cc::TextureLayerClient* canvas_client) {
  base::AutoLock lock(texture_vector_lock_);
  for (auto it = texture_layers_.begin(); it != texture_layers_.end(); ++it) {
    // see if the texture client match and remove
    if ((*it)->canvas_client == canvas_client) {
      texture_layers_.erase(it);
      return;
    }
  }
}

void BlinkPlatformImpl::WaitUntilWebThreadTLSUpdate(
    blink::scheduler::WebThreadBase* thread) {
  base::WaitableEvent event(base::WaitableEvent::ResetPolicy::AUTOMATIC,
                            base::WaitableEvent::InitialState::NOT_SIGNALED);
  thread->GetTaskRunner()->PostTask(
      FROM_HERE,
      base::BindOnce(&BlinkPlatformImpl::UpdateWebThreadTLS,
                     base::Unretained(this), base::Unretained(thread),
                     base::Unretained(&event)));
  event.Wait();
}

void BlinkPlatformImpl::UpdateWebThreadTLS(blink::WebThread* thread,
                                           base::WaitableEvent* event) {
  DCHECK(!current_thread_slot_.Get());
  current_thread_slot_.Set(thread);
  event->Signal();
}

WebString BlinkPlatformImpl::UserAgent() {
  return blink::WebString::FromUTF8(common::GetClient()->GetUserAgent());
}

std::unique_ptr<blink::WebThread> BlinkPlatformImpl::CreateThread(
    const blink::WebThreadCreationParams& params) {
  std::unique_ptr<blink::scheduler::WebThreadBase> thread =
      blink::scheduler::WebThreadBase::CreateWorkerThread(params);
  thread->Init();
  WaitUntilWebThreadTLSUpdate(thread.get());
  return std::move(thread);
}

std::unique_ptr<blink::WebThread> BlinkPlatformImpl::CreateWebAudioThread() {
  blink::WebThreadCreationParams params(blink::WebThreadType::kWebAudioThread);
  // WebAudio uses a thread with |DISPLAY| priority to avoid glitch when the
  // system is under the high pressure. Note that the main browser thread also
  // runs with same priority. (see: crbug.com/734539)
  params.thread_options.priority = base::ThreadPriority::DISPLAY;

  std::unique_ptr<blink::scheduler::WebThreadBase> thread =
      blink::scheduler::WebThreadBase::CreateWorkerThread(params);
  thread->Init();
  WaitUntilWebThreadTLSUpdate(thread.get());
  return std::move(thread);
}

blink::WebThread* BlinkPlatformImpl::CurrentThread() {
  if (main_thread_->IsCurrentThread())
    return main_thread_.get();

  return static_cast<blink::WebThread*>(current_thread_slot_.Get());
}

blink::BlameContext* BlinkPlatformImpl::GetTopLevelBlameContext() {
  return &top_level_blame_context_;
}

blink::WebThread* BlinkPlatformImpl::CompositorThread() const {
  return compositor_thread_;
}

viz::FrameSinkId BlinkPlatformImpl::GenerateFrameSinkId() {
  viz::FrameSinkId frame_sink_id(thread_->application_process_id(),
                                 thread_->GenerateRoutingID());
  return frame_sink_id;
}

bool BlinkPlatformImpl::IsThreadedCompositingEnabled() {
  return thread_->compositor_task_runner().get();
}

bool BlinkPlatformImpl::IsGpuCompositingDisabled() {
  //DCHECK_CALLED_ON_VALID_THREAD(main_thread_checker_);
  return thread_->IsGpuCompositingDisabled();
}

bool BlinkPlatformImpl::IsThreadedAnimationEnabled() {
  return thread_->IsThreadedAnimationEnabled();
}

void BlinkPlatformImpl::RecordAction(const blink::UserMetricsAction& name) {
  //if (ChildThread* child_thread = ChildThread::Get())
  //  child_thread->RecordComputedAction(name.Action());
}

void BlinkPlatformImpl::DidStartWorkerThread() {
  WorkerThreadRegistry::Instance()->DidStartCurrentWorkerThread();
}

void BlinkPlatformImpl::WillStopWorkerThread() {
  WorkerThreadRegistry::Instance()->WillStopCurrentWorkerThread();
}

void BlinkPlatformImpl::WorkerContextCreated(
    const v8::Local<v8::Context>& worker) {
  //GetContentClient()->renderer()->DidInitializeWorkerContextOnWorkerThread(
  //    worker);
}

static void Collect3DContextInformation(
    blink::Platform::GraphicsInfo* gl_info,
    const gpu::GPUInfo& gpu_info) {
  DCHECK(gl_info);
  gl_info->vendor_id = gpu_info.gpu.vendor_id;
  gl_info->device_id = gpu_info.gpu.device_id;
  gl_info->renderer_info = WebString::FromUTF8(gpu_info.gl_renderer);
  gl_info->vendor_info = WebString::FromUTF8(gpu_info.gl_vendor);
  gl_info->driver_version = WebString::FromUTF8(gpu_info.driver_version);
  gl_info->reset_notification_strategy =
      gpu_info.gl_reset_notification_strategy;
  gl_info->sandboxed = gpu_info.sandboxed;
  gl_info->amd_switchable = gpu_info.amd_switchable;
  gl_info->optimus = gpu_info.optimus;
}

std::unique_ptr<blink::WebGraphicsContext3DProvider>
BlinkPlatformImpl::CreateOffscreenGraphicsContext3DProvider(
    const blink::Platform::ContextAttributes& web_attributes,
    const blink::WebURL& top_document_web_url,
    blink::Platform::GraphicsInfo* gl_info) {
  DCHECK(gl_info);
  //if (!ApplicationThread::current()) {
  //  std::string error_message("Failed to run in Current ApplicationThread");
  //  gl_info->error_message = WebString::FromUTF8(error_message);
  //  return nullptr;
  //}

  scoped_refptr<gpu::GpuChannelHost> gpu_channel_host(
      thread_->EstablishGpuChannelSync());
  if (!gpu_channel_host) {
    std::string error_message(
        "OffscreenContext Creation failed, GpuChannelHost creation failed");
    gl_info->error_message = WebString::FromUTF8(error_message);
    return nullptr;
  }
  Collect3DContextInformation(gl_info, gpu_channel_host->gpu_info());

  bool is_software_rendering = gpu_channel_host->gpu_info().software_rendering;

  // This is an offscreen context. Generally it won't use the default
  // frame buffer, in that case don't request any alpha, depth, stencil,
  // antialiasing. But we do need those attributes for the "own
  // offscreen surface" optimization which supports directly drawing
  // to a custom surface backed frame buffer.
  gpu::ContextCreationAttribs attributes;
  attributes.alpha_size = web_attributes.support_alpha ? 8 : -1;
  attributes.depth_size = web_attributes.support_depth ? 24 : 0;
  attributes.stencil_size = web_attributes.support_stencil ? 8 : 0;
  attributes.samples = web_attributes.support_antialias ? 4 : 0;
  attributes.own_offscreen_surface =
      web_attributes.support_alpha || web_attributes.support_depth ||
      web_attributes.support_stencil || web_attributes.support_antialias;
  attributes.sample_buffers = 0;
  attributes.bind_generates_resource = false;
  attributes.enable_raster_interface = web_attributes.enable_raster_interface;
  // Prefer discrete GPU for WebGL.
  attributes.gpu_preference = gl::PreferDiscreteGpu;

  attributes.fail_if_major_perf_caveat =
      web_attributes.fail_if_major_performance_caveat;

  attributes.context_type = ToGpuContextType(web_attributes.context_type);

  constexpr bool automatic_flushes = true;
  constexpr bool support_locking = false;

  scoped_refptr<ui::ContextProviderCommandBuffer> provider(
      new ui::ContextProviderCommandBuffer(
          std::move(gpu_channel_host),
          thread_->GetGpuMemoryBufferManager(),
          common::kGpuStreamIdDefault, common::kGpuStreamPriorityDefault,
          gpu::kNullSurfaceHandle, 
          GURL(top_document_web_url.GetString().Utf8().data(), top_document_web_url.GetParsed(), top_document_web_url.IsValid()),
          automatic_flushes, support_locking, web_attributes.support_grcontext,
          gpu::SharedMemoryLimits(), attributes,
          ui::command_buffer_metrics::OFFSCREEN_CONTEXT_FOR_WEBGL));
  return std::make_unique<WebGraphicsContext3DProviderImpl>(
      std::move(provider), is_software_rendering);
}


std::unique_ptr<blink::WebGraphicsContext3DProvider>
BlinkPlatformImpl::CreateSharedOffscreenGraphicsContext3DProvider() {
  scoped_refptr<ui::ContextProviderCommandBuffer> provider =
      thread_->SharedMainThreadContextProvider();
  if (!provider)
    return nullptr;

  scoped_refptr<gpu::GpuChannelHost> host = thread_->EstablishGpuChannelSync();
  // This shouldn't normally fail because we just got |provider|. But the
  // channel can become lost on the IO thread since then. It is important that
  // this happens after getting |provider|. In the case that this GpuChannelHost
  // is not the same one backing |provider|, the context behind the |provider|
  // will be already lost/dead on arrival, so the value we get for
  // |is_software_rendering| will never be wrong.
  if (!host)
    return nullptr;

  bool is_software_rendering = host->gpu_info().software_rendering;

  return std::make_unique<WebGraphicsContext3DProviderImpl>(
      std::move(provider), is_software_rendering);
}

gpu::GpuMemoryBufferManager* BlinkPlatformImpl::GetGpuMemoryBufferManager() {
  return thread_->GetGpuMemoryBufferManager();
}

blink::WebCompositorSupport* BlinkPlatformImpl::CompositorSupport() {
  return &compositor_support_;
}

service_manager::Connector* BlinkPlatformImpl::GetConnector() {
  DCHECK(connector_);
  return connector_.get();
}

blink::InterfaceProvider* BlinkPlatformImpl::GetInterfaceProvider() {
  DCHECK(blink_interface_provider_);
  return blink_interface_provider_.get();
}

base::Optional<std::string> BlinkPlatformImpl::WebRtcStunProbeTrialParameter() {
  const base::CommandLine* cmd_line = base::CommandLine::ForCurrentProcess();
  if (!cmd_line->HasSwitch(switches::kWebRtcStunProbeTrialParameter))
    return base::nullopt;

  return cmd_line->GetSwitchValueASCII(
      switches::kWebRtcStunProbeTrialParameter);
}

WebData BlinkPlatformImpl::GetDataResource(const char* name) {
  // Some clients will call into this method with an empty |name| when they have
  // optional resources.  For example, the PopupMenuChromium code can have icons
  // for some Autofill items but not for others.
  if (!strlen(name))
    return WebData();

  // Check the name prefix to see if it's an audio resource.
  if (base::StartsWith(name, "IRC_Composite", base::CompareCase::SENSITIVE) ||
      base::StartsWith(name, "Composite", base::CompareCase::SENSITIVE))
    return loadAudioSpatializationResource(name);

  // TODO(flackr): We should use a better than linear search here, a trie would
  // be ideal.
  for (size_t i = 0; i < arraysize(kDataResources); ++i) {
    if (!strcmp(name, kDataResources[i].name)) {
      base::StringPiece resource = common::GetClient()->GetDataResource(
          kDataResources[i].id, kDataResources[i].scale_factor);
      if (!resource.empty() && kDataResources[i].is_gzipped) {
        std::string uncompressed;
        CHECK(compression::GzipUncompress(resource.as_string(), &uncompressed));
        return WebData(uncompressed.data(), uncompressed.size());
      }
      return WebData(resource.data(), resource.size());
    }
  }

  NOTREACHED() << "Unknown image resource " << name;
  return WebData();
}

WebString BlinkPlatformImpl::QueryLocalizedString(
    WebLocalizedString::Name name) {
  int message_id = ToMessageID(name);
  if (message_id < 0)
    return WebString();
  return WebString::FromUTF16(
      common::GetClient()->GetLocalizedString(message_id));
}

WebString BlinkPlatformImpl::queryLocalizedString(
    WebLocalizedString::Name name, int numeric_value) {
  return QueryLocalizedString(
      name, WebString::FromUTF16(base::IntToString16(numeric_value)));
}

WebString BlinkPlatformImpl::QueryLocalizedString(WebLocalizedString::Name name,
                                                  const WebString& value) {
  int message_id = ToMessageID(name);
  if (message_id < 0)
    return WebString();

  base::string16 format_string =
      common::GetClient()->GetLocalizedString(message_id);

  // If the ContentClient returned an empty string, e.g. because it's using the
  // default implementation of ContentClient::GetLocalizedString, return an
  // empty string instead of crashing with a failed DCHECK in
  // base::ReplaceStringPlaceholders below. This is useful for tests that don't
  // specialize a full ContentClient, since this way they can behave as though
  // there isn't a defined |message_id| for the |name| instead of crashing
  // outright.
  if (format_string.empty())
    return WebString();

  return WebString::FromUTF16(
      base::ReplaceStringPlaceholders(format_string, value.Utf16(), nullptr));
}

WebString BlinkPlatformImpl::QueryLocalizedString(WebLocalizedString::Name name,
                                                  const WebString& value1,
                                                  const WebString& value2) {
  int message_id = ToMessageID(name);
  if (message_id < 0)
    return WebString();
  std::vector<base::string16> values;
  values.reserve(2);
  values.push_back(value1.Utf16());
  values.push_back(value2.Utf16());
  return WebString::FromUTF16(base::ReplaceStringPlaceholders(
      common::GetClient()->GetLocalizedString(message_id), values, nullptr));
}

bool BlinkPlatformImpl::IsRendererSideResourceSchedulerEnabled() const {
  // We are assuming that kRendererSideResourceScheduler will be shipped when
  // launching Network Service, so let's act as if
  // kRendererSideResourceScheduler is enabled when kNetworkService is enabled.
  // Note: This is identical to
  // ResourceScheduler::IsRendererSideResourceSchedulerEnabled but we duplicate
  // the logic in order to avoid a DEPS issue.
  return base::FeatureList::IsEnabled(
             network::features::kRendererSideResourceScheduler) ||
         base::FeatureList::IsEnabled(network::features::kNetworkService);
}

std::unique_ptr<blink::WebGestureCurve>
BlinkPlatformImpl::CreateFlingAnimationCurve(
    blink::WebGestureDevice device_source,
    const blink::WebFloatPoint& velocity,
    const blink::WebSize& cumulative_scroll) {
  return ui::WebGestureCurveImpl::CreateFromDefaultPlatformCurve(
      device_source, gfx::Vector2dF(velocity.x, velocity.y),
      gfx::Vector2dF(cumulative_scroll.width, cumulative_scroll.height),
      IsMainThread());
}

bool BlinkPlatformImpl::AllowScriptExtensionForServiceWorker(
    const blink::WebURL& script_url) {
  GURL gscript_url(script_url.GetString().Utf8().data(), script_url.GetParsed(), script_url.IsValid());
  return common::GetClient()->AllowScriptExtensionForServiceWorker(gscript_url);
}

blink::WebCrypto* BlinkPlatformImpl::Crypto() {
  return &web_crypto_;
}

const char* BlinkPlatformImpl::GetBrowserServiceName() const {
  return common::mojom::kHostServiceName;
}

blink::WebMediaCapabilitiesClient*
BlinkPlatformImpl::MediaCapabilitiesClient() {
  return &media_capabilities_client_;
}

WebThemeEngine* BlinkPlatformImpl::ThemeEngine() {
  return &native_theme_engine_;
}

WebFallbackThemeEngine* BlinkPlatformImpl::FallbackThemeEngine() {
  return &fallback_theme_engine_;
}

blink::Platform::FileHandle BlinkPlatformImpl::DatabaseOpenFile(
    const blink::WebString& vfs_file_name,
    int desired_flags) {
#if defined(OS_WIN)
  return INVALID_HANDLE_VALUE;
#elif defined(OS_POSIX)
  return -1;
#endif
}

int BlinkPlatformImpl::DatabaseDeleteFile(const blink::WebString& vfs_file_name,
                                          bool sync_dir) {
  return -1;
}

long BlinkPlatformImpl::DatabaseGetFileAttributes(
    const blink::WebString& vfs_file_name) {
  return 0;
}

long long BlinkPlatformImpl::DatabaseGetFileSize(
    const blink::WebString& vfs_file_name) {
  return 0;
}

long long BlinkPlatformImpl::DatabaseGetSpaceAvailableForOrigin(
    const blink::WebSecurityOrigin& origin) {
  return 0;
}

bool BlinkPlatformImpl::DatabaseSetFileSize(
    const blink::WebString& vfs_file_name,
    long long size) {
  return false;
}

size_t BlinkPlatformImpl::NumberOfProcessors() {
  return static_cast<size_t>(base::SysInfo::NumberOfProcessors());
}

size_t BlinkPlatformImpl::MaxDecodedImageBytes() {
  const int kMB = 1024 * 1024;
  const int kMaxNumberOfBytesPerPixel = 4;
#if defined(OS_ANDROID)
  if (base::SysInfo::IsLowEndDevice()) {
    // Limit image decoded size to 3M pixels on low end devices.
    // 4 is maximum number of bytes per pixel.
    return 3 * kMB * kMaxNumberOfBytesPerPixel;
  }
  // For other devices, limit decoded image size based on the amount of physical
  // memory.
  // In some cases all physical memory is not accessible by Chromium, as it can
  // be reserved for direct use by certain hardware. Thus, we set the limit so
  // that 1.6GB of reported physical memory on a 2GB device is enough to set the
  // limit at 16M pixels, which is a desirable value since 4K*4K is a relatively
  // common texture size.
  return base::SysInfo::AmountOfPhysicalMemory() / 25;
#else
  size_t max_decoded_image_byte_limit = kNoDecodedImageByteLimit;
  base::CommandLine& command_line = *base::CommandLine::ForCurrentProcess();
  if (command_line.HasSwitch(switches::kMaxDecodedImageSizeMb)) {
    if (base::StringToSizeT(
            command_line.GetSwitchValueASCII(switches::kMaxDecodedImageSizeMb),
            &max_decoded_image_byte_limit)) {
      max_decoded_image_byte_limit *= kMB * kMaxNumberOfBytesPerPixel;
    }
  }
  return max_decoded_image_byte_limit;
#endif
}

bool BlinkPlatformImpl::IsLowEndDevice() {
  return base::SysInfo::IsLowEndDevice();
}

uint32_t BlinkPlatformImpl::GetUniqueIdForProcess() {
  // TODO(rickyz): Replace this with base::GetUniqueIdForProcess when that's
  // ready.
  return base::trace_event::TraceLog::GetInstance()->process_id();
}

bool BlinkPlatformImpl::IsMainThread() const {
  return main_thread_task_runner_.get() &&
         main_thread_task_runner_->BelongsToCurrentThread();
}

WebString BlinkPlatformImpl::DomCodeStringFromEnum(int dom_code) {
  return WebString::FromUTF8(ui::KeycodeConverter::DomCodeToCodeString(
      static_cast<ui::DomCode>(dom_code)));
}

int BlinkPlatformImpl::DomEnumFromCodeString(const WebString& code) {
  return static_cast<int>(
      ui::KeycodeConverter::CodeStringToDomCode(code.Utf8()));
}

WebString BlinkPlatformImpl::DomKeyStringFromEnum(int dom_key) {
  return WebString::FromUTF8(ui::KeycodeConverter::DomKeyToKeyString(
      static_cast<ui::DomKey>(dom_key)));
}

int BlinkPlatformImpl::DomKeyEnumFromString(const WebString& key_string) {
  return static_cast<int>(
      ui::KeycodeConverter::KeyStringToDomKey(key_string.Utf8()));
}

bool BlinkPlatformImpl::IsDomKeyForModifier(int dom_key) {
  return ui::KeycodeConverter::IsDomKeyForModifier(
      static_cast<ui::DomKey>(dom_key));
}

scoped_refptr<base::SingleThreadTaskRunner> BlinkPlatformImpl::GetIOTaskRunner()
    const {
  return io_thread_task_runner_;
}

std::unique_ptr<blink::Platform::NestedMessageLoopRunner>
BlinkPlatformImpl::CreateNestedMessageLoopRunner() const {
  return std::make_unique<NestedMessageLoopRunnerImpl>();
}

std::unique_ptr<blink::WebURLLoaderFactory> BlinkPlatformImpl::CreateDefaultURLLoaderFactory() {
  //DLOG(INFO) << "BlinkPlatformImpl::CreateDefaultURLLoaderFactory";
  // CBlinkPlatformCallbacks callbacks;

  // callbacks.URLLoaderLoadAsynchronously = &URLLoaderLoadAsynchronously;
  // callbacks.URLLoaderLoadSynchronously = &URLLoaderLoadSynchronously;
  // callbacks.URLLoaderCancel = &URLLoaderCancel;
  // callbacks.URLLoaderSetDefersLoading = &URLLoaderSetDefersLoading;
  // callbacks.URLLoaderDidChangePriority = &URLLoaderDidChangePriority;

  ApplicationWindowDispatcher* window = thread_->window_dispatcher();

  // void* loader_state = window->CreateURLLoader(//callbacks_.CreateURLLoader(
  //     const_cast<blink::WebURLRequest *>(&request),
  //     &callbacks);

  //   //return std::make_unique<application::ApplicationURLLoader>(request);//, std::move(callbacks), loader_state);

  //   // FIXME: we need to add the ServiceWorkerSubresourceLoader from the service_worker directory
  //   //        here

  //   auto loader = std::make_unique<application::ApplicationURLLoader>(
  //     thread->resource_dispatcher(),
  //     task_runner,
  //     // get the loader factories defined by the last CommitNavigation() IPC
  //     // NOTE: we need a way to get the specific loader factories for the specific
  //     //       commit.. or else we might get the factories of other commits
  //     //       because we are using the "global" window
  //     //window->loader_factories(),
  //     base::MakeRefCounted<common::WeakWrapperSharedURLLoaderFactory>(
  //       provider_->script_loader_factory()),
  //     std::move(callbacks), 
  //     loader_state);

  return std::make_unique<ApplicationURLLoaderFactory>(
      ApplicationThread::current()->resource_dispatcher()->GetWeakPtr(),
      CreateDefaultURLLoaderFactoryBundle(), window);
      //CreateDefaultURLLoaderFactoryBundle(), callbacks, window);
  //return std::unique_ptr<blink::WebURLLoaderFactory>();
}

scoped_refptr<ChildURLLoaderFactoryBundle>
BlinkPlatformImpl::CreateDefaultURLLoaderFactoryBundle() {
 // //DLOG(INFO) << "BlinkPlatformImpl::CreateDefaultURLLoaderFactoryBundle";
  return base::MakeRefCounted<ChildURLLoaderFactoryBundle>(
      base::BindOnce(&BlinkPlatformImpl::CreateNetworkURLLoaderFactory,
                     base::Unretained(this)),
      //base::FeatureList::IsEnabled(network::features::kNetworkService)
      //    ? base::BindOnce(&GetBlobURLLoaderFactoryGetter)
          //: 
          ChildURLLoaderFactoryBundle::FactoryGetterCallback());
}

common::PossiblyAssociatedInterfacePtr<network::mojom::URLLoaderFactory>
BlinkPlatformImpl::CreateNetworkURLLoaderFactory() {
  ApplicationThread* app_thread = ApplicationThread::current();
  DCHECK(app_thread);
  common::PossiblyAssociatedInterfacePtr<network::mojom::URLLoaderFactory>
      url_loader_factory;

  // if (base::FeatureList::IsEnabled(network::features::kNetworkService)) {
  //   network::mojom::URLLoaderFactoryPtr factory_ptr;
  //   connector_->BindInterface(common::mojom::kHostServiceName, &factory_ptr);
  //   url_loader_factory = std::move(factory_ptr);
  // } else {
    network::mojom::URLLoaderFactoryAssociatedPtr factory_ptr;
    app_thread->channel()->GetRemoteAssociatedInterface(&factory_ptr);
    url_loader_factory = std::move(factory_ptr);
  //}
  return url_loader_factory;
}

std::unique_ptr<blink::WebDataConsumerHandle>
BlinkPlatformImpl::CreateDataConsumerHandle(
    mojo::ScopedDataPipeConsumerHandle handle) {
  return std::make_unique<WebDataConsumerHandleImpl>(std::move(handle));
}

std::unique_ptr<blink::WebServiceWorkerCacheStorage> BlinkPlatformImpl::CreateCacheStorage(
    service_manager::InterfaceProvider* mojo_provider) {
  //DLOG(INFO) << "BlinkPlatformImpl::CreateCacheStorage";
  // Requires the Interface Provider from ExecutionContext, because it can be
  // different of RendererBlinkPlatformImpl::GetInterfaceProvider()
  
  //return std::make_unique<WebServiceWorkerCacheStorageImpl>(mojo_provider);

  // FIXME: diverted from the main implementation by using the 'local' blink provider
  //        we might have problems on the switch between Document(ExecutionContext)
  //        and ServiceWorker or Worker ExecutionContext's which lives in another thread
  //return std::make_unique<WebServiceWorkerCacheStorageImpl>(thread_->GetRemoteInterfaces());
  return std::make_unique<WebServiceWorkerCacheStorageImpl>(thread_->channel());
}

// std::unique_ptr<blink::WebURLLoaderFactory> BlinkPlatformImpl::WrapURLLoaderFactory(
//   mojo::ScopedMessagePipeHandle url_loader_factory_handle) {
//   return std::make_unique<ApplicationURLLoaderFactory>(
//       ApplicationThread::current()->resource_dispatcher()->GetWeakPtr(),
//       base::MakeRefCounted<network::WrapperSharedURLLoaderFactory>(
//           network::mojom::URLLoaderFactoryPtrInfo(
//               std::move(url_loader_factory_handle),
//               network::mojom::URLLoaderFactory::Version_)));
// }

}  // namespace application
