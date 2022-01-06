// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Singly or Multiply-included shared traits file depending on circumstances.
// This allows the use of IPC serialization macros in more than one IPC message
// file.
#ifndef CONTENT_PUBLIC_COMMON_COMMON_PARAM_TRAITS_MACROS_H_
#define CONTENT_PUBLIC_COMMON_COMMON_PARAM_TRAITS_MACROS_H_

#include "build/build_config.h"
//#include "content/public/common/console_message_level.h"
//#include "content/public/common/referrer.h"
//#include "content/public/common/web_preferences.h"
//#include "content/public/common/webplugininfo_param_traits.h"
#include "components/viz/common/frame_sinks/begin_frame_args.h"
#include "components/viz/common/quads/compositor_frame.h"
#include "components/viz/common/quads/shared_bitmap.h"
#include "core/shared/common/content_param_traits.h"
#include "core/shared/common/date_time_suggestion.h"
#include "core/shared/common/frame_replication_state.h"
#include "core/shared/common/navigation_gesture.h"
#include "core/shared/common/text_input_state.h"
#include "core/shared/common/view_message_enums.h"
#include "core/shared/common/visual_properties.h"
#include "core/shared/common/common_param_traits.h"
#include "core/shared/common/menu_item.h"
#include "core/shared/common/page_state.h"
#include "core/shared/common/page_zoom.h"
#include "core/shared/common/referrer.h"
#include "core/shared/common/renderer_preferences.h"
//#include "core/shared/common/three_d_api_types.h"
#include "core/shared/common/web_application_info.h"
#include "ipc/ipc_channel_handle.h"
#include "ipc/ipc_message_macros.h"
#include "cc/ipc/cc_param_traits.h"
#include "media/base/audio_parameters.h"
#include "media/base/channel_layout.h"
#include "media/base/ipc/media_param_traits.h"
#include "media/capture/ipc/capture_param_traits.h"
#include "net/base/network_change_notifier.h"
#include "third_party/blink/public/common/screen_orientation/web_screen_orientation_type.h"
#include "third_party/blink/public/platform/web_display_mode.h"
#include "third_party/blink/public/platform/web_float_point.h"
#include "third_party/blink/public/platform/web_float_rect.h"
#include "third_party/blink/public/platform/web_intrinsic_sizing_info.h"
#include "third_party/blink/public/web/web_device_emulation_params.h"
#include "third_party/blink/public/web/web_media_player_action.h"
#include "third_party/blink/public/web/web_plugin_action.h"
#include "third_party/blink/public/web/web_popup_type.h"
#include "third_party/blink/public/web/web_text_direction.h"
#include "ui/base/ime/text_input_mode.h"
#include "ui/base/ime/text_input_type.h"
#include "ui/base/ui_base_types.h"
#include "ui/gfx/color_space.h"
#include "ui/gfx/geometry/point.h"
#include "ui/gfx/geometry/rect.h"
#include "ui/gfx/geometry/rect_f.h"
#include "ui/gfx/geometry/vector2d.h"
#include "ui/gfx/geometry/vector2d_f.h"
#include "ui/gfx/ipc/color/gfx_param_traits.h"
#include "ui/gfx/ipc/gfx_param_traits.h"
#include "ui/gfx/ipc/skia/gfx_skia_param_traits.h"

#include "ipc/ipc_message_macros.h"
#include "net/base/network_change_notifier.h"
#include "services/network/public/cpp/network_param_ipc_traits.h"
#include "third_party/blink/public/platform/modules/permissions/permission_status.mojom.h"
#include "third_party/blink/public/platform/web_history_scroll_restoration_type.h"
#include "third_party/blink/public/platform/web_point.h"
#include "third_party/blink/public/platform/web_rect.h"
#include "third_party/blink/public/platform/web_referrer_policy.h"
#include "third_party/blink/public/platform/web_security_style.h"
#include "third_party/blink/public/platform/web_url_request.h"
#include "third_party/blink/public/web/web_frame_serializer_cache_control_policy.h"
#include "third_party/blink/public/web/window_features.mojom.h"
#if defined(OS_MACOSX)
#include "third_party/blink/public/platform/mac/web_scrollbar_theme.h"
#include "third_party/blink/public/platform/web_scrollbar_buttons_placement.h"
#endif
#include "ui/accessibility/ax_node_data.h"
#include "ui/accessibility/ax_relative_bounds.h"
#include "ui/accessibility/ax_tree_update.h"
#include "ui/base/page_transition_types.h"
#include "ui/base/window_open_disposition.h"
#include "ui/gfx/ipc/geometry/gfx_param_traits.h"
#include "ui/gfx/ipc/gfx_param_traits.h"
#include "ui/gfx/ipc/skia/gfx_skia_param_traits.h"
#include "ui/gfx/transform.h"
#include "ipc/ipc_message_macros.h"
#include "net/base/network_change_notifier.h"
#include "core/shared/common/content_export.h"
#include "core/shared/common/web_preferences.h"
#include "core/shared/common/renderer_preferences.h"
#include "core/shared/common/visual_properties.h"
#include "core/shared/common/screen_info.h"
#include "net/rpc/rpc.h"
#include "services/network/public/cpp/network_param_ipc_traits.h"

#undef IPC_MESSAGE_EXPORT
#define IPC_MESSAGE_EXPORT CONTENT_EXPORT


IPC_ENUM_TRAITS_VALIDATE(ui::PageTransition,
                         ((value &
                           ui::PageTransition::PAGE_TRANSITION_CORE_MASK) <=
                          ui::PageTransition::PAGE_TRANSITION_LAST_CORE))
IPC_ENUM_TRAITS_MAX_VALUE(net::NetworkChangeNotifier::ConnectionType,
                          net::NetworkChangeNotifier::CONNECTION_LAST)
//IPC_ENUM_TRAITS_MAX_VALUE(common::ConsoleMessageLevel,
//                          common::CONSOLE_MESSAGE_LEVEL_LAST)
IPC_ENUM_TRAITS_MAX_VALUE(blink::WebFrameSerializerCacheControlPolicy,
                          blink::WebFrameSerializerCacheControlPolicy::kLast)
IPC_ENUM_TRAITS_MAX_VALUE(blink::WebReferrerPolicy,
                          blink::kWebReferrerPolicyLast)
IPC_ENUM_TRAITS_MAX_VALUE(blink::WebHistoryScrollRestorationType,
                          blink::kWebHistoryScrollRestorationManual)
IPC_ENUM_TRAITS_MAX_VALUE(blink::WebSecurityStyle, blink::kWebSecurityStyleLast)
IPC_ENUM_TRAITS_MAX_VALUE(blink::mojom::PermissionStatus,
                          blink::mojom::PermissionStatus::LAST)
IPC_ENUM_TRAITS_MAX_VALUE(common::EditingBehavior,
                          common::EDITING_BEHAVIOR_LAST)
IPC_ENUM_TRAITS_MAX_VALUE(WindowOpenDisposition,
                          WindowOpenDisposition::MAX_VALUE)
IPC_ENUM_TRAITS_MAX_VALUE(common::V8CacheOptions,
                          common::V8_CACHE_OPTIONS_LAST)
IPC_ENUM_TRAITS_MAX_VALUE(common::SavePreviousDocumentResources,
                          common::SavePreviousDocumentResources::LAST)
IPC_ENUM_TRAITS_MIN_MAX_VALUE(ui::PointerType,
                              ui::POINTER_TYPE_FIRST,
                              ui::POINTER_TYPE_LAST)
IPC_ENUM_TRAITS_MIN_MAX_VALUE(ui::HoverType,
                              ui::HOVER_TYPE_FIRST,
                              ui::HOVER_TYPE_LAST)
IPC_ENUM_TRAITS_MIN_MAX_VALUE(common::ImageAnimationPolicy,
                              common::IMAGE_ANIMATION_POLICY_ALLOWED,
                              common::IMAGE_ANIMATION_POLICY_NO_ANIMATION)
IPC_ENUM_TRAITS_MIN_MAX_VALUE(common::ViewportStyle,
                              common::ViewportStyle::DEFAULT,
                              common::ViewportStyle::LAST)
IPC_ENUM_TRAITS_MIN_MAX_VALUE(
    common::AutoplayPolicy,
    common::AutoplayPolicy::kNoUserGestureRequired,
    common::AutoplayPolicy::kDocumentUserActivationRequired)

IPC_STRUCT_TRAITS_BEGIN(blink::WebPoint)
  IPC_STRUCT_TRAITS_MEMBER(x)
  IPC_STRUCT_TRAITS_MEMBER(y)
IPC_STRUCT_TRAITS_END()

IPC_STRUCT_TRAITS_BEGIN(blink::WebRect)
  IPC_STRUCT_TRAITS_MEMBER(x)
  IPC_STRUCT_TRAITS_MEMBER(y)
  IPC_STRUCT_TRAITS_MEMBER(width)
  IPC_STRUCT_TRAITS_MEMBER(height)
IPC_STRUCT_TRAITS_END()

IPC_ENUM_TRAITS_MAX_VALUE(blink::WebDeviceEmulationParams::ScreenPosition,
                          blink::WebDeviceEmulationParams::kScreenPositionLast)
IPC_ENUM_TRAITS_MAX_VALUE(blink::WebMediaPlayerAction::Type,
                          blink::WebMediaPlayerAction::Type::kTypeLast)
IPC_ENUM_TRAITS_MAX_VALUE(blink::WebPluginAction::Type,
                          blink::WebPluginAction::Type::kTypeLast)
IPC_ENUM_TRAITS_MAX_VALUE(blink::WebPopupType,
                          blink::WebPopupType::kWebPopupTypeLast)
IPC_ENUM_TRAITS_MIN_MAX_VALUE(blink::WebScreenOrientationType,
                              blink::kWebScreenOrientationUndefined,
                              blink::WebScreenOrientationTypeLast)
IPC_ENUM_TRAITS_MAX_VALUE(blink::WebTextDirection,
                          blink::WebTextDirection::kWebTextDirectionLast)
IPC_ENUM_TRAITS_MAX_VALUE(blink::WebDisplayMode,
                          blink::WebDisplayMode::kWebDisplayModeLast)
IPC_ENUM_TRAITS_MAX_VALUE(common::MenuItem::Type, common::MenuItem::TYPE_LAST)
IPC_ENUM_TRAITS_MAX_VALUE(common::NavigationGesture,
                          common::NavigationGestureLast)
IPC_ENUM_TRAITS_MIN_MAX_VALUE(common::PageZoom,
                              common::PageZoom::PAGE_ZOOM_OUT,
                              common::PageZoom::PAGE_ZOOM_IN)
IPC_ENUM_TRAITS_MAX_VALUE(gfx::FontRenderParams::Hinting,
                          gfx::FontRenderParams::HINTING_MAX)
IPC_ENUM_TRAITS_MAX_VALUE(gfx::FontRenderParams::SubpixelRendering,
                          gfx::FontRenderParams::SUBPIXEL_RENDERING_MAX)
IPC_ENUM_TRAITS_MAX_VALUE(common::ScreenOrientationValues,
                          common::SCREEN_ORIENTATION_VALUES_LAST)
IPC_ENUM_TRAITS_MAX_VALUE(common::TapMultipleTargetsStrategy,
                          common::TAP_MULTIPLE_TARGETS_STRATEGY_MAX)
//IPC_ENUM_TRAITS_MAX_VALUE(common::ThreeDAPIType,
//                          common::THREE_D_API_TYPE_LAST)
IPC_ENUM_TRAITS_MAX_VALUE(ui::TextInputMode, ui::TEXT_INPUT_MODE_MAX)
IPC_ENUM_TRAITS_MAX_VALUE(ui::TextInputType, ui::TEXT_INPUT_TYPE_MAX)

#if defined(OS_MACOSX)
IPC_ENUM_TRAITS_MAX_VALUE(
    blink::WebScrollbarButtonsPlacement,
    blink::WebScrollbarButtonsPlacement::kWebScrollbarButtonsPlacementLast)

IPC_ENUM_TRAITS_MAX_VALUE(blink::ScrollerStyle, blink::kScrollerStyleOverlay)
#endif

IPC_STRUCT_TRAITS_BEGIN(blink::WebMediaPlayerAction)
  IPC_STRUCT_TRAITS_MEMBER(type)
  IPC_STRUCT_TRAITS_MEMBER(enable)
IPC_STRUCT_TRAITS_END()

IPC_STRUCT_TRAITS_BEGIN(blink::WebFloatPoint)
  IPC_STRUCT_TRAITS_MEMBER(x)
  IPC_STRUCT_TRAITS_MEMBER(y)
IPC_STRUCT_TRAITS_END()

IPC_STRUCT_TRAITS_BEGIN(blink::WebFloatRect)
  IPC_STRUCT_TRAITS_MEMBER(x)
  IPC_STRUCT_TRAITS_MEMBER(y)
  IPC_STRUCT_TRAITS_MEMBER(width)
  IPC_STRUCT_TRAITS_MEMBER(height)
IPC_STRUCT_TRAITS_END()

IPC_STRUCT_TRAITS_BEGIN(blink::WebSize)
  IPC_STRUCT_TRAITS_MEMBER(width)
  IPC_STRUCT_TRAITS_MEMBER(height)
IPC_STRUCT_TRAITS_END()

IPC_STRUCT_TRAITS_BEGIN(blink::WebDeviceEmulationParams)
  IPC_STRUCT_TRAITS_MEMBER(screen_position)
  IPC_STRUCT_TRAITS_MEMBER(screen_size)
  IPC_STRUCT_TRAITS_MEMBER(view_position)
  IPC_STRUCT_TRAITS_MEMBER(device_scale_factor)
  IPC_STRUCT_TRAITS_MEMBER(view_size)
  IPC_STRUCT_TRAITS_MEMBER(scale)
  IPC_STRUCT_TRAITS_MEMBER(viewport_offset)
  IPC_STRUCT_TRAITS_MEMBER(viewport_scale)
  IPC_STRUCT_TRAITS_MEMBER(screen_orientation_angle)
  IPC_STRUCT_TRAITS_MEMBER(screen_orientation_type)
IPC_STRUCT_TRAITS_END()

IPC_STRUCT_TRAITS_BEGIN(common::MenuItem)
  IPC_STRUCT_TRAITS_MEMBER(label)
  IPC_STRUCT_TRAITS_MEMBER(tool_tip)
  IPC_STRUCT_TRAITS_MEMBER(type)
  IPC_STRUCT_TRAITS_MEMBER(action)
  IPC_STRUCT_TRAITS_MEMBER(rtl)
  IPC_STRUCT_TRAITS_MEMBER(has_directional_override)
  IPC_STRUCT_TRAITS_MEMBER(enabled)
  IPC_STRUCT_TRAITS_MEMBER(checked)
  IPC_STRUCT_TRAITS_MEMBER(submenu)
IPC_STRUCT_TRAITS_END()

IPC_STRUCT_TRAITS_BEGIN(common::DateTimeSuggestion)
  IPC_STRUCT_TRAITS_MEMBER(value)
  IPC_STRUCT_TRAITS_MEMBER(localized_value)
  IPC_STRUCT_TRAITS_MEMBER(label)
IPC_STRUCT_TRAITS_END()

IPC_STRUCT_TRAITS_BEGIN(common::Referrer)
  IPC_STRUCT_TRAITS_MEMBER(url)
  IPC_STRUCT_TRAITS_MEMBER(policy)
IPC_STRUCT_TRAITS_END()

IPC_ENUM_TRAITS_MAX_VALUE(net::RpcMethodType,
                          net::RpcMethodType::kBIDI_STREAM)


IPC_STRUCT_TRAITS_BEGIN(common::WebPreferences)
  IPC_STRUCT_TRAITS_MEMBER(standard_font_family_map)
  IPC_STRUCT_TRAITS_MEMBER(fixed_font_family_map)
  IPC_STRUCT_TRAITS_MEMBER(serif_font_family_map)
  IPC_STRUCT_TRAITS_MEMBER(sans_serif_font_family_map)
  IPC_STRUCT_TRAITS_MEMBER(cursive_font_family_map)
  IPC_STRUCT_TRAITS_MEMBER(fantasy_font_family_map)
  IPC_STRUCT_TRAITS_MEMBER(default_font_size)
  IPC_STRUCT_TRAITS_MEMBER(default_fixed_font_size)
  IPC_STRUCT_TRAITS_MEMBER(minimum_font_size)
  IPC_STRUCT_TRAITS_MEMBER(minimum_logical_font_size)
  IPC_STRUCT_TRAITS_MEMBER(default_encoding)
  IPC_STRUCT_TRAITS_MEMBER(context_menu_on_mouse_up)
  IPC_STRUCT_TRAITS_MEMBER(javascript_enabled)
  IPC_STRUCT_TRAITS_MEMBER(web_security_enabled)
  IPC_STRUCT_TRAITS_MEMBER(loads_images_automatically)
  IPC_STRUCT_TRAITS_MEMBER(images_enabled)
  IPC_STRUCT_TRAITS_MEMBER(plugins_enabled)
  IPC_STRUCT_TRAITS_MEMBER(dom_paste_enabled)
  IPC_STRUCT_TRAITS_MEMBER(shrinks_standalone_images_to_fit)
  IPC_STRUCT_TRAITS_MEMBER(text_areas_are_resizable)
  IPC_STRUCT_TRAITS_MEMBER(allow_scripts_to_close_windows)
  IPC_STRUCT_TRAITS_MEMBER(remote_fonts_enabled)
  IPC_STRUCT_TRAITS_MEMBER(javascript_can_access_clipboard)
  IPC_STRUCT_TRAITS_MEMBER(xslt_enabled)
  IPC_STRUCT_TRAITS_MEMBER(xss_auditor_enabled)
  IPC_STRUCT_TRAITS_MEMBER(dns_prefetching_enabled)
  IPC_STRUCT_TRAITS_MEMBER(data_saver_enabled)
  IPC_STRUCT_TRAITS_MEMBER(local_storage_enabled)
  IPC_STRUCT_TRAITS_MEMBER(databases_enabled)
  IPC_STRUCT_TRAITS_MEMBER(application_cache_enabled)
  IPC_STRUCT_TRAITS_MEMBER(tabs_to_links)
  IPC_STRUCT_TRAITS_MEMBER(history_entry_requires_user_gesture)
  IPC_STRUCT_TRAITS_MEMBER(disable_pushstate_throttle)
  IPC_STRUCT_TRAITS_MEMBER(hyperlink_auditing_enabled)
  IPC_STRUCT_TRAITS_MEMBER(allow_universal_access_from_file_urls)
  IPC_STRUCT_TRAITS_MEMBER(allow_file_access_from_file_urls)
  IPC_STRUCT_TRAITS_MEMBER(webgl1_enabled)
  IPC_STRUCT_TRAITS_MEMBER(webgl2_enabled)
  IPC_STRUCT_TRAITS_MEMBER(pepper_3d_enabled)
  IPC_STRUCT_TRAITS_MEMBER(record_whole_document)
  IPC_STRUCT_TRAITS_MEMBER(use_solid_color_scrollbars)
  IPC_STRUCT_TRAITS_MEMBER(flash_3d_enabled)
  IPC_STRUCT_TRAITS_MEMBER(flash_stage3d_enabled)
  IPC_STRUCT_TRAITS_MEMBER(flash_stage3d_baseline_enabled)
  IPC_STRUCT_TRAITS_MEMBER(privileged_webgl_extensions_enabled)
  IPC_STRUCT_TRAITS_MEMBER(webgl_errors_to_console_enabled)
  IPC_STRUCT_TRAITS_MEMBER(mock_scrollbars_enabled)
  IPC_STRUCT_TRAITS_MEMBER(hide_scrollbars)
  IPC_STRUCT_TRAITS_MEMBER(accelerated_2d_canvas_enabled)
  IPC_STRUCT_TRAITS_MEMBER(minimum_accelerated_2d_canvas_size)
  IPC_STRUCT_TRAITS_MEMBER(antialiased_2d_canvas_disabled)
  IPC_STRUCT_TRAITS_MEMBER(antialiased_clips_2d_canvas_enabled)
  IPC_STRUCT_TRAITS_MEMBER(accelerated_2d_canvas_msaa_sample_count)
  IPC_STRUCT_TRAITS_MEMBER(accelerated_filters_enabled)
  IPC_STRUCT_TRAITS_MEMBER(deferred_filters_enabled)
  //IPC_STRUCT_TRAITS_MEMBER(container_culling_enabled)
  IPC_STRUCT_TRAITS_MEMBER(allow_running_insecure_content)
  IPC_STRUCT_TRAITS_MEMBER(disable_reading_from_canvas)
  IPC_STRUCT_TRAITS_MEMBER(strict_mixed_content_checking)
  IPC_STRUCT_TRAITS_MEMBER(strict_powerful_feature_restrictions)
  IPC_STRUCT_TRAITS_MEMBER(allow_geolocation_on_insecure_origins)
  IPC_STRUCT_TRAITS_MEMBER(strictly_block_blockable_mixed_content)
  IPC_STRUCT_TRAITS_MEMBER(block_mixed_plugin_content)
  IPC_STRUCT_TRAITS_MEMBER(enable_scroll_animator)
  IPC_STRUCT_TRAITS_MEMBER(password_echo_enabled)
  IPC_STRUCT_TRAITS_MEMBER(should_clear_document_background)
  IPC_STRUCT_TRAITS_MEMBER(touch_event_feature_detection_enabled)
  IPC_STRUCT_TRAITS_MEMBER(touch_adjustment_enabled)
  IPC_STRUCT_TRAITS_MEMBER(pointer_events_max_touch_points)
  IPC_STRUCT_TRAITS_MEMBER(available_pointer_types)
  IPC_STRUCT_TRAITS_MEMBER(primary_pointer_type)
  IPC_STRUCT_TRAITS_MEMBER(available_hover_types)
  IPC_STRUCT_TRAITS_MEMBER(primary_hover_type)
  IPC_STRUCT_TRAITS_MEMBER(barrel_button_for_drag_enabled)
  IPC_STRUCT_TRAITS_MEMBER(sync_xhr_in_documents_enabled)
  IPC_STRUCT_TRAITS_MEMBER(should_respect_image_orientation)
  IPC_STRUCT_TRAITS_MEMBER(number_of_cpu_cores)
  IPC_STRUCT_TRAITS_MEMBER(editing_behavior)
  IPC_STRUCT_TRAITS_MEMBER(supports_multiple_windows)
  IPC_STRUCT_TRAITS_MEMBER(viewport_enabled)
  IPC_STRUCT_TRAITS_MEMBER(viewport_meta_enabled)
  IPC_STRUCT_TRAITS_MEMBER(shrinks_viewport_contents_to_fit)
  IPC_STRUCT_TRAITS_MEMBER(viewport_style)
  IPC_STRUCT_TRAITS_MEMBER(smooth_scroll_for_find_enabled)
  IPC_STRUCT_TRAITS_MEMBER(main_frame_resizes_are_orientation_changes)
  IPC_STRUCT_TRAITS_MEMBER(initialize_at_minimum_page_scale)
  IPC_STRUCT_TRAITS_MEMBER(smart_insert_delete_enabled)
  IPC_STRUCT_TRAITS_MEMBER(cookie_enabled)
  IPC_STRUCT_TRAITS_MEMBER(navigate_on_drag_drop)
  IPC_STRUCT_TRAITS_MEMBER(spatial_navigation_enabled)
  IPC_STRUCT_TRAITS_MEMBER(v8_cache_options)
  IPC_STRUCT_TRAITS_MEMBER(accelerated_video_decode_enabled)
  IPC_STRUCT_TRAITS_MEMBER(animation_policy)
  IPC_STRUCT_TRAITS_MEMBER(user_gesture_required_for_presentation)
  IPC_STRUCT_TRAITS_MEMBER(text_track_margin_percentage)
  IPC_STRUCT_TRAITS_MEMBER(save_previous_document_resources)
#if defined(OS_ANDROID)
  IPC_STRUCT_TRAITS_MEMBER(text_autosizing_enabled)
  IPC_STRUCT_TRAITS_MEMBER(font_scale_factor)
  IPC_STRUCT_TRAITS_MEMBER(device_scale_adjustment)
  IPC_STRUCT_TRAITS_MEMBER(force_enable_zoom)
  IPC_STRUCT_TRAITS_MEMBER(fullscreen_supported)
  IPC_STRUCT_TRAITS_MEMBER(double_tap_to_zoom_enabled)
  IPC_STRUCT_TRAITS_MEMBER(media_playback_gesture_whitelist_scope)
  IPC_STRUCT_TRAITS_MEMBER(default_video_poster_url)
  IPC_STRUCT_TRAITS_MEMBER(support_deprecated_target_density_dpi)
  IPC_STRUCT_TRAITS_MEMBER(use_legacy_background_size_shorthand_behavior)
  IPC_STRUCT_TRAITS_MEMBER(wide_viewport_quirk)
  IPC_STRUCT_TRAITS_MEMBER(use_wide_viewport)
  IPC_STRUCT_TRAITS_MEMBER(force_zero_layout_height)
  IPC_STRUCT_TRAITS_MEMBER(viewport_meta_layout_size_quirk)
  IPC_STRUCT_TRAITS_MEMBER(viewport_meta_merge_content_quirk)
  IPC_STRUCT_TRAITS_MEMBER(viewport_meta_non_user_scalable_quirk)
  IPC_STRUCT_TRAITS_MEMBER(viewport_meta_zero_values_quirk)
  IPC_STRUCT_TRAITS_MEMBER(clobber_user_agent_initial_scale_quirk)
  IPC_STRUCT_TRAITS_MEMBER(ignore_main_frame_overflow_hidden_quirk)
  IPC_STRUCT_TRAITS_MEMBER(report_screen_size_in_physical_pixels_quirk)
  IPC_STRUCT_TRAITS_MEMBER(reuse_global_for_unowned_main_frame)
  IPC_STRUCT_TRAITS_MEMBER(spellcheck_enabled_by_default)
  IPC_STRUCT_TRAITS_MEMBER(video_fullscreen_orientation_lock_enabled)
  IPC_STRUCT_TRAITS_MEMBER(video_rotate_to_fullscreen_enabled)
  IPC_STRUCT_TRAITS_MEMBER(video_fullscreen_detection_enabled)
  IPC_STRUCT_TRAITS_MEMBER(embedded_media_experience_enabled)
  IPC_STRUCT_TRAITS_MEMBER(immersive_mode_enabled)
  IPC_STRUCT_TRAITS_MEMBER(css_hex_alpha_color_enabled)
  IPC_STRUCT_TRAITS_MEMBER(enable_media_download_in_product_help)
  IPC_STRUCT_TRAITS_MEMBER(scroll_top_left_interop_enabled)
#endif  // defined(OS_ANDROID)
  IPC_STRUCT_TRAITS_MEMBER(default_minimum_page_scale_factor)
  IPC_STRUCT_TRAITS_MEMBER(default_maximum_page_scale_factor)
  IPC_STRUCT_TRAITS_MEMBER(hide_download_ui)
  IPC_STRUCT_TRAITS_MEMBER(background_video_track_optimization_enabled)
  IPC_STRUCT_TRAITS_MEMBER(presentation_receiver)
  IPC_STRUCT_TRAITS_MEMBER(media_controls_enabled)
  IPC_STRUCT_TRAITS_MEMBER(do_not_update_selection_on_mutating_selection_range)
  IPC_STRUCT_TRAITS_MEMBER(autoplay_policy)
  IPC_STRUCT_TRAITS_MEMBER(low_priority_iframes_threshold)
  IPC_STRUCT_TRAITS_MEMBER(picture_in_picture_enabled)
IPC_STRUCT_TRAITS_END()

IPC_STRUCT_TRAITS_BEGIN(common::VisualProperties)
  IPC_STRUCT_TRAITS_MEMBER(screen_info)
  IPC_STRUCT_TRAITS_MEMBER(auto_resize_enabled)
  IPC_STRUCT_TRAITS_MEMBER(min_size_for_auto_resize)
  IPC_STRUCT_TRAITS_MEMBER(max_size_for_auto_resize)
  IPC_STRUCT_TRAITS_MEMBER(new_size)
  IPC_STRUCT_TRAITS_MEMBER(compositor_viewport_pixel_size)
  IPC_STRUCT_TRAITS_MEMBER(browser_controls_shrink_blink_size)
  IPC_STRUCT_TRAITS_MEMBER(scroll_focused_node_into_view)
  IPC_STRUCT_TRAITS_MEMBER(top_controls_height)
  IPC_STRUCT_TRAITS_MEMBER(bottom_controls_height)
  IPC_STRUCT_TRAITS_MEMBER(local_surface_id)
  IPC_STRUCT_TRAITS_MEMBER(visible_viewport_size)
  IPC_STRUCT_TRAITS_MEMBER(is_fullscreen_granted)
  IPC_STRUCT_TRAITS_MEMBER(display_mode)
  IPC_STRUCT_TRAITS_MEMBER(needs_resize_ack)
  IPC_STRUCT_TRAITS_MEMBER(content_source_id)
  IPC_STRUCT_TRAITS_MEMBER(capture_sequence_number)
IPC_STRUCT_TRAITS_END()

IPC_STRUCT_TRAITS_BEGIN(common::RendererPreferences)
  IPC_STRUCT_TRAITS_MEMBER(can_accept_load_drops)
  IPC_STRUCT_TRAITS_MEMBER(should_antialias_text)
  IPC_STRUCT_TRAITS_MEMBER(hinting)
  IPC_STRUCT_TRAITS_MEMBER(use_autohinter)
  IPC_STRUCT_TRAITS_MEMBER(use_bitmaps)
  IPC_STRUCT_TRAITS_MEMBER(subpixel_rendering)
  IPC_STRUCT_TRAITS_MEMBER(use_subpixel_positioning)
  IPC_STRUCT_TRAITS_MEMBER(focus_ring_color)
  IPC_STRUCT_TRAITS_MEMBER(thumb_active_color)
  IPC_STRUCT_TRAITS_MEMBER(thumb_inactive_color)
  IPC_STRUCT_TRAITS_MEMBER(track_color)
  IPC_STRUCT_TRAITS_MEMBER(active_selection_bg_color)
  IPC_STRUCT_TRAITS_MEMBER(active_selection_fg_color)
  IPC_STRUCT_TRAITS_MEMBER(inactive_selection_bg_color)
  IPC_STRUCT_TRAITS_MEMBER(inactive_selection_fg_color)
  IPC_STRUCT_TRAITS_MEMBER(browser_handles_all_top_level_requests)
  IPC_STRUCT_TRAITS_MEMBER(caret_blink_interval)
  IPC_STRUCT_TRAITS_MEMBER(use_custom_colors)
  IPC_STRUCT_TRAITS_MEMBER(enable_referrers)
  IPC_STRUCT_TRAITS_MEMBER(enable_do_not_track)
  IPC_STRUCT_TRAITS_MEMBER(enable_encrypted_media)
  IPC_STRUCT_TRAITS_MEMBER(webrtc_ip_handling_policy)
  IPC_STRUCT_TRAITS_MEMBER(webrtc_udp_min_port)
  IPC_STRUCT_TRAITS_MEMBER(webrtc_udp_max_port)
  IPC_STRUCT_TRAITS_MEMBER(user_agent_override)
  IPC_STRUCT_TRAITS_MEMBER(accept_languages)
  IPC_STRUCT_TRAITS_MEMBER(tap_multiple_targets_strategy)
  IPC_STRUCT_TRAITS_MEMBER(disable_client_blocked_error_page)
  IPC_STRUCT_TRAITS_MEMBER(plugin_fullscreen_allowed)
  IPC_STRUCT_TRAITS_MEMBER(network_contry_iso)
#if defined(OS_LINUX)
  IPC_STRUCT_TRAITS_MEMBER(system_font_family_name)
#endif
#if defined(OS_WIN)
  IPC_STRUCT_TRAITS_MEMBER(caption_font_family_name)
  IPC_STRUCT_TRAITS_MEMBER(caption_font_height)
  IPC_STRUCT_TRAITS_MEMBER(small_caption_font_family_name)
  IPC_STRUCT_TRAITS_MEMBER(small_caption_font_height)
  IPC_STRUCT_TRAITS_MEMBER(menu_font_family_name)
  IPC_STRUCT_TRAITS_MEMBER(menu_font_height)
  IPC_STRUCT_TRAITS_MEMBER(status_font_family_name)
  IPC_STRUCT_TRAITS_MEMBER(status_font_height)
  IPC_STRUCT_TRAITS_MEMBER(message_font_family_name)
  IPC_STRUCT_TRAITS_MEMBER(message_font_height)
  IPC_STRUCT_TRAITS_MEMBER(vertical_scroll_bar_width_in_dips)
  IPC_STRUCT_TRAITS_MEMBER(horizontal_scroll_bar_height_in_dips)
  IPC_STRUCT_TRAITS_MEMBER(arrow_bitmap_height_vertical_scroll_bar_in_dips)
  IPC_STRUCT_TRAITS_MEMBER(arrow_bitmap_width_horizontal_scroll_bar_in_dips)
#endif
IPC_STRUCT_TRAITS_END()

IPC_STRUCT_TRAITS_BEGIN(common::ScreenInfo)
  IPC_STRUCT_TRAITS_MEMBER(device_scale_factor)
  IPC_STRUCT_TRAITS_MEMBER(color_space)
#if defined(OS_MACOSX)
  IPC_STRUCT_TRAITS_MEMBER(icc_profile)
#endif
  IPC_STRUCT_TRAITS_MEMBER(depth)
  IPC_STRUCT_TRAITS_MEMBER(depth_per_component)
  IPC_STRUCT_TRAITS_MEMBER(is_monochrome)
  IPC_STRUCT_TRAITS_MEMBER(rect)
  IPC_STRUCT_TRAITS_MEMBER(available_rect)
  IPC_STRUCT_TRAITS_MEMBER(orientation_type)
  IPC_STRUCT_TRAITS_MEMBER(orientation_angle)
IPC_STRUCT_TRAITS_END()

IPC_ENUM_TRAITS_MAX_VALUE(common::WebApplicationInfo::MobileCapable,
                          common::WebApplicationInfo::MOBILE_CAPABLE_APPLE)

IPC_STRUCT_TRAITS_BEGIN(common::WebApplicationInfo::IconInfo)
  IPC_STRUCT_TRAITS_MEMBER(url)
  IPC_STRUCT_TRAITS_MEMBER(width)
  IPC_STRUCT_TRAITS_MEMBER(height)
  IPC_STRUCT_TRAITS_MEMBER(data)
IPC_STRUCT_TRAITS_END()

IPC_STRUCT_TRAITS_BEGIN(common::WebApplicationInfo)
  IPC_STRUCT_TRAITS_MEMBER(title)
  IPC_STRUCT_TRAITS_MEMBER(description)
  IPC_STRUCT_TRAITS_MEMBER(app_url)
  IPC_STRUCT_TRAITS_MEMBER(icons)
  IPC_STRUCT_TRAITS_MEMBER(mobile_capable)
IPC_STRUCT_TRAITS_END()


#endif  // CONTENT_PUBLIC_COMMON_COMMON_PARAM_TRAITS_MACROS_H_
