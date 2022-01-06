// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_RUNTIME_MUMBA_SHIMS_WEB_STRUCTS_PRIVATE_H_
#define MUMBA_RUNTIME_MUMBA_SHIMS_WEB_STRUCTS_PRIVATE_H_

#include "WebShims.h"
#include "CompositorStructsPrivate.h"

#define INSIDE_BLINK 1

#include "base/logging.h"
#include "base/macros.h"
#include "base/bind.h"
#include "base/callback.h"
#include "base/callback_forward.h"
#include "base/callback_internal.h"
#include "base/unguessable_token.h"
#include "base/strings/utf_string_conversions.h"
#include "ui/gfx/color_space.h"
#include "media/blink/webmediaplayer_impl.h"
#include "third_party/blink/renderer/platform/wtf/assertions.h"
#include "third_party/blink/renderer/platform/wtf/compiler.h"
#include "third_party/blink/renderer/core/dom/element_registration_options.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_element_registration_options.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_offscreen_canvas.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/platform/graphics/image.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "third_party/blink/renderer/core/imagebitmap/image_bitmap.h"
#include "third_party/blink/public/platform/web_common.h"
#include "third_party/blink/public/platform/web_cursor_info.h"
#include "third_party/blink/public/platform/web_private_ptr.h"
#include "third_party/blink/public/platform/web_string.h"
#include "third_party/blink/public/platform/web_url_response.h"
#include "third_party/blink/public/platform/web_url_request.h"
#include "third_party/blink/public/web/web_autofill_client.h"
#include "third_party/blink/public/platform/web_vector.h"
#include "third_party/blink/public/platform/web_input_event.h"
#include "third_party/blink/public/platform/web_http_load_info.h"
#include "third_party/blink/public/platform/web_float_rect.h"
#include "third_party/blink/public/platform/web_media_player_source.h"
#include "third_party/blink/public/web/web_selection.h"
#include "third_party/blink/public/web/web_console_message.h"
#include "third_party/blink/public/web/web_node.h"
#include "third_party/blink/public/web/web_window_features.h"
#include "third_party/blink/public/web/web_view.h"
#include "third_party/blink/public/web/web_frame_client.h"
#include "third_party/blink/public/web/web_frame_widget.h"
#include "third_party/blink/public/web/web_remote_frame_client.h"
#include "third_party/blink/public/web/web_find_options.h"
#include "third_party/blink/public/web/web_view_client.h"
#include "third_party/blink/public/web/web_hit_test_result.h"
#include "third_party/blink/public/web/web_element.h"
#include "third_party/blink/public/web/web_form_element.h"
#include "third_party/blink/public/web/web_document.h"
#include "third_party/blink/public/web/web_date_time_chooser_params.h"
#include "third_party/blink/public/web/web_ax_object.h"
#include "third_party/blink/public/web/web_dom_event.h"
#include "third_party/blink/public/web/web_frame.h"
#include "third_party/blink/public/web/web_plugin.h"
#include "third_party/blink/public/web/web_local_frame.h"
#include "third_party/blink/public/web/web_remote_frame.h"
#include "third_party/blink/renderer/core/html/html_image_element.h"
#include "third_party/blink/renderer/core/html/html_iframe_element.h"
#include "third_party/blink/renderer/core/html/html_anchor_element.h"
#include "third_party/blink/renderer/core/html/html_area_element.h"
#include "third_party/blink/renderer/core/html/html_base_element.h"
#include "third_party/blink/renderer/core/html/html_body_element.h"
#include "third_party/blink/renderer/core/html/html_br_element.h"
#include "third_party/blink/renderer/core/html/html_collection.h"
#include "third_party/blink/renderer/core/html/html_content_element.h"
#include "third_party/blink/renderer/core/html/html_data_element.h"
#include "third_party/blink/renderer/core/html/html_details_element.h"
#include "third_party/blink/renderer/core/html/html_dialog_element.h"
#include "third_party/blink/renderer/core/html/html_dimension.h"
#include "third_party/blink/renderer/core/html/html_directory_element.h"
#include "third_party/blink/renderer/core/html/html_div_element.h"
#include "third_party/blink/renderer/core/html/html_dlist_element.h"
#include "third_party/blink/renderer/core/html/html_document.h"
#include "third_party/blink/renderer/core/html/html_embed_element.h"
#include "third_party/blink/renderer/core/html/html_font_element.h"
#include "third_party/blink/renderer/core/html/html_frame_element.h"
#include "third_party/blink/renderer/core/html/html_frame_owner_element.h"
#include "third_party/blink/renderer/core/html/html_frame_set_element.h"
#include "third_party/blink/renderer/core/html/html_head_element.h"
#include "third_party/blink/renderer/core/html/html_heading_element.h"
#include "third_party/blink/renderer/core/html/html_hr_element.h"
#include "third_party/blink/renderer/core/html/html_html_element.h"
#include "third_party/blink/renderer/core/html/html_li_element.h"
#include "third_party/blink/renderer/core/html/html_link_element.h"
#include "third_party/blink/renderer/core/html/html_map_element.h"
#include "third_party/blink/renderer/core/html/html_marquee_element.h"
#include "third_party/blink/renderer/core/html/html_menu_element.h"
#include "third_party/blink/renderer/core/html/media/html_media_element.h"
#include "third_party/blink/renderer/core/html/html_meta_element.h"
#include "third_party/blink/renderer/core/html/html_meter_element.h"
#include "third_party/blink/renderer/core/html/html_mod_element.h"
#include "third_party/blink/renderer/core/html/html_name_collection.h"
#include "third_party/blink/renderer/core/html/html_no_embed_element.h"
#include "third_party/blink/renderer/core/html/html_no_script_element.h"
#include "third_party/blink/renderer/core/html/html_object_element.h"
#include "third_party/blink/renderer/core/html/html_olist_element.h"
#include "third_party/blink/renderer/core/html/html_paragraph_element.h"
#include "third_party/blink/renderer/core/html/html_param_element.h"
#include "third_party/blink/renderer/core/html/html_picture_element.h"
#include "third_party/blink/renderer/core/html/html_plugin_element.h"
#include "third_party/blink/renderer/core/html/html_pre_element.h"
#include "third_party/blink/renderer/core/html/html_progress_element.h"
#include "third_party/blink/renderer/core/html/html_quote_element.h"
#include "third_party/blink/renderer/core/html/html_rt_element.h"
#include "third_party/blink/renderer/core/html/html_ruby_element.h"
#include "third_party/blink/renderer/core/html/html_script_element.h"
#include "third_party/blink/renderer/core/html/html_shadow_element.h"
#include "third_party/blink/renderer/core/html/html_slot_element.h"
#include "third_party/blink/renderer/core/html/html_source_element.h"
#include "third_party/blink/renderer/core/html/html_span_element.h"
#include "third_party/blink/renderer/core/html/html_style_element.h"
#include "third_party/blink/renderer/core/html/html_summary_element.h"
#include "third_party/blink/renderer/core/html/html_table_caption_element.h"
#include "third_party/blink/renderer/core/html/html_table_cell_element.h"
#include "third_party/blink/renderer/core/html/html_table_col_element.h"
#include "third_party/blink/renderer/core/html/html_table_element.h"
#include "third_party/blink/renderer/core/html/html_table_part_element.h"
#include "third_party/blink/renderer/core/html/html_table_row_element.h"
#include "third_party/blink/renderer/core/html/html_table_rows_collection.h"
#include "third_party/blink/renderer/core/html/html_table_section_element.h"
#include "third_party/blink/renderer/core/html/html_tag_collection.h"
#include "third_party/blink/renderer/core/html/html_time_element.h"
#include "third_party/blink/renderer/core/html/html_title_element.h"
#include "third_party/blink/renderer/core/html/html_ulist_element.h"
#include "third_party/blink/renderer/core/html/media/media_controls.h"
#include "third_party/blink/renderer/core/html/html_unknown_element.h"
#include "third_party/blink/renderer/core/html/html_view_source_document.h"
#include "third_party/blink/renderer/core/html/html_wbr_element.h"
#include "third_party/blink/renderer/modules/websockets/web_socket_channel_client.h"
#include "third_party/blink/renderer/modules/websockets/web_socket_channel.h"
#include "third_party/blink/renderer/modules/websockets/web_socket_channel_impl.h"
#include "third_party/blink/renderer/core/svg/svg_image_element.h"
#include "third_party/blink/renderer/platform/wtf/typed_arrays/uint8_array.h"
#include "third_party/blink/renderer/core/fetch/global_fetch.h"
#include "third_party/blink/renderer/core/fetch/request.h"
#include "third_party/blink/renderer/core/fetch/request_init.h"
#include "third_party/blink/renderer/core/fetch/response.h"
#include "third_party/blink/renderer/core/fetch/headers.h"
#include "third_party/blink/renderer/modules/canvas/canvas2d/path_2d.h"
#include "third_party/blink/renderer/modules/serviceworkers/service_worker_global_scope.h"
#include "third_party/blink/renderer/core/streams/readable_stream.h"
#include "third_party/blink/renderer/core/streams/writable_stream.h"
#include "third_party/blink/renderer/core/streams/transform_stream.h"
#include "third_party/blink/renderer/modules/mediasource/media_source.h"
#include "third_party/blink/renderer/modules/mediasource/source_buffer.h"
#include "third_party/blink/renderer/core/html/image_document.h"
#include "third_party/blink/renderer/core/html/time_ranges.h"
#include "third_party/blink/renderer/modules/mediasource/html_video_element_media_source.h"
#include "third_party/blink/renderer/modules/mediasource/video_playback_quality.h"
#include "third_party/blink/renderer/modules/csspaint/paint_rendering_context_2d.h"
#include "third_party/blink/renderer/core/messaging/message_channel.h"
#include "third_party/blink/renderer/core/html/media/html_media_element.h"
#include "third_party/blink/renderer/core/html/media/html_audio_element.h"
#include "third_party/blink/renderer/core/html/media/html_video_element.h"
#include "third_party/blink/renderer/core/html/track/audio_track_list.h"
#include "third_party/blink/renderer/core/html/track/video_track_list.h"
#include "third_party/blink/renderer/core/html/track/text_track_list.h"
#include "third_party/blink/renderer/core/html/plugin_document.h"
#include "third_party/blink/renderer/core/html/text_document.h"
#include "third_party/blink/renderer/modules/canvas/htmlcanvas/html_canvas_element_module.h"
#include "third_party/blink/renderer/modules/csspaint/paint_size.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_array_buffer.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_blob.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_document.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_form_data.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_readable_stream.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_readable_stream_default_reader.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_writable_stream.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_navigator.h"
#include "third_party/blink/renderer/modules/csspaint/css_paint_worklet.h"
#include "third_party/blink/renderer/core/workers/dedicated_worker.h"
#include "third_party/blink/renderer/core/workers/worker_native_client.h"
#include "third_party/blink/renderer/core/streams/transform_stream_transformer.h"
#include "third_party/blink/renderer/core/streams/writable_stream_native.h"
#include "third_party/blink/public/web/web_element_collection.h"
#include "third_party/blink/public/web/web_plugin_container.h"
#include "third_party/blink/public/web/web_plugin_params.h"
#include "third_party/blink/public/platform/web_media_stream.h"
#include "third_party/blink/public/platform/web_keyboard_event.h"
#include "third_party/blink/public/platform/web_input_event.h"
#include "third_party/blink/public/platform/web_mouse_wheel_event.h"
#include "third_party/blink/public/platform/web_mouse_event.h"
#include "third_party/blink/public/platform/web_network_state_notifier.h"
#include "third_party/blink/renderer/core/frame/location.h"
#include "third_party/blink/public/web/web_print_params.h"
#include "third_party/blink/public/web/web_print_scaling_option.h"
#include "third_party/blink/public/web/web_print_preset_options.h"
#include "third_party/blink/public/web/web_performance.h"
#include "third_party/blink/public/web/web_popup_menu_info.h"
#include "third_party/blink/public/web/web_media_player_action.h"
#include "third_party/blink/public/web/web_plugin_action.h"
#include "third_party/blink/public/web/web_script_source.h"
#include "third_party/blink/public/web/web_surrounding_text.h"
#include "third_party/blink/renderer/core/html/html_template_element.h"
#include "third_party/blink/renderer/core/html/html_frame_element.h"
#include "third_party/blink/renderer/core/html/canvas/html_canvas_element.h"
#include "third_party/blink/renderer/core/html/canvas/canvas_context_creation_attributes_core.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_descriptor.h"
#include "third_party/blink/renderer/platform/graphics/paint/paint_recorder.h"
#include "third_party/blink/renderer/core/editing/frame_caret.h"
#include "third_party/blink/renderer/core/editing/editor.h"
#include "third_party/blink/renderer/core/editing/editing_utilities.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/public/platform/web_double_size.h"
#include "third_party/blink/renderer/core/dom/ax_object_cache.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/document_type.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/url/dom_url.h"
#include "third_party/blink/renderer/core/frame/use_counter.h"
#include "third_party/blink/renderer/core/streams/writable_stream_default_writer.h"
#include "third_party/blink/renderer/core/dom/node.h"
#include "third_party/blink/renderer/core/dom/range.h"
#include "third_party/blink/renderer/core/dom/node_list.h"
#include "third_party/blink/renderer/core/dom/static_node_list.h"
#include "third_party/blink/renderer/core/dom/tag_collection.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/fullscreen/fullscreen.h"
#include "third_party/blink/renderer/core/css/css_style_sheet.h"
#include "third_party/blink/renderer/core/css/css_style_sheet_init.h"
#include "third_party/blink/renderer/core/css/css_selector.h"
#include "third_party/blink/renderer/core/css/css_selector_watch.h"
#include "third_party/blink/renderer/core/css/css_selector_list.h"
#include "third_party/blink/renderer/core/css/selector_query.h"
#include "third_party/blink/renderer/core/css/style_sheet_contents.h"
#include "third_party/blink/renderer/core/css/parser/css_parser.h"
#include "third_party/blink/renderer/core/editing/serializers/serialization.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/editing/ime/input_method_controller.h"
#include "third_party/blink/renderer/core/editing/editing_utilities.h"
#include "third_party/blink/renderer/core/editing/ime/ime_text_span_vector_builder.h"
#include "third_party/blink/renderer/core/events/keyboard_event.h"
#include "third_party/blink/renderer/core/events/progress_event.h"
#include "third_party/blink/renderer/core/html/html_all_collection.h"
#include "third_party/blink/renderer/core/html/html_collection.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/html/html_link_element.h"
#include "third_party/blink/renderer/core/html/html_head_element.h"
#include "third_party/blink/renderer/core/html/forms/html_form_element.h"
#include "third_party/blink/renderer/core/html/forms/html_form_control_element.h"
#include "third_party/blink/renderer/core/html/forms/html_text_area_element.h"
#include "third_party/blink/renderer/core/html/forms/html_input_element.h"
#include "third_party/blink/renderer/core/html/forms/html_select_element.h"
#include "third_party/blink/renderer/core/html/custom/v0_custom_element_processing_stack.h"
#include "third_party/blink/renderer/core/html_element_type_helpers.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/loader/frame_loader.h"
#include "third_party/blink/renderer/core/frame/web_frame_widget_base.h"
#include "third_party/blink/renderer/core/editing/dom_selection.h"
#include "third_party/blink/renderer/core/editing/plain_text_range.h"
#include "third_party/blink/renderer/core/editing/ephemeral_range.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/bindings/core/v8/worker_or_worklet_script_controller.h"
#include "third_party/blink/renderer/bindings/core/v8/script_source_code.h"
#include "third_party/blink/renderer/core/workers/worker_global_scope.h"
#include "third_party/blink/renderer/core/xmlhttprequest/xml_http_request.h"
#include "third_party/blink/renderer/platform/graphics/canvas_2d_layer_bridge.h"
#include "third_party/blink/public/web/web_associated_url_loader_options.h"
#include "third_party/blink/public/web/web_device_emulation_params.h"
#include "third_party/blink/public/platform/web_media_stream_source.h"
#include "third_party/blink/public/platform/web_media_source.h"
#include "third_party/blink/public/platform/web_media_stream.h"
#include "third_party/blink/public/platform/web_media_stream_track.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_source.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_component.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/modules/accessibility/ax_object.h"
#include "third_party/blink/renderer/modules/accessibility/ax_object_cache_impl.h"
#include "third_party/blink/renderer/modules/serviceworkers/navigator_service_worker.h"
#include "third_party/blink/renderer/bindings/core/v8/exception_state.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_frame_request_callback.h"
#include "third_party/blink/renderer/bindings/core/v8/serialization/serialized_script_value.h"
#include "third_party/blink/renderer/core/editing/selection_template.h"
#include "third_party/blink/renderer/core/streams/readable_stream_reader.h"
#include "third_party/blink/renderer/core/editing/iterators/text_iterator_behavior.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"
#include "third_party/blink/renderer/core/exported/web_view_impl.h"
#include "third_party/blink/renderer/core/exported/web_plugin_container_impl.h"
#include "third_party/blink/renderer/platform/heap/handle.h"
#include "third_party/blink/renderer/platform/wtf/type_traits.h"
#include "third_party/blink/renderer/platform/drag_image.h"
#include "third_party/blink/renderer/platform/graphics/bitmap_image.h"
#include "third_party/blink/renderer/platform/graphics/image.h"
#include "third_party/blink/renderer/platform/graphics/graphics_layer.h"
#include "third_party/blink/renderer/modules/serviceworkers/fetch_event.h"
#include "third_party/blink/renderer/modules/canvas/canvas2d/canvas_rendering_context_2d.h"
#include "third_party/blink/public/web/web_settings.h"
#include "third_party/blink/public/platform/web_runtime_features.h"
#include "third_party/blink/public/mojom/page/page_visibility_state.mojom-shared.h"
#include "third_party/blink/public/platform/modules/serviceworker/web_service_worker_network_provider.h"
#include "third_party/blink/renderer/bindings/core/v8/serialization/transferables.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_service_worker_registration.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_clients.h"
#include "third_party/blink/renderer/core/fetch/response.h"
#include "third_party/icu/source/common/unicode/uchar.h"
#include "third_party/icu/source/common/unicode/uscript.h"
#include "cc/paint/skia_paint_canvas.h"
#include "cc/paint/paint_recorder.h"
#include "cc/paint/display_item_list.h"
#include "cc/animation/animation_host.h"
#include "cc/trees/swap_promise.h"
#include "cc/trees/layer_tree_host.h"
#include "skia/ext/platform_canvas.h"
#include "third_party/skia/include/core/SkRefCnt.h"
#include "third_party/skia/include/core/SkImage.h"
#include "core/shared/application/frame_blame_context.h"
#include "core/shared/application/application_thread.h"
#include "core/shared/application/application_url_loader.h"
#include "core/shared/application/resource_dispatcher.h"
#include "core/shared/application/blink_platform_impl.h"
#include "core/shared/application/child_url_loader_factory_bundle.h"
#include "core/shared/application/application_window_dispatcher.h"
#include "core/shared/application/websocket_handshake_throttle_provider_impl.h"
#include "core/shared/application/url_loader_throttle_provider_impl.h"
#include "core/shared/application/service_worker/web_service_worker_provider_impl.h"
#include "core/shared/application/service_worker/service_worker_network_provider.h"
#include "core/shared/application/service_worker/service_worker_dispatcher.h"
#include "core/shared/application/service_worker/worker_fetch_context_impl.h"
#include "core/shared/application/request_extra_data.h"
#include "core/shared/common/service_worker/service_worker_provider_host_info.h"
#include "core/shared/common/service_worker/service_worker_utils.h"
#include "core/shared/common/web_helper.h"
#include "core/shared/common/wrapper_shared_url_loader_factory.h"
#include "third_party/blink/public/mojom/service_worker/service_worker_object.mojom.h"
#include "third_party/blink/public/platform/modules/serviceworker/web_service_worker_network_provider.h"
#include "runtime/MumbaShims/v8/v8_engine.h"
#include "runtime/MumbaShims/v8/v8_context.h"
#include "runtime/MumbaShims/v8/v8_value.h"
#include "runtime/MumbaShims/v8/v8_exception.h"
#include "runtime/MumbaShims/CompositorHelper.h"
#include "third_party/blink/renderer/core/streams/transform_stream_default_controller.h"
#include "third_party/blink/renderer/bindings/core/v8/array_buffer_or_array_buffer_view_or_blob_or_document_or_string_or_form_data_or_url_search_params.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_response.h"
#include "third_party/blink/renderer/modules/webgl/webgl_rendering_context.h"
#include "third_party/blink/renderer/modules/webgl/webgl2_rendering_context.h"
#include "third_party/blink/renderer/modules/serviceworkers/service_worker_container.h"
#include "third_party/blink/renderer/modules/serviceworkers/service_worker.h"
#include "third_party/blink/renderer/modules/serviceworkers/extendable_message_event.h"
#include "third_party/blink/renderer/bindings/core/v8/local_window_proxy.h"
#include "third_party/blink/renderer/bindings/core/v8/script_controller.h"
#include "third_party/blink/renderer/modules/serviceworkers/service_worker_registration.h"
#include "third_party/blink/renderer/modules/csspaint/paint_worklet.h"
#include "third_party/blink/renderer/modules/csspaint/paint_worklet_global_scope.h"
#include "third_party/blink/renderer/modules/csspaint/paint_worklet_global_scope_proxy.h"
#include "third_party/blink/renderer/bindings/core/v8/serialization/v8_script_value_serializer.h"
#include "third_party/blink/renderer/bindings/core/v8/serialization/v8_script_value_deserializer.h"
#include "third_party/blink/renderer/modules/canvas/offscreencanvas2d/offscreen_canvas_rendering_context_2d.h"

using blink::HeapObjectHeader;
using blink::TraceDescriptor;
using blink::TraceWrapperDescriptor;
using blink::ThreadingTrait;
using blink::TraceEagerlyTrait;
using blink::ScriptWrappableVisitor;
using blink::kLargeObjectSizeThreshold;
using blink::IsEagerlyFinalizedType;
using blink::ThreadState;
using blink::ThreadStateFor;
using blink::GarbageCollectedMixinConstructorMarker;
using blink::TraceTrait;

class WebLayerTreeViewImpl;

using blink::WebSettings;
using blink::WebRuntimeFeatures;
using blink::WebString;

namespace {

// class WebNodeDispatchEventTask: public blink::SuspendableTask {
// public:
//   WebNodeDispatchEventTask(const blink::WebPrivatePtr<blink::Node>& node, const PassRefPtr<blink::Event>& event) {
//     node_ = node;
//     event_ = event;
//   }

//   ~WebNodeDispatchEventTask() {
//     event_.clear();
//     node_.reset();
//   }

//   void run() override {
//     node_->dispatchEvent(event_.release());
//   }

// private:
//   blink::WebPrivatePtr<blink::Node> node_;
//   RefPtr<blink::Event> event_;

//   DISALLOW_COPY_AND_ASSIGN(WebNodeDispatchEventTask);
// };

template <typename Functor>
struct OnceFunction {
  uintptr_t entry; 
  base::OnceCallback<Functor> callback;
  OnceFunction(
    uintptr_t entry,
    base::OnceCallback<Functor> callback):
   entry(entry),
   callback(std::move(callback)){}
  
  ~OnceFunction() {}
};

template <typename Functor>
struct Function {
  uintptr_t entry; 
  base::Callback<Functor> callback;
  Function(
    uintptr_t entry,
    base::Callback<Functor> callback):
   entry(entry),
   callback(std::move(callback)){}
  
  ~Function() {}
};

typedef void(*CLayerTreeHostRequestPresentationCallback)(void *peer, int64_t, int64_t, uint32_t);

double MonotonicallyIncreasingTime() {
  return static_cast<double>(base::TimeTicks::Now().ToInternalValue()) /
         base::Time::kMicrosecondsPerSecond;
}

struct ReportTimeFunction {
  blink::WebLayerTreeView::ReportTimeCallback callback;
  ReportTimeFunction(
    blink::WebLayerTreeView::ReportTimeCallback callback):
   callback(std::move(callback)){}
  ~ReportTimeFunction() {}
};

class ReportTimeSwapPromise : public cc::SwapPromise {
 public:
  ReportTimeSwapPromise(
      blink::WebLayerTreeView::ReportTimeCallback callback,
      scoped_refptr<base::SingleThreadTaskRunner> task_runner);

  ~ReportTimeSwapPromise() override;

  void DidActivate() override {
    //DLOG(INFO) << "ReportTimeSwapPromise::OnCommit";
  }
  void WillSwap(viz::CompositorFrameMetadata* metadata,
                cc::FrameTokenAllocator* frame_token_allocator) override {
    //DLOG(INFO) << "ReportTimeSwapPromise::WillSwap";
  }
  void DidSwap() override;
  DidNotSwapAction DidNotSwap(DidNotSwapReason reason) override;

  int64_t TraceId() const override;

 private:

  blink::WebLayerTreeView::ReportTimeCallback callback_;
  scoped_refptr<base::SingleThreadTaskRunner> task_runner_;

  DISALLOW_COPY_AND_ASSIGN(ReportTimeSwapPromise);
};

ReportTimeSwapPromise::ReportTimeSwapPromise(
    blink::WebLayerTreeView::ReportTimeCallback callback,
    scoped_refptr<base::SingleThreadTaskRunner> task_runner)
    : callback_(std::move(callback)), task_runner_(std::move(task_runner)) {}

ReportTimeSwapPromise::~ReportTimeSwapPromise() {}

void ReportTimeSwapPromise::DidSwap() {
  //DLOG(INFO) << "\n\nReportTimeSwapPromise::DidSwap (" << this << ")";
  task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(std::move(callback_),
                     blink::WebLayerTreeView::SwapResult::kDidSwap,
                     MonotonicallyIncreasingTime()));
}

cc::SwapPromise::DidNotSwapAction ReportTimeSwapPromise::DidNotSwap(
    cc::SwapPromise::DidNotSwapReason reason) {
  //DLOG(INFO) << "\n\nReportTimeSwapPromise::DidNotSwap (" << this << ")";
  blink::WebLayerTreeView::SwapResult result;
  switch (reason) {
    case cc::SwapPromise::DidNotSwapReason::SWAP_FAILS:
      result = blink::WebLayerTreeView::SwapResult::kDidNotSwapSwapFails;
      break;
    case cc::SwapPromise::DidNotSwapReason::COMMIT_FAILS:
      result = blink::WebLayerTreeView::SwapResult::kDidNotSwapCommitFails;
      break;
    case cc::SwapPromise::DidNotSwapReason::COMMIT_NO_UPDATE:
      result = blink::WebLayerTreeView::SwapResult::kDidNotSwapCommitNoUpdate;
      break;
    case cc::SwapPromise::DidNotSwapReason::ACTIVATION_FAILS:
      result = blink::WebLayerTreeView::SwapResult::kDidNotSwapActivationFails;
      break;
  }
  task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(
        std::move(callback_),
        result, 
        MonotonicallyIncreasingTime()));
  return cc::SwapPromise::DidNotSwapAction::BREAK_PROMISE;
}

int64_t ReportTimeSwapPromise::TraceId() const {
  return 0;
}

//void ReportTimeSwapPromise::OnSwap(blink::WebLayerTreeView::SwapResult result, double time) {
//  //DLOG(INFO) << "\n **\n **\n **\n ** ReportTimeSwapPromise::OnSwap: cb? : " << !callback_.is_null() << " did_swap? " << (result == blink::WebLayerTreeView::SwapResult::kDidSwap) << " result: " << result;  
//  if (!callback_.is_null()) {
//    //DLOG(INFO) << "ReportTimeSwapPromise::OnSwap: executing callback..";
//    std::move(callback_).Run(result, time);
//  }
//}

// Must be unique in the child process.
// int GetNextProviderId() {
//   static base::AtomicSequenceNumber sequence;
//   return sequence.GetNext();  // We start at zero.
// }

void LayoutAndPaintAsyncImpl(base::Callback<void()> cb) {
  //DLOG(INFO) << "LayoutAndPaintAsyncImpl";
  std::move(cb).Run();
}

void CompositeAndReadbackAsyncImpl(base::Callback<void(const SkBitmap&)> cb, BitmapRef bmp) {
  std::move(cb).Run(*static_cast<SkBitmap*>(bmp));
}

// void NotifySwapTimeImpl(base::Callback<void(blink::WebLayerTreeView::SwapResult, double)> cb, blink::WebLayerTreeView::SwapResult swap, double time) {
//   //DLOG(INFO) << "NotifySwapTimeImpl: cb ? " << !cb.is_null();
//   if (cb) {
//     //DLOG(INFO) << "NotifySwapTimeImpl: executing callback";
//     std::move(cb).Run(swap, time);
//   }
//   //DLOG(INFO) << "NotifySwapTimeImpl: end";
// }

void RequestDecodeImpl(base::OnceCallback<void(bool)> cb, bool value) {
  std::move(cb).Run(value);
}

void LayoutAndPaintAsyncCallback(void* state) {
  //DLOG(INFO) << "LayoutAndPaintAsyncCallback";
  
  Function<void()>* fn_ptr = static_cast<Function<void()>*>(state);
  reinterpret_cast<void(*)(base::Callback<void()>)>(fn_ptr->entry)(std::move(fn_ptr->callback));
  delete fn_ptr;
}

void CompositeAndReadbackAsyncCallback(void* state, BitmapRef bmp) {
  Function<void(BitmapRef)>* fn_ptr = static_cast<Function<void(BitmapRef)>*>(state);
  reinterpret_cast<void(*)(base::Callback<void(BitmapRef)>, BitmapRef)>(fn_ptr->entry)(std::move(fn_ptr->callback), bmp);
  delete fn_ptr; 
}

// void NotifySwapTimeCallback(void* state, WebSwapResultEnum swap, double time) {
//   //DLOG(INFO) << "NotifySwapTimeCallback";
//   Function<void(WebSwapResultEnum, double)>* fn_ptr = static_cast<Function<void(WebSwapResultEnum, double)>*>(state);
//   //DLOG(INFO) << "NotifySwapTimeCallback: recovered function pointer " << fn_ptr << ". running it..";
//   reinterpret_cast<void(*)(base::Callback<void(WebSwapResultEnum, double)>, WebSwapResultEnum, double)>(fn_ptr->entry)(std::move(fn_ptr->callback), swap, time);
//   //DLOG(INFO) << "NotifySwapTimeCallback: deleting function pointer";
//   delete fn_ptr;
//   //DLOG(INFO) << "NotifySwapTimeCallback end";
// }

void RequestDecodeCallback(void* state, int value) {
  OnceFunction<void(int)>* fn_ptr = static_cast<OnceFunction<void(int)>*>(state);
  reinterpret_cast<void(*)(base::OnceCallback<void(int)>, int)>(fn_ptr->entry)(std::move(fn_ptr->callback), value);
  delete fn_ptr;
}


typedef std::map<std::string, base::string16> ScriptFontFamilyMap;


typedef void (*SetFontFamilyWrapper)(blink::WebSettings*,
                                     const base::string16&,
                                     UScriptCode);


const char* const kWebKitScriptsForFontFamilyMaps[] = {
#define EXPAND_SCRIPT_FONT(x, script_name) script_name ,
#define ALL_FONT_SCRIPTS(x)     \
  EXPAND_SCRIPT_FONT(x, "Afak") \
  EXPAND_SCRIPT_FONT(x, "Arab") \
  EXPAND_SCRIPT_FONT(x, "Armi") \
  EXPAND_SCRIPT_FONT(x, "Armn") \
  EXPAND_SCRIPT_FONT(x, "Avst") \
  EXPAND_SCRIPT_FONT(x, "Bali") \
  EXPAND_SCRIPT_FONT(x, "Bamu") \
  EXPAND_SCRIPT_FONT(x, "Bass") \
  EXPAND_SCRIPT_FONT(x, "Batk") \
  EXPAND_SCRIPT_FONT(x, "Beng") \
  EXPAND_SCRIPT_FONT(x, "Blis") \
  EXPAND_SCRIPT_FONT(x, "Bopo") \
  EXPAND_SCRIPT_FONT(x, "Brah") \
  EXPAND_SCRIPT_FONT(x, "Brai") \
  EXPAND_SCRIPT_FONT(x, "Bugi") \
  EXPAND_SCRIPT_FONT(x, "Buhd") \
  EXPAND_SCRIPT_FONT(x, "Cakm") \
  EXPAND_SCRIPT_FONT(x, "Cans") \
  EXPAND_SCRIPT_FONT(x, "Cari") \
  EXPAND_SCRIPT_FONT(x, "Cham") \
  EXPAND_SCRIPT_FONT(x, "Cher") \
  EXPAND_SCRIPT_FONT(x, "Cirt") \
  EXPAND_SCRIPT_FONT(x, "Copt") \
  EXPAND_SCRIPT_FONT(x, "Cprt") \
  EXPAND_SCRIPT_FONT(x, "Cyrl") \
  EXPAND_SCRIPT_FONT(x, "Cyrs") \
  EXPAND_SCRIPT_FONT(x, "Deva") \
  EXPAND_SCRIPT_FONT(x, "Dsrt") \
  EXPAND_SCRIPT_FONT(x, "Dupl") \
  EXPAND_SCRIPT_FONT(x, "Egyd") \
  EXPAND_SCRIPT_FONT(x, "Egyh") \
  EXPAND_SCRIPT_FONT(x, "Egyp") \
  EXPAND_SCRIPT_FONT(x, "Elba") \
  EXPAND_SCRIPT_FONT(x, "Ethi") \
  EXPAND_SCRIPT_FONT(x, "Geor") \
  EXPAND_SCRIPT_FONT(x, "Geok") \
  EXPAND_SCRIPT_FONT(x, "Glag") \
  EXPAND_SCRIPT_FONT(x, "Goth") \
  EXPAND_SCRIPT_FONT(x, "Gran") \
  EXPAND_SCRIPT_FONT(x, "Grek") \
  EXPAND_SCRIPT_FONT(x, "Gujr") \
  EXPAND_SCRIPT_FONT(x, "Guru") \
  EXPAND_SCRIPT_FONT(x, "Hang") \
  EXPAND_SCRIPT_FONT(x, "Hani") \
  EXPAND_SCRIPT_FONT(x, "Hano") \
  EXPAND_SCRIPT_FONT(x, "Hans") \
  EXPAND_SCRIPT_FONT(x, "Hant") \
  EXPAND_SCRIPT_FONT(x, "Hebr") \
  EXPAND_SCRIPT_FONT(x, "Hluw") \
  EXPAND_SCRIPT_FONT(x, "Hmng") \
  EXPAND_SCRIPT_FONT(x, "Hung") \
  EXPAND_SCRIPT_FONT(x, "Inds") \
  EXPAND_SCRIPT_FONT(x, "Ital") \
  EXPAND_SCRIPT_FONT(x, "Java") \
  EXPAND_SCRIPT_FONT(x, "Jpan") \
  EXPAND_SCRIPT_FONT(x, "Jurc") \
  EXPAND_SCRIPT_FONT(x, "Kali") \
  EXPAND_SCRIPT_FONT(x, "Khar") \
  EXPAND_SCRIPT_FONT(x, "Khmr") \
  EXPAND_SCRIPT_FONT(x, "Khoj") \
  EXPAND_SCRIPT_FONT(x, "Knda") \
  EXPAND_SCRIPT_FONT(x, "Kpel") \
  EXPAND_SCRIPT_FONT(x, "Kthi") \
  EXPAND_SCRIPT_FONT(x, "Lana") \
  EXPAND_SCRIPT_FONT(x, "Laoo") \
  EXPAND_SCRIPT_FONT(x, "Latf") \
  EXPAND_SCRIPT_FONT(x, "Latg") \
  EXPAND_SCRIPT_FONT(x, "Latn") \
  EXPAND_SCRIPT_FONT(x, "Lepc") \
  EXPAND_SCRIPT_FONT(x, "Limb") \
  EXPAND_SCRIPT_FONT(x, "Lina") \
  EXPAND_SCRIPT_FONT(x, "Linb") \
  EXPAND_SCRIPT_FONT(x, "Lisu") \
  EXPAND_SCRIPT_FONT(x, "Loma") \
  EXPAND_SCRIPT_FONT(x, "Lyci") \
  EXPAND_SCRIPT_FONT(x, "Lydi") \
  EXPAND_SCRIPT_FONT(x, "Mand") \
  EXPAND_SCRIPT_FONT(x, "Mani") \
  EXPAND_SCRIPT_FONT(x, "Maya") \
  EXPAND_SCRIPT_FONT(x, "Mend") \
  EXPAND_SCRIPT_FONT(x, "Merc") \
  EXPAND_SCRIPT_FONT(x, "Mero") \
  EXPAND_SCRIPT_FONT(x, "Mlym") \
  EXPAND_SCRIPT_FONT(x, "Moon") \
  EXPAND_SCRIPT_FONT(x, "Mong") \
  EXPAND_SCRIPT_FONT(x, "Mroo") \
  EXPAND_SCRIPT_FONT(x, "Mtei") \
  EXPAND_SCRIPT_FONT(x, "Mymr") \
  EXPAND_SCRIPT_FONT(x, "Narb") \
  EXPAND_SCRIPT_FONT(x, "Nbat") \
  EXPAND_SCRIPT_FONT(x, "Nkgb") \
  EXPAND_SCRIPT_FONT(x, "Nkoo") \
  EXPAND_SCRIPT_FONT(x, "Nshu") \
  EXPAND_SCRIPT_FONT(x, "Ogam") \
  EXPAND_SCRIPT_FONT(x, "Olck") \
  EXPAND_SCRIPT_FONT(x, "Orkh") \
  EXPAND_SCRIPT_FONT(x, "Orya") \
  EXPAND_SCRIPT_FONT(x, "Osma") \
  EXPAND_SCRIPT_FONT(x, "Palm") \
  EXPAND_SCRIPT_FONT(x, "Perm") \
  EXPAND_SCRIPT_FONT(x, "Phag") \
  EXPAND_SCRIPT_FONT(x, "Phli") \
  EXPAND_SCRIPT_FONT(x, "Phlp") \
  EXPAND_SCRIPT_FONT(x, "Phlv") \
  EXPAND_SCRIPT_FONT(x, "Phnx") \
  EXPAND_SCRIPT_FONT(x, "Plrd") \
  EXPAND_SCRIPT_FONT(x, "Prti") \
  EXPAND_SCRIPT_FONT(x, "Rjng") \
  EXPAND_SCRIPT_FONT(x, "Roro") \
  EXPAND_SCRIPT_FONT(x, "Runr") \
  EXPAND_SCRIPT_FONT(x, "Samr") \
  EXPAND_SCRIPT_FONT(x, "Sara") \
  EXPAND_SCRIPT_FONT(x, "Sarb") \
  EXPAND_SCRIPT_FONT(x, "Saur") \
  EXPAND_SCRIPT_FONT(x, "Sgnw") \
  EXPAND_SCRIPT_FONT(x, "Shaw") \
  EXPAND_SCRIPT_FONT(x, "Shrd") \
  EXPAND_SCRIPT_FONT(x, "Sind") \
  EXPAND_SCRIPT_FONT(x, "Sinh") \
  EXPAND_SCRIPT_FONT(x, "Sora") \
  EXPAND_SCRIPT_FONT(x, "Sund") \
  EXPAND_SCRIPT_FONT(x, "Sylo") \
  EXPAND_SCRIPT_FONT(x, "Syrc") \
  EXPAND_SCRIPT_FONT(x, "Syre") \
  EXPAND_SCRIPT_FONT(x, "Syrj") \
  EXPAND_SCRIPT_FONT(x, "Syrn") \
  EXPAND_SCRIPT_FONT(x, "Tagb") \
  EXPAND_SCRIPT_FONT(x, "Takr") \
  EXPAND_SCRIPT_FONT(x, "Tale") \
  EXPAND_SCRIPT_FONT(x, "Talu") \
  EXPAND_SCRIPT_FONT(x, "Taml") \
  EXPAND_SCRIPT_FONT(x, "Tang") \
  EXPAND_SCRIPT_FONT(x, "Tavt") \
  EXPAND_SCRIPT_FONT(x, "Telu") \
  EXPAND_SCRIPT_FONT(x, "Teng") \
  EXPAND_SCRIPT_FONT(x, "Tfng") \
  EXPAND_SCRIPT_FONT(x, "Tglg") \
  EXPAND_SCRIPT_FONT(x, "Thaa") \
  EXPAND_SCRIPT_FONT(x, "Thai") \
  EXPAND_SCRIPT_FONT(x, "Tibt") \
  EXPAND_SCRIPT_FONT(x, "Tirh") \
  EXPAND_SCRIPT_FONT(x, "Ugar") \
  EXPAND_SCRIPT_FONT(x, "Vaii") \
  EXPAND_SCRIPT_FONT(x, "Visp") \
  EXPAND_SCRIPT_FONT(x, "Wara") \
  EXPAND_SCRIPT_FONT(x, "Wole") \
  EXPAND_SCRIPT_FONT(x, "Xpeo") \
  EXPAND_SCRIPT_FONT(x, "Xsux") \
  EXPAND_SCRIPT_FONT(x, "Yiii") \
  EXPAND_SCRIPT_FONT(x, "Zmth") \
  EXPAND_SCRIPT_FONT(x, "Zsym") \
  EXPAND_SCRIPT_FONT(x, "Zyyy")
ALL_FONT_SCRIPTS("unused param")
#undef EXPAND_SCRIPT_FONT
};

const size_t kWebKitScriptsForFontFamilyMapsLength = arraysize(kWebKitScriptsForFontFamilyMaps);

}

class XMLHttpRequestEventListener : public blink::EventListener {
 public:
  XMLHttpRequestEventListener(void* state, void(*cb)(void*, void*, void*)):
   blink::EventListener(kCPPEventListenerType),
   state_(state), 
   cb_(cb),
   progress_cb_(nullptr) {}

  XMLHttpRequestEventListener(void* state, void(*progress_cb)(void*, int, uint64_t, uint64_t)):
   blink::EventListener(kCPPEventListenerType),
   state_(state), 
   cb_(nullptr),
   progress_cb_(progress_cb) {}

  ~XMLHttpRequestEventListener() override {}

  // Implementation of EventListener interface.
  bool operator==(const blink::EventListener& other) const override {
    return this == &other;
  }

  void handleEvent(blink::ExecutionContext* context, blink::Event* event) override {
    base::AutoLock lock(callback_lock_);
    // assert we will execute the handler on main the thread
    //application::ApplicationThread* app = application::ApplicationThread::current();
    //DLOG(INFO) << "XMLHttpRequestEventListener::handleEvent: execution_context = " << context;
    if (cb_) {
      cb_(state_, context, event);
    } else if (progress_cb_) {
      blink::ProgressEvent* progress_event = static_cast<blink::ProgressEvent*>(event);
      progress_cb_(state_, progress_event->lengthComputable(), progress_event->loaded(), progress_event->total());
    }
    // garbage collected by oil pan ?
    //delete this;
  }

 private:
  void* state_; 
  void(*cb_)(void*, void*, void*);  
  void(*progress_cb_)(void*, int, uint64_t, uint64_t);
  base::Lock callback_lock_;
};

class WebAXObjectWrapper {
public:
 WebAXObjectWrapper() {}
 WebAXObjectWrapper(blink::AXObject* object): object_(object) {}
 ~WebAXObjectWrapper() {}

 blink::AXObject* get() const {
   return object_;
 }

private:
 blink::AXObject* object_;
 
 DISALLOW_COPY_AND_ASSIGN(WebAXObjectWrapper);
};

class HTMLCollectionWrapper {
public:
 HTMLCollectionWrapper(const HTMLCollectionWrapper& other): offset_(0) { 
   assign(other); 
 }

 HTMLCollectionWrapper(blink::HTMLCollection* collection)
    : collection_(collection), offset_(0){
 }


 HTMLCollectionWrapper& operator=(blink::HTMLCollection* collection) {
    collection_ = collection;
    return *this;
 }

 operator blink::HTMLCollection*() const {
    return collection_.Get();
 }
 
 ~HTMLCollectionWrapper() {
   collection_ = nullptr;
 }
 
 HTMLCollectionWrapper& operator=(const HTMLCollectionWrapper& other){
  assign(other);
  return *this;
 }

 void assign(const HTMLCollectionWrapper& other) {
   collection_ = other.collection_;
 }

 blink::HTMLCollection* unwrap() {
  return collection_.Get();
 }

 const blink::HTMLCollection* constUnwrap() const {
  return static_cast<const blink::HTMLCollection*>(collection_.Get());
 }

 size_t offset() const {
   return offset_;
 }

 void reset() {
   offset_ = 0;
 }

 blink::Element* iterateNext() {
   blink::Element* element = collection_->item(offset_);
   if (element) {
     offset_++;
   }
   return element;
 }

 blink::Element* iterateTo(size_t offset) {
   size_t last_offset = collection_->length() - 1;
   size_t current_offset = offset > last_offset ? last_offset : offset; 
   offset_ = current_offset;
   blink::Element* element = collection_->item(offset_);
   return element;
 }

 blink::Element* iterateFirst() {
  offset_ = 0;
  blink::Element* element = collection_->TraverseToFirst();
  return element;
 }

 blink::Element* iterateLast() {
  offset_ = collection_->length() - 1;
  blink::Element* element = collection_->TraverseToLast();
  return element;
 }

private:
 blink::Persistent<blink::HTMLCollection> collection_;
 size_t offset_;

 //DISALLOW_COPY_AND_ASSIGN(HTMLCollectionWrapper);
};

class WebElementArrayWrapper {
public:
 WebElementArrayWrapper(const WebElementArrayWrapper& other) { 
   assign(other); 
 }

 WebElementArrayWrapper(blink::StaticElementList* collection)
    : collection_(collection) {
 }

 WebElementArrayWrapper& operator=(blink::StaticElementList* collection) {
    collection_ = collection;
    return *this;
 }

 operator blink::StaticElementList*() const {
    return collection_.Get();
 }
 
 ~WebElementArrayWrapper() {
   collection_ = nullptr;
 }
 
 WebElementArrayWrapper& operator=(const WebElementArrayWrapper& other){
  assign(other);
  return *this;
 }

 void assign(const WebElementArrayWrapper& other) {
   collection_ = other.collection_;
 }

 blink::StaticElementList* unwrap() {
  return collection_.Get();
 }

 const blink::StaticElementList* constUnwrap() const {
  return static_cast<const blink::StaticElementList *>(collection_.Get());
 }
private:
  blink::Persistent<blink::StaticElementList> collection_;

  //DISALLOW_COPY_AND_ASSIGN(WebElementArrayWrapper);
};

class WebRangeWrapper {
public:
 WebRangeWrapper(blink::Range* range): range_(range) {}
 
 ~WebRangeWrapper() {
   range_ = nullptr;
 }

 blink::Range* unwrap() {
  return range_.Get();
 }

 const blink::Range* constUnwrap() const {
  return range_.Get();
 }

//  blink::WebRange asWebRange() const {
//   return blink::WebRange(range_.Get());
//  }

private:
  blink::Persistent<blink::Range> range_;
};


class WebURLRequestWrapper {
public:
 //WebURLRequestWrapper(const blink::WebURLRequest& other) {
 //  url_request_ = other;
 //}

 WebURLRequestWrapper(blink::WebURLRequest req): url_request_(std::move(req)) {

 }

 ~WebURLRequestWrapper() {
   //url_request_.reset();
 }

 const blink::WebURLRequest& get() const {
  return url_request_;
 }

 blink::WebURLRequest& get() {
  return url_request_;
 }

private:
  blink::WebURLRequest url_request_;
};


class WebSecurityOriginWrapper {
public:
 WebSecurityOriginWrapper(blink::SecurityOrigin* origin): origin_(origin) {}
 
 ~WebSecurityOriginWrapper() {
   origin_ = nullptr;
 }

 blink::SecurityOrigin* unwrap() {
  return origin_.get();
 }

 const blink::SecurityOrigin* constUnwrap() const {
  return origin_.get();
 }

 blink::WebSecurityOrigin asWebSecurityOrigin() const {
  return blink::WebSecurityOrigin(origin_.get());
 }

private:
  scoped_refptr<blink::SecurityOrigin> origin_;
};

class WebHitTestResultWrapper {
public:
 WebHitTestResultWrapper(const blink::WebHitTestResult& other) {
   hit_test_.Assign(other);
 }

 ~WebHitTestResultWrapper() {
   hit_test_.Reset();
 }

 const blink::WebHitTestResult& get() const {
  return hit_test_;
 }

 blink::WebHitTestResult& get() {
  return hit_test_;
 }

private:
  blink::WebHitTestResult hit_test_;
};

// WHOAA: Why we are controlling the node relashionship outside of the 
// blink managed object dom?

// We shouldnt need a wrapper to wrapper relationship.. now theres oilpan
// and GC in Blink so we should care or manage the life time of parents, siblings, etc..
// rethink this interface
class WebEventListenerImpl;
class WebNodeWrapper {
public:

 WebNodeWrapper(const WebNodeWrapper& other): 
  node_ptr_(nullptr), cached_(false), refcount_(0), is_html_element_(false), stack_allocated_(false) { 
   assign(other); 
 }

 WebNodeWrapper(const blink::WebNode& other): node_ptr_(nullptr), cached_(false), refcount_(0), is_html_element_(false), stack_allocated_(false) { 
   assign(other);
 }

 WebNodeWrapper(const blink::WebNode& other, bool cached): node_ptr_(nullptr), cached_(cached), refcount_(0), is_html_element_(false), stack_allocated_(false) { 
   assign(other);
 }

 WebNodeWrapper(blink::Node* node)
    : node_(node), node_ptr_(nullptr), cached_(false), refcount_(0), is_html_element_(false), stack_allocated_(false) {
 }

 WebNodeWrapper(blink::Document* node)
    : node_(node), node_ptr_(nullptr), cached_(false), refcount_(0), is_html_element_(false) {
 }

 WebNodeWrapper(blink::Node* node, bool cached)
    : node_(node), node_ptr_(nullptr), cached_(cached), refcount_(0), is_html_element_(false), stack_allocated_(false) {
 }

 WebNodeWrapper& operator=(blink::Node* node) {
    node_ = node;
    return *this;
 }

 operator blink::Node*() const {
    return node_ptr_ ? const_cast<blink::Node*>(node_ptr_) : node_.Get();
 }
 
 ~WebNodeWrapper() {
   node_ = nullptr;
   node_ptr_ = nullptr;
 }
 
 WebNodeWrapper& operator=(const WebNodeWrapper& other){
  assign(other);
  return *this;
 }

 WebNodeWrapper& operator=(const blink::WebNode& other){
  assign(other);
  return *this;
 }

 void assign(const WebNodeWrapper& other) {
   other.node_ptr_ ? 
      node_ptr_ = other.node_ptr_ :
      node_ = other.node_;
 }

 //void assign(const blink::Node& other) {
 //  node_ = PassRefPtrWillBeRawPtr<blink::Node>(other);
 //}

 //void assign(blink::WebNode* other) {
 //  node_ = other->Unwrap<blink::Node>();
 //}

 void assign(const blink::WebNode& other) {
   node_ptr_ = other.ConstUnwrap<blink::Node>();
 }

 template<typename T> T* unwrap() {
  return node_ptr_ ? const_cast<T*>(static_cast<const T*>(node_ptr_)) : static_cast<T*>(node_.Get());
 }

 template<typename T> const T* constUnwrap() const {
  return node_ptr_ ? static_cast<const T*>(node_ptr_) : static_cast<const T*>(node_.Get());
 }

 bool equals(const WebNodeWrapper* other) const {
   return other->node_ptr_ ? 
    (node_ptr_ == other->node_ptr_) : 
    (node_.Get() == other->node_.Get());
 }

 bool less_than(const WebNodeWrapper* other) const {
   return other->node_ptr_ ? 
    (node_ptr_ < other->node_ptr_) :
    (node_.Get() < other->node_.Get());
 }


 // TODO: we need to use flags instead
 bool is_stack_allocated() const {
   return stack_allocated_;
 }

 void set_stack_allocated(bool stack_allocated) {
   stack_allocated_ = stack_allocated;
 }

 WebNodeWrapper* parent() const { return parent_.get(); }
 void set_parent(WebNodeWrapper* parent) { parent_.reset(parent); }

 WebNodeWrapper* document() const { return document_.get(); }
 void set_document(WebNodeWrapper* document) { document_.reset(document); }

 WebNodeWrapper* first_child() const { return first_child_.get(); }
 void set_first_child(WebNodeWrapper* child) { first_child_.reset(child); }

 WebNodeWrapper* last_child() const { return last_child_.get(); }
 void set_last_child(WebNodeWrapper* child) { last_child_.reset(child); }

 WebNodeWrapper* previous_sibling() const { return previous_sibling_.get(); }
 void set_previous_sibling(WebNodeWrapper* previous_sibling) { previous_sibling_.reset(previous_sibling); }

 WebNodeWrapper* next_sibling() const { return next_sibling_.get(); }
 void set_next_sibling(WebNodeWrapper* next_sibling) { next_sibling_.reset(next_sibling); }

//  void dispatchEvent(blink::Event* event) {
//    node_->GetExecutionContext()->postSuspendableTask(new blink::WebNodeDispatchEventTask(node_, event));
//  }

 int refcount() const {
   return refcount_;
 }
 
 void retain() {
   refcount_++;
 }

 void release() {
   DCHECK(refcount_ > 0);
   refcount_--;
 }

 bool is_html_element() const { return is_html_element_; }

 void set_is_html_element(bool value) { is_html_element_ = value; }

 bool is_cached() const { return cached_; }

 void AddListener(const std::string& property, WebEventListenerImpl* listener) {
   listeners_.emplace(std::make_pair(property, listener));
 }

 WebEventListenerImpl* RemoveListener(const std::string& property) {
   WebEventListenerImpl* result = nullptr;
   auto it = listeners_.find(property);
   if (it != listeners_.end()) {
     result = it->second;
     listeners_.erase(it);
   }
   return result;
 }

private:
 
 blink::Persistent<blink::Node> node_;
 const blink::Node* node_ptr_;

 std::unique_ptr<WebNodeWrapper>        parent_;
 std::unique_ptr<WebNodeWrapper>        document_;
 std::unique_ptr<WebNodeWrapper>        first_child_;
 std::unique_ptr<WebNodeWrapper>        last_child_;
 std::unique_ptr<WebNodeWrapper>        previous_sibling_;
 std::unique_ptr<WebNodeWrapper>        next_sibling_;

 std::unordered_map<std::string, WebEventListenerImpl*> listeners_;
 bool cached_;
 mutable int refcount_;
 bool is_html_element_;
 bool stack_allocated_;
};

class WebHTTPLoadInfoWrapper {
public:
  
  WebHTTPLoadInfoWrapper(): resourceLoadInfo_(new blink::ResourceLoadInfo()) {
  }

  WebHTTPLoadInfoWrapper(blink::ResourceLoadInfo* value) : resourceLoadInfo_(value) {

  }

  ~WebHTTPLoadInfoWrapper(){
    resourceLoadInfo_ = nullptr;
  }

  int httpStatusCode() const {
    return resourceLoadInfo_->http_status_code;
  }

  void setHTTPStatusCode(int statusCode) {
    resourceLoadInfo_->http_status_code = statusCode;
  }

  String httpStatusText() const {
    return resourceLoadInfo_->http_status_text;
  }

  void setHTTPStatusText(const String& statusText) {
    resourceLoadInfo_->http_status_text = statusText;
  }

  // long long encodedDataLength() const {
  //   return resourceLoadInfo_->encoded_data_length;
  // }

  // void setEncodedDataLength(long long encodedDataLength) {
  //   resourceLoadInfo_->encoded_data_length = encodedDataLength;
  // }

  static void addHeader(blink::HTTPHeaderMap* map, const AtomicString& name, const AtomicString& value) {
    blink::HTTPHeaderMap::AddResult result = map->Add(name, value);
    //if (!result.IsNewEntry) {
    result.stored_value->value = result.stored_value->value + "\n" + String(value);
    //}
  }

  void addRequestHeader(const AtomicString& name, const AtomicString& value) {
    addHeader(&resourceLoadInfo_->request_headers, name, value);
  }

  void addResponseHeader(const AtomicString& name, const AtomicString& value) {
    addHeader(&resourceLoadInfo_->response_headers, name, value);
  }

  String requestHeadersText() const {
    return resourceLoadInfo_->request_headers_text;
  }

  void setRequestHeadersText(const String& headersText) {
    resourceLoadInfo_->request_headers_text = headersText;
  }

  String responseHeadersText() const {
    return resourceLoadInfo_->response_headers_text;
  }

  void setResponseHeadersText(const String& headersText) {
    resourceLoadInfo_->response_headers_text = headersText;
  }

  String npnNegotiatedProtocol() const {
    return resourceLoadInfo_->npn_negotiated_protocol;
  }

  void setNPNNegotiatedProtocol(const String& npnNegotiatedProtocol) {
    resourceLoadInfo_->npn_negotiated_protocol = npnNegotiatedProtocol;
  }

  operator blink::ResourceLoadInfo*() const {
    return resourceLoadInfo_.get();    
  }

private:
  scoped_refptr<blink::ResourceLoadInfo> resourceLoadInfo_;  
};

class ViewOnWeb : public blink::WebPlugin {
 public:
  explicit ViewOnWeb(const blink::WebPluginParams& params):
   layer_(blink::Platform::Current()->CompositorSupport()->CreateLayer()) {
    //DLOG(INFO) << "ViewOnWeb::ViewOnWeb()";
  }

  ViewOnWeb(const blink::WebPluginParams& params, cc::Layer* layer):
   layer_(blink::Platform::Current()->CompositorSupport()->CreateLayerFromCCLayer(layer)) {
    //DLOG(INFO) << "ViewOnWeb::ViewOnWeb(with cc::Layer*)";
  }

  // WebPlugin methods:
  bool Initialize(blink::WebPluginContainer* container) override {
    //DLOG(INFO) << "ViewOnWeb::Initialize";
    container_ = container;
    container_->SetWebLayer(layer_.get());
    return true;
  }

  void Destroy() override {
    container_->SetWebLayer(nullptr);
    container_ = nullptr;
  }

  blink::WebPluginContainer* Container() const override { 
    return container_; 
  }

  blink::WebLayer* layer() const {
    return layer_.get();
  }

  bool CanProcessDrag() const override { 
    //DLOG(INFO) << "ViewOnWeb::CanProcessDrag";
    return false; 
  }
  
  void UpdateAllLifecyclePhases() override {
    //DLOG(INFO) << "ViewOnWeb::UpdateAllLifecyclePhases";
  }

  void Paint(blink::WebCanvas*, const blink::WebRect&) override {
    //DLOG(INFO) << "ViewOnWeb::Paint";
  }
  
  void UpdateGeometry(const blink::WebRect& client_rect,
                      const blink::WebRect& clip_rect,
                      const blink::WebRect& window_clip_rect,
                      bool is_visible) override {
    //DLOG(INFO) << "ViewOnWeb::UpdateGeometry";
  }

  void UpdateFocus(bool focus, blink::WebFocusType) override {
    //DLOG(INFO) << "ViewOnWeb::UpdateFocus";
  }

  void UpdateVisibility(bool visible) override {
    //DLOG(INFO) << "ViewOnWeb::UpdateVisibility";
  }
  
  blink::WebInputEventResult HandleInputEvent(
    const blink::WebCoalescedInputEvent& event,
    blink::WebCursorInfo& info) override {
    //DLOG(INFO) << "ViewOnWeb::HandleInputEvent";

    return blink::WebInputEventResult::kNotHandled;
  }

  bool HandleDragStatusUpdate(blink::WebDragStatus status,
                              const blink::WebDragData& data,
                              blink::WebDragOperationsMask mask,
                              const blink::WebFloatPoint& position,
                              const blink::WebFloatPoint& screen_position) override {
    //DLOG(INFO) << "ViewOnWeb::HandleDragStatusUpdate";
    return false;
  }

  void DidReceiveResponse(const blink::WebURLResponse& url) override {
    //DLOG(INFO) << "ViewOnWeb::DidReceiveResponse";
  }
  
  void DidReceiveData(const char* data, int data_length) override {
    //DLOG(INFO) << "ViewOnWeb::DidReceiveData";
  }

  void DidFinishLoading() override {
    //DLOG(INFO) << "ViewOnWeb::DidFinishLoading";
  }

  void DidFailLoading(const blink::WebURLError& err) override {
    //DLOG(INFO) << "ViewOnWeb::DidFailLoading";
  }

  bool IsPlaceholder() override { 
    return false; 
  }

private:

  blink::WebPluginContainer* container_;
  
  std::unique_ptr<blink::WebLayer> layer_;

  DISALLOW_COPY_AND_ASSIGN(ViewOnWeb);
};


class WebLayerTreeViewImpl : public blink::WebLayerTreeView {
 public:
  WebLayerTreeViewImpl(void* state, WebLayerTreeViewCbs callbacks):
    state_(state),
    callbacks_(callbacks),
    weak_animation_host_(nullptr) {
  }

  ~WebLayerTreeViewImpl() override {}

  cc::LayerTreeSettings GetLayerTreeSettings() {
    int /*bool*/ single_thread_proxy_scheduler;
    int /*bool*/ main_frame_before_activation_enabled;
    int /*bool*/ using_synchronous_renderer_compositor;
    int /*bool*/ enable_early_damage_check;
    int damaged_frame_limit;
    int /*bool*/ enable_latency_recovery;
    int /*bool*/ can_use_lcd_text;
    int /*bool*/ gpu_rasterization_forced;
    int gpu_rasterization_msaa_sample_count;
    float gpu_rasterization_skewport_target_time_in_seconds;
    int /*bool*/ create_low_res_tiling;
    int /*bool*/ use_stream_video_draw_quad;
    int64_t scrollbar_fade_delay;
    int64_t scrollbar_fade_duration;
    int64_t scrollbar_thinning_duration;
    int /*bool*/ scrollbar_flash_after_any_scroll_update;
    int /*bool*/ scrollbar_flash_when_mouse_enter;
    uint8_t solid_color_scrollbar_color_a;
    uint8_t solid_color_scrollbar_color_r;
    uint8_t solid_color_scrollbar_color_g;
    uint8_t solid_color_scrollbar_color_b;
    int /*bool*/ timeout_and_draw_when_animation_checkerboards;
    int /*bool*/ layer_transforms_should_scale_layer_contents;
    int /*bool*/ layers_always_allowed_lcd_text;
    float minimum_contents_scale;
    float low_res_contents_scale_factor;
    float top_controls_show_threshold;
    float top_controls_hide_threshold;
    double background_animation_rate;
    int default_tile_size_width;
    int default_tile_size_height;
    int max_untiled_layer_size_width;
    int max_untiled_layer_size_height;
    int max_gpu_raster_tile_size_width;
    int max_gpu_raster_tile_size_height;
    int minimum_occlusion_tracking_size_width;
    int minimum_occlusion_tracking_size_height;
    int tiling_interest_area_padding;
    float skewport_target_time_in_seconds;
    int skewport_extrapolation_limit_in_screen_pixels;
    int max_memory_for_prepaint_percentage;
    int /*bool*/ use_zero_copy;
    int /*bool*/ use_partial_raster;
    int /*bool*/ enable_elastic_overscroll;
    int /*bool*/ ignore_root_layer_flings;
    int scheduled_raster_task_limit;
    int /*bool*/ use_occlusion_for_tile_prioritization;
    int /*bool*/ use_layer_lists;
    int max_staging_buffer_usage_in_bytes;
    int memory_policy_bytes_limit_when_visible;
    int memory_policy_priority_cutoff_when_visible;
    int decoded_image_working_set_budget_bytes;
    int max_preraster_distance_in_screen_pixels;
    int /*bool*/ use_rgba_4444;
    int /*bool*/ unpremultiply_and_dither_low_bit_depth_tiles;
    int /*bool*/ enable_mask_tiling;
    int /*bool*/ enable_checker_imaging;
    int min_image_bytes_to_checker;
    int /*bool*/ only_checker_images_with_gpu_raster;
    int /*bool*/ enable_surface_synchronization;
    int /*bool*/ is_layer_tree_for_subframe;
    int /*bool*/ disallow_non_exact_resource_reuse;
    int /*bool*/ wait_for_all_pipeline_stages_before_draw;
    int /*bool*/ commit_to_active_tree;
    int /*bool*/ enable_oop_rasterization;
    int /*bool*/ enable_image_animation_resync;
    int /*bool*/ enable_edge_anti_aliasing;
    int /*bool*/ always_request_presentation_time;
    int /*bool*/ use_painted_device_scale_factor;

    callbacks_.GetLayerTreeSettings(
      state_,
      &single_thread_proxy_scheduler,
      &main_frame_before_activation_enabled,
      &using_synchronous_renderer_compositor,
      &enable_early_damage_check,
      &damaged_frame_limit,
      &enable_latency_recovery,
      &can_use_lcd_text,
      &gpu_rasterization_forced,
      &gpu_rasterization_msaa_sample_count,
      &gpu_rasterization_skewport_target_time_in_seconds,
      &create_low_res_tiling,
      &use_stream_video_draw_quad,
      &scrollbar_fade_delay,
      &scrollbar_fade_duration,
      &scrollbar_thinning_duration,
      &scrollbar_flash_after_any_scroll_update,
      &scrollbar_flash_when_mouse_enter,
      &solid_color_scrollbar_color_a,
      &solid_color_scrollbar_color_r,
      &solid_color_scrollbar_color_g,
      &solid_color_scrollbar_color_b,
      &timeout_and_draw_when_animation_checkerboards,
      &layer_transforms_should_scale_layer_contents,
      &layers_always_allowed_lcd_text,
      &minimum_contents_scale,
      &low_res_contents_scale_factor,
      &top_controls_show_threshold,
      &top_controls_hide_threshold,
      &background_animation_rate,
      &default_tile_size_width,
      &default_tile_size_height,
      &max_untiled_layer_size_width,
      &max_untiled_layer_size_height,
      &max_gpu_raster_tile_size_width,
      &max_gpu_raster_tile_size_height,
      &minimum_occlusion_tracking_size_width,
      &minimum_occlusion_tracking_size_height,
      &tiling_interest_area_padding,
      &skewport_target_time_in_seconds,
      &skewport_extrapolation_limit_in_screen_pixels,
      &max_memory_for_prepaint_percentage,
      &use_zero_copy,
      &use_partial_raster,
      &enable_elastic_overscroll,
      &ignore_root_layer_flings,
      &scheduled_raster_task_limit,
      &use_occlusion_for_tile_prioritization,
      &use_layer_lists,
      &max_staging_buffer_usage_in_bytes,
      &memory_policy_bytes_limit_when_visible,
      &memory_policy_priority_cutoff_when_visible,
      &decoded_image_working_set_budget_bytes,
      &max_preraster_distance_in_screen_pixels,
      &use_rgba_4444,
      &unpremultiply_and_dither_low_bit_depth_tiles,
      &enable_mask_tiling,
      &enable_checker_imaging,
      &min_image_bytes_to_checker,
      &only_checker_images_with_gpu_raster,
      &enable_surface_synchronization,
      &is_layer_tree_for_subframe,
      &disallow_non_exact_resource_reuse,
      &wait_for_all_pipeline_stages_before_draw,
      &commit_to_active_tree,
      &enable_oop_rasterization,
      &enable_image_animation_resync,
      &enable_edge_anti_aliasing,
      &always_request_presentation_time,
      &use_painted_device_scale_factor);

    cc::LayerTreeSettings settings;
    settings.single_thread_proxy_scheduler = single_thread_proxy_scheduler;
    settings.main_frame_before_activation_enabled = main_frame_before_activation_enabled;
    settings.using_synchronous_renderer_compositor = using_synchronous_renderer_compositor;
    settings.enable_early_damage_check = enable_early_damage_check;
    settings.damaged_frame_limit = damaged_frame_limit;
    settings.enable_latency_recovery = enable_latency_recovery;
    settings.can_use_lcd_text = can_use_lcd_text;
    settings.gpu_rasterization_forced = gpu_rasterization_forced;
    settings.gpu_rasterization_msaa_sample_count = gpu_rasterization_msaa_sample_count;
    settings.gpu_rasterization_skewport_target_time_in_seconds = gpu_rasterization_skewport_target_time_in_seconds;
    settings.create_low_res_tiling = create_low_res_tiling;
    settings.use_stream_video_draw_quad = use_stream_video_draw_quad;
    settings.scrollbar_fade_delay = base::TimeDelta::FromMicroseconds(scrollbar_fade_delay);
    settings.scrollbar_fade_duration = base::TimeDelta::FromMicroseconds(scrollbar_fade_duration);
    settings.scrollbar_thinning_duration = base::TimeDelta::FromMicroseconds(scrollbar_thinning_duration); 
    settings.scrollbar_flash_after_any_scroll_update = scrollbar_flash_after_any_scroll_update;
    settings.scrollbar_flash_when_mouse_enter = scrollbar_flash_when_mouse_enter;
    settings.solid_color_scrollbar_color = SkColorSetARGB(solid_color_scrollbar_color_a, solid_color_scrollbar_color_r, solid_color_scrollbar_color_g, solid_color_scrollbar_color_b);
    settings.timeout_and_draw_when_animation_checkerboards = timeout_and_draw_when_animation_checkerboards;
    settings.layer_transforms_should_scale_layer_contents = layer_transforms_should_scale_layer_contents;
    settings.layers_always_allowed_lcd_text = layers_always_allowed_lcd_text;
    settings.minimum_contents_scale = minimum_contents_scale;
    settings.low_res_contents_scale_factor = low_res_contents_scale_factor;
    settings.top_controls_show_threshold = top_controls_show_threshold;
    settings.top_controls_hide_threshold = top_controls_hide_threshold;
    settings.background_animation_rate = background_animation_rate;
    settings.default_tile_size = gfx::Size(default_tile_size_width, default_tile_size_height);
    settings.max_untiled_layer_size = gfx::Size(max_untiled_layer_size_width, max_untiled_layer_size_height);
    settings.max_gpu_raster_tile_size = gfx::Size(max_gpu_raster_tile_size_width, max_gpu_raster_tile_size_height);
    settings.minimum_occlusion_tracking_size = gfx::Size(minimum_occlusion_tracking_size_width, minimum_occlusion_tracking_size_height);
    settings.tiling_interest_area_padding = tiling_interest_area_padding;
    settings.skewport_target_time_in_seconds = skewport_target_time_in_seconds;
    settings.skewport_extrapolation_limit_in_screen_pixels = skewport_extrapolation_limit_in_screen_pixels;
    settings.max_memory_for_prepaint_percentage = max_memory_for_prepaint_percentage;
    settings.use_zero_copy = use_zero_copy;
    settings.use_partial_raster = use_partial_raster;
    settings.enable_elastic_overscroll = enable_elastic_overscroll;
    settings.ignore_root_layer_flings = ignore_root_layer_flings;
    settings.scheduled_raster_task_limit = scheduled_raster_task_limit;
    settings.use_occlusion_for_tile_prioritization = use_occlusion_for_tile_prioritization;
    settings.use_layer_lists = use_layer_lists;
    settings.max_staging_buffer_usage_in_bytes = max_staging_buffer_usage_in_bytes;
    settings.memory_policy.bytes_limit_when_visible = memory_policy_bytes_limit_when_visible;
    settings.memory_policy.priority_cutoff_when_visible = static_cast<gpu::MemoryAllocation::PriorityCutoff>(memory_policy_priority_cutoff_when_visible);
    settings.decoded_image_working_set_budget_bytes = decoded_image_working_set_budget_bytes;
    settings.max_preraster_distance_in_screen_pixels = max_preraster_distance_in_screen_pixels;
    settings.use_rgba_4444 = use_rgba_4444;
    settings.unpremultiply_and_dither_low_bit_depth_tiles = unpremultiply_and_dither_low_bit_depth_tiles;
    settings.enable_mask_tiling = enable_mask_tiling;
    settings.enable_checker_imaging = enable_checker_imaging;
    settings.min_image_bytes_to_checker = min_image_bytes_to_checker;
    settings.only_checker_images_with_gpu_raster = only_checker_images_with_gpu_raster;
    settings.enable_surface_synchronization = enable_surface_synchronization;
    settings.is_layer_tree_for_subframe = is_layer_tree_for_subframe;
    settings.disallow_non_exact_resource_reuse = disallow_non_exact_resource_reuse;
    settings.wait_for_all_pipeline_stages_before_draw = wait_for_all_pipeline_stages_before_draw;
    settings.commit_to_active_tree = commit_to_active_tree;
    settings.enable_oop_rasterization = enable_oop_rasterization;
    settings.enable_image_animation_resync = enable_image_animation_resync;
    settings.enable_edge_anti_aliasing = enable_edge_anti_aliasing;
    settings.always_request_presentation_time = always_request_presentation_time;
    settings.use_painted_device_scale_factor = use_painted_device_scale_factor;
    return settings;
  }

  void SetRootLayer(const blink::WebLayer& layer) override {
    callbacks_.SetRootLayer(state_, const_cast<blink::WebLayer *>(&layer));
  }
  void ClearRootLayer() override {
    callbacks_.ClearRootLayer(state_);
  }
  cc::AnimationHost* CompositorAnimationHost() override {
    // the WebFrameWidget expects to own the animation host
    // so we release the ownership in the first time
    // so that WebFrameWidget can manage it
    if (!weak_animation_host_) {
      _AnimationHost* wrapper = reinterpret_cast<_AnimationHost*>(callbacks_.CompositorAnimationHost(state_));
      // not owned anyway..
      if (!wrapper->owned()) {
        weak_animation_host_ = wrapper->handle();
      } else {
        weak_animation_host_ = wrapper->owned_handle_.release();
      }
    }
    DCHECK(weak_animation_host_);
    return weak_animation_host_;
  }

  cc::LayerTreeHost* GetLayerTreeHost() {
    _LayerTreeHost* wrapper = reinterpret_cast<_LayerTreeHost*>(callbacks_.GetLayerTreeHost(state_));
    return wrapper->handle.get();
  }

  blink::WebSize GetViewportSize() const override {
    int w = 0;
    int h = 0;
    callbacks_.GetViewportSize(state_, &w, &h);
    //DLOG(INFO) << "WebLayerTreeViewImpl::GetViewportSize: -> (" << w << " , " << h << ") ";
    return blink::WebSize(w, h);
  }
  void SetBackgroundColor(blink::WebColor color) override {
    callbacks_.SetBackgroundColor(state_, SkColorGetA(color), SkColorGetR(color), SkColorGetG(color), SkColorGetB(color));
  }
  void SetVisible(bool visible) override {
    callbacks_.SetVisible(state_, visible ? 1 : 0);
  }
  void SetPageScaleFactorAndLimits(float page_scale_factor,
                                   float minimum,
                                   float maximum) override {
    callbacks_.SetPageScaleFactorAndLimits(state_, page_scale_factor, minimum, maximum);
  }
  void StartPageScaleAnimation(const blink::WebPoint& destination,
                               bool use_anchor,
                               float new_page_scale,
                               double duration_sec) override {
    callbacks_.StartPageScaleAnimation(state_,
      destination.x,
      destination.y,
      use_anchor ? 1 : 0,
      new_page_scale,
      duration_sec);
  }
  bool HasPendingPageScaleAnimation() const override {
    return callbacks_.HasPendingPageScaleAnimation(state_) != 0;
  }
  void HeuristicsForGpuRasterizationUpdated(bool heuristics) override {
    callbacks_.HeuristicsForGpuRasterizationUpdated(state_, heuristics ? 1 : 0);
  }
  void SetBrowserControlsShownRatio(float ratio) override {
    callbacks_.SetBrowserControlsShownRatio(state_, ratio);
  }
  void UpdateBrowserControlsState(blink::WebBrowserControlsState constraints,
                                  blink::WebBrowserControlsState current,
                                  bool animate) override {
    callbacks_.UpdateBrowserControlsState(state_, 
      static_cast<WebTopControlsStateEnum>(constraints), 
      static_cast<WebTopControlsStateEnum>(current), 
      animate ? 1 : 0);
  }
  void SetBrowserControlsHeight(float top_height,
                                float bottom_height,
                                bool shrink_viewport) override {
    callbacks_.SetBrowserControlsHeight(state_,
      top_height,
      bottom_height,
      shrink_viewport ? 1 : 0);
  }
  void SetOverscrollBehavior(const blink::WebOverscrollBehavior& behavior) override {
    callbacks_.SetOverscrollBehavior(state_,
      static_cast<WebOverscrollBehaviorTypeEnum>(behavior.x),
      static_cast<WebOverscrollBehaviorTypeEnum>(behavior.y));
  }
  void SetNeedsBeginFrame() override {
    callbacks_.SetNeedsBeginFrame(state_);
  }
  void DidStopFlinging() override {
    callbacks_.DidStopFlinging(state_);
  }
  
  void LayoutAndPaintAsync(base::OnceClosure callback) override {
    //DLOG(INFO) << "\n\n **** WebLayerTreeViewClient::LayoutAndPaintAsync ***\n\n";
    callbacks_.LayoutAndPaintAsync(
      state_, 
      new OnceFunction<void()>(
        reinterpret_cast<uintptr_t>(&LayoutAndPaintAsyncImpl),
        std::move(callback)), 
      &LayoutAndPaintAsyncCallback);
  }

  void CompositeAndReadbackAsync(
      base::OnceCallback<void(const SkBitmap&)> callback) override {
    callbacks_.CompositeAndReadbackAsync(
      state_, 
      new OnceFunction<void(const SkBitmap&)>(
        reinterpret_cast<uintptr_t>(&CompositeAndReadbackAsyncImpl),
        std::move(callback)), 
      &CompositeAndReadbackAsyncCallback);
  }
  void SynchronouslyCompositeNoRasterForTesting() override {
    callbacks_.SynchronouslyCompositeNoRasterForTesting(state_);
  }
  void CompositeWithRasterForTesting() override {
    callbacks_.CompositeWithRasterForTesting(state_);
  }
  void SetDeferCommits(bool defer_commits) override {
    callbacks_.SetDeferCommits(state_, defer_commits ? 1 : 0);
  }
  void RegisterViewportLayers(const ViewportLayers& viewport_layers) override {
    callbacks_.RegisterViewportLayers(state_,
      viewport_layers.overscroll_elasticity ? const_cast<blink::WebLayer*>(viewport_layers.overscroll_elasticity) : nullptr,
      viewport_layers.page_scale ? const_cast<blink::WebLayer*>(viewport_layers.page_scale) : nullptr,
      viewport_layers.inner_viewport_container ? const_cast<blink::WebLayer*>(viewport_layers.inner_viewport_container) : nullptr,
      viewport_layers.outer_viewport_container ? const_cast<blink::WebLayer*>(viewport_layers.outer_viewport_container) : nullptr,
      viewport_layers.inner_viewport_scroll ? const_cast<blink::WebLayer*>(viewport_layers.inner_viewport_scroll) : nullptr,
      viewport_layers.outer_viewport_scroll ? const_cast<blink::WebLayer*>(viewport_layers.outer_viewport_scroll) : nullptr);
  }
  void ClearViewportLayers() override {
    callbacks_.ClearViewportLayers(state_);
  }
  void RegisterSelection(const blink::WebSelection& sel) override {
    WebSelectionTypeEnum type = WebSelectionTypeNoSelection;
    if (sel.IsCaret()) {
      type = WebSelectionTypeCaretSelection;
    } else if (sel.IsRange()) {
      type = WebSelectionTypeRangeSelection;
    }
      
    callbacks_.RegisterSelection(state_,
      type,
      static_cast<WebSelectionBoundTypeEnum>(sel.Start().type),
      sel.Start().layer_id,
      sel.Start().edge_top_in_layer.x,
      sel.Start().edge_top_in_layer.y,
      sel.Start().edge_bottom_in_layer.x,
      sel.Start().edge_bottom_in_layer.y,
      sel.Start().is_text_direction_rtl ? 1 : 0,
      sel.Start().hidden ? 1 : 0,
      static_cast<WebSelectionBoundTypeEnum>(sel.end().type),
      sel.end().layer_id,
      sel.end().edge_top_in_layer.x,
      sel.end().edge_top_in_layer.y,
      sel.end().edge_bottom_in_layer.x,
      sel.end().edge_bottom_in_layer.y,
      sel.end().is_text_direction_rtl ? 1 : 0,
      sel.end().hidden ? 1 : 0);
  }
  void ClearSelection() override {
    callbacks_.ClearSelection(state_);
  }
  void SetMutatorClient(std::unique_ptr<cc::LayerTreeMutator> mutator) override {
    cc::LayerTreeMutator* mutator_ref = mutator.release();
    callbacks_.SetMutatorClient(state_, mutator_ref);
  }
  void ForceRecalculateRasterScales() override {
    callbacks_.ForceRecalculateRasterScales(state_);
  }
  void SetEventListenerProperties(blink::WebEventListenerClass cls,
                                  blink::WebEventListenerProperties props) override {
    callbacks_.SetEventListenerProperties(state_, 
      static_cast<WebEventListenerClassEnum>(cls), 
      static_cast<WebEventListenerPropertiesEnum>(props));
  }
  void UpdateEventRectsForSubframeIfNecessary() override {
    callbacks_.UpdateEventRectsForSubframeIfNecessary(state_);
  }
  void SetHaveScrollEventHandlers(bool have) override {
    callbacks_.SetHaveScrollEventHandlers(state_, have ? 1 : 0);
  }
  viz::FrameSinkId GetFrameSinkId() override { 
    uint32_t client = 0;
    uint32_t sink = 0;
    callbacks_.GetFrameSinkId(state_, &client, &sink);
    viz::FrameSinkId frame_sink(client, sink);
    //DLOG(INFO) << "\n\nWebLayerTreeViewImpl::GetFrameSinkId: " << frame_sink.client_id() << ", " << frame_sink.sink_id();
    return frame_sink; 
  }
  blink::WebEventListenerProperties EventListenerProperties(
      blink::WebEventListenerClass cls) const override {
    return static_cast<blink::WebEventListenerProperties>(callbacks_.EventListenerProperties(state_, static_cast<WebEventListenerClassEnum>(cls)));
  }
  bool HaveScrollEventHandlers() const override { 
    return callbacks_.HaveScrollEventHandlers(state_) != 0;
  }
  int LayerTreeId() const override {
    return callbacks_.LayerTreeId(state_);
  }
  void SetShowFPSCounter(bool show) override {
    callbacks_.SetShowFPSCounter(state_, show ? 1 : 0);
  }
  void SetShowPaintRects(bool show) override {
    callbacks_.SetShowPaintRects(state_, show ? 1 : 0);
  }
  void SetShowDebugBorders(bool show) override {
    callbacks_.SetShowDebugBorders(state_, show ? 1 : 0);
  }
  void SetShowScrollBottleneckRects(bool show) override {
    callbacks_.SetShowScrollBottleneckRects(state_, show ? 1 : 0);
  }
  void NotifySwapTime(ReportTimeCallback callback) override {
    cc::LayerTreeHost* layer_tree_host = GetLayerTreeHost();
    //DLOG(INFO) << "\n\n\nWebLayerTreeViewImpl::NotifySwapTime: queueying ReportTimeSwapPromise into LayerTreeHost: " << layer_tree_host;
    layer_tree_host->QueueSwapPromise(
      std::make_unique<ReportTimeSwapPromise>(std::move(callback), layer_tree_host->GetTaskRunnerProvider()->MainThreadTaskRunner()));
  }
  void RequestBeginMainFrameNotExpected(bool new_state) override {
    callbacks_.RequestBeginMainFrameNotExpected(state_, new_state ? 1 : 0);
  }
  void RequestDecode(const blink::PaintImage& image,
                     base::OnceCallback<void(bool)> callback) override {
    blink::PaintImage* image_ref = const_cast<blink::PaintImage*>(&image);
    callbacks_.RequestDecode(
      state_,
      new OnceFunction<void(bool)>(
        reinterpret_cast<uintptr_t>(&RequestDecodeImpl),
        std::move(callback)),
      image_ref, 
      &RequestDecodeCallback);
  }
private:

  void* state_;
  WebLayerTreeViewCbs callbacks_;
  cc::AnimationHost* weak_animation_host_;
};

// WebViewClient
class WebViewClientImpl : public blink::WebViewClient {
public:
 WebViewClientImpl(void* peer, WebViewClientCbs callbacks): callbacks_(callbacks), peer_(peer) {}

 ~WebViewClientImpl() override {}

 WebLayerTreeViewImpl* web_layer_tree_view() const {
    return web_layer_tree_view_.get();
 }

 // WebWidgetClient
 blink::WebLayerTreeView* InitializeLayerTreeView() override {
   void* compositor_state = nullptr;
   WebLayerTreeViewCbs cbs;
   callbacks_.initializeLayerTreeView(peer_, &compositor_state, &cbs);
   web_layer_tree_view_.reset(new WebLayerTreeViewImpl(compositor_state, std::move(cbs)));
   return web_layer_tree_view_.get();
 }

 void IntrinsicSizingInfoChanged(const blink::WebIntrinsicSizingInfo& info) override {
   callbacks_.intrinsicSizingInfoChanged(peer_,
   info.size.width,
   info.size.height,
   info.aspect_ratio.width,
   info.aspect_ratio.height,
   info.has_width ? 1 : 0,
   info.has_height ? 1 : 0);
 }

 void DidMeaningfulLayout(blink::WebMeaningfulLayout layout) override {
   callbacks_.didMeaningfulLayout(peer_, static_cast<WebMeaningfulLayoutTypeEnum>(layout));
 }

 void DidChangeCursor(const blink::WebCursorInfo& info) override {
   sk_sp<SkImage> skiaImage = SkImage::MakeFromBitmap(info.custom_image.GetSkBitmap());
   SkiaImage image(std::move(skiaImage));
   callbacks_.didChangeCursor(peer_, static_cast<WebCursorEnum>(info.type), info.hot_spot.x, info.hot_spot.y, info.image_scale_factor, &image);
 }

 void AutoscrollStart(const blink::WebFloatPoint& point) override {
   callbacks_.autoscrollStart(peer_,
    point.x,
    point.y);
 }
 
 void AutoscrollFling(const blink::WebFloatSize& velocity) override {
   callbacks_.autoscrollFling(peer_,
    velocity.width,
    velocity.height);
 }
 
 void AutoscrollEnd() override {
   callbacks_.autoscrollEnd(peer_);
 }

 void CloseWidgetSoon() override {
   callbacks_.closeWidgetSoon(peer_);
 }

 void Show(blink::WebNavigationPolicy policy) override {
   callbacks_.show(peer_, static_cast<WebNavigationPolicyEnum>(policy));
 }
 
 blink::WebRect WindowRect() override {
   blink::WebRect rect;
   callbacks_.windowRect(peer_, &rect.x, &rect.y, &rect.width, &rect.height);
   return rect;
 }

 blink::WebRect ViewRect() override {
   blink::WebRect rect;
   callbacks_.viewRect(peer_, &rect.x, &rect.y, &rect.width, &rect.height);
   return rect;
 }

 void SetToolTipText(const blink::WebString& text, blink::WebTextDirection hint) override {
   callbacks_.setToolTipText(peer_, text.Utf8().c_str(), static_cast<WebTextDirectionEnum>(hint));
 }
 
 void SetWindowRect(const blink::WebRect& rect) override {
   callbacks_.setWindowRect(peer_, rect.x, rect.y, rect.width, rect.height);
 }

 blink::WebScreenInfo GetScreenInfo() override {
  blink::WebScreenInfo i;
  WebScreenOrientationEnum orientation;
  int monochrome;
  callbacks_.screenInfo(peer_, &i.device_scale_factor, &i.depth, &i.depth_per_component, &monochrome, &i.rect.x, &i.rect.y, &i.rect.width, &i.rect.height, &i.available_rect.x, &i.available_rect.y, &i.available_rect.width, &i.available_rect.height, &orientation, &i.orientation_angle);
  i.orientation_type = static_cast<blink::WebScreenOrientationType>(orientation);
  i.is_monochrome = monochrome == 0 ? false : true;
  return i;
 }

 void DidHandleGestureEvent(const blink::WebGestureEvent& event, bool eventCancelled) override {
    callbacks_.didHandleGestureEvent(
      peer_,
      const_cast<blink::WebGestureEvent *>(&event),
      eventCancelled);
 }

 void DidOverscroll(
   const blink::WebFloatSize& overscrollDelta, 
   const blink::WebFloatSize& accumulatedRootOverScroll, 
   const blink::WebFloatPoint& position, 
   const blink::WebFloatSize& velocity,
   const blink::WebOverscrollBehavior& behavior) override {
    
   callbacks_.didOverscroll(peer_, 
    overscrollDelta.width, overscrollDelta.height, 
    accumulatedRootOverScroll.width, accumulatedRootOverScroll.height, 
    position.x, position.y, 
    velocity.width, velocity.height,
    static_cast<int>(behavior.x), static_cast<int>(behavior.y));
 }

 void ShowVirtualKeyboardOnElementFocus() override {
   NOTIMPLEMENTED();
 }

 void ConvertViewportToWindow(blink::WebRect* rect) override {
   //int x, y, w, h;
   //callbacks_.convertViewportToWindow(peer_, &x, &y, &w, &h);
   //rect->x = x;
   //rect->y = y;
   //rect->width = w;
   //rect->height = h;
   callbacks_.convertViewportToWindow(peer_, &rect->x, &rect->y, &rect->width, &rect->height);
 }

 void ConvertWindowToViewport(blink::WebFloatRect* rect) override {
   callbacks_.convertWindowToViewport(peer_, &rect->x, &rect->y, &rect->width, &rect->height);
 }

 bool RequestPointerLock() override { 
   return callbacks_.requestPointerLock(peer_); 
 }
 
 void RequestPointerUnlock() override {
   callbacks_.requestPointerUnlock(peer_);
 }
 
 bool IsPointerLocked() override { 
   return callbacks_.isPointerLocked(peer_); 
 }

 void StartDragging(
   blink::WebReferrerPolicy policy, 
   const blink::WebDragData& data, 
   blink::WebDragOperationsMask mask, 
   const blink::WebImage& image, 
   const blink::WebPoint& dragImageOffset) override {
  SkiaImage* skimage = nullptr;
  if (!image.IsNull()) {
    sk_sp<SkImage> skiaImage = SkImage::MakeFromBitmap(image.GetSkBitmap());
    skimage = new SkiaImage(std::move(skiaImage));
  }
  callbacks_.startDragging(peer_, 
      static_cast<WebReferrerPolicyEnum>(policy), 
      const_cast<blink::WebDragData *>(&data), 
      static_cast<WebDragOperationsMask>(mask), 
      skimage, 
      dragImageOffset.x, 
      dragImageOffset.y);
  
 }

 bool CanHandleGestureEvent() override {
   return callbacks_.canHandleGestureEvent(peer_) == 1 ? true : false;
 }
 
 bool CanUpdateLayout() override {
   return callbacks_.canUpdateLayout(peer_) == 1 ? true : false;
 }

 void HasTouchEventHandlers(bool handlers) override {
   callbacks_.hasTouchEventHandlers(peer_, handlers);
 }

 void SetTouchAction(blink::WebTouchAction touchAction) override {
   callbacks_.setTouchAction(peer_, static_cast<WebTouchActionEnum>(touchAction));
 }

 blink::WebWidgetClient* WidgetClient() override {
   return this;
 }

 // WebViewClient
 blink::WebView* CreateView(blink::WebLocalFrame* creator,
                            const blink::WebURLRequest& request,
                            const blink::WebWindowFeatures& features,
                            const blink::WebString& name,
                            blink::WebNavigationPolicy policy,
                            bool suppressOpener,
                            blink::WebSandboxFlags sandbox_flags) override {
  WebURLRequestWrapper req(request);
  return reinterpret_cast<blink::WebView *>(callbacks_.createView(
                    peer_, 
                    creator, 
                    &req, 
                    features.x, 
                    features.x_set, 
                    features.y, 
                    features.y_set, 
                    features.width,
                    features.width_set, 
                    features.height, 
                    features.height_set, 
                    features.menu_bar_visible, 
                    features.status_bar_visible, 
                    features.tool_bar_visible, 
                    features.scrollbars_visible, 
                    features.resizable, 
                    features.noopener,
                    features.background,
                    features.persistent,                    
                    name.Utf8().c_str(), 
                    static_cast<WebNavigationPolicyEnum>(policy), 
                    suppressOpener));
}

// blink::WebWidget* CreatePopupMenu(blink::WebPopupType type) override {
//   return reinterpret_cast<blink::WebWidget *>(callbacks_.createPopupMenu(peer_, static_cast<WebPopupTypeEnum>(type)));
// }

blink::WebWidget* CreatePopup(blink::WebLocalFrame* frame, blink::WebPopupType popup_type) override {
  return reinterpret_cast<blink::WebWidget *>(callbacks_.createPopup(peer_, frame, static_cast<WebPopupTypeEnum>(popup_type)));
}

  // Returns the session storage namespace id associated with this WebView.
base::StringPiece GetSessionStorageNamespaceId() override {
  // return base::StringPiece();
  return base::StringPiece(callbacks_.getSessionStorageNamespaceId(peer_));
}

// blink::WebStorageNamespace* CreateSessionStorageNamespace() override {
//   return reinterpret_cast<blink::WebStorageNamespace *>(callbacks_.createSessionStorageNamespace(peer_));
// }

void PrintPage(blink::WebLocalFrame* frame) override {
  callbacks_.printPage(peer_, frame);
}

bool EnumerateChosenDirectory(const blink::WebString& path, blink::WebFileChooserCompletion* completion) override { 
  return callbacks_.enumerateChosenDirectory(peer_, path.Utf8().c_str(), completion);
}

void SetMouseOverURL(const blink::WebURL& url) override {
  callbacks_.setMouseOverURL(peer_, url.GetString().Utf8().c_str());
}

void SetKeyboardFocusURL(const blink::WebURL& url) override {
  callbacks_.setKeyboardFocusURL(peer_, url.GetString().Utf8().c_str());
}

bool AcceptsLoadDrops() override { 
  return callbacks_.acceptsLoadDrops(peer_); 
}

void FocusNext() override {
  callbacks_.focusNext(peer_);
}

void FocusPrevious() override {
  callbacks_.focusPrevious(peer_);
}

void FocusedNodeChanged(const blink::WebNode& fromNode, const blink::WebNode& toNode) override {
  if (fromNode.IsNull() && toNode.IsNull()) {
    callbacks_.focusedNodeChanged(peer_, nullptr, nullptr);
  } else if (fromNode.IsNull()) {
    WebNodeWrapper to(toNode);
    to.set_stack_allocated(true);
    callbacks_.focusedNodeChanged(peer_, nullptr, &to);
  } else if (toNode.IsNull()) {
    WebNodeWrapper from(fromNode);
    from.set_stack_allocated(true);
    callbacks_.focusedNodeChanged(peer_, &from, nullptr);
  } else {
    WebNodeWrapper from(fromNode);
    WebNodeWrapper to(toNode);
    to.set_stack_allocated(true);
    from.set_stack_allocated(true);
    callbacks_.focusedNodeChanged(peer_, &from, &to);
  }
}

void DidUpdateLayout() override {
  callbacks_.didUpdateLayout(peer_);
}

#if defined(OS_ANDROID)
bool DidTapMultipleTargets(const blink::WebSize& pinchViewportOffset, const blink::WebRect& touchRect, const blink::WebVector<blink::WebRect>& targetRects) override {
  int targetLen = targetRects.size();
  int targetx[targetLen];
  int targety[targetLen];
  int targetw[targetLen];
  int targeth[targetLen];

  for(int i = 0; i < targetLen; i++) {
    targetx[i] = targetRects[i].x;
    targety[i] = targetRects[i].y;
    targetw[i] = targetRects[i].width;
    targeth[i] = targetRects[i].height;
  }

  return callbacks_.didTapMultipleTargets(peer_, pinchViewportOffset.width, pinchViewportOffset.height, touchRect.x, touchRect.y, touchRect.width, touchRect.height, targetx, targety, targetw, targeth, targetLen);
}

bool OpenDateTimeChooser(const blink::WebDateTimeChooserParams& params, blink::WebDateTimeChooserCompletion* completion) override { 
  return callbacks_.openDateTimeChooser(peer_, 
    static_cast<WebDateTimeInputTypeEnum>(params.type),
    params.anchorRectInScreen.x, 
    params.anchorRectInScreen.y, 
    params.anchorRectInScreen.width, 
    params.anchorRectInScreen.height,
    params.doubleValue,
    params.minimum,
    params.maximum,
    params.step,
    params.stepBase,
    params.isRequired,
    params.isAnchorElementRTL, 
    completion);
}

#endif

blink::WebString AcceptLanguages() override {
  return blink::WebString::FromUTF8(callbacks_.acceptLanguages(peer_));
}

void NavigateBackForwardSoon(int offset) override {
  callbacks_.navigateBackForwardSoon(peer_, offset);
}

int HistoryBackListCount() override { 
  return callbacks_.historyBackListCount(peer_); 
}

int HistoryForwardListCount() override { 
  return callbacks_.historyForwardListCount(peer_); 
}

void ZoomLimitsChanged(double minimumLevel, double maximumLevel) override {
  callbacks_.zoomLimitsChanged(peer_, minimumLevel, maximumLevel);
}

void PageScaleFactorChanged() override { 
  callbacks_.pageScaleFactorChanged(peer_);
}

void DidAutoResize(const blink::WebSize& newSize) override {
  callbacks_.didAutoResize(peer_, newSize.width, newSize.height);
}

blink::WebRect RootWindowRect() override {
   blink::WebRect rect;
   callbacks_.rootWindowRect(peer_, &rect.x, &rect.y, &rect.width, &rect.height);
   return rect;
}
 
void DidFocus(blink::WebLocalFrame* calling_frame) override {
  callbacks_.didFocus(peer_, calling_frame);
}

// RenderView end
 
// void DidBlur() override {
//   callbacks_.didBlur(peer_);
// }

// void SaveImageFromDataURL(const blink::WebString& url) override {
//   callbacks_.saveImageFromDataURL(peer_, url.utf8().c_str());
// }

void PageImportanceSignalsChanged() override {
  callbacks_.pageImportanceSignalsChanged(peer_);
}

// void DidCancelCompositionOnSelectionChange() override {
//   callbacks_.didCancelCompositionOnSelectionChange(peer_);
// }

// void DidChangeContents() override {
//   callbacks_.didChangeContents(peer_);
// }

// bool HandleCurrentKeyboardEvent() override { 
//   return callbacks_.handleCurrentKeyboardEvent(peer_); 
// }

// bool RunFileChooser(const blink::WebFileChooserParams& params,
//                     blink::WebFileChooserCompletion* completion) override { 
   
//   const char* accept[params.acceptTypes.size()];
//   const char* selected[params.selectedFiles.size()]; 

//   for (size_t i = 0; i < params.acceptTypes.size(); i++) {
//     accept[i] = params.acceptTypes[i].utf8().c_str();
//   }

//   for (size_t i = 0; i < params.selectedFiles.size(); i++) {
//     selected[i] = params.selectedFiles[i].utf8().c_str();
//   }

//   return callbacks_.runFileChooser(peer_,
//     params.multiSelect,
//     params.directory,
//     params.saveAs,
//     params.title.utf8().c_str(),
//     params.initialValue.utf8().c_str(),
//     accept,
//     selected,
//     params.capture.utf8().c_str(),
//     params.useMediaCapture,
//     params.needLocalPath,
//     params.requestor.string().utf8().c_str(), 
//     completion); 
// }

// void ShowValidationMessage(const blink::WebRect& anchorInViewport, const blink::WebString& mainText, blink::WebTextDirection mainTextDir, const blink::WebString& supplementalText, blink::WebTextDirection supplementalTextDir) override {
//   callbacks_.showValidationMessage(peer_, anchorInViewport.x, anchorInViewport.y, anchorInViewport.width, anchorInViewport.height, mainText.utf8().c_str(), static_cast<WebTextDirectionEnum>(mainTextDir), supplementalText.utf8().c_str(), static_cast<WebTextDirectionEnum>(supplementalTextDir));
// }

// void HideValidationMessage() override {
//   callbacks_.hideValidationMessage(peer_);
// }

// void MoveValidationMessage(const blink::WebRect& anchorInViewport) override {
//   callbacks_.moveValidationMessage(peer_, anchorInViewport.x, anchorInViewport.y, anchorInViewport.width, anchorInViewport.height);
// }

// void SetStatusText(const blink::WebString& text) override {
//   callbacks_.setStatusText(peer_, text.utf8().c_str());
// }

void DidUpdateInspectorSettings() override {
  callbacks_.didUpdateInspectorSettings(peer_);
}

void DidUpdateInspectorSetting(const blink::WebString& key, const blink::WebString& value) override {
  callbacks_.didUpdateInspectorSetting(peer_, key.Utf8().c_str(), value.Utf8().c_str());
}

/* blink::WebSpeechRecognizer* SpeechRecognizer() override { 
  return reinterpret_cast<blink::WebSpeechRecognizer *>(callbacks_.speechRecognizer(peer_)); 
} */

// blink::WebPageVisibilityState VisibilityState() const override {
//   return static_cast<blink::WebPageVisibilityState>(callbacks_.visibilityState(peer_));
// }

// blink::WebContentDetectionResult DetectContentAround(const blink::WebHitTestResult& result) override { 
//   WebRangeRef range = nullptr;
//   const char* string;
//   const char* intent;

//   callbacks_.detectContentAround(peer_, 
//       const_cast<blink::WebHitTestResult *>(&result),
//       range,
//       &string,
//       &intent);

//   if (range) {
//     blink::WebContentDetectionResult result(*reinterpret_cast<blink::WebRange *>(range), blink::WebString::FromUTF8(string), blink::KURL(blink::ParsedURLString, intent));
//     return result;
//   }

//   return blink::WebContentDetectionResult();
// }

// void ScheduleContentIntent(const blink::WebURL& url, bool isMainFrame) override {
//   callbacks_.scheduleContentIntent(peer_, url.string().utf8().c_str(), isMainFrame);
// }

// void CancelScheduledContentIntents() override { 
//   callbacks_.cancelScheduledContentIntents(peer_);
// }

// void DraggableRegionsChanged() override { 
//   callbacks_.draggableRegionsChanged(peer_);
// }

// probably deprecated WebWidgetClient stuff

 void DidInvalidateRect(const blink::WebRect& rect) override { 
   callbacks_.didInvalidateRect(peer_, rect.x, rect.y, rect.width, rect.height);
 }
 
//  void DidUpdateLayoutSize(const blink::WebSize& newSize) override {
//    callbacks_.didUpdateLayoutSize(peer_, newSize.width, newSize.height);
//  }
 
 void ScheduleAnimation() override {
   callbacks_.scheduleAnimation(peer_);
 }
 
 void DidFirstLayoutAfterFinishedParsing() override {
   callbacks_.didFirstLayoutAfterFinishedParsing(peer_);
 }
 
//  blink::WebRect WindowResizerRect() override {
//    blink::WebRect rect;
//    callbacks_.windowResizerRect(peer_, &rect.x, &rect.y, &rect.width, &rect.height);
//    return rect;
//  }
 
//  void ResetInputMethod() override {
//    callbacks_.resetInputMethod(peer_);
//  }
  
//  void DidUpdateTextOfFocusedElementByNonUserInput() override {
//    callbacks_.didUpdateTextOfFocusedElementByNonUserInput(peer_);
//  }
 
//  void ShowImeIfNeeded() override {
//    callbacks_.showImeIfNeeded(peer_);
//  }
 
//  void ShowUnhandledTapUIIfNeeded(const blink::WebPoint& tappedPosition, const blink::WebNode& tappedNode, bool pageChanged) override {
//    WebNodeWrapper node(PassRefPtrWillBeRawPtr<blink::Node>(const_cast<blink::WebNode &>(tappedNode)));
//    callbacks_.showUnhandledTapUIIfNeeded(peer_, tappedPosition.x, tappedPosition.y, &node, pageChanged);
//  }
 
//  void OnMouseDown(const blink::WebNode& mouseDownNode) override {
//   WebNodeWrapper node(mouseDownNode);
//   callbacks_.onMouseDown(peer_, &node);
//  }

private:
  WebViewClientCbs callbacks_;
  void* peer_;
  std::unique_ptr<WebLayerTreeViewImpl> web_layer_tree_view_;
};

class ReceivedDataImpl : public application::RequestPeer::ReceivedData {
public:
  ReceivedDataImpl():
   payload_(nullptr), length_(0) {}

  ReceivedDataImpl(char* payload, int length):
   payload_(payload), length_(length) {

  }

  ~ReceivedDataImpl() {
    if (payload_) {
      free(payload_);
    }
  }

  const char* payload() const override {
    return payload_;
  } 

  int length() const override {
    return length_;
  }

private:
  char* payload_;
  int length_;
};


class ApplicationResponseHandler : public application::ResponseHandler {
public:
  ApplicationResponseHandler(void* state, CResponseHandler cbs):
   state_(state),
   callbacks_(std::move(cbs)) {
     //DLOG(INFO) << "ApplicationResponseHandler (constructor): calling callbacks_.GetName()";
     name_ = std::string(callbacks_.GetName(state_));
   }

  ~ApplicationResponseHandler() override {}

  const std::string& name() const {
    return name_;
  }

  bool WillHandleResponse(blink::WebURLResponse* response) override {
    //DLOG(INFO) << "ApplicationResponseHandler::WillHandleResponse";
    return callbacks_.WillHandleResponse(state_, response) != 0;
  }

  int OnDataAvailable(const char* input, int input_len) override {
    //DLOG(INFO) << "ApplicationResponseHandler::OnDataAvailable";
    return callbacks_.OnDataAvailable(state_, input, input_len); 
  }

  int OnFinishLoading(int error_code, int total_transfer_size) override {
    //DLOG(INFO) << "ApplicationResponseHandler::OnFinishLoading";
    return callbacks_.OnFinishLoading(state_, error_code, total_transfer_size);
  }

  std::unique_ptr<application::RequestPeer::ReceivedData> GetResult() override {
    //DLOG(INFO) << "ApplicationResponseHandler::GetResult";
    char* data = nullptr;
    int len = 0;
    callbacks_.GetResult(state_, &data, &len);
    return std::make_unique<ReceivedDataImpl>(data, len);
  }

private:
  void* state_;
  CResponseHandler callbacks_;
  std::string name_;

  DISALLOW_COPY_AND_ASSIGN(ApplicationResponseHandler);
};


class WebServiceWorkerNetworkProviderImpl : public blink::WebServiceWorkerNetworkProvider {
public: 
  WebServiceWorkerNetworkProviderImpl(int provider_id, int route_id, void* state, WebServiceWorkerNetworkProviderCbs callbacks):
    owned_(true),
    provider_id_(provider_id),
    route_id_(route_id),
    state_(state),
    callbacks_(callbacks) {  
    application::ApplicationThread* thread = application::ApplicationThread::current();

    //int provider_id = GetNextProviderId();
    
    // FIXME: Host must send this to us on CommitNavigation that is called over IPC
    //        then we should catch it and pass here ..
    common::mojom::ControllerServiceWorkerInfoPtr controller_info;
    
    scoped_refptr<network::SharedURLLoaderFactory> direct_network_loader_factory =
        base::MakeRefCounted<common::PossiblyAssociatedWrapperSharedURLLoaderFactory>(
            thread->blink_platform()->CreateNetworkURLLoaderFactory());

    // common::ServiceWorkerProviderHostInfo host_info(
    //   provider_id_, 
    //   route_id_, 
    //   provider_type, 
    //   true);
    // common::mojom::ServiceWorkerContainerAssociatedRequest client_request =
    // mojo::MakeRequest(&host_info.client_ptr_info);
    // common::mojom::ServiceWorkerContainerHostAssociatedPtrInfo host_ptr_info;
    // host_info.host_request = mojo::MakeRequest(&host_ptr_info);

    // application::ServiceWorkerDispatcher::GetOrCreateThreadSpecificInstance();
    // context_ = base::MakeRefCounted<application::ServiceWorkerProviderContext>(
    //   provider_id, provider_type, std::move(client_request),
    //   std::move(host_ptr_info), 
    //   std::move(controller_info),
    //   std::move(direct_network_loader_factory));
    provider_ = base::WrapUnique(new application::ServiceWorkerNetworkProvider(
      route_id_, blink::mojom::ServiceWorkerProviderType::kForWindow,
      provider_id_, true, std::move(controller_info),
      std::move(direct_network_loader_factory)));
      //std::move(default_loader_factory)));
    // application::ApplicationThread::current()->channel()->GetRemoteAssociatedInterface(
    //     &dispatcher_host_);
    // dispatcher_host_->OnProviderCreated(std::move(host_info));
  }

  ~WebServiceWorkerNetworkProviderImpl() override {
    //DLOG(INFO) << "WebServiceWorkerNetworkProviderImpl destructor";
  }

  bool is_owned() const {
    return owned_;
  }

  void set_owned(bool owned) {
    owned_ = owned;
  }

  void set_provider_id(int provider_id) {
    provider_id_ = provider_id;
    provider_->context()->set_provider_id(provider_id);
  }

  void WillSendRequest(blink::WebURLRequest& request) override {
    if (!request.GetExtraData())
      request.SetExtraData(std::make_unique<application::RequestExtraData>());
    auto* extra_data = static_cast<application::RequestExtraData*>(request.GetExtraData());
    extra_data->set_service_worker_provider_id(provider_->provider_id());

    // If the provider does not have a controller at this point, the renderer
    // expects the request to never be handled by a service worker, so call
    // SetSkipServiceWorker() with true to skip service workers here. Otherwise,
    // a service worker that is in the process of becoming the controller (i.e.,
    // via claim()) on the browser-side could handle the request and break the
    // assumptions of the renderer.
    if (request.GetFrameType() !=
            network::mojom::RequestContextFrameType::kTopLevel &&
        request.GetFrameType() !=
            network::mojom::RequestContextFrameType::kNested &&
        !provider_->IsControlledByServiceWorker()) {
      request.SetSkipServiceWorker(true);
    }
    //DLOG(INFO) << "WebServiceWorkerNetworkProviderImpl::WillSendRequest";
    callbacks_.WillSendRequest(state_, const_cast<blink::WebURLRequest *>(&request));
  }
  
  int ProviderID() const override {
    //DLOG(INFO) << "WebServiceWorkerNetworkProviderImpl::ProviderID";
    //return callbacks_.GetProviderId(state_);
    return provider_->provider_id();
  }
  
  bool HasControllerServiceWorker() override {
    //DLOG(INFO) << "WebServiceWorkerNetworkProviderImpl::HasControllerServiceWorker";
    //DCHECK(state_);
    //return callbacks_.HasControllerServiceWorker(state_) != 0; 
    return provider_->IsControlledByServiceWorker();
  }
  
  int64_t ControllerServiceWorkerID() override {
    //DLOG(INFO) << "WebServiceWorkerNetworkProviderImpl::ControllerServiceWorkerID";
    //return callbacks_.GetControllerServiceWorkerId(state_);
    if (provider_->context())
      return provider_->context()->GetControllerVersionId();
    return blink::mojom::kInvalidServiceWorkerVersionId;
  }
  
  std::unique_ptr<blink::WebURLLoader> CreateURLLoader(
      const blink::WebURLRequest& request,
      scoped_refptr<base::SingleThreadTaskRunner> task_runner) override {
    CBlinkPlatformCallbacks callbacks;

    void* loader_state = callbacks_.CreateURLLoader(
      state_, 
      const_cast<blink::WebURLRequest *>(&request),
      &callbacks);

    //return std::make_unique<application::ApplicationURLLoader>(request);//, std::move(callbacks), loader_state);
    application::ApplicationThread* thread = application::ApplicationThread::current();
    application::ApplicationWindowDispatcher* window = thread->window_dispatcher();

    // FIXME: we need to add the ServiceWorkerSubresourceLoader from the service_worker directory
    //        here

    auto loader = std::make_unique<application::ApplicationURLLoader>(
      thread->resource_dispatcher(),
      task_runner,
      // get the loader factories defined by the last CommitNavigation() IPC
      // NOTE: we need a way to get the specific loader factories for the specific
      //       commit.. or else we might get the factories of other commits
      //       because we are using the "global" window
      window->loader_factories(),
      std::move(callbacks), 
      loader_state);

    int resp_handler_count = callbacks_.CountResponseHandler(state_);
    //DLOG(INFO) << "WebServiceWorkerNetworkProviderImpl: CountResponseHandler = " << resp_handler_count;
    for (int i = 0; i < resp_handler_count; i++) {
      CResponseHandler handler;
      //DLOG(INFO) << "WebServiceWorkerNetworkProviderImpl: getting response handler" << i;
      void* handler_state = callbacks_.GetResponseHandlerAt(
      state_, 
      i,
      &handler);
      if (handler_state) {
        //DLOG(INFO) << "WebServiceWorkerNetworkProviderImpl: adding response handler " << i << " to url loader";
        loader->AddHandler(std::make_unique<ApplicationResponseHandler>(
          handler_state,
          std::move(handler)));
      }
    }
    return loader;
  }

  application::ServiceWorkerProviderContext* context() const { 
    return provider_->context(); 
  }

private:
  bool owned_;
  int provider_id_;
  int route_id_;
  void* state_;
  WebServiceWorkerNetworkProviderCbs callbacks_;
  //scoped_refptr<application::ServiceWorkerProviderContext> context_;
  std::unique_ptr<application::ServiceWorkerNetworkProvider> provider_;
  common::mojom::ServiceWorkerDispatcherHostAssociatedPtr dispatcher_host_;
  
  DISALLOW_COPY_AND_ASSIGN(WebServiceWorkerNetworkProviderImpl);
};


class WebFrameClientImpl : public blink::WebFrameClient,
                           public blink::WebRemoteFrameClient {
public:  
  WebFrameClientImpl(void* peer, WebFrameClientCbs callbacks): 
    callbacks_(callbacks), 
    peer_(peer), 
    // TODO: pass the real routing id
    frame_blame_context_(new application::FrameBlameContext(1)) {
      frame_blame_context_->Initialize();
    }
  ~WebFrameClientImpl() override {}

  void BindToFrame(blink::WebLocalFrame* frame) override {
    //DLOG(INFO) << "WebFrameClientImpl::BindToFrame: this = " << this << " callbacks_.bindToFrame = " << callbacks_.bindToFrame << " peer = " << peer_;
    callbacks_.bindToFrame(peer_, frame);
  }

  blink::WebPlugin* CreatePlugin(const blink::WebPluginParams& params) override {
    const char* attributeNames[params.attribute_names.size()];
    const char* attributeValues[params.attribute_values.size()]; 

    for (size_t i = 0; i < params.attribute_names.size(); i++) {
      attributeNames[i] = params.attribute_names[i].Utf8().c_str();
    }

    for (size_t i = 0; i < params.attribute_values.size(); i++) {
      attributeValues[i] = params.attribute_values[i].Utf8().c_str();
    }      

    return reinterpret_cast<blink::WebPlugin *>(callbacks_.createPlugin(peer_,
      params.url.GetString().Utf8().c_str(),
      params.mime_type.Utf8().c_str(),
      attributeNames,
      params.attribute_names.size(),
      attributeValues,
      params.attribute_values.size(),
      params.load_manually));
  }

  blink::WebMediaPlayer* CreateMediaPlayer(
    const blink::WebMediaPlayerSource& source, 
    blink::WebMediaPlayerClient* playerClient, 
    blink::WebMediaPlayerEncryptedMediaClient* encClient, 
    blink::WebContentDecryptionModule* mod, 
    const blink::WebString& sinkId,
    blink::WebLayerTreeView* layer_tree_view) override { 

    const char* sink_id_cstr = nullptr;
    if (!sinkId.IsEmpty()) {
      sink_id_cstr = sinkId.Utf8().c_str();
    }

    if (source.IsMediaStream()) {
      blink::WebMediaStream media_stream = source.GetAsMediaStream();
      return reinterpret_cast<blink::WebMediaPlayer *>(callbacks_.createMediaPlayerStream(
        peer_,  
        static_cast<blink::MediaStreamDescriptor*>(media_stream),
        playerClient, 
        encClient, 
        mod, 
        sink_id_cstr,
        layer_tree_view));
    }

    blink::WebString url = source.GetAsURL().GetString();
    return reinterpret_cast<blink::WebMediaPlayer *>(callbacks_.createMediaPlayer(
      peer_,  
      url.Utf8().c_str(),
      playerClient, 
      encClient, 
      mod, 
      sink_id_cstr,
      layer_tree_view));
  }

  blink::WebMediaSession* CreateMediaSession() override { 
    return reinterpret_cast<blink::WebMediaSession *>(callbacks_.createMediaSession(peer_));
  }

  std::unique_ptr<blink::WebApplicationCacheHost> CreateApplicationCacheHost(blink::WebApplicationCacheHostClient* client) override {
    return std::unique_ptr<blink::WebApplicationCacheHost>(reinterpret_cast<blink::WebApplicationCacheHost *>(callbacks_.createApplicationCacheHost(peer_, client)));
  }

  std::unique_ptr<blink::WebServiceWorkerProvider> CreateServiceWorkerProvider() override {
    // auto* ptr = callbacks_.createServiceWorkerProvider(peer_);
    // if (ptr) {
    //   return std::unique_ptr<blink::WebServiceWorkerProvider>(reinterpret_cast<blink::WebServiceWorkerProvider *>(ptr));
    // }
    //application::ApplicationThread* app_thread = application::ApplicationThread::current();
    //DCHECK(app_thread);
    blink::WebLocalFrame* frame = reinterpret_cast<blink::WebLocalFrame *>(callbacks_.getCurrentLocalFrame(peer_));
    DCHECK(frame);
    blink::WebDocumentLoader* loader = frame->GetDocumentLoader(); 
    DCHECK(loader);
    DCHECK(loader->GetServiceWorkerNetworkProvider());
    // if (!loader->GetServiceWorkerNetworkProvider()) {
    //   std::unique_ptr<blink::WebServiceWorkerNetworkProvider> provider(reinterpret_cast<blink::WebServiceWorkerNetworkProvider *>(callback_->createServiceWorkerNetworkProvider()));
    //   loader->SetServiceWorkerNetworkProvider(std::move(provider));
    // }
    WebServiceWorkerNetworkProviderImpl* provider = static_cast<WebServiceWorkerNetworkProviderImpl*>(loader->GetServiceWorkerNetworkProvider());//application::ServiceWorkerNetworkProvider::FromWebServiceWorkerNetworkProvider(loader->GetServiceWorkerNetworkProvider());
    DCHECK(provider);
    if (!provider->context()) {
      // The context can be null when the frame is sandboxed.
      return nullptr;
    }
    return std::make_unique<application::WebServiceWorkerProviderImpl>(provider->context());
  }

  // blink::WebWorkerContentSettingsClientProxy* CreateWorkerContentSettingsClientProxy() override {
  //   return reinterpret_cast<blink::WebWorkerContentSettingsClientProxy *>(callbacks_.createWorkerContentSettingsClientProxy(peer_));
  // }

  std::unique_ptr<blink::WebWorkerFetchContext> CreateWorkerFetchContext() override {
    
   // DCHECK(false);
    
    blink::WebLocalFrame* frame = reinterpret_cast<blink::WebLocalFrame *>(callbacks_.getCurrentLocalFrame(peer_));

    blink::WebServiceWorkerNetworkProvider* web_provider =
      frame->GetDocumentLoader()->GetServiceWorkerNetworkProvider();
    DCHECK(web_provider);
    //application::ServiceWorkerNetworkProvider* provider =
    //  application::ServiceWorkerNetworkProvider::FromWebServiceWorkerNetworkProvider(
    //        web_provider);
    WebServiceWorkerNetworkProviderImpl* provider = static_cast<WebServiceWorkerNetworkProviderImpl*>(web_provider);
    common::mojom::ServiceWorkerWorkerClientRequest service_worker_client_request;
    common::mojom::ServiceWorkerContainerHostPtrInfo container_host_ptr_info;
    application::ServiceWorkerProviderContext* provider_context = provider->context();
    // Some sandboxed iframes are not allowed to use service worker so don't have
    // a real service worker provider, so the provider context is null.
    if (provider_context) {
      service_worker_client_request =
          provider_context->CreateWorkerClientRequest();
      // TODO(horo): Use this host pointer also when S13nServiceWorker is not
      // enabled once we support navigator.serviceWorker on dedicated workers:
      // crbug.com/371690. Currently we use this only to call
      // GetControllerServiceWorker() from the worker thread if S13nServiceWorker
      // is enabled.
      if (common::ServiceWorkerUtils::IsServicificationEnabled())
        container_host_ptr_info = provider_context->CloneContainerHostPtrInfo();
    }

    application::ApplicationThread* render_thread = application::ApplicationThread::current();
    std::unique_ptr<network::SharedURLLoaderFactoryInfo>
        direct_network_loader_factory_info;
    // Could be null in tests.
    if (render_thread) {
      direct_network_loader_factory_info =
          base::MakeRefCounted<common::PossiblyAssociatedWrapperSharedURLLoaderFactory>(
              render_thread->blink_platform()
                  ->CreateNetworkURLLoaderFactory())
              ->Clone();
    }
    
    scoped_refptr<application::ChildURLLoaderFactoryBundle> url_loader_factory_bundle = 
      render_thread->window_dispatcher()->loader_factories();

    std::unique_ptr<application::WorkerFetchContextImpl> worker_fetch_context =
        std::make_unique<application::WorkerFetchContextImpl>(
            std::move(service_worker_client_request),
            std::move(container_host_ptr_info), url_loader_factory_bundle->Clone(),
            std::move(direct_network_loader_factory_info),
            std::make_unique<application::URLLoaderThrottleProviderImpl>(application::URLLoaderThrottleProviderType::kWorker),
            std::make_unique<application::WebSocketHandshakeThrottleProviderImpl>(),
            render_thread->thread_safe_sender(),
            render_thread->window_dispatcher());

    //worker_fetch_context->set_parent_frame_id(routing_id_);
    worker_fetch_context->set_parent_frame_id(callbacks_.getRoutingId(peer_));
    worker_fetch_context->set_site_for_cookies(
        frame->GetDocument().SiteForCookies());
    worker_fetch_context->set_is_secure_context(
        frame->GetDocument().IsSecureContext());
    worker_fetch_context->set_service_worker_provider_id(provider->ProviderID());
    worker_fetch_context->set_is_controlled_by_service_worker(
        provider->HasControllerServiceWorker());
    worker_fetch_context->set_origin_url(
        GURL(frame->GetDocument().Url().GetString().Utf8()).GetOrigin());
    
    //for (auto& observer : observers_)
    //  observer.WillCreateWorkerFetchContext(worker_fetch_context.get());
    
    return worker_fetch_context;
  }

  blink::WebExternalPopupMenu* CreateExternalPopupMenu(const blink::WebPopupMenuInfo& info, blink::WebExternalPopupMenuClient* client) override {
    return reinterpret_cast<blink::WebExternalPopupMenu *>(callbacks_.createExternalPopupMenu(peer_, 
      info.item_height,
      info.item_font_size,
      info.selected_index,
      info.right_aligned,
      info.allow_multiple_selection, 
      client));
  }

  blink::WebCookieJar* CookieJar() override {
    return reinterpret_cast<blink::WebCookieJar *>(callbacks_.cookieJar(peer_));
  }

  blink::BlameContext* GetFrameBlameContext() override { 
    return frame_blame_context_.get();//reinterpret_cast<blink::BlameContext *>(callbacks_.frameBlameContext(peer_));
  }

  service_manager::InterfaceProvider* GetInterfaceProvider() override {
    application::ApplicationThread* app_thread = application::ApplicationThread::current();
    DCHECK(app_thread);
    return app_thread->GetRemoteInterfaces();
  }

  blink::AssociatedInterfaceProvider* GetRemoteNavigationAssociatedInterfaces() override {
    application::ApplicationThread* app_thread = application::ApplicationThread::current();
    DCHECK(app_thread);
    return app_thread->GetRemoteAssociatedInterfaces();
  }

  bool CanCreatePluginWithoutRenderer(const blink::WebString& mimeType) override {
    return callbacks_.canCreatePluginWithoutRenderer(peer_, mimeType.Utf8().c_str());
  }

  void DidAccessInitialDocument() override { 
    callbacks_.didAccessInitialDocument(peer_);
  }

  blink::WebLocalFrame* CreateChildFrame(
    blink::WebLocalFrame* parent, 
    blink::WebTreeScopeType type, 
    const blink::WebString& frameName,
    const blink::WebString& fallback_name,
    blink::WebSandboxFlags sandboxFlags,
    const blink::ParsedFeaturePolicy& container_policy,
    const blink::WebFrameOwnerProperties& props) override { 
    return reinterpret_cast<blink::WebLocalFrame *>(callbacks_.createChildFrame(peer_, 
      parent,
      static_cast<WebTreeScopeEnum>(type),
      frameName.Utf8().c_str(),
      fallback_name.Utf8().c_str(),
      static_cast<WebSandboxFlagsEnum>(sandboxFlags),
      static_cast<WebScrollingModeEnum>(props.scrolling_mode), 
      props.margin_width, 
      props.margin_height,
      props.allow_fullscreen,
      props.allow_payment_request,
      props.is_display_none));
  }

  blink::WebFrame* FindFrame(const blink::WebString& name) override {
    return reinterpret_cast<blink::WebFrame *>(callbacks_.findFrame(peer_, name.Utf8().c_str()));
  }

  void DidChangeOpener(blink::WebFrame* frame) override { 
    callbacks_.didChangeOpener(peer_, frame);
  }

  void FrameDetached(blink::WebFrameClient::DetachType type) override { 
    callbacks_.frameDetached(peer_, static_cast<WebDetachEnum>(type));
  }

  void FrameFocused() override { 
    callbacks_.frameFocused(peer_);
  }

  void WillCommitProvisionalLoad() override {
    callbacks_.willCommitProvisionalLoad(peer_);
  }

  // void WillClose(blink::WebFrame* frame) override {
  //   callbacks_.willClose(peer_, frame);
  // }

  void DidChangeName(const blink::WebString& name) override {
    callbacks_.didChangeName(peer_, name.Utf8().c_str());
  }

  // void DidChangeSandboxFlags(blink::WebFrame* childFrame, blink::WebSandboxFlags flags) override {
  //   callbacks_.didChangeSandboxFlags(peer_, childFrame, static_cast<WebSandboxFlagsEnum>(flags));
  // }

  // This frame has set an insecure request policy.
  void DidEnforceInsecureRequestPolicy(blink::WebInsecureRequestPolicy) override {
    callbacks_.didEnforceInsecureRequestPolicy(peer_);
  }

  // This frame has set an upgrade insecure navigations set.
  void DidEnforceInsecureNavigationsSet(const std::vector<unsigned>&) override {
    callbacks_.didEnforceInsecureNavigationsSet(peer_);
  }
  // The sandbox flags or shell policy have changed for a child frame of
  // this frame.
  void DidChangeFramePolicy(
      blink::WebFrame* child_frame,
      blink::WebSandboxFlags flags,
      const blink::ParsedFeaturePolicy& container_policy) override {
    callbacks_.didChangeFramePolicy(peer_, child_frame, static_cast<WebSandboxFlagsEnum>(flags));
  }

  // Called when a Feature-Policy or Content-Security-Policy HTTP header (for
  // sandbox flags) is encountered while loading the frame's document.
  void DidSetFramePolicyHeaders(
      blink::WebSandboxFlags flags,
      const blink::ParsedFeaturePolicy& parsed_header) override {
    callbacks_.didSetFramePolicyHeaders(peer_);
  }

  // Called when a new Content Security Policy is added to the frame's
  // document.  This can be triggered by handling of HTTP headers, handling
  // of <meta> element, or by inheriting CSP from the parent (in case of
  // about:blank).
  void DidAddContentSecurityPolicies(
      const blink::WebVector<blink::WebContentSecurityPolicy>& policies) override {
   callbacks_.didAddContentSecurityPolicies(peer_);
  }

  void DidChangeFrameOwnerProperties(blink::WebFrame* childFrame, const blink::WebFrameOwnerProperties& props) override {
    callbacks_.didChangeFrameOwnerProperties(peer_, 
      childFrame,
      static_cast<WebScrollingModeEnum>(props.scrolling_mode), 
      props.margin_width, 
      props.margin_height);
  }

  void DidMatchCSS(const blink::WebVector<blink::WebString>& newlyMatchingSelectors, const blink::WebVector<blink::WebString>& stoppedMatchingSelectors) override {
    const char* newly[newlyMatchingSelectors.size()];
    const char* stopped[stoppedMatchingSelectors.size()]; 

    for (size_t i = 0; i < newlyMatchingSelectors.size(); i++) {
      newly[i] = newlyMatchingSelectors[i].Utf8().c_str();
    }

    for (size_t i = 0; i < stoppedMatchingSelectors.size(); i++) {
      stopped[i] = stoppedMatchingSelectors[i].Utf8().c_str();
    }

    callbacks_.didMatchCSS(peer_, 
      newly, 
      newlyMatchingSelectors.size(), 
      stopped, 
      stoppedMatchingSelectors.size());
  }

  // Called the first time this frame is the target of a user gesture.
  void SetHasReceivedUserGesture() override {
     callbacks_.setHasReceivedUserGesture(peer_);
  }

  // Called if the previous document had a user gesture and is on the same
  // eTLD+1 as the current document.
  void SetHasReceivedUserGestureBeforeNavigation(bool value) override {
    callbacks_.setHasReceivedUserGestureBeforeNavigation(peer_, value ? 1 : 0);
  }

  bool ShouldReportDetailedMessageForSource(const blink::WebString& source) override {
    return callbacks_.shouldReportDetailedMessageForSource(peer_, source.Utf8().c_str());
  }

  void DidAddMessageToConsole(const blink::WebConsoleMessage& message, const blink::WebString& sourceName, unsigned sourceLine, const blink::WebString& stackTrace) override {
    callbacks_.didAddMessageToConsole(peer_,
      static_cast<WebConsoleMessageLevelEnum>(message.level), 
      message.text.Utf8().c_str(),
      sourceName.Utf8().c_str(),
      sourceLine,
      stackTrace.Utf8().c_str());
  }

  void DownloadURL(const blink::WebURLRequest& url_request) override {
    WebURLRequestWrapper req(url_request);
    callbacks_.downloadURL(peer_, &req);
  }

  void LoadErrorPage(int reason) override {
    callbacks_.loadErrorPage(peer_, reason);
  }

  // void LoadURLExternally(const blink::WebURLRequest& url, blink::WebNavigationPolicy policy, const blink::WebString& downloadName, bool shouldReplaceCurrentEntry) override {
  //   callbacks_.loadURLExternally(peer_, const_cast<blink::WebURLRequest *>(&url), static_cast<WebNavigationPolicyEnum>(policy), downloadName.utf8().c_str(), shouldReplaceCurrentEntry);
  // }

  blink::WebNavigationPolicy DecidePolicyForNavigation(const NavigationPolicyInfo& info) override {
    return static_cast<blink::WebNavigationPolicy>(callbacks_.decidePolicyForNavigation(peer_, 
      info.extra_data,
      &info.url_request,
      static_cast<WebNavigationTypeEnum>(info.navigation_type),
      static_cast<WebNavigationPolicyEnum>(info.default_policy),
      info.replaces_current_history_item));
  }

  bool AllowContentInitiatedDataUrlNavigations(const blink::WebURL& url) override {
    return callbacks_.allowContentInitiatedDataUrlNavigations(peer_, url.GetString().Utf8().c_str()) == 1  ? true : false;
  }

  // blink::WebHistoryItem HistoryItemForNewChildFrame(blink::WebFrame* frame) override { 
  //   blink::WebHistoryItem* handle = reinterpret_cast<blink::WebHistoryItem *>(callbacks_.historyItemForNewChildFrame(peer_, frame));
  //   if (handle) {
  //     return *handle;
  //   }
  //   return blink::WebHistoryItem();
  // }

  // bool HasPendingNavigation(blink::WebLocalFrame* frame) override { 
  //   return callbacks_.hasPendingNavigation(peer_, frame);
  // }

  void DidStartLoading(bool toDifferentDocument) override {
    callbacks_.didStartLoading(peer_, toDifferentDocument);
  }
  
  void DidStopLoading() override { 
    callbacks_.didStopLoading(peer_);
  }

  void DidChangeLoadProgress(double loadProgress) override { 
    callbacks_.didChangeLoadProgress(peer_, loadProgress);
  }

  void WillSendSubmitEvent(const blink::WebFormElement& elem) override { 
    WebNodeWrapper formElem(elem);
    callbacks_.willSendSubmitEvent(peer_, &formElem);
  }

  void WillSubmitForm(const blink::WebFormElement& elem) override { 
    WebNodeWrapper formElem(elem);
    callbacks_.willSubmitForm(peer_, &formElem);
  }

  void DidCreateDocumentLoader(blink::WebDocumentLoader* dl) override {
    callbacks_.didCreateDocumentLoader(peer_, dl);
  }
  
  // void DidCreateDataSource(blink::WebLocalFrame* frame, blink::WebDataSource* ds) override { 
  //   callbacks_.didCreateDataSource(peer_, frame, ds);
  // }

  void DidStartProvisionalLoad(blink::WebDocumentLoader* document_loader, blink::WebURLRequest& request) override { 
    WebURLRequestWrapper req(request);
    callbacks_.didStartProvisionalLoad(peer_, document_loader, &req);
  }

  void DidReceiveServerRedirectForProvisionalLoad() override { 
    callbacks_.didReceiveServerRedirectForProvisionalLoad(peer_);
  }

  void DidFailProvisionalLoad(const blink::WebURLError& err, blink::WebHistoryCommitType type) override { 
    callbacks_.didFailProvisionalLoad(peer_, 
      err.url().GetString().Utf8().c_str(),
      err.reason(),
      err.has_copy_in_cache(),
      err.is_web_security_violation(),
      //err.was_ignored_by_handler,
     // err.unreachable_url.GetString().Utf8().c_str(),
     // err.localizedDescription.Utf8().c_str(),
      static_cast<WebHistoryCommitEnum>(type));
  }

  void DidCommitProvisionalLoad(const blink::WebHistoryItem& item, blink::WebHistoryCommitType type,
    blink::WebGlobalObjectReusePolicy policy) override { 
    callbacks_.didCommitProvisionalLoad(peer_, 
      const_cast<blink::WebHistoryItem *>(&item),
      static_cast<WebHistoryCommitEnum>(type));
  }

  void DidCreateNewDocument() override { 
    callbacks_.didCreateNewDocument(peer_);
  }

  void DidClearWindowObject() override { 
    callbacks_.didClearWindowObject(peer_);
  }

  void DidCreateDocumentElement() override { 
    callbacks_.didCreateDocumentElement(peer_);
  }

  void RunScriptsAtDocumentElementAvailable() override {
    callbacks_.runScriptsAtDocumentElementAvailable(peer_);
  }

  void DidReceiveTitle(const blink::WebString& title, blink::WebTextDirection direction) override { 
    callbacks_.didReceiveTitle(peer_, title.Utf16().data(), title.length(), static_cast<WebTextDirectionEnum>(direction));
  }

  void DidChangeIcon(blink::WebIconURL::Type type) override { 
    callbacks_.didChangeIcon(peer_, static_cast<WebIconURLEnum>(type));
  }

  void DidFinishDocumentLoad() override { 
    callbacks_.didFinishDocumentLoad(peer_);
  }

  void RunScriptsAtDocumentReady(bool document_is_empty) override {
    callbacks_.runScriptsAtDocumentReady(peer_, document_is_empty ? 1 : 0);
  }

  // The frame's window.onload event is ready to fire. This method may delay
  // window.onload by incrementing LoadEventDelayCount.
  void RunScriptsAtDocumentIdle() override {
    callbacks_.runScriptsAtDocumentIdle(peer_);
  }

  void DidHandleOnloadEvents() override { 
    callbacks_.didHandleOnloadEvents(peer_);
  }

  void DidFailLoad(const blink::WebURLError& err, blink::WebHistoryCommitType type) override { 
    callbacks_.didFailLoad(
      peer_, 
      err.url().GetString().Utf8().c_str(),
      err.reason(),
      err.has_copy_in_cache(),
      err.is_web_security_violation(),
     // err.was_ignored_by_handler,
     // err.unreachable_url.GetString().Utf8().c_str(),
      //err.localized_description.Utf8().c_str(),
      static_cast<WebHistoryCommitEnum>(type));
  }

  void DidFinishLoad() override { 
    callbacks_.didFinishLoad(peer_);
  }

  void DidNavigateWithinPage(const blink::WebHistoryItem& item, 
    blink::WebHistoryCommitType type,
    bool content_initiated) override { 
    callbacks_.didNavigateWithinPage(peer_, const_cast<blink::WebHistoryItem *>(&item), static_cast<WebHistoryCommitEnum>(type), content_initiated ? 1 : 0);
  }

  void DidUpdateCurrentHistoryItem() override { 
    callbacks_.didUpdateCurrentHistoryItem(peer_);
  }

  void DidChangeManifest() override { 
    callbacks_.didChangeManifest(peer_);
  }

  void DidChangeThemeColor() override { 
    callbacks_.didChangeThemeColor(peer_);
  }

  void ForwardResourceTimingToParent(const blink::WebResourceTimingInfo& info) override {
    callbacks_.forwardResourceTimingToParent(peer_);
  }

  void DispatchLoad() override {
    callbacks_.dispatchLoad(peer_);
  }

  blink::WebEffectiveConnectionType GetEffectiveConnectionType() override {
    return static_cast<blink::WebEffectiveConnectionType>(callbacks_.getEffectiveConnectionType(peer_));
  }

  blink::WebURLRequest::PreviewsState GetPreviewsStateForFrame() const override {
    return static_cast<blink::WebURLRequest::PreviewsState>(callbacks_.getPreviewsStateForFrame(peer_));
  }

  void DidBlockFramebust(const blink::WebURL& url) override {
    callbacks_.didBlockFramebust(peer_, url.GetString().Utf8().c_str());
  }

  void AbortClientNavigation() override {
    callbacks_.abortClientNavigation(peer_);
  }
  // void RequestNotificationPermission(const blink::WebSecurityOrigin& origin, blink::WebNotificationPermissionCallback* callback) override { 
  //   WebSecurityOriginWrapper wrapper(PassRefPtrWillBeRawPtr<blink::SecurityOrigin>(const_cast<blink::WebSecurityOrigin &>(origin)));
  //   callbacks_.requestNotificationPermission(peer_, &wrapper, callback);
  // }

  blink::WebPushClient* PushClient() override { 
    return reinterpret_cast<blink::WebPushClient *>(callbacks_.pushClient(peer_));
  }

  // blink::WebPresentationClient* PresentationClient() override {
  //   return reinterpret_cast<blink::WebPresentationClient *>(callbacks_.presentationClient(peer_));
  // }
  
  void DidChangeSelection(bool isSelectionEmpty) override {
    callbacks_.didChangeSelection(peer_, isSelectionEmpty);
  }

  void DidChangeContents() override {
    callbacks_.didChangeContents(peer_);
  }

  // blink::WebColorChooser* CreateColorChooser(
  //     blink::WebColorChooserClient* client,
  //     const blink::WebColor& color,
  //     const blink::WebVector<blink::WebColorSuggestion>& suggestions) override {
    
  //   return reinterpret_cast<blink::WebColorChooser *>(callbacks_.createColorChooser(peer_, 
  //     client, 
  //     color));
  // }

  bool HandleCurrentKeyboardEvent() override {
    return callbacks_.handleCurrentKeyboardEvent(peer_) == 1 ? true : false;
  }

  void RunModalAlertDialog(const blink::WebString& message) override {
    callbacks_.runModalAlertDialog(peer_, message.Utf8().c_str());
  }

  bool RunModalConfirmDialog(const blink::WebString& message) override {
    return callbacks_.runModalConfirmDialog(peer_, message.Utf8().c_str());
  }

  bool RunModalPromptDialog(
      const blink::WebString& message, const blink::WebString& defaultValue,
      blink::WebString* actualValue) override {
    const char* actual;
    int result = callbacks_.runModalPromptDialog(peer_, message.Utf8().c_str(), defaultValue.Utf8().c_str(), &actual);
    *actualValue = blink::WebString::FromUTF8(actual);
    return result == 0 ? false : true;
  }

  bool RunModalBeforeUnloadDialog(
      bool isReload) override {
    return callbacks_.runModalBeforeUnloadDialog(peer_, isReload) == 0 ? false : true;    
  }

  bool RunFileChooser(const blink::WebFileChooserParams& params,
                      blink::WebFileChooserCompletion* completion) override { 
    
    const char* accept[params.accept_types.size()];
    const char* selected[params.selected_files.size()]; 

    for (size_t i = 0; i < params.accept_types.size(); i++) {
      accept[i] = params.accept_types[i].Utf8().c_str();
    }

    for (size_t i = 0; i < params.selected_files.size(); i++) {
      selected[i] = params.selected_files[i].Utf8().c_str();
    }

    return callbacks_.runFileChooser(peer_,
      params.multi_select,
      params.directory,
      params.save_as,
      params.title.Utf8().c_str(),
      //params.initial_value.Utf8().c_str(),
      accept,
      selected,
      params.capture.Utf8().c_str(),
      params.use_media_capture,
      params.need_local_path,
      params.requestor.GetString().Utf8().c_str(), 
      completion); 
  }

  void ShowContextMenu(const blink::WebContextMenuData& data) override {
    callbacks_.showContextMenu(peer_, const_cast<blink::WebContextMenuData *>(&data));
  }

  void SaveImageFromDataURL(const blink::WebString& url) override {
    callbacks_.saveImageFromDataURL(peer_, url.Utf8().c_str());
  }

  // void ClearContextMenu() override {
  //   callbacks_.clearContextMenu(peer_);
  // }

  void FrameRectsChanged(const blink::WebRect& rect) override {
    callbacks_.frameRectsChanged(peer_, rect.x, rect.y, rect.width, rect.height);
  }

  void WillSendRequest(
      blink::WebURLRequest& req) override {
    WebURLRequestWrapper request(req);
    callbacks_.willSendRequest(peer_, &request); 
  }

  void DidReceiveResponse(
      const blink::WebURLResponse& resp) override {
    callbacks_.didReceiveResponse(peer_, const_cast<blink::WebURLResponse *>(&resp));    
  }

  // void DidChangeResourcePriority(
  //     blink::WebLocalFrame* webFrame, unsigned identifier, const blink::WebURLRequest::Priority& priority, int n) override {
  //   callbacks_.didChangeResourcePriority(peer_, webFrame, identifier, static_cast<WebURLRequestPriorityEnum>(priority), n);
  // }

  // void DidFinishResourceLoad(
  //     blink::WebLocalFrame* frame, unsigned identifier) override {
  //   callbacks_.didFinishResourceLoad(peer_, frame, identifier);
  // }

  void DidLoadResourceFromMemoryCache(
      const blink::WebURLRequest& req, const blink::WebURLResponse& resp) override {
    WebURLRequestWrapper request(req);
    callbacks_.didLoadResourceFromMemoryCache(peer_, &request, const_cast<blink::WebURLResponse *>(&resp)); 
  }

  void DidDisplayInsecureContent() override {
    callbacks_.didDisplayInsecureContent(peer_);
  }

  void DidContainInsecureFormAction() override {
    callbacks_.didContainInsecureFormAction(peer_);
  }

  void DidRunInsecureContent(const blink::WebSecurityOrigin& origin, const blink::WebURL& insecureURL) override {
    WebSecurityOriginWrapper wrapper(const_cast<blink::SecurityOrigin *>(origin.Get()));

    callbacks_.didRunInsecureContent(
      peer_, 
      &wrapper, 
      insecureURL.GetString().Utf8().c_str());
  }

  void DidDetectXSS(const blink::WebURL& url, bool didBlockEntirePage) override {
    callbacks_.didDetectXSS(peer_, url.GetString().Utf8().c_str(), didBlockEntirePage);
  }

  void DidDispatchPingLoader(const blink::WebURL& url) override {
    callbacks_.didDispatchPingLoader(peer_, url.GetString().Utf8().c_str());
  }

  void DidDisplayContentWithCertificateErrors() override {
    callbacks_.didDisplayContentWithCertificateErrors(peer_);
  }
  // This frame has run active content (such as a script) from a
  // connection with certificate errors.
  void DidRunContentWithCertificateErrors() override {
    callbacks_.didRunContentWithCertificateErrors(peer_);
  }
  
  void DidChangePerformanceTiming() override {
    callbacks_.didChangePerformanceTiming(peer_);
  }

  // void DidAbortLoading(blink::WebLocalFrame* frame) override {
  //   callbacks_.didAbortLoading(peer_, frame);
  // }

  void DidObserveLoadingBehavior(blink::WebLoadingBehaviorFlag) override {

  }

  bool ShouldTrackUseCounter(const blink::WebURL&) override {
    return false;
  }

  void DidObserveNewFeatureUsage(blink::WebFeature) override {

  }

  void DidObserveNewCssPropertyUsage(int /*css_property*/,
                                             bool /*is_animated*/) override {

  }

  void DidCreateScriptContext(v8::Local<v8::Context> context, int worldId) override {
    v8::Isolate* isolate = v8::Isolate::GetCurrent();  
    mumba::V8Context v8context(isolate, context);
    callbacks_.didCreateScriptContext(peer_, &v8context, worldId);
  }

  void WillReleaseScriptContext(v8::Local<v8::Context> context, int worldId) override {
    v8::Isolate* isolate = v8::Isolate::GetCurrent();  
    //mumba::V8Engine* engine = mumba::V8Engine::GetInstance();
    DCHECK(isolate);
    mumba::V8Context v8context(isolate, context);
    callbacks_.willReleaseScriptContext(peer_, &v8context, worldId);
  }

  void DidChangeScrollOffset() override {
    callbacks_.didChangeScrollOffset(peer_);
  }

  void WillInsertBody() override { 
    callbacks_.willInsertBody(peer_);
  }

  void DraggableRegionsChanged() override {
    callbacks_.draggableRegionsChanged(peer_);
  }

  // Scrolls a local frame in its remote process. Called on the WebFrameClient
  // of a local frame only.
  void ScrollRectToVisibleInParentFrame(
      const blink::WebRect& rect,
      const blink::WebScrollIntoViewParams& params) override {
    // TODO: pass WebScrollIntoViewParams
    callbacks_.scrollRectToVisibleInParentFrame(peer_, rect.x, rect.y, rect.width, rect.height);
  }

  void ReportFindInPageMatchCount(
      int identifier, int count, bool finalUpdate) override {
    callbacks_.reportFindInPageMatchCount(peer_, identifier, count, finalUpdate);
  }

  // void ReportFindInFrameMatchCount(
  //       int identifier, int count, bool finalUpdate) override {
  //   callbacks_.reportFindInFrameMatchCount(peer_, identifier, count, finalUpdate);    
  // }

  void ReportFindInPageSelection(
        int identifier, int activeMatchOrdinal, const blink::WebRect& selection) override { 
    callbacks_.reportFindInPageSelection(peer_, 
      identifier, 
      activeMatchOrdinal, 
      selection.x,
      selection.y,
      selection.width,
      selection.height);
  }

  // bool ShouldSearchSingleFrame() override {
  //   return callbacks_.shouldSearchSingleFrame(peer_);
  // }

  // void RequestStorageQuota(
  //       blink::WebLocalFrame* frame, 
  //       blink::WebStorageQuotaType type,
  //       unsigned long long newQuotaInBytes,
  //       blink::WebStorageQuotaCallbacks cbs) override { 
    
  //   callbacks_.requestStorageQuota(peer_, 
  //     frame, 
  //     static_cast<WebStorageQuotaTypeEnum>(type), 
  //     newQuotaInBytes,
  //     &cbs);
  // }

  // void WillOpenWebSocket(blink::WebSocketHandle* handle) override {
  //   callbacks_.willOpenWebSocket(peer_, handle);
  // }

  // blink::WebWakeLockClient* WakeLockClient() override {
  //   return reinterpret_cast<blink::WebWakeLockClient *>(callbacks_.wakeLockClient(peer_));
  // }

  // blink::WebGeolocationClient* GeolocationClient() override {
  //   return reinterpret_cast<blink::WebGeolocationClient *>(callbacks_.geolocationClient(peer_));
  // }

  void WillStartUsingPeerConnectionHandler(blink::WebRTCPeerConnectionHandler* handler) override {
    callbacks_.willStartUsingPeerConnectionHandler(peer_, handler);
  }

  blink::WebUserMediaClient* UserMediaClient() override {
    return reinterpret_cast<blink::WebUserMediaClient *>(callbacks_.userMediaClient(peer_));
  }

  blink::WebEncryptedMediaClient* EncryptedMediaClient() override {
    return reinterpret_cast<blink::WebEncryptedMediaClient *>(callbacks_.encryptedMediaClient(peer_));
  }

  // blink::WebMIDIClient* WebMIDIClient() override {
  //   return reinterpret_cast<blink::WebMIDIClient *>(callbacks_.webMIDIClient(peer_));
  // }

  // bool WillCheckAndDispatchMessageEvent(
  //     blink::WebLocalFrame* sourceFrame,
  //     blink::WebFrame* targetFrame,
  //     blink::WebSecurityOrigin target,
  //     blink::WebDOMMessageEvent event) override { 
    
  //   WebSecurityOriginWrapper wrapper(PassRefPtrWillBeRawPtr<blink::SecurityOrigin>(const_cast<blink::WebSecurityOrigin &>(target)));

  //   return callbacks_.willCheckAndDispatchMessageEvent(peer_, sourceFrame, targetFrame, &wrapper, const_cast<blink::WebDOMMessageEvent *>(&event)); 
  // }

  blink::WebString UserAgentOverride()  override {
    const char* buf = callbacks_.userAgentOverride(peer_); 
    return buf ? blink::WebString::FromUTF8(buf) : blink::WebString();
  }

  blink::WebString DoNotTrackValue() override {
    return blink::WebString::FromUTF8(callbacks_.doNotTrackValue(peer_));
  }

  bool ShouldBlockWebGL() override { 
    return callbacks_.shouldBlockWebGL(peer_);
  }

  // bool AllowWebGL(blink::WebLocalFrame* frame, bool defaultValue) override {
  //   return callbacks_.allowWebGL(peer_, frame, defaultValue);
  // }

  // void DidLoseWebGLContext(blink::WebLocalFrame* frame, int context) override {
  //   callbacks_.didLoseWebGLContext(peer_, frame, context);
  // }

  // blink::WebScreenOrientationClient* WebScreenOrientationClient() override {
  //   return reinterpret_cast<blink::WebScreenOrientationClient *>(callbacks_.webScreenOrientationClient(peer_));
  // }

  void PostAccessibilityEvent(const blink::WebAXObject& obj, blink::WebAXEvent event) override {
    // FIX: turned off right now, given we dont have access to this
    // when is a shared dll build

    //WebAXObjectWrapper axobj(obj);
    //callbacks_.postAccessibilityEvent(peer_, &axobj, static_cast<WebAXEventEnum>(event));
  }

  void HandleAccessibilityFindInPageResult(
      int identifier,
      int matchIndex,
      const blink::WebNode& startObject,
      int startOffset,
      const blink::WebNode& endObject,
      int endOffset) override {
    WebNodeWrapper axStart(startObject);
    WebNodeWrapper axEnd(endObject);
    callbacks_.handleAccessibilityFindInPageResult(peer_, identifier, matchIndex, &axStart, startOffset, &axEnd, endOffset);
  }

  // bool IsControlledByServiceWorker(blink::WebDataSource& source) override {
  //   return callbacks_.isControlledByServiceWorker(peer_, &source);
  // }

  // int64_t ServiceWorkerID(blink::WebDataSource& source) override {
  //   return callbacks_.serviceWorkerID(peer_, const_cast<blink::WebDataSource *>(&source));
  // }

  void EnterFullscreen(const blink::WebFullscreenOptions& options) override {
    callbacks_.enterFullscreen(peer_);
  }

  void ExitFullscreen() override {
    callbacks_.exitFullscreen(peer_);
  }

  void SuddenTerminationDisablerChanged(bool present, blink::WebSuddenTerminationDisablerType type) override { 
    callbacks_.suddenTerminationDisablerChanged(peer_, present, static_cast<WebSuddenTerminationDisablerTypeEnum>(type));
  }

  // blink::WebPermissionClient* PermissionClient() override {
  //   return reinterpret_cast<blink::WebPermissionClient *>(callbacks_.permissionClient(peer_));
  // }

  // blink::WebVRClient* WebVRClient() override {
  //   return reinterpret_cast<blink::WebVRClient *>(callbacks_.webVRClient(peer_));
  // }

  // blink::WebAppBannerClient* AppBannerClient() override { 
  //   return reinterpret_cast<blink::WebAppBannerClient *>(callbacks_.appBannerClient(peer_));
  // }

  void RegisterProtocolHandler(const blink::WebString& scheme,
      const blink::WebURL& url,
      const blink::WebString& title) override { 
    callbacks_.registerProtocolHandler(peer_, scheme.Utf8().c_str(), url.GetString().Utf8().c_str(), title.Utf8().c_str());  
  }

  void UnregisterProtocolHandler(const blink::WebString& scheme, const blink::WebURL& url) override { 
    callbacks_.unregisterProtocolHandler(peer_, scheme.Utf8().c_str(), url.GetString().Utf8().c_str());
  }

  // blink::WebCustomHandlersState IsProtocolHandlerRegistered(const blink::WebString& scheme, const blink::WebURL& url) override {
  //   return static_cast<blink::WebCustomHandlersState>(callbacks_.isProtocolHandlerRegistered(peer_, scheme.utf8().c_str(), url.string().utf8().c_str()));
  // }

  // blink::WebBluetooth* bluetooth() override {
  //   return reinterpret_cast<blink::WebBluetooth *>(callbacks_.bluetooth(peer_));
  // }

  // blink::WebUSBClient* UsbClient() override {
  //   return reinterpret_cast<blink::WebUSBClient *>(callbacks_.usbClient(peer_));
  // }

  void CheckIfAudioSinkExistsAndIsAuthorized(
      const blink::WebString& sink_id,
      blink::WebSetSinkIdCallbacks* callbacks) override {
    if (callbacks) {
      callbacks->OnError(blink::WebSetSinkIdError::kNotSupported);
      delete callbacks;
    }
  }

  // Speech --------------------------------------------------------------

  // Access the embedder API for speech recognition services.
  blink::WebSpeechRecognizer* SpeechRecognizer() override { return nullptr; }

  // Visibility ----------------------------------------------------------

  // Returns the current visibility of the WebFrame.
  blink::mojom::PageVisibilityState VisibilityState() const override {
    return static_cast<blink::mojom::PageVisibilityState>(callbacks_.visibilityState(peer_));
  }

  // Overwrites the given URL to use an HTML5 embed if possible.
  // An empty URL is returned if the URL is not overriden.
  blink::WebURL OverrideFlashEmbedWithHTML(const blink::WebURL& url) override {
    return blink::WebURL();
  }

  // Loading --------------------------------------------------------------

  std::unique_ptr<blink::WebURLLoaderFactory> CreateURLLoaderFactory() override {
    //DLOG(INFO) << "WebFrameClient::CreateURLLoaderFactory()";
    //NOTREACHED();
    //return nullptr;
    application::ApplicationThread* app_thread = application::ApplicationThread::current();
    return app_thread->blink_platform()->CreateDefaultURLLoaderFactory();
  }

  // Accessibility Object Model -------------------------------------------

  // This method is used to expose the AX Tree stored in content/renderer to the
  // DOM as part of AOM Phase 4.
  blink::WebComputedAXTree* GetOrCreateWebComputedAXTree() override { return nullptr; }

  // WebSocket -----------------------------------------------------------
  std::unique_ptr<blink::WebSocketHandshakeThrottle> CreateWebSocketHandshakeThrottle() override {
    return nullptr;
  }

  // from WebRemoteFrameClient
  void FrameDetached(blink::WebRemoteFrameClient::DetachType type) override { 
    callbacks_.frameDetached(peer_, static_cast<WebDetachEnum>(type));
  }

  void CheckCompleted() override {
    callbacks_.checkCompleted(peer_);
  }

  void ForwardPostMessage(blink::WebLocalFrame* source_frame,
                          blink::WebRemoteFrame* target_frame,
                          blink::WebSecurityOrigin target_origin,
                          blink::WebDOMMessageEvent event,
                          bool has_user_gesture) override {
    WebSecurityOriginWrapper origin(const_cast<blink::SecurityOrigin *>(target_origin.Get()));
    callbacks_.forwardPostMessage(peer_, source_frame, target_frame, &origin, event, has_user_gesture ? 1 : 0);
  }

  void Navigate(const blink::WebURLRequest& request,
               bool should_replace_current_entry) override {
    WebURLRequestWrapper req(request); 
    callbacks_.navigate(peer_, &req, should_replace_current_entry ? 1 : 0);
  }

  void Reload(blink::WebFrameLoadType type, blink::ClientRedirectPolicy policy) override {
    callbacks_.reload(peer_, static_cast<WebFrameLoadTypeEnum>(type), static_cast<WebClientRedirectPolicyEnum>(policy)); 
  }

  void FrameRectsChanged(const blink::WebRect& local_frame_rect,
                         const blink::WebRect& screen_space_rect) override {
    callbacks_.frameRectsChangedRemote(
      peer_, 
      local_frame_rect.x, 
      local_frame_rect.y, 
      local_frame_rect.width, 
      local_frame_rect.height,
      screen_space_rect.x, 
      screen_space_rect.y, 
      screen_space_rect.width, 
      screen_space_rect.height);
  }

  void UpdateRemoteViewportIntersection(
    const blink::WebRect& viewport_intersection) override {
    callbacks_.updateRemoteViewportIntersection(peer_, 
      viewport_intersection.x, 
      viewport_intersection.y, 
      viewport_intersection.width, 
      viewport_intersection.height);
  }

  void VisibilityChanged(bool visible) override {
    callbacks_.visibilityChanged(peer_, visible ? 1 : 0);
  }

  void SetIsInert(bool inert) override {
    callbacks_.setIsInert(peer_, inert ? 1 : 0);
  }

  void UpdateRenderThrottlingStatus(bool is_throttled,
                                    bool subtree_throttled) override {
    callbacks_.updateRenderThrottlingStatus(peer_, is_throttled ? 1 : 0, subtree_throttled ? 1 : 0);
  }

  void AdvanceFocus(blink::WebFocusType type, blink::WebLocalFrame* source) override {
    callbacks_.advanceFocus(peer_, static_cast<WebFocusTypeEnum>(type), source);
  }

private:
   WebFrameClientCbs callbacks_;
   void*  peer_;
   std::unique_ptr<application::FrameBlameContext> frame_blame_context_;
};

class WebEventListenerImpl : public blink::EventListener {
public:  
  WebEventListenerImpl(void* state, void(*on_event)(void*,void*))://scoped_refptr<base::SingleThreadTaskRunner> task_runner, void* state, void(*on_event)(void*,void*,void*)):
    EventListener(blink::EventListener::kCPPEventListenerType),
    //task_runner_(std::move(task_runner)),
    state_(state),
    on_event_(on_event) {}
  
  ~WebEventListenerImpl() override {}

  bool operator==(const blink::EventListener& other) const override {
    return this == &other;
  }

  void handleEvent(blink::ExecutionContext* context, blink::Event* event) override {
    //DLOG(INFO) << "WebEventListenerImpl::handleEvent: this = " << this << " state_ = " << state_ << " event = " << event << " context is document? " << context->IsDocument();
    //blink::Document* document = blink::ToDocument(context);
    //DLOG(INFO) << "WebEventListenerImpl::handleEvent: document = " << document << " event = " << event ;
    //task_runner_->PostTask(FROM_HERE, base::BindOnce(on_event_, base::Unretained(state_), base::Unretained(event)));
    //on_event_(state_, document, event);
    on_event_(state_, event);
    //event->SetDefaultHandled();
  }
  
  bool BelongsToTheCurrentWorld(blink::ExecutionContext* context) const override {
    return false;
  }

private:
  //scoped_refptr<base::SingleThreadTaskRunner> task_runner_;
  void* state_;
  void(*on_event_)(void*,void*);
};

enum WebWorkerType : int {
  kWebWorkerClassic = 0,
  kWebWorkerModule = 1,
  kWebWorkerNative = 2
};

class WebWorkerShim {
public:
 WebWorkerShim(WebWorkerType type, blink::DedicatedWorker* worker, std::unique_ptr<WorkerNativeClientImpl> client, std::string url):
  type_(type),
  worker_(worker),
  client_(std::move(client)),
  url_string_(std::move(url)) {

 }

 ~WebWorkerShim() {}

  int GetThreadId() const {
    DCHECK(is_native());
    DCHECK(client_->initialized());
    return client_->thread_id();
  }

  WebWorkerType GetType() const {
    return type_;
  }

  bool is_native() const {
    return client_.get() != nullptr;
  }

  const std::string& url() const {
   return url_string_;
  }

  WorkerNativeClientImpl* client() const {
    return client_.get();
  }

  blink::WorkerGlobalScope* worker_global_scope() const {
    DCHECK(is_native());
    return client_->worker_global_scope();
  }

  blink::DedicatedWorker* worker() const {
    return worker_.Get();
  }

  void Terminate() {
    worker_->terminate();
  }

private:
 WebWorkerType type_;
 blink::Persistent<blink::DedicatedWorker> worker_;
 std::unique_ptr<WorkerNativeClientImpl> client_;
 std::string url_string_;
};

struct ScriptPromiseWrapper;

class JavascriptFunctionHandler {
public:
  v8::Isolate* isolate_;
  void* state_;
  void(*callback_)(void*);
  void(*callback1_)(void*, void*);
  void(*callback2_)(void*, void*, void*);
  ScriptPromiseWrapper* promise;
  v8::Global<v8::External> wrapper_;
  
  JavascriptFunctionHandler(v8::Isolate* isolate, void* state, void(*callback)(void*)):
    isolate_(isolate),
    state_(state),
    callback_(callback),
    callback1_(nullptr),
    callback2_(nullptr),
    promise(nullptr),
    wrapper_(isolate,
            v8::External::New(isolate, this)) {
    wrapper_.SetWeak(this, Cleanup, v8::WeakCallbackType::kParameter);
  }

  JavascriptFunctionHandler(v8::Isolate* isolate, void* state, void(*callback)(void*, void*)):
    isolate_(isolate),
    state_(state),
    callback_(nullptr),
    callback1_(callback),
    callback2_(nullptr),
    promise(nullptr),
    wrapper_(isolate,
            v8::External::New(isolate, this)) {
    wrapper_.SetWeak(this, Cleanup, v8::WeakCallbackType::kParameter);
  }

  JavascriptFunctionHandler(v8::Isolate* isolate, void* state, void(*callback)(void*, void*, void*)):
    isolate_(isolate),
    state_(state),
    callback_(nullptr),
    callback1_(nullptr),
    callback2_(callback),
    promise(nullptr),
    wrapper_(isolate,
            v8::External::New(isolate, this)) {
    wrapper_.SetWeak(this, Cleanup, v8::WeakCallbackType::kParameter);
  }

  static void Cleanup(
      const v8::WeakCallbackInfo<JavascriptFunctionHandler>& data) {
    //DLOG(INFO) << "JavascriptFunctionHandler::Cleanup";
    if (!data.GetParameter()->wrapper_.IsEmpty()) {
      data.GetParameter()->wrapper_.Reset();
      data.SetSecondPassCallback(Cleanup);
    } else {
      delete data.GetParameter();
    }
  }
  
};

struct ScriptPromiseWrapper {
  ScriptPromiseWrapper(blink::ScriptPromise p): parent(nullptr), promise(std::move(p)), handler(nullptr), reject(nullptr), handled(false), activated(false), should_be_deleted(false) {}
  ScriptPromiseWrapper(blink::ScriptPromise p, JavascriptFunctionHandler* h, JavascriptFunctionHandler* r): parent(nullptr), promise(std::move(p)), handler(h), reject(r), handled(false), activated(false), should_be_deleted(false) {
    if (h) {
      h->promise = this;
    }
    if (r) {
      r->promise = this;
    }
  }
  ScriptPromiseWrapper(ScriptPromiseWrapper* parent, blink::ScriptPromise p): parent(parent), promise(std::move(p)), handler(nullptr), reject(nullptr), handled(false), activated(false), should_be_deleted(false) {}
  ScriptPromiseWrapper(ScriptPromiseWrapper* parent, blink::ScriptPromise p, JavascriptFunctionHandler* h, JavascriptFunctionHandler* r): parent(parent), promise(std::move(p)), handler(h), reject(r), handled(false), activated(false), should_be_deleted(false) {
    if (h) {
      h->promise = this;
    }
    if (r) {
      r->promise = this;
    }
  }
  ~ScriptPromiseWrapper() {
    //DLOG(INFO) << "~ScriptPromiseWrapper: begin";
    // if (handler) {
    //   //DLOG(INFO) << "~ScriptPromiseWrapper: delete handler";
    //   delete handler;
    //   //DLOG(INFO) << "~ScriptPromiseWrapper: done delete handler";
    // }
    // if (reject) {
    //   //DLOG(INFO) << "~ScriptPromiseWrapper: delete reject";
    //   delete reject;
    //   //DLOG(INFO) << "~ScriptPromiseWrapper: done delete reject";
    // }
    // if (parent) {
    //   //DLOG(INFO) << "~ScriptPromiseWrapper: not deleting parent " << parent << " but maybe we should";
    //   //DLOG(INFO) << "~ScriptPromiseWrapper: delete parent";
    //   delete parent;
    //   //DLOG(INFO) << "~ScriptPromiseWrapper: done delete parent";
    // }
    //DLOG(INFO) << "~ScriptPromiseWrapper: end";
  }
  ScriptPromiseWrapper* parent;
  blink::ScriptPromise promise;
  JavascriptFunctionHandler* handler;
  JavascriptFunctionHandler* reject;
  bool handled;
  bool activated;
  bool should_be_deleted;
};

class ThenFunction final : public blink::ScriptFunction {
 public:
  static v8::Local<v8::Function> CreateFunction(
      blink::ScriptState* script_state,
      void* state, 
      void(*cb)(void*, void*)) {
    ThenFunction* self =
        new ThenFunction(script_state, state, cb);
    return self->BindToV8Function();
  }

  void Trace(blink::Visitor* visitor) override {
    blink::ScriptFunction::Trace(visitor);
  }

 private:
  ThenFunction(blink::ScriptState* script_state,
               void* state, void(*cb)(void*, void*))
      : blink::ScriptFunction(script_state),
        state_(state),
        callback_(cb) {}

  blink::ScriptValue Call(blink::ScriptValue value) override {
    if (value.IsEmpty()) {
      callback_(state_, nullptr);
    } else {
      v8::Isolate* isolate = v8::Isolate::GetCurrent();
      v8::HandleScope handle_scope(isolate);
      v8::Local<v8::Value> v8_value = value.V8Value();
      if (v8_value->IsNull() || v8_value->IsUndefined()) {
        callback_(state_, nullptr);
        return value;
      }
      mumba::V8Value scoped_wrapper(isolate, v8_value);
      callback_(state_, &scoped_wrapper);
    }
    return value;
  }
  void* state_;
  void(*callback_)(void*, void*);
};

struct OffscreenCanvasWrapper {
  OffscreenCanvasWrapper(blink::OffscreenCanvas* c): canvas(c) {}
  ~OffscreenCanvasWrapper() {
    canvas = nullptr;
  }
  //blink::Member<blink::OffscreenCanvas> canvas;
  blink::Persistent<blink::OffscreenCanvas> canvas;
};


struct SerializedScriptValueWrapper {
  blink::Transferables transferables;
  scoped_refptr<blink::SerializedScriptValue> handle;

  SerializedScriptValueWrapper() {}
  SerializedScriptValueWrapper(scoped_refptr<blink::SerializedScriptValue> ptr): handle(std::move(ptr)) {}
  SerializedScriptValueWrapper(DOMArrayBufferRef const* arrays, int array_count, OffscreenCanvasRef const* canvas, int canvas_count, MessagePortRef const* ports, int port_count, WebImageBitmapRef const* images, int image_count) {
    for (int i = 0; i < array_count; i++) {
      transferables.array_buffers.push_back(reinterpret_cast<blink::DOMArrayBuffer*>(arrays[i]));
    }

    for (int i = 0; i < canvas_count; i++) {
      transferables.offscreen_canvases.push_back(reinterpret_cast<OffscreenCanvasWrapper*>(canvas[i])->canvas);
    }

    for (int i = 0; i < port_count; i++) {
      transferables.message_ports.push_back(reinterpret_cast<blink::MessagePort*>(ports[i]));
    }

    for (int i = 0; i < image_count; i++) {
      transferables.image_bitmaps.push_back(reinterpret_cast<blink::ImageBitmap*>(images[i]));
    }
  }

  void Serialize(blink::LocalDOMWindow* window, const String& string) {
    v8::Isolate* isolate = v8::Isolate::GetCurrent();
    v8::Isolate::Scope isolate_scope(isolate);
    v8::HandleScope handleScope(isolate);
    blink::ExceptionState exceptionState(isolate, blink::ExceptionState::kExecutionContext, "SerializedScriptValue", "Serialize");
    blink::LocalFrame* local_frame = window->GetFrame();
    blink::LocalWindowProxy* proxy = local_frame->GetScriptController().WindowProxy(blink::DOMWrapperWorld::MainWorld());
    v8::Local<v8::Context> v8_context = proxy->ContextIfInitialized();
    v8::Local<v8::Value> string_value = blink::ToV8(string, v8_context->Global(), isolate);
    SerializeInternal(isolate, v8_context, string_value, exceptionState);
  }

  void Serialize(WebWorkerShim* worker, const String& string) {
    v8::Isolate* isolate = v8::Isolate::GetCurrent();
    v8::Isolate::Scope isolate_scope(isolate);
    v8::HandleScope handleScope(isolate);
    blink::ExceptionState exceptionState(isolate, blink::ExceptionState::kExecutionContext, "SerializedScriptValue", "Serialize");
    v8::Local<v8::Context> v8_context = worker->worker_global_scope()->ScriptController()->GetContext();
    v8::Local<v8::Value> string_value = blink::ToV8(string, v8_context->Global(), isolate);
    SerializeInternal(isolate, v8_context, string_value, exceptionState);
  }

  void Serialize(blink::ServiceWorkerGlobalScope* scope, const String& string) {
    v8::Isolate* isolate = v8::Isolate::GetCurrent();
    v8::Isolate::Scope isolate_scope(isolate);
    v8::HandleScope handleScope(isolate);
    blink::ExceptionState exceptionState(isolate, blink::ExceptionState::kExecutionContext, "SerializedScriptValue", "Serialize");
    v8::Local<v8::Context> v8_context = scope->ScriptController()->GetContext();
    v8::Local<v8::Value> string_value = blink::ToV8(string, v8_context->Global(), isolate);
    SerializeInternal(isolate, v8_context, string_value, exceptionState);
  }


  void Serialize(blink::LocalDOMWindow* window, blink::Blob* blob) {
    v8::Isolate* isolate = v8::Isolate::GetCurrent();
    v8::Isolate::Scope isolate_scope(isolate);
    v8::HandleScope handleScope(isolate);
    blink::ExceptionState exceptionState(isolate, blink::ExceptionState::kExecutionContext, "SerializedScriptValue", "Serialize");
    blink::LocalFrame* local_frame = window->GetFrame();
    blink::LocalWindowProxy* proxy = local_frame->GetScriptController().WindowProxy(blink::DOMWrapperWorld::MainWorld());
    v8::Local<v8::Context> v8_context = proxy->ContextIfInitialized();
    v8::Local<v8::Value> blob_value = blink::ToV8(blob, v8_context->Global(), v8_context->GetIsolate());
    SerializeInternal(isolate, v8_context, blob_value, exceptionState);
  }

  void Serialize(WebWorkerShim* worker, blink::Blob* blob) {
    v8::Isolate* isolate = v8::Isolate::GetCurrent();
    v8::Isolate::Scope isolate_scope(isolate);
    v8::HandleScope handleScope(isolate);
    blink::ExceptionState exceptionState(isolate, blink::ExceptionState::kExecutionContext, "SerializedScriptValue", "Serialize");
    v8::Local<v8::Context> v8_context = worker->worker_global_scope()->ScriptController()->GetContext();
    v8::Local<v8::Value> blob_value = blink::ToV8(blob, v8_context->Global(), v8_context->GetIsolate());
    SerializeInternal(isolate, v8_context, blob_value, exceptionState);
  }

  void Serialize(blink::LocalDOMWindow* window, blink::DOMArrayBuffer* array) {
    v8::Isolate* isolate = v8::Isolate::GetCurrent();
    v8::Isolate::Scope isolate_scope(isolate);
    v8::HandleScope handleScope(isolate);
    blink::ExceptionState exceptionState(isolate, blink::ExceptionState::kExecutionContext, "SerializedScriptValue", "Serialize");
    blink::LocalFrame* local_frame = window->GetFrame();
    blink::LocalWindowProxy* proxy = local_frame->GetScriptController().WindowProxy(blink::DOMWrapperWorld::MainWorld());
    v8::Local<v8::Context> v8_context = proxy->ContextIfInitialized();
    v8::Local<v8::Value> array_value = blink::ToV8(array, v8_context->Global(), v8_context->GetIsolate());
    SerializeInternal(isolate, v8_context, array_value, exceptionState);
  }

  void Serialize(WebWorkerShim* worker, blink::DOMArrayBuffer* array) {
    v8::Isolate* isolate = v8::Isolate::GetCurrent();
    v8::Isolate::Scope isolate_scope(isolate);
    v8::HandleScope handleScope(isolate);
    blink::ExceptionState exceptionState(isolate, blink::ExceptionState::kExecutionContext, "SerializedScriptValue", "Serialize");
    v8::Local<v8::Context> v8_context = worker->worker_global_scope()->ScriptController()->GetContext();
    v8::Local<v8::Value> array_value = blink::ToV8(array, v8_context->Global(), v8_context->GetIsolate());
    SerializeInternal(isolate, v8_context, array_value, exceptionState);
  }

  void Serialize(blink::LocalDOMWindow* window, blink::OffscreenCanvas* canvas) {
    blink::SerializedScriptValue::SerializeOptions options;
    v8::Isolate* isolate = v8::Isolate::GetCurrent();
    v8::Isolate::Scope isolate_scope(isolate);
    v8::HandleScope handleScope(isolate);
    blink::ExceptionState exceptionState(isolate, blink::ExceptionState::kExecutionContext, "SerializedScriptValue", "Serialize");
    blink::LocalFrame* local_frame = window->GetFrame();
    blink::LocalWindowProxy* proxy = local_frame->GetScriptController().WindowProxy(blink::DOMWrapperWorld::MainWorld());
    v8::Local<v8::Context> v8_context = proxy->ContextIfInitialized();
    options.transferables = &transferables;
    v8_context->Enter();
    v8::Local<v8::Value> v8_value = blink::ToV8(canvas, v8_context->Global(), isolate);
    handle = blink::SerializedScriptValue::Serialize(isolate, v8_value, options, exceptionState);
    v8_context->Exit();
  }

  void Serialize(WebWorkerShim* worker, blink::OffscreenCanvas* canvas) {
    blink::SerializedScriptValue::SerializeOptions options;
    v8::Isolate* isolate = v8::Isolate::GetCurrent();
    v8::Isolate::Scope isolate_scope(isolate);
    v8::HandleScope handleScope(isolate);
    blink::ExceptionState exceptionState(isolate, blink::ExceptionState::kExecutionContext, "SerializedScriptValue", "Serialize");
    v8::Local<v8::Context> v8_context = worker->worker_global_scope()->ScriptController()->GetContext();
    options.transferables = &transferables;
    v8_context->Enter();
    v8::Local<v8::Value> v8_value = blink::ToV8(canvas, v8_context->Global(), isolate);
    handle = blink::SerializedScriptValue::Serialize(isolate, v8_value, options, exceptionState);
    v8_context->Exit();
  }

  void Serialize(blink::ServiceWorkerGlobalScope* scope, blink::OffscreenCanvas* canvas) {
    blink::SerializedScriptValue::SerializeOptions options;
    v8::Isolate* isolate = v8::Isolate::GetCurrent();
    v8::Isolate::Scope isolate_scope(isolate);
    v8::HandleScope handleScope(isolate);
    blink::ExceptionState exceptionState(isolate, blink::ExceptionState::kExecutionContext, "SerializedScriptValue", "Serialize");
    v8::Local<v8::Context> v8_context = scope->ScriptController()->GetContext();
    options.transferables = &transferables;
    v8_context->Enter();
    v8::Local<v8::Value> v8_value = blink::ToV8(canvas, v8_context->Global(), isolate);
    handle = blink::SerializedScriptValue::Serialize(isolate, v8_value, options, exceptionState);
    v8_context->Exit();
  }

  void SerializeInternal(v8::Isolate* isolate, v8::Local<v8::Context> v8_context, v8::Local<v8::Value> value, blink::ExceptionState& exceptionState) {
    blink::SerializedScriptValue::SerializeOptions options;
    options.transferables = &transferables;
    v8_context->Enter();
    handle = blink::SerializedScriptValue::Serialize(isolate, value, options, exceptionState);
    v8_context->Exit();
  }

};

// make it own it so we have a better control of lifetime
struct MessagePortWrapper {
  MessagePortWrapper(blink::MessagePort* p): port(p) {}
  //blink::Persistent<blink::MessagePort> port;
  blink::Member<blink::MessagePort> port;
};

struct MessageChannelWrapper {
  MessageChannelWrapper(blink::MessageChannel* ch): channel(ch) {
  }
  //blink::Member<blink::MessageChannel> channel;
  blink::Persistent<blink::MessageChannel> channel;
};

struct PaintWorkletShim {
  blink::Persistent<blink::PaintWorklet> worklet;
  blink::LocalDOMWindow* window;
  PaintWorkletShim(blink::PaintWorklet* worklet, blink::LocalDOMWindow* window): worklet(worklet), window(window) {}
};

struct Path2dWrapper {
  Path2dWrapper(blink::Path2D* path): path(path) {}
  blink::Persistent<blink::Path2D> path;
};

struct ImageDataWrapper {
  ImageDataWrapper(blink::ImageData* data): data(data) {}
  blink::Persistent<blink::ImageData> data;
};

struct ImageBitmapWrapper {
  ImageBitmapWrapper(blink::ImageBitmap* bmp): bmp(bmp) {}
  ~ImageBitmapWrapper() { bmp = nullptr; }
  blink::Persistent<blink::ImageBitmap> bmp;
};

struct Uint8ArrayWrapper {
  Uint8ArrayWrapper(scoped_refptr<WTF::Uint8Array> array): array(std::move(array)) {}
  scoped_refptr<WTF::Uint8Array> array;
};

struct SVGMatrixWrapper {
  SVGMatrixWrapper(blink::SVGMatrixTearOff* matrix): matrix(matrix) {}
  blink::Persistent<blink::SVGMatrixTearOff> matrix;
};




#endif