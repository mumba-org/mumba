// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.


#include "launcher/command_executor.h"

#include "base/strings/string_number_conversions.h"
#include "base/strings/string_piece.h"
#include "base/strings/utf_string_conversions.h"
#include "base/files/file_util.h"
#include "base/files/file_enumerator.h"
#include "base/task_scheduler/post_task.h"
#include "base/path_service.h"
#include "base/strings/string_number_conversions.h"
#include "mumba/app/resources/grit/content_resources.h"
#include "launcher/bootstrapper.h"
#include "launcher/application_close_command.h"
#include "launcher/application_instance_list_command.h"
#include "launcher/application_launch_command.h"
#include "launcher/application_list_command.h"
#include "launcher/application_manifest_command.h"
#include "launcher/application_pin_command.h"
#include "launcher/application_schedule_command.h"
#include "launcher/application_start_command.h"
#include "launcher/application_status_command.h"
#include "launcher/application_stop_command.h"
#include "launcher/application_unpin_command.h"
#include "launcher/battery_info_command.h"
#include "launcher/blob_create_command.h"
#include "launcher/blob_delete_command.h"
#include "launcher/blob_list_command.h"
#include "launcher/blob_read_command.h"
#include "launcher/blob_write_command.h"
#include "launcher/bootstrapper.h"
#include "launcher/cache_create_command.h"
#include "launcher/cache_drop_command.h"
#include "launcher/cache_item_add_command.h"
#include "launcher/cache_item_read_command.h"
#include "launcher/cache_item_remove_command.h"
#include "launcher/cache_item_write_command.h"
#include "launcher/capture_take_photo_command.h"
#include "launcher/channel_create_command.h"
#include "launcher/channel_drop_command.h"
#include "launcher/clipboard_read_command.h"
#include "launcher/clipboard_readtext_command.h"
#include "launcher/clipboard_write_command.h"
#include "launcher/clipboard_writetext_command.h"
#include "launcher/finance_create_wallet_command.h"
#include "launcher/command.h"
#include "launcher/cookie_delete_command.h"
#include "launcher/cookie_getall_command.h"
#include "launcher/cookie_get_command.h"
#include "launcher/cookie_has_command.h"
#include "launcher/cookie_set_command.h"
#include "launcher/css_add_rule_command.h"
#include "launcher/css_get_stylesheet_command.h"
#include "launcher/css_set_stylesheet_text_command.h"
#include "launcher/css_set_style_texts_command.h"
#include "launcher/device_list_command.h"
#include "launcher/dom_focus_command.h"
#include "launcher/dom_get_attributes_command.h"
#include "launcher/dom_get_outer_html_command.h"
#include "launcher/dom_get_search_result_command.h"
#include "launcher/dom_move_to_command.h"
#include "launcher/dom_perform_search_command.h"
#include "launcher/dom_query_selector_command.h"
#include "launcher/dom_set_attribute_command.h"
#include "launcher/dom_set_node_name_command.h"
#include "launcher/dom_set_node_value_command.h"
#include "launcher/dom_set_outer_html_command.h"
#include "launcher/dom_storage_get_command.h"
#include "launcher/dom_storage_remove_command.h"
#include "launcher/dom_storage_set_command.h"
#include "launcher/bundle_build_command.h"
#include "launcher/bundle_init_command.h"
#include "launcher/bundle_install_command.h"
#include "launcher/bundle_sign_command.h"
#include "launcher/bundle_uninstall_command.h"
#include "launcher/bundle_update_command.h"
#include "launcher/fetch_close_command.h"
#include "launcher/fetch_start_command.h"
#include "launcher/filesystem_directory_get_directory_command.h"
#include "launcher/filesystem_directory_get_file_command.h"
#include "launcher/filesystem_directory_list_command.h"
#include "launcher/filesystem_directory_remove_command.h"
#include "launcher/filesystem_entry_copy_command.h"
#include "launcher/filesystem_entry_get_parent_command.h"
#include "launcher/filesystem_entry_info_command.h"
#include "launcher/filesystem_entry_metadata_command.h"
#include "launcher/filesystem_entry_move_command.h"
#include "launcher/filesystem_entry_remove_command.h"
#include "launcher/filesystem_info_command.h"
#include "launcher/geolocation_clear_watch_command.h"
#include "launcher/geolocation_get_current_position_command.h"
#include "launcher/geolocation_watch_position_command.h"
#include "launcher/identity_create_command.h"
#include "launcher/credential_create_command.h"
#include "launcher/credential_drop_command.h"
#include "launcher/credential_list_command.h"
#include "launcher/identity_drop_command.h"
#include "launcher/identity_get_command.h"
#include "launcher/identity_update_command.h"
#include "launcher/index_add_command.h"
#include "launcher/index_create_command.h"
#include "launcher/index_drop_command.h"
#include "launcher/indexed_db_clear_object_store_command.h"
#include "launcher/indexed_db_count_command.h"
#include "launcher/indexed_db_delete_db_command.h"
#include "launcher/indexed_db_get_all_command.h"
#include "launcher/indexed_db_get_command.h"
#include "launcher/indexed_db_get_key_command.h"
#include "launcher/indexed_db_request_data_command.h"
#include "launcher/index_query_command.h"
#include "launcher/index_remove_command.h"
#include "launcher/input_keyboard_command.h"
#include "launcher/input_mouse_command.h"
#include "launcher/input_touch_command.h"
#include "launcher/keyboard_lock_command.h"
#include "launcher/keyboard_unlock_command.h"
#include "launcher/media_get_audio_configuration_command.h"
#include "launcher/media_get_video_configuration_command.h"
#include "launcher/midi_close_command.h"
#include "launcher/midi_open_command.h"
#include "launcher/midi_send_command.h"
#include "launcher/ml_dataset_add_command.h"
#include "launcher/ml_dataset_drop_command.h"
#include "launcher/ml_dataset_list_command.h"
#include "launcher/ml_model_add_command.h"
#include "launcher/ml_model_drop_command.h"
#include "launcher/ml_model_list_command.h"
#include "launcher/ml_predictor_install_command.h"
#include "launcher/ml_predictor_list_command.h"
#include "launcher/ml_predictor_remove_command.h"
#include "launcher/network_info_command.h"
#include "launcher/os_cpu_info_command.h"
#include "launcher/os_gpu_info_command.h"
#include "launcher/os_memory_info_command.h"
#include "launcher/os_storage_info_command.h"
#include "launcher/page_add_script_command.h"
#include "launcher/page_bring_to_front_command.h"
#include "launcher/page_close_command.h"
#include "launcher/page_get_content_command.h"
#include "launcher/page_navigate_command.h"
#include "launcher/page_reload_command.h"
#include "launcher/page_remove_script_command.h"
#include "launcher/page_save_to_pdf_command.h"
#include "launcher/page_screenshot_command.h"
#include "launcher/page_set_content_command.h"
#include "launcher/page_stop_loading_command.h"
#include "launcher/payment_clear_command.h"
#include "launcher/payment_delete_command.h"
#include "launcher/payment_get_command.h"
#include "launcher/payment_keys_command.h"
#include "launcher/payment_list_command.h"
#include "launcher/payment_set_command.h"
#include "launcher/presentation_close_command.h"
#include "launcher/presentation_reconnect_command.h"
#include "launcher/presentation_start_command.h"
#include "launcher/push_message_send_command.h"
#include "launcher/push_message_subscribe_command.h"
#include "launcher/push_message_unsubscribe_command.h"
#include "launcher/remote_playback_cancel_watch_availability_command.h"
#include "launcher/remote_playback_prompt_command.h"
#include "launcher/remote_playback_watch_availability_command.h"
#include "launcher/repo_install_command.h"
#include "launcher/repo_list_command.h"
#include "launcher/repo_remove_command.h"
#include "launcher/route_copy_command.h"
#include "launcher/route_create_collection_command.h"
#include "launcher/route_create_entry_command.h"
#include "launcher/route_create_property_command.h"
#include "launcher/route_get_entry_command.h"
#include "launcher/route_get_metadata_command.h"
#include "launcher/route_list_collections_command.h"
#include "launcher/route_list_entries_command.h"
#include "launcher/route_list_properties_command.h"
#include "launcher/route_query_command.h"
#include "launcher/route_remove_collection_command.h"
#include "launcher/route_remove_entry_command.h"
#include "launcher/route_remove_property_command.h"
#include "launcher/route_resolve_command.h"
#include "launcher/route_set_entry_command.h"
#include "launcher/route_set_property_command.h"
#include "launcher/rpc_call_command.h"
#include "launcher/schema_create_command.h"
#include "launcher/schema_get_command.h"
#include "launcher/schema_list_command.h"
#include "launcher/schema_remove_command.h"
#include "launcher/screen_get_keep_awake_command.h"
#include "launcher/screen_orientation_get_command.h"
#include "launcher/screen_orientation_lock_command.h"
#include "launcher/screen_orientation_unlock_command.h"
#include "launcher/screen_set_keep_awake_command.h"
#include "launcher/script_add_command.h"
#include "launcher/script_list_command.h"
#include "launcher/script_module_list_command.h"
#include "launcher/script_read_command.h"
#include "launcher/script_remove_command.h"
#include "launcher/script_run_command.h"
#include "launcher/script_schedule_command.h"
#include "launcher/script_write_command.h"
#include "launcher/sensor_accelerometer_info_command.h"
#include "launcher/sensor_accelerometer_start_command.h"
#include "launcher/sensor_accelerometer_stop_command.h"
#include "launcher/sensor_ambient_light_info_command.h"
#include "launcher/sensor_ambient_light_start_command.h"
#include "launcher/sensor_ambient_light_stop_command.h"
#include "launcher/sensor_gyroscope_info_command.h"
#include "launcher/sensor_gyroscope_start_command.h"
#include "launcher/sensor_gyroscope_stop_command.h"
#include "launcher/sensor_magnetometer_info_command.h"
#include "launcher/sensor_magnetometer_start_command.h"
#include "launcher/sensor_magnetometer_stop_command.h"
#include "launcher/sensor_orientation_info_command.h"
#include "launcher/sensor_orientation_start_command.h"
#include "launcher/sensor_orientation_stop_command.h"
#include "launcher/service_list_command.h"
#include "launcher/service_start_command.h"
#include "launcher/service_stop_command.h"
#include "launcher/session_info_command.h"
#include "launcher/session_list_command.h"
#include "launcher/share_add_fileset_command.h"
#include "launcher/share_add_sqldb_command.h"
#include "launcher/share_copy_command.h"
#include "launcher/share_create_fileset_command.h"
#include "launcher/share_create_kvdb_command.h"
#include "launcher/share_create_sqldb_command.h"
#include "launcher/share_dht_get_command.h"
#include "launcher/share_kvdb_get_all_command.h"
#include "launcher/share_kvdb_get_command.h"
#include "launcher/share_kvdb_get_keys_command.h"
#include "launcher/share_kvdb_get_values_command.h"
#include "launcher/share_kvdb_set_command.h"
#include "launcher/share_list_command.h"
#include "launcher/share_pause_command.h"
#include "launcher/share_peer_list_command.h"
#include "launcher/share_peer_service_list_command.h"
#include "launcher/share_peer_status_command.h"
#include "launcher/share_read_command.h"
#include "launcher/share_remove_command.h"
#include "launcher/share_resume_command.h"
#include "launcher/share_status_command.h"
#include "launcher/share_write_command.h"
#include "launcher/sqldb_create_command.h"
#include "launcher/sqldb_drop_command.h"
#include "launcher/sqldb_dump_command.h"
#include "launcher/sqldb_list_command.h"
#include "launcher/sqldb_list_tables_command.h"
#include "launcher/sqldb_query_command.h"
#include "launcher/stream_list_command.h"
#include "launcher/stream_read_command.h"
#include "launcher/stream_write_command.h"
#include "launcher/system_shutdown_command.h"
#include "launcher/system_status_command.h"
#include "launcher/system_update_command.h"
#include "launcher/system_version_command.h"
#include "launcher/tab_activate_command.h"
#include "launcher/tab_close_command.h"
#include "launcher/tab_list_command.h"
#include "launcher/url_request_close_command.h"
#include "launcher/url_request_start_command.h"
#include "launcher/usb_device_info_command.h"
#include "launcher/usb_get_devices_command.h"
#include "launcher/usb_request_device_command.h"
#include "launcher/vibration_vibrate_command.h"
#include "launcher/webshare_share_command.h"
#include "launcher/websocket_close_command.h"
#include "launcher/websocket_send_command.h"
#include "launcher/websocket_start_command.h"
#include "launcher/window_activate_command.h"
#include "launcher/window_close_command.h"
#include "launcher/window_info_command.h"
#include "launcher/window_list_command.h"
#include "launcher/worker_list_command.h"
#include "launcher/worker_terminate_command.h"
#include "launcher/rpc_client.h"
#include "ui/base/resource/resource_bundle.h"
#include "third_party/protobuf/src/google/protobuf/compiler/parser.h"
#include "third_party/protobuf/src/google/protobuf/io/tokenizer.h"
#include "third_party/protobuf/src/google/protobuf/io/zero_copy_stream_impl.h"
#include "third_party/protobuf/src/google/protobuf/stubs/strutil.h"
#include "third_party/protobuf/src/google/protobuf/io/zero_copy_stream_impl_lite.h"
#include "third_party/protobuf/src/google/protobuf/arena.h"
#include "third_party/protobuf/src/google/protobuf/arenastring.h"
#include "third_party/protobuf/src/google/protobuf/generated_message_table_driven.h"
#include "third_party/protobuf/src/google/protobuf/generated_message_util.h"
#include "third_party/protobuf/src/google/protobuf/inlined_string_field.h"
#include "third_party/protobuf/src/google/protobuf/metadata.h"
#include "third_party/protobuf/src/google/protobuf/message.h"
#include "third_party/protobuf/src/google/protobuf/dynamic_message.h"


namespace {

class SingleFileErrorCollector : public google::protobuf::io::ErrorCollector {
 public:
  SingleFileErrorCollector(const std::string& filename)
    : filename_(filename),
      had_errors_(false) {}
  ~SingleFileErrorCollector() {}

  bool had_errors() { return had_errors_; }

  // implements ErrorCollector ---------------------------------------
  void AddError(int line, int column, const std::string& message) override {
    had_errors_ = true;
    printf("protobuf error %d:%d: %s\n", line, column, message.c_str());
  }

 private:
  std::string filename_;
  bool had_errors_;
};

}

ApplicationProfile::ApplicationProfile(const std::string& app_name): name_(app_name) {

}

ApplicationProfile::~ApplicationProfile() {

}

CommandCode ApplicationProfile::GetCommandCode(const std::string& name) {
  // if the first token is a argument or is empty fallback to a launch
  if (name.find("--") != std::string::npos) {
    return kAPPLICATION_INSTANCE_LAUNCH_COMMAND;
  } else if (name == "install") {
    return kBUNDLE_INSTALL_COMMAND;
  } else if (name == "launch") {
    return kAPPLICATION_INSTANCE_LAUNCH_COMMAND;
  } else if (name == "start") {
    return kAPPLICATION_START_COMMAND;
  } else if (name == "stop") {
    return kAPPLICATION_STOP_COMMAND;
  } else if (name == "status") {
    return kAPPLICATION_STATUS_COMMAND;
  } else if (name == "uninstall") {
    return kBUNDLE_UNINSTALL_COMMAND;
  } else if (name == "update") {
    return kBUNDLE_UPDATE_COMMAND;
  } else if (name == "close") {
    return kAPPLICATION_INSTANCE_CLOSE_COMMAND;
  } else if (name == "sign") {
    return kBUNDLE_SIGN_COMMAND;
  } else if (name == "pin") {
    return kAPPLICATION_PIN_COMMAND;
  } else if (name == "unpin") {
    return kAPPLICATION_UNPIN_COMMAND;
  } else if (name == "go") {
    return kPAGE_NAVIGATE_COMMAND;
  } else if (name == "call") {
    return kRPC_CALL_COMMAND;
  }
  return kAPPLICATION_INSTANCE_LAUNCH_COMMAND; 
}

SystemProfile::SystemProfile(): name_("world") {

}

SystemProfile::~SystemProfile() {

}

CommandCode SystemProfile::GetCommandCode(const std::string& name) {
  // this part is very alike the application
  if (name == "install") {
    return kBUNDLE_INSTALL_COMMAND;
  } else if (name == "launch") {
    return kAPPLICATION_INSTANCE_LAUNCH_COMMAND;
  } else if (name == "start") {
    return kAPPLICATION_START_COMMAND;
  } else if (name == "stop") {
    return kAPPLICATION_STOP_COMMAND;
  } else if (name == "status") {
    return kAPPLICATION_STATUS_COMMAND;
  } else if (name == "uninstall") {
    return kBUNDLE_UNINSTALL_COMMAND;
  } else if (name == "update") {
    return kBUNDLE_UPDATE_COMMAND;
  } else if (name == "close") {
    return kAPPLICATION_INSTANCE_CLOSE_COMMAND;
  } else if (name == "sign") {
    return kBUNDLE_SIGN_COMMAND;
  } else if (name == "pin") {
    return kAPPLICATION_PIN_COMMAND;
  } else if (name == "unpin") {
    return kAPPLICATION_UNPIN_COMMAND;
  } else if (name == "go") {
    return kPAGE_NAVIGATE_COMMAND;
  } else if (name == "call") {
    return kRPC_CALL_COMMAND;
  }
  return kUNDEFINED_COMMAND; 
}

CommandExecutor::CommandExecutor(Bootstrapper* bootstrapper, Profile* profile, std::unique_ptr<base::MessageLoop> main_message_loop): 
  bootstrapper_(bootstrapper),
  profile_(profile),
  descriptor_pool_(new google::protobuf::DescriptorPool()),
  main_message_loop_(std::move(main_message_loop)),
  factory_(descriptor_pool_.get()),
  file_proto_(nullptr) {

}

CommandExecutor::~CommandExecutor() {

}

int CommandExecutor::Run(base::CommandLine* cmd) {
  const base::CommandLine::StringVector& args = cmd->argv();
  const std::string& command_string = args[1];
  std::string port_string("27761");
  std::string host("127.0.0.1");
  int port = 27761;

  file_proto_ = LoadProtobufFromResourceBundle();
  if (!file_proto_) {
    return 1;
  }

  if (cmd->HasSwitch("host")) {
    host = cmd->GetSwitchValueASCII("host");
  }

  if (cmd->HasSwitch("port")) {
    port_string = cmd->GetSwitchValueASCII("port");
    if (!base::StringToInt(port_string, &port)) {
      printf("error: port parameter is not a integer\n");
      return 1;
    }
  }

  rpc_client_ = std::make_unique<RPCClient>(host, port);

  CommandCode command = GetCommandCode(command_string);
  if (command == kUNDEFINED_COMMAND) {
    printf("command '%s' not found.\n", command_string.c_str());
    return 1;
  }
  
  if (!bootstrapper_->DoBootstrap(args)) {
    printf("failure while bootstraping environment\n");
    return 1;
  }

  return Execute(command, args);
}

  
CommandCode CommandExecutor::GetCommandCode(const std::string& name) {
  return profile_->GetCommandCode(name);
}

int CommandExecutor::Execute(CommandCode command, const base::CommandLine::StringVector& args) { 
  switch (command) {
    case kSYSTEM_SHUTDOWN_COMMAND:
      command_ = SystemShutdownCommand::Create();
      break;
    case kSYSTEM_VERSION_COMMAND:
      command_ = SystemVersionCommand::Create();
      break;
    case kSYSTEM_STATUS_COMMAND:
      command_ = SystemStatusCommand::Create();
      break;
    case kSYSTEM_UPDATE_COMMAND:
      command_ = ApplicationCloseCommand::Create();
      break;
    case kAPPLICATION_INSTANCE_CLOSE_COMMAND:
      command_ = ApplicationCloseCommand::Create();
      break;
    case kAPPLICATION_INSTANCE_LIST_COMMAND: 
      command_ = ApplicationInstanceListCommand::Create();
      break;
    case kAPPLICATION_INSTANCE_LAUNCH_COMMAND:
      command_ = ApplicationLaunchCommand::Create();
      break;
    case kAPPLICATION_INSTANCE_SCHEDULE_COMMAND:
      command_ = ApplicationScheduleCommand::Create();
      break;
    case kAPPLICATION_LIST_COMMAND:     
      command_ = ApplicationListCommand::Create();
      break;
    case kAPPLICATION_MANIFEST_COMMAND:     
      command_ = ApplicationManifestCommand::Create();  
      break;
    case kAPPLICATION_PIN_COMMAND:
      command_ = ApplicationPinCommand::Create();
      break;
    case kAPPLICATION_START_COMMAND:
      command_ = ApplicationStartCommand::Create();
      break;
    case kAPPLICATION_STOP_COMMAND:
      command_ = ApplicationStopCommand::Create();
      break;
    case kAPPLICATION_STATUS_COMMAND:
      command_ = ApplicationStatusCommand::Create();
      break;
    case kAPPLICATION_UNPIN_COMMAND:
      command_ = ApplicationUnpinCommand::Create();
      break;
    case kFINANCE_CREATE_WALLET_COMMAND:
      command_ = FinanceCreateWalletCommand::Create();  
      break;
    case kBATTERY_INFO_COMMAND:
      command_ = BatteryInfoCommand::Create();
      break;
    case kBLOB_CREATE_COMMAND:
      command_ = BlobCreateCommand::Create();
      break;
    case kBLOB_DELETE_COMMAND:
      command_ = BlobDeleteCommand::Create();
      break;
    case kBLOB_LIST_COMMAND:
      command_ = BlobListCommand::Create();
      break;
    case kBLOB_READ_COMMAND:
      command_ = BlobReadCommand::Create();
      break;
    case kBLOB_WRITE_COMMAND:
      command_ = BlobWriteCommand::Create();
      break;
    case kCACHE_CREATE_COMMAND:
      command_ = CacheCreateCommand::Create();
      break;
    case kCACHE_DROP_COMMAND:
      command_ = CacheDropCommand::Create();
      break;
    case kCACHE_ITEM_ADD_COMMAND:
      command_ = CacheItemAddCommand::Create();
      break;
    case kCACHE_ITEM_READ_COMMAND:
      command_ = CacheItemReadCommand::Create();
      break;
    case kCACHE_ITEM_REMOVE_COMMAND:
      command_ = CacheItemRemoveCommand::Create();
      break;
    case kCACHE_ITEM_WRITE_COMMAND:
      command_ = CacheItemWriteCommand::Create();
      break;
    case kCAPTURE_TAKE_PHOTO_COMMAND:
      command_ = CaptureTakePhotoCommand::Create();
      break;
    case kCHANNEL_CREATE_COMMAND:
      command_ = ChannelCreateCommand::Create();
      break;
    case kCHANNEL_DROP_COMMAND:
      command_ = ChannelDropCommand::Create();
      break;
    case kCLIPBOARD_READ_COMMAND:
      command_ = ClipboardReadCommand::Create();
      break;
    case kCLIPBOARD_READTEXT_COMMAND:
      command_ = ClipboardReadTextCommand::Create();
      break;
    case kCLIPBOARD_WRITE_COMMAND:
      command_ = ClipboardWriteCommand::Create();
      break;
    case kCLIPBOARD_WRITETEXT_COMMAND:
      command_ = ClipboardWriteTextCommand::Create();
      break;
    case kCOOKIE_DELETE_COMMAND:
      command_ = CookieDeleteCommand::Create();
      break;
    case kCOOKIE_GETALL_COMMAND:
      command_ = CookieGetAllCommand::Create();
      break;
    case kCOOKIE_GET_COMMAND:
      command_ = CookieGetCommand::Create();
      break;
    case kCOOKIE_HAS_COMMAND:
      command_ = CookieHasCommand::Create();
      break;
    case kCOOKIE_SET_COMMAND:
      command_ = CookieSetCommand::Create();
      break;
    case kCSS_ADD_RULE_COMMAND:
      command_ = CSSAddRuleCommand::Create();
      break;
    case kCSS_GET_STYLESHEET_TEXT_COMMAND:
      command_ = CSSGetStyleSheetCommand::Create();
      break;
    case kCSS_SET_STYLE_TEXTS_COMMAND:
      command_ = CSSSetStyleTextsCommand::Create();
      break;
    case kCSS_SET_STYLESHEET_TEXT_COMMAND:
      command_ = CSSSetStyleSheetTextCommand::Create();
      break;
    case kDEVICE_LIST_COMMAND:
      command_ = DeviceListCommand::Create();
      break;
    case kDOM_FOCUS_COMMAND:
      command_ = DOMFocusCommand::Create();
      break;
    case kDOM_GET_ATTRIBUTES_COMMAND:
      command_ = DOMGetAttributesCommand::Create();
      break;
    case kDOM_GET_OUTER_HTML_COMMAND:
      command_ = DOMGetOuterHtmlCommand::Create();
      break;
    case kDOM_GET_SEARCH_RESULT_COMMAND:
      command_ = DOMGetSearchResultCommand::Create();
      break;
    case kDOM_MOVE_TO_COMMAND:
      command_ = DOMMoveToCommand::Create();
      break;
    case kDOM_PERFORM_SEARCH_COMMAND:
      command_ = DOMPerformSearchCommand::Create();
      break;
    case kDOM_QUERY_SELECTOR_COMMAND:
      command_ = DOMQuerySelectorCommand::Create();
      break;
    case kDOM_SET_ATTRIBUTE_COMMAND:
      command_ = DOMSetAttributeCommand::Create();
      break;
    case kDOM_SET_NODE_NAME_COMMAND:
      command_ = DOMSetNodeNameCommand::Create();
      break;
    case kDOM_SET_NODE_VALUE_COMMAND:
      command_ = DOMSetNodeValueCommand::Create();
      break;
    case kDOM_SET_OUTER_HTML_COMMAND:
      command_ = DOMSetOuterHtmlCommand::Create();
      break;
    case kDOM_STORAGE_GET_COMMAND:
      command_ = DOMStorageGetCommand::Create();
      break;
    case kDOM_STORAGE_REMOVE_COMMAND:
      command_ = DOMStorageRemoveCommand::Create();
      break;
    case kDOM_STORAGE_SET_COMMAND:
      command_ = DOMStorageSetCommand::Create();
      break;
    case kFETCH_CLOSE_COMMAND:
      command_ = FetchCloseCommand::Create();
      break;
    case kFETCH_START_COMMAND:
      command_ = FetchStartCommand::Create();
      break;
    case kFILESYSTEM_DIRECTORY_GET_DIRECTORY_COMMAND:
      command_ = FilesystemDirectoryGetDirectoryCommand::Create();
      break;
    case kFILESYSTEM_DIRECTORY_GET_FILE_COMMAND:
      command_ = FilesystemDirectoryGetFileCommand::Create();
      break;
    case kFILESYSTEM_DIRECTORY_LIST_COMMAND:
      command_ = FilesystemDirectoryListCommand::Create();
      break;
    case kFILESYSTEM_DIRECTORY_REMOVE_COMMAND:
      command_ = FilesystemDirectoryRemoveCommand::Create();
      break;
    case kFILESYSTEM_ENTRY_COPY_COMMAND:
      command_ = FilesystemEntryCopyCommand::Create();
      break;
    case kFILESYSTEM_ENTRY_GET_PARENT_COMMAND:
      command_ = FilesystemEntryGetParentCommand::Create();
      break;
    case kFILESYSTEM_ENTRY_INFO_COMMAND:
      command_ = FilesystemEntryInfoCommand::Create();
      break;
    case kFILESYSTEM_ENTRY_METADATA_COMMAND:
      command_ = FilesystemEntryMetadataCommand::Create();
      break;
    case kFILESYSTEM_ENTRY_MOVE_COMMAND:
      command_ = FilesystemEntryMoveCommand::Create();
      break;
    case kFILESYSTEM_ENTRY_REMOVE_COMMAND:
      command_ = FilesystemEntryRemoveCommand::Create();
      break;
    case kFILESYSTEM_INFO_COMMAND:
      command_ = FilesystemInfoCommand::Create();
      break;
    case kGEOLOCATION_CLEAR_WATCH_COMMAND:
      command_ = GeolocationClearWatchCommand::Create();
      break;
    case kGEOLOCATION_GET_CURRENT_POSITION_COMMAND:
      command_ = GeolocationGetCurrentPositionCommand::Create();
      break;
    case kGEOLOCATION_WATCH_POSITION_COMMAND:
      command_ = GeolocationWatchPositionCommand::Create();
      break;
    case kIDENTITY_CREATE_COMMAND:
      command_ = IdentityCreateCommand::Create();
      break;
    case kIDENTITY_DROP_COMMAND:
      command_ = IdentityDropCommand::Create(); 
      break;
    case kIDENTITY_GET_COMMAND:
      command_ = IdentityGetCommand::Create(); 
      break;
    case kIDENTITY_UPDATE_COMMAND:
      command_ = IdentityUpdateCommand::Create();
      break;
    case kCREDENTIAL_CREATE_COMMAND:
      command_ = CredentialCreateCommand::Create(); 
      break;
    case kCREDENTIAL_DROP_COMMAND:
      command_ = CredentialDropCommand::Create(); 
      break;
    case kCREDENTIAL_LIST_COMMAND:
      command_ = CredentialListCommand::Create(); 
      break;
    case kINDEX_ADD_COMMAND:
      command_ = IndexAddCommand::Create(); 
      break;
    case kINDEX_CREATE_COMMAND:
      command_ = IndexCreateCommand::Create(); 
      break;
    case kINDEX_DROP_COMMAND:
      command_ = IndexDropCommand::Create(); 
      break;
    case kINDEX_QUERY_COMMAND:
      command_ = IndexQueryCommand::Create(); 
      break;
    case kINDEX_REMOVE_COMMAND:
      command_ = IndexRemoveCommand::Create(); 
      break;
    case kINDEXED_DB_CLEAR_OBJECT_STORE_COMMAND:
      command_ = IndexedDBClearObjectStoreCommand::Create(); 
      break;
    case kINDEXED_DB_COUNT_COMMAND:
      command_ = IndexedDBCountCommand::Create(); 
      break;
    case kINDEXED_DB_DELETE_DB_COMMAND:
      command_ = IndexedDBDeleteDBCommand::Create();
      break;
    case kINDEXED_DB_GET_ALL_COMMAND:
      command_ = IndexedDBGetAllCommand::Create();
      break;
    case kINDEXED_DB_GET_COMMAND:
      command_ = IndexedDBGetCommand::Create();
      break;
    case kINDEXED_DB_GET_KEY_COMMAND:
      command_ = IndexedDBGetKeyCommand::Create();
      break;
    case kINDEXED_DB_REQUEST_DATA_COMMAND:
      command_ = IndexedDBRequestDataCommand::Create();
      break;
    case kINPUT_KEYBOARD_COMMAND:
      command_ = InputKeyboardCommand::Create();
      break;
    case kINPUT_MOUSE_COMMAND:
      command_ = InputMouseCommand::Create();
      break;
    case kINPUT_TOUCH_COMMAND:
      command_ = InputTouchCommand::Create();
      break;
    case kKEYBOARD_LOCK_COMMAND:
      command_ = KeyboardLockCommand::Create(); 
      break;
    case kKEYBOARD_UNLOCK_COMMAND:
      command_ = KeyboardUnlockCommand::Create(); 
      break;
    case kMEDIA_GET_AUDIO_CONFIGURATION_COMMAND:
      command_ = MediaGetAudioConfigurationCommand::Create(); 
      break;
    case kMEDIA_GET_VIDEO_CONFIGURATION_COMMAND:
      command_ = MediaGetVideoConfigurationCommand::Create(); 
      break;
    case kMIDI_CLOSE_COMMAND:
      command_ = MidiCloseCommand::Create(); 
      break;
    case kMIDI_OPEN_COMMAND:
      command_ = MidiOpenCommand::Create(); 
      break;
    case kMIDI_SEND_COMMAND:
      command_ = MidiSendCommand::Create(); 
      break;
    case kML_DATASET_ADD_COMMAND:
      command_ = MLDatasetAddCommand::Create(); 
      break;
    case kML_DATASET_DROP_COMMAND:
      command_ = MLDatasetDropCommand::Create(); 
      break;
    case kML_DATASET_LIST_COMMAND:
      command_ = MLDatasetListCommand::Create(); 
      break;
    case kML_MODEL_ADD_COMMAND:
      command_ = MLModelAddCommand::Create(); 
      break;
    case kML_MODEL_DROP_COMMAND:
      command_ = MLModelDropCommand::Create(); 
      break;
    case kML_MODEL_LIST_COMMAND:
      command_ = MLModelListCommand::Create(); 
      break;
    case kML_PREDICTOR_INSTALL_COMMAND:
      command_ = MLPredictorInstallCommand::Create(); 
      break;
    case kML_PREDICTOR_LIST_COMMAND:
      command_ = MLPredictorListCommand::Create(); 
      break;
    case kML_PREDICTOR_REMOVE_COMMAND:
      command_ = MLPredictorRemoveCommand::Create(); 
      break;
    case kNETWORK_INFO_COMMAND:
      command_ = NetworkInfoCommand::Create(); 
      break;
    case kPAGE_ADD_SCRIPT_COMMAND:
      command_ = PageAddScriptCommand::Create(); 
      break;
    case kPAGE_BRING_TO_FRONT_COMMAND:
      command_ = PageBringToFrontCommand::Create(); 
      break;
    case kPAGE_CLOSE_COMMAND:
      command_ = PageCloseCommand::Create(); 
      break;
    case kPAGE_GET_CONTENT_COMMAND:
      command_ = PageGetContentCommand::Create(); 
      break;
    case kPAGE_NAVIGATE_COMMAND:
      command_ = PageNavigateCommand::Create(); 
      break;
    case kPAGE_RELOAD_COMMAND:
      command_ = PageReloadCommand::Create(); 
      break;
    case kPAGE_REMOVE_SCRIPT_COMMAND:
      command_ = PageRemoveScriptCommand::Create(); 
      break;
    case kPAGE_SAVE_TO_PDF_COMMAND:
      command_ = PageSaveToPdfCommand::Create(); 
      break;
    case kPAGE_SCREENSHOT_COMMAND:
      command_ = PageScreenshotCommand::Create(); 
      break;
    case kPAGE_SET_CONTENT_COMMAND:
      command_ = PageSetContentCommand::Create(); 
      break;
    case kPAGE_STOP_LOADING_COMMAND:
      command_ = PageStopLoadingCommand::Create(); 
      break;
    case kPAYMENT_CLEAR_COMMAND:
      command_ = PaymentClearCommand::Create(); 
      break;
    case kPAYMENT_DELETE_COMMAND:
      command_ = PaymentDeleteCommand::Create(); 
      break;
    case kPAYMENT_GET_COMMAND:
      command_ = PaymentGetCommand::Create(); 
      break;
    case kPAYMENT_KEYS_COMMAND:
      command_ = PaymentKeysCommand::Create(); 
      break;
    case kPAYMENT_LIST_COMMAND:
      command_ = PaymentListCommand::Create(); 
      break;
    case kPAYMENT_SET_COMMAND:
      command_ = PaymentSetCommand::Create(); 
      break;
    case kPRESENTATION_CLOSE_COMMAND:
      command_ = PresentationCloseCommand::Create(); 
      break;
    case kPRESENTATION_RECONNECT_COMMAND:
      command_ = PresentationReconnectCommand::Create(); 
      break;
    case kPRESENTATION_START_COMMAND:
      command_ = PresentationStartCommand::Create(); 
      break;
    case kPUSH_MESSAGE_SEND_COMMAND:
      command_ = PushMessageSendCommand::Create(); 
      break;
    case kPUSH_MESSAGE_SUBSCRIBE_COMMAND:
      command_ = PushMessageSubscribeCommand::Create(); 
      break;
    case kPUSH_MESSAGE_UNSUBSCRIBE_COMMAND:
      command_ = PushMessageUnsubscribeCommand::Create(); 
      break;
    case kREMOTE_PLAYBACK_CANCEL_WATCH_AVAILABILITY_COMMAND:
      command_ = RemotePlaybackCancelWatchAvailabilityCommand::Create(); 
      break;
    case kREMOTE_PLAYBACK_PROMPT_COMMAND:
      command_ = RemotePlaybackPromptCommand::Create(); 
      break;
    case kREMOTE_PLAYBACK_WATCH_AVAILABILITY_COMMAND:
      command_ = RemotePlaybackWatchAvailabilityCommand::Create(); 
      break;
    case kREPO_INSTALL_COMMAND:
      command_ = RepoInstallCommand::Create(); 
      break;
    case kREPO_LIST_COMMAND:
      command_ = RepoListCommand::Create(); 
      break;
    case kREPO_REMOVE_COMMAND:
      command_ = RepoRemoveCommand::Create(); 
      break;
    case kRPC_CALL_COMMAND:
      command_ = RPCCallCommand::Create(); 
      break;
    case kSCHEMA_CREATE_COMMAND:
      command_ = SchemaCreateCommand::Create(); 
      break;
    case kSCHEMA_GET_COMMAND:
      command_ = SchemaGetCommand::Create(); 
      break;
    case kSCHEMA_LIST_COMMAND:
      command_ = SchemaListCommand::Create(); 
      break;
    case kSCHEMA_REMOVE_COMMAND:
      command_ = SchemaRemoveCommand::Create(); 
      break;
    case kSCREEN_GET_KEEP_AWAKE_COMMAND:
      command_ = ScreenGetKeepAwakeCommand::Create(); 
      break;
    case kSCREEN_SET_KEEP_AWAKE_COMMAND:
      command_ = ScreenSetKeepAwakeCommand::Create(); 
      break;
    case kSCREEN_ORIENTATION_GET_COMMAND:
      command_ = ScreenOrientationGetCommand::Create(); 
      break;
    case kSCREEN_ORIENTATION_LOCK_COMMAND:
      command_ = ScreenOrientationLockCommand::Create(); 
      break;
    case kSCREEN_ORIENTATION_UNLOCK_COMMAND:
      command_ = ScreenOrientationUnlockCommand::Create(); 
      break;
    case kSENSOR_ACCELEROMETER_INFO_COMMAND:
      command_ = SensorAccelerometerInfoCommand::Create(); 
      break;
    case kSENSOR_ACCELEROMETER_START_COMMAND:
      command_ = SensorAccelerometerStartCommand::Create(); 
      break;
    case kSENSOR_ACCELEROMETER_STOP_COMMAND:
      command_ = SensorAccelerometerStopCommand::Create(); 
      break;
    case kSENSOR_AMBIENT_LIGHT_INFO_COMMAND:
      command_ = SensorAmbientLightInfoCommand::Create(); 
      break;
    case kSENSOR_AMBIENT_LIGHT_START_COMMAND:
      command_ = SensorAmbientLightStartCommand::Create(); 
      break;
    case kSENSOR_AMBIENT_LIGHT_STOP_COMMAND:
      command_ = SensorAmbientLightStopCommand::Create(); 
      break;
    case kSENSOR_GYROSCOPE_INFO_COMMAND:
      command_ = SensorGyroscopeInfoCommand::Create(); 
      break;
    case kSENSOR_GYROSCOPE_START_COMMAND:
      command_ = SensorGyroscopeStartCommand::Create(); 
      break;
    case kSENSOR_GYROSCOPE_STOP_COMMAND:
      command_ = SensorGyroscopeStopCommand::Create(); 
      break;
    case kSENSOR_MAGNETOMETER_INFO_COMMAND:
      command_ = SensorMagnetometerInfoCommand::Create(); 
      break;
    case kSENSOR_MAGNETOMETER_START_COMMAND:
      command_ = SensorMagnetometerStartCommand::Create(); 
      break;
    case kSENSOR_MAGNETOMETER_STOP_COMMAND:
      command_ = SensorMagnetometerStopCommand::Create(); 
      break;
    case kSENSOR_ORIENTATION_INFO_COMMAND:
      command_ = SensorOrientationInfoCommand::Create(); 
      break;
    case kSENSOR_ORIENTATION_START_COMMAND:
      command_ = SensorOrientationStartCommand::Create(); 
      break;
    case kSENSOR_ORIENTATION_STOP_COMMAND:
      command_ = SensorOrientationStopCommand::Create(); 
      break;
    case kSERVICE_LIST_COMMAND:
      command_ = ServiceListCommand::Create(); 
      break;
    case kSERVICE_START_COMMAND:
      command_ = ServiceStartCommand::Create(); 
      break;
    case kSERVICE_STOP_COMMAND:
      command_ = ServiceStopCommand::Create();
      break;
    case kSESSION_LIST_COMMAND:
      command_ = SessionListCommand::Create();
      break;
    case kSESSION_INFO_COMMAND:
      command_ = SessionInfoCommand::Create();
      break;
    case kSHARE_ADD_FILESET_COMMAND:
      command_ = ShareAddFilesetCommand::Create(); 
      break;
    case kSHARE_ADD_SQLDB_COMMAND:
      command_ = ShareAddSqlDbCommand::Create(); 
      break;
    case kSHARE_COPY_COMMAND:
      command_ = ShareCopyCommand::Create(); 
      break;
    case kSHARE_CREATE_FILESET_COMMAND:
      command_ = ShareCreateFilesetCommand::Create(); 
      break;
    case kSHARE_CREATE_KVDB_COMMAND:
      command_ = ShareCreateKvDbCommand::Create(); 
      break;
    case kSHARE_CREATE_SQLDB_COMMAND:
      command_ = ShareCreateSqlDbCommand::Create(); 
      break;
    case kSHARE_DHT_GET_COMMAND:
      command_ = ShareDHTGetCommand::Create(); 
      break;
    case kSHARE_LIST_COMMAND:
      command_ = ShareListCommand::Create(); 
      break;
    case kSHARE_PAUSE_COMMAND:
      command_ = SharePauseCommand::Create(); 
      break;
    case kSHARE_PEER_LIST_COMMAND:
      command_ = SharePeerListCommand::Create(); 
      break;
    case kSHARE_PEER_SERVICE_LIST_COMMAND:
      command_ = SharePeerServiceListCommand::Create(); 
      break;
    case kSHARE_PEER_STATUS_COMMAND:
      command_ = SharePeerStatusCommand::Create(); 
      break;
    case kSHARE_READ_COMMAND:
      command_ = ShareReadCommand::Create(); 
      break;
    case kSHARE_REMOVE_COMMAND:
      command_ = ShareRemoveCommand::Create(); 
      break;
    case kSHARE_RESUME_COMMAND:
      command_ = ShareResumeCommand::Create(); 
      break;
    case kSHARE_STATUS_COMMAND:
      command_ = ShareStatusCommand::Create(); 
      break;
    case kSHARE_WRITE_COMMAND:
      command_ = ShareWriteCommand::Create(); 
      break;
    case kSHARE_KVDB_GET_ALL_COMMAND:
      command_ = ShareKvDbGetAllCommand::Create(); 
      break;
    case kSHARE_KVDB_GET_COMMAND:
      command_ = ShareKvDbGetCommand::Create(); 
      break;
    case kSHARE_KVDB_GET_KEYS_COMMAND:
      command_ = ShareKvDbGetKeysCommand::Create(); 
      break;
    case kSHARE_KVDB_GET_VALUES_COMMAND:
      command_ = ShareKvDbGetValuesCommand::Create(); 
      break;
    case kSHARE_KVDB_SET_COMMAND:
      command_ = ShareKvDbSetCommand::Create(); 
      break;
    case kSQLDB_CREATE_COMMAND:
      command_ = SqlDbCreateCommand::Create();
      break;
    case kSQLDB_DROP_COMMAND:
      command_ = SqlDbDropCommand::Create();
      break;
    case kSQLDB_DUMP_COMMAND:
      command_ = SqlDbDumpCommand::Create();
      break;
    case kSQLDB_LIST_COMMAND:
      command_ = SqlDbListCommand::Create();
      break;
    case kSQLDB_LIST_TABLES_COMMAND:
      command_ = SqlDbListTablesCommand::Create();
      break;
    case kSQLDB_QUERY_COMMAND:
      command_ = SqlDbQueryCommand::Create();
      break;
    case kSTREAM_LIST_COMMAND:
      command_ = StreamListCommand::Create();
      break;
    case kSTREAM_READ_COMMAND:
      command_ = StreamReadCommand::Create();
      break;
    case kSTREAM_WRITE_COMMAND:
      command_ = StreamWriteCommand::Create();
      break;
    case kOS_CPU_INFO_COMMAND:
      command_ = OSCpuInfoCommand::Create();
      break;
    case kOS_GPU_INFO_COMMAND:
      command_ = OSGpuInfoCommand::Create();
      break;
    case kOS_MEMORY_INFO_COMMAND:
      command_ = OSMemoryInfoCommand::Create();
      break;
    case kOS_STORAGE_INFO_COMMAND:
      command_ = OSStorageInfoCommand::Create();
      break;
    case kTAB_CLOSE_COMMAND:
      command_ = TabCloseCommand::Create();
      break;
    case kTAB_LIST_COMMAND:
      command_ = TabListCommand::Create();
      break;
    case kTAB_ACTIVATE_COMMAND:
      command_ = TabActivateCommand::Create();
      break;
    case kROUTE_CREATE_ENTRY_COMMAND:
      command_ = RouteCreateEntryCommand::Create();
      break;
    case kROUTE_CREATE_COLLECTION_COMMAND:
      command_ = RouteCreateCollectionCommand::Create();
      break;
    case kROUTE_CREATE_PROPERTY_COMMAND:
      command_ = RouteCreatePropertyCommand::Create();
      break;
    case kROUTE_COPY_COMMAND:
      command_ = RouteCopyCommand::Create();
      break;
    case kROUTE_GET_ENTRY_COMMAND:
      command_ = RouteGetEntryCommand::Create();
      break;
    case kROUTE_GET_METADATA_COMMAND:
      command_ = RouteGetMetadataCommand::Create();
      break;
    case kROUTE_LIST_ENTRIES_COMMAND:
      command_ = RouteListEntriesCommand::Create();
      break;
    case kROUTE_LIST_COLLECTIONS_COMMAND:
      command_ = RouteListCollectionsCommand::Create();
      break;
    case kROUTE_LIST_PROPERTIES_COMMAND:
      command_ = RouteListPropertiesCommand::Create();
      break;
    case kROUTE_SET_ENTRY_COMMAND:
      command_ = RouteSetEntryCommand::Create();
      break;
    case kROUTE_QUERY_COMMAND:
      command_ = RouteQueryCommand::Create();
      break;
    case kROUTE_REMOVE_ENTRY_COMMAND:
      command_ = RouteRemoveEntryCommand::Create();
      break;
    case kROUTE_REMOVE_COLLECTION_COMMAND:
      command_ = RouteRemoveCollectionCommand::Create();
      break;
    case kROUTE_REMOVE_PROPERTY_COMMAND:
      command_ = RouteRemovePropertyCommand::Create();
      break;
    case kROUTE_RESOLVE_COMMAND:
      command_ = RouteResolveCommand::Create();
      break;
    case kROUTE_SET_PROPERTY_COMMAND:
      command_ = RouteSetPropertyCommand::Create();
      break;
    case kURL_REQUEST_START_COMMAND:
      command_ = URLRequestStartCommand::Create();
      break;
    case kURL_REQUEST_CLOSE_COMMAND:
      command_ = URLRequestCloseCommand::Create();
      break;
    case kUSB_DEVICE_INFO_COMMAND:
      command_ = USBDeviceInfoCommand::Create();
      break;
    case kUSB_GET_DEVICES_COMMAND:
      command_ = USBGetDevicesCommand::Create();
      break;
    case kUSB_REQUEST_DEVICE_COMMAND:
      command_ = USBRequestDeviceCommand::Create();
      break;
    case kVIBRATION_VIBRATE_COMMAND:
      command_ = VibrationVibrateCommand::Create();
      break;
    case kWEBSHARE_SHARE_COMMAND:
      command_ = WebshareShareCommand::Create();
      break;
    case kWEBSOCKET_CLOSE_COMMAND:
      command_ = WebsocketCloseCommand::Create();
      break;
    case kWEBSOCKET_SEND_COMMAND:
      command_ = WebsocketSendCommand::Create();
      break;
    case kWEBSOCKET_START_COMMAND:
      command_ = WebsocketStartCommand::Create();
      break;
    case kWINDOW_LIST_COMMAND:
      command_ = WindowListCommand::Create();
      break;
    case kWINDOW_ACTIVATE_COMMAND:
      command_ = WindowActivateCommand::Create();
      break;
    case kWINDOW_CLOSE_COMMAND:
      command_ = WindowCloseCommand::Create();
      break;
    case kWINDOW_INFO_COMMAND:
      command_ = WindowInfoCommand::Create();
      break;
    case kWORKER_LIST_COMMAND:
      command_ = WorkerListCommand::Create();
      break;
    case kWORKER_TERMINATE_COMMAND:
      command_ = WorkerTerminateCommand::Create();
      break;
    case kBUNDLE_BUILD_COMMAND:
      command_ = BundleBuildCommand::Create();
      break;
    case kBUNDLE_INSTALL_COMMAND:
      command_ = BundleInstallCommand::Create();
      break;
    case kBUNDLE_SIGN_COMMAND:
      command_ = BundleSignCommand::Create();
      break;
    case kBUNDLE_UNINSTALL_COMMAND:
      command_ = BundleUninstallCommand::Create();
      break;
    case kBUNDLE_UPDATE_COMMAND:
      command_ = BundleUpdateCommand::Create();
      break;
    case kBUNDLE_INIT_COMMAND:
      command_ = BundleInitCommand::Create();
      break;
    case kSCRIPT_ADD_COMMAND:
      command_ = ScriptAddCommand::Create();
      break;
    case kSCRIPT_LIST_COMMAND:
      command_ = ScriptListCommand::Create();
      break;
    case kSCRIPT_MODULE_LIST_COMMAND:
      command_ = ScriptModuleListCommand::Create();
      break;
    case kSCRIPT_READ_COMMAND:
      command_ = ScriptReadCommand::Create();
      break;
    case kSCRIPT_REMOVE_COMMAND:
      command_ = ScriptRemoveCommand::Create();
      break;
    case kSCRIPT_RUN_COMMAND:
      command_ = ScriptRunCommand::Create();
      break;
    case kSCRIPT_SCHEDULE_COMMAND:
      command_ = ScriptScheduleCommand::Create();
      break;
    case kSCRIPT_WRITE_COMMAND:
      command_ = ScriptWriteCommand::Create();
      break;
    case kUNDEFINED_COMMAND:
      return 1;
  }
  return command_->Run(this, args);
}

const google::protobuf::FileDescriptor* CommandExecutor::BuildFile(const google::protobuf::FileDescriptorProto& schema) {
  const google::protobuf::FileDescriptor* result = descriptor_pool_->BuildFile(schema);
  return result;
}


const google::protobuf::FileDescriptor* CommandExecutor::LoadProtobufFromResourceBundle() {
  base::FilePath exe_path;
  std::string schema_contents_str;

  base::PathService::Get(base::DIR_CURRENT, &exe_path);
  base::FilePath resource_pak = exe_path.Append(FILE_PATH_LITERAL("gen/mumba/app/resources/content_resources_100_percent.pak"));
  ui::ResourceBundle::InitSharedInstanceWithPakPath(resource_pak); 
  base::StringPiece schema_contents = ui::ResourceBundle::GetSharedInstance().GetRawDataResource(IDR_MUMBA_PROTO);
  base::internal::CopyToString(schema_contents, &schema_contents_str);
  
  if (schema_contents_str.empty()) {
    printf("contents of schema file is empty. id = IDR_MUMBA_PROTO\n");
    return nullptr;
  }

  google::protobuf::io::ArrayInputStream input(schema_contents_str.data(), schema_contents_str.size());
  SingleFileErrorCollector file_error_collector("_");
  google::protobuf::io::Tokenizer tokenizer(&input, &file_error_collector);
  google::protobuf::compiler::Parser parser;
 
  google::protobuf::FileDescriptorProto file_proto;
  file_proto.set_name("mumba.proto"); 
  if (!parser.Parse(&tokenizer, &file_proto)) {
    printf("failed to parse 'mumba.proto'\n");
    return nullptr;
  }
  
  return BuildFile(file_proto);
}

size_t CommandExecutor::GetMessageDescriptorCount() const {
  return file_proto_->message_type_count();
}

const google::protobuf::Descriptor* CommandExecutor::GetMessageDescriptorAt(size_t index) {
  return file_proto_->message_type(index);
}

const google::protobuf::Descriptor* CommandExecutor::GetMessageDescriptorNamed(const std::string& name) {
  const google::protobuf::Descriptor* result = nullptr;
  for (size_t i = 0; i < GetMessageDescriptorCount(); i++) {
    const google::protobuf::Descriptor* current = GetMessageDescriptorAt(i);
    if (current->name() == name) {
      result = current;
      break;
    }
  }
  return result;
}

const google::protobuf::Message* CommandExecutor::GetMessageNamed(const std::string& name) {
  const google::protobuf::Descriptor* descriptor = GetMessageDescriptorNamed(name);
  if (!descriptor) {
    return nullptr;
  }
  const google::protobuf::Message* message = factory_.GetPrototype(descriptor);
  return message;
}

const google::protobuf::Message* CommandExecutor::GetMessageNamed(const google::protobuf::Descriptor* descriptor, const std::string& name) {
  const google::protobuf::Message* message = factory_.GetPrototype(descriptor);
  return message; 
}

std::unique_ptr<RPCUnaryCall> CommandExecutor::CreateRPCUnaryCall(const std::string& method_name) {
  return rpc_client_->CreateRPCUnaryCall(method_name);
}

bool CommandExecutor::EncodeMessage(
  const std::string& message_name,
  std::map<std::string, std::string> kvmap, 
  std::string* out) {
  
  const google::protobuf::Descriptor* message_descriptor = GetMessageDescriptorNamed(message_name);
  if (!message_descriptor) {
    DLOG(INFO) << "EncodeMessage(Request): failed while trying to find '" << message_name << "' in protobuf descriptor";
    return false;
  }
  const google::protobuf::Message* message = factory_.GetPrototype(message_descriptor);
  google::protobuf::Message* mutable_message = message->New();
  const google::protobuf::Reflection* reflection = mutable_message->GetReflection();
  // theres parameters in url? try to find fields with the same name
  if (kvmap.size() > 0) {
    for (auto it = kvmap.begin(); it != kvmap.end(); ++it) {
      for (int i = 0; i < message_descriptor->field_count(); ++i) {
        const google::protobuf::FieldDescriptor* field_descriptor = message_descriptor->field(i);
        if (field_descriptor && field_descriptor->name() == it->first) {
          switch (field_descriptor->cpp_type()) {
            case google::protobuf::FieldDescriptor::CPPTYPE_STRING: {
              reflection->SetString(mutable_message, field_descriptor, it->second);
              break;
            }
            case google::protobuf::FieldDescriptor::CPPTYPE_INT32: {
              int number;
              DCHECK(base::StringToInt(it->second, &number));
              reflection->SetInt32(mutable_message, field_descriptor, number);
              break;
            }
            case google::protobuf::FieldDescriptor::CPPTYPE_INT64: {
              int64_t number;
              DCHECK(base::StringToInt64(it->second, &number));
              reflection->SetInt64(mutable_message, field_descriptor, number);
              break;
            }
            case google::protobuf::FieldDescriptor::CPPTYPE_UINT32: {
              unsigned number;
              DCHECK(base::StringToUint(it->second, &number));
              reflection->SetUInt32(mutable_message, field_descriptor, number);
              break;
            }
            case google::protobuf::FieldDescriptor::CPPTYPE_UINT64: {
              uint64_t number;
              DCHECK(base::StringToUint64(it->second, &number));
              reflection->SetUInt64(mutable_message, field_descriptor, number);
              break;
            }
            case google::protobuf::FieldDescriptor::CPPTYPE_DOUBLE: {
              double number;
              DCHECK(base::StringToDouble(it->second, &number));
              reflection->SetDouble(mutable_message, field_descriptor, number);
              break;
            }
            case google::protobuf::FieldDescriptor::CPPTYPE_FLOAT: {
              double number;
              DCHECK(base::StringToDouble(it->second, &number));
              // static_cast will do ? cant remember that other unusual/fancy cast name for those situations
              reflection->SetFloat(mutable_message, field_descriptor, static_cast<float>(number));
              break;
            }
            case google::protobuf::FieldDescriptor::CPPTYPE_BOOL: {
              bool boolean = it->second == "true" ? true : false;
              reflection->SetBool(mutable_message, field_descriptor, boolean);
              break;
            }
            case google::protobuf::FieldDescriptor::CPPTYPE_ENUM: {
              int number;
              DCHECK(base::StringToInt(it->second, &number));
              const google::protobuf::EnumDescriptor* enum_descr = field_descriptor->enum_type();
              const google::protobuf::EnumValueDescriptor* enum_value_descr =  enum_descr->FindValueByNumber(number);
              if (enum_value_descr) {
                reflection->SetEnum(mutable_message, field_descriptor, enum_value_descr);
              }
              break;
            }
            // do nothing
            case google::protobuf::FieldDescriptor::CPPTYPE_MESSAGE:
            default:
             break;
          }
          break;
        }
      }
    }
  }
  
  if (!mutable_message->SerializeToString(out)) {
    return false;
  }
  return true;
}

#if defined(OS_POSIX)
void CommandExecutor::ProcessSigint(int sig) {
  if (command_) {
    command_->ProcessSigint(sig);
  }
}
#endif
