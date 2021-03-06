//
// Copyright 2015 gRPC authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

#include "rpc/transport/service_config.h"

#include <string.h>

#include <rpc/impl/codegen/grpc_types.h>
#include <rpc/support/alloc.h>
#include <rpc/support/log.h>
#include <rpc/support/string_util.h>

#include "rpc/json/json.h"
#include "rpc/slice/slice_hash_table.h"
#include "rpc/slice/slice_internal.h"
#include "rpc/slice/slice_string_helpers.h"
#include "rpc/support/string.h"

// The main purpose of the code here is to parse the service config in
// JSON form, which will look like this:
//
// {
//   "loadBalancingPolicy": "string",  // optional
//   "methodConfig": [  // array of one or more method_config objects
//     {
//       "name": [  // array of one or more name objects
//         {
//           "service": "string",  // required
//           "method": "string",  // optional
//         }
//       ],
//       // remaining fields are optional.
//       // see https://developers.google.com/protocol-buffers/docs/proto3#json
//       // for format details.
//       "waitForReady": bool,
//       "timeout": "duration_string",
//       "maxRequestMessageBytes": "int64_string",
//       "maxResponseMessageBytes": "int64_string",
//     }
//   ]
// }

struct grpc_service_config {
  char* json_string;  // Underlying storage for json_tree.
  grpc_json* json_tree;
};

grpc_service_config* grpc_service_config_create(const char* json_string) {
  grpc_service_config* service_config =
      (grpc_service_config*)gpr_malloc(sizeof(*service_config));
  service_config->json_string = gpr_strdup(json_string);
  service_config->json_tree =
      grpc_json_parse_string(service_config->json_string);
  if (service_config->json_tree == nullptr) {
    gpr_log(GPR_INFO, "failed to parse JSON for service config");
    gpr_free(service_config->json_string);
    gpr_free(service_config);
    return nullptr;
  }
  return service_config;
}

void grpc_service_config_destroy(grpc_service_config* service_config) {
  grpc_json_destroy(service_config->json_tree);
  gpr_free(service_config->json_string);
  gpr_free(service_config);
}

void grpc_service_config_parse_global_params(
    const grpc_service_config* service_config,
    void (*process_json)(const grpc_json* json, void* arg), void* arg) {
  const grpc_json* json = service_config->json_tree;
  if (json->type != GRPC_JSON_OBJECT || json->key != nullptr) return;
  for (grpc_json* field = json->child; field != nullptr; field = field->next) {
    if (field->key == nullptr) return;
    if (strcmp(field->key, "methodConfig") == 0) continue;
    process_json(field, arg);
  }
}

const char* grpc_service_config_get_lb_policy_name(
    const grpc_service_config* service_config) {
  const grpc_json* json = service_config->json_tree;
  if (json->type != GRPC_JSON_OBJECT || json->key != nullptr) return nullptr;
  const char* lb_policy_name = nullptr;
  for (grpc_json* field = json->child; field != nullptr; field = field->next) {
    if (field->key == nullptr) return nullptr;
    if (strcmp(field->key, "loadBalancingPolicy") == 0) {
      if (lb_policy_name != nullptr) return nullptr;  // Duplicate.
      if (field->type != GRPC_JSON_STRING) return nullptr;
      lb_policy_name = field->value;
    }
  }
  return lb_policy_name;
}

// Returns the number of names specified in the method config \a json.
static size_t count_names_in_method_config_json(grpc_json* json) {
  size_t num_names = 0;
  for (grpc_json* field = json->child; field != nullptr; field = field->next) {
    if (field->key != nullptr && strcmp(field->key, "name") == 0) {
      if (field->type != GRPC_JSON_ARRAY) return -1;
      for (grpc_json* name = field->child; name != nullptr; name = name->next) {
        if (name->type != GRPC_JSON_OBJECT) return -1;
        ++num_names;
      }
    }
  }
  return num_names;
}

// Returns a path string for the JSON name object specified by \a json.
// Returns NULL on error.  Caller takes ownership of result.
static char* parse_json_method_name(grpc_json* json) {
  if (json->type != GRPC_JSON_OBJECT) return nullptr;
  const char* service_name = nullptr;
  const char* method_name = nullptr;
  for (grpc_json* child = json->child; child != nullptr; child = child->next) {
    if (child->key == nullptr) return nullptr;
    if (child->type != GRPC_JSON_STRING) return nullptr;
    if (strcmp(child->key, "service") == 0) {
      if (service_name != nullptr) return nullptr;  // Duplicate.
      if (child->value == nullptr) return nullptr;
      service_name = child->value;
    } else if (strcmp(child->key, "method") == 0) {
      if (method_name != nullptr) return nullptr;  // Duplicate.
      if (child->value == nullptr) return nullptr;
      method_name = child->value;
    }
  }
  if (service_name == nullptr) return nullptr;  // Required field.
  char* path;
  gpr_asprintf(&path, "/%s/%s", service_name,
               method_name == nullptr ? "*" : method_name);
  return path;
}

// Parses the method config from \a json.  Adds an entry to \a entries for
// each name found, incrementing \a idx for each entry added.
// Returns false on error.
static bool parse_json_method_config(
    grpc_exec_ctx* exec_ctx, grpc_json* json,
    void* (*create_value)(const grpc_json* method_config_json),
    void* (*ref_value)(void* value),
    void (*unref_value)(grpc_exec_ctx* exec_ctx, void* value),
    grpc_slice_hash_table_entry* entries, size_t* idx) {
  // Construct value.
  void* method_config = create_value(json);
  if (method_config == nullptr) return false;
  // Construct list of paths.
  bool success = false;
  gpr_strvec paths;
  gpr_strvec_init(&paths);
  for (grpc_json* child = json->child; child != nullptr; child = child->next) {
    if (child->key == nullptr) continue;
    if (strcmp(child->key, "name") == 0) {
      if (child->type != GRPC_JSON_ARRAY) goto done;
      for (grpc_json* name = child->child; name != nullptr; name = name->next) {
        char* path = parse_json_method_name(name);
        if (path == nullptr) goto done;
        gpr_strvec_add(&paths, path);
      }
    }
  }
  if (paths.count == 0) goto done;  // No names specified.
  // Add entry for each path.
  for (size_t i = 0; i < paths.count; ++i) {
    entries[*idx].key = grpc_slice_from_copied_string(paths.strs[i]);
    entries[*idx].value = ref_value(method_config);
    ++*idx;
  }
  success = true;
done:
  unref_value(exec_ctx, method_config);
  gpr_strvec_destroy(&paths);
  return success;
}

grpc_slice_hash_table* grpc_service_config_create_method_config_table(
    grpc_exec_ctx* exec_ctx, const grpc_service_config* service_config,
    void* (*create_value)(const grpc_json* method_config_json),
    void* (*ref_value)(void* value),
    void (*unref_value)(grpc_exec_ctx* exec_ctx, void* value)) {
  const grpc_json* json = service_config->json_tree;
  // Traverse parsed JSON tree.
  if (json->type != GRPC_JSON_OBJECT || json->key != nullptr) return nullptr;
  size_t num_entries = 0;
  grpc_slice_hash_table_entry* entries = nullptr;
  for (grpc_json* field = json->child; field != nullptr; field = field->next) {
    if (field->key == nullptr) return nullptr;
    if (strcmp(field->key, "methodConfig") == 0) {
      if (entries != nullptr) return nullptr;  // Duplicate.
      if (field->type != GRPC_JSON_ARRAY) return nullptr;
      // Find number of entries.
      for (grpc_json* method = field->child; method != nullptr;
           method = method->next) {
        size_t count = count_names_in_method_config_json(method);
        if (count <= 0) return nullptr;
        num_entries += count;
      }
      // Populate method config table entries.
      entries = (grpc_slice_hash_table_entry*)gpr_malloc(
          num_entries * sizeof(grpc_slice_hash_table_entry));
      size_t idx = 0;
      for (grpc_json* method = field->child; method != nullptr;
           method = method->next) {
        if (!parse_json_method_config(exec_ctx, method, create_value, ref_value,
                                      unref_value, entries, &idx)) {
          for (size_t i = 0; i < idx; ++i) {
            grpc_slice_unref_internal(exec_ctx, entries[i].key);
            unref_value(exec_ctx, entries[i].value);
          }
          gpr_free(entries);
          return nullptr;
        }
      }
      GPR_ASSERT(idx == num_entries);
    }
  }
  // Instantiate method config table.
  grpc_slice_hash_table* method_config_table = nullptr;
  if (entries != nullptr) {
    method_config_table = grpc_slice_hash_table_create(num_entries, entries,
                                                       unref_value, nullptr);
    gpr_free(entries);
  }
  return method_config_table;
}

void* grpc_method_config_table_get(grpc_exec_ctx* exec_ctx,
                                   const grpc_slice_hash_table* table,
                                   grpc_slice path) {
  void* value = grpc_slice_hash_table_get(table, path);
  // If we didn't find a match for the path, try looking for a wildcard
  // entry (i.e., change "/service/method" to "/service/*").
  if (value == nullptr) {
    char* path_str = grpc_slice_to_c_string(path);
    const char* sep = strrchr(path_str, '/') + 1;
    const size_t len = (size_t)(sep - path_str);
    char* buf = (char*)gpr_malloc(len + 2);  // '*' and NUL
    memcpy(buf, path_str, len);
    buf[len] = '*';
    buf[len + 1] = '\0';
    grpc_slice wildcard_path = grpc_slice_from_copied_string(buf);
    gpr_free(buf);
    value = grpc_slice_hash_table_get(table, wildcard_path);
    grpc_slice_unref_internal(exec_ctx, wildcard_path);
    gpr_free(path_str);
  }
  return value;
}
