// Copyright (c) 2018 Mutante. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "gen/swift_output_map_writer.h"

#include "build/build_config.h"
#include "base/files/file_util.h"
#include "base/strings/string_util.h"
#include "base/strings/utf_string_conversions.h"
#include "gen/deps_iterator.h"
#include "gen/err.h"
#include "gen/escape.h"
#include "gen/filesystem_utils.h"
#include "gen/scheduler.h"
#include "gen/settings.h"
#include "gen/source_file_type.h"
#include "gen/string_utils.h"
#include "gen/substitution_writer.h"
#include "gen/target.h"
#include "gen/ninja_utils.h"
#include "third_party/jsoncpp/source/include/json/json.h"

bool SwiftOutputMapWriter::WriteFile(scoped_refptr<Target> target) {

  OutputFile output_file_map_file =
      GetBuildDirForTargetAsOutputFile(target, BuildDirType::OBJ);

  std::string out_dir = target->settings()->build_settings()->root_path_utf8() +  
    target->settings()->toolchain_output_dir().value().substr(
      target->settings()->toolchain_output_dir().value().find('/')+1);
#if defined(OS_WIN)
  base::FilePath output_file_map_dir(base::ASCIIToUTF16(out_dir.append(output_file_map_file.value() + target->label().name())));
#elif defined(OS_POSIX)
  base::FilePath output_file_map_dir(out_dir.append(output_file_map_file.value() + target->label().name()));
#endif
  base::FilePath output_file_map_path = output_file_map_dir.AppendASCII("output-file-map.json");
  base::FilePath output_obj_dir = output_file_map_dir;

  Json::Value output(Json::objectValue);
  Json::Value dependencies(Json::objectValue);
#if defined(OS_WIN)
  dependencies["swift-dependencies"] = base::UTF16ToASCII(output_file_map_dir.value()) + "/master.swiftdeps";
#elif defined(OS_POSIX)
  dependencies["swift-dependencies"] = output_file_map_dir.value() + "/master.swiftdeps";
#endif
  output[""] = dependencies;

  // now for each source file
  std::vector<OutputFile> tool_outputs; 
    
  for (const auto& source : target->sources()) {
    Toolchain::ToolType tool_type = Toolchain::TYPE_NONE;

    if (!target->GetOutputFilesForSource(source, &tool_type, &tool_outputs)) {
      continue;
    }
    
    const std::string& source_file_name = source.GetName();
    const std::string& source_file_name_noext = source_file_name.substr(0, source_file_name.find_last_of('.'));
    const std::string& source_file_full = source.value().substr(1);
  
    Json::Value settings_body(Json::objectValue);
#if defined(OS_WIN)
    settings_body["dependencies"] = base::UTF16ToASCII(output_obj_dir.value()) + "/" + source_file_name_noext + ".d";
    settings_body["object"] = base::UTF16ToASCII(output_obj_dir.value()) + "/" + source_file_name_noext + ".o";
    settings_body["swiftmodule"] = base::UTF16ToASCII(output_obj_dir.value()) + "/" + source_file_name_noext + "~partial.swiftmodule";
    settings_body["swift-dependencies"] = base::UTF16ToASCII(output_obj_dir.value()) + "/" + source_file_name_noext + ".swiftdeps";
#elif defined(OS_POSIX)
    settings_body["dependencies"] = output_obj_dir.value() + "/" + source_file_name_noext + ".d";
    settings_body["object"] = output_obj_dir.value() + "/" + source_file_name_noext + ".o";
    settings_body["swiftmodule"] = output_obj_dir.value() + "/" + source_file_name_noext + "~partial.swiftmodule";
    settings_body["swift-dependencies"] = output_obj_dir.value() + "/" + source_file_name_noext + ".swiftdeps";
#endif
    // add it to the output obj
    output[target->settings()->build_settings()->root_path_utf8() + source_file_full] = settings_body;
  }

  Json::StyledWriter writer;
  std::string s = writer.write(output);
  if (s.empty()) {
    DLOG(ERROR) << "WriteOutputFileMap: failed writing json object to string";
    return false;
  }
    
  if (!base::DirectoryExists(output_file_map_dir)) {
    if (!base::CreateDirectory(output_file_map_dir)) {
      DLOG(ERROR) << "WriteOutputFileMap: failed creating directory " << output_file_map_dir.value();
      return false;
    }
    if (!base::CreateDirectory(output_obj_dir)) {
      DLOG(ERROR) << "WriteOutputFileMap: failed creating obj directory " << output_obj_dir.value();
      return false;
    }
  }

  if (!base::WriteFile(output_file_map_path, s.data(), s.size())) {
    DLOG(ERROR) << "WriteOutputFileMap: failed writing " << output_file_map_path.value();    
  }

  return true;
}