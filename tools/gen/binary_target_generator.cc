// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "gen/binary_target_generator.h"

#include "gen/config_values_generator.h"
#include "gen/deps_iterator.h"
#include "gen/err.h"
#include "gen/filesystem_utils.h"
#include "gen/functions.h"
#include "gen/scope.h"
#include "gen/settings.h"
#include "gen/value_extractors.h"
#include "gen/variables.h"
#include "gen/config.h"

BinaryTargetGenerator::BinaryTargetGenerator(
    Target* target,
    Scope* scope,
    const FunctionCallNode* function_call,
    Target::OutputType type,
    Err* err)
    : TargetGenerator(target, scope, function_call, err),
      output_type_(type) {
}

BinaryTargetGenerator::~BinaryTargetGenerator() = default;

void BinaryTargetGenerator::DoRun() {
  target_->set_output_type(output_type_);

  if (!FillOutputName())
    return;

  if (!FillOutputPrefixOverride())
    return;

  if (!FillOutputDir())
    return;

  if (!FillOutputExtension())
    return;

  if (!FillSources())
    return;

  if (!FillPublic())
    return;

  if (!FillFriends())
    return;

  if (!FillCheckIncludes())
    return;

  if (!FillConfigs())
    return;

  if (!FillAllowCircularIncludesFrom())
    return;

  if (!FillCompleteStaticLib())
    return;

  // Config values (compiler flags, etc.) set directly on this target.
  ConfigValuesGenerator gen(&target_->config_values(), scope_,
                            scope_->GetSourceDir(), err_);
  gen.Run();
  if (err_->has_error())
    return;

  if (!FillIfSwiftTarget()) {
    return;
  }
}

bool BinaryTargetGenerator::FillCompleteStaticLib() {
  if (target_->output_type() == Target::STATIC_LIBRARY) {
    const Value* value = scope_->GetValue(variables::kCompleteStaticLib, true);
    if (!value)
      return true;
    if (!value->VerifyTypeIs(Value::BOOLEAN, err_))
      return false;
    target_->set_complete_static_lib(value->boolean_value());
  }
  return true;
}

bool BinaryTargetGenerator::FillFriends() {
  const Value* value = scope_->GetValue(variables::kFriend, true);
  if (value) {
    return ExtractListOfLabelPatterns(*value, scope_->GetSourceDir(),
                                      &target_->friends(), err_);
  }
  return true;
}

bool BinaryTargetGenerator::FillOutputName() {
  const Value* value = scope_->GetValue(variables::kOutputName, true);
  if (!value)
    return true;
  if (!value->VerifyTypeIs(Value::STRING, err_))
    return false;
  target_->set_output_name(value->string_value());
  return true;
}

bool BinaryTargetGenerator::FillOutputPrefixOverride() {
  const Value* value = scope_->GetValue(variables::kOutputPrefixOverride, true);
  if (!value)
    return true;
  if (!value->VerifyTypeIs(Value::BOOLEAN, err_))
    return false;
  target_->set_output_prefix_override(value->boolean_value());
  return true;
}

bool BinaryTargetGenerator::FillOutputDir() {
  const Value* value = scope_->GetValue(variables::kOutputDir, true);
  if (!value)
    return true;
  if (!value->VerifyTypeIs(Value::STRING, err_))
    return false;

  if (value->string_value().empty())
    return true;  // Treat empty string as the default and do nothing.

  const BuildSettings* build_settings = scope_->settings()->build_settings();
  SourceDir dir = scope_->GetSourceDir().ResolveRelativeDir(
      *value, err_, build_settings->root_path_utf8());
  if (err_->has_error())
    return false;

//  if (!EnsureStringIsInOutputDir(build_settings->build_dir(),
 //                                dir.value(), value->origin(), err_))
//    return false;
  target_->set_output_dir(dir);
  return true;
}

bool BinaryTargetGenerator::FillOutputExtension() {
  const Value* value = scope_->GetValue(variables::kOutputExtension, true);
  if (!value)
    return true;
  if (!value->VerifyTypeIs(Value::STRING, err_))
    return false;
  target_->set_output_extension(value->string_value());
  return true;
}

bool BinaryTargetGenerator::FillAllowCircularIncludesFrom() {
  const Value* value = scope_->GetValue(
      variables::kAllowCircularIncludesFrom, true);
  if (!value)
    return true;

  UniqueVector<Label> circular;
  ExtractListOfUniqueLabels(*value, scope_->GetSourceDir(),
                            ToolchainLabelForScope(scope_), &circular, err_);
  if (err_->has_error())
    return false;

  // Validate that all circular includes entries are in the deps.
  for (const auto& cur : circular) {
    bool found_dep = false;
    for (const auto& dep_pair : target_->GetDeps(Target::DEPS_LINKED)) {
      if (dep_pair.label == cur) {
        found_dep = true;
        break;
      }
    }
    if (!found_dep) {
      *err_ = Err(*value, "Label not in deps.",
          "The label \"" + cur.GetUserVisibleName(false) +
          "\"\nwas not in the deps of this target. "
          "allow_circular_includes_from only allows\ntargets present in the "
          "deps.");
      return false;
    }
  }

  // Add to the set.
  for (const auto& cur : circular)
    target_->allow_circular_includes_from().insert(cur);
  return true;
}

bool BinaryTargetGenerator::FillIfSwiftTarget() {
 //  std::vector<SourceFile> module_maps;
  
 //  if (!is_swift_target_) {
 //    return true;
 //  }

 //  // 1 - add extra includes
 //  // TODO: maybe if we use rebase
 //  std::string out_dir = 
 //    target_->settings()->build_settings()->root_path_utf8() + 
 //    target_->settings()->toolchain_output_dir().value().substr(
 //      target_->settings()->toolchain_output_dir().value().find('/')+1);
    
 //  //for (auto& mut_config : target_->configs()) {
 //  //if (target_->configs().size() > 0) {
 //    //std::vector<SourceDir>& include_dirs = target_->configs()[0].ptr->own_values().include_dirs();
 //    //scoped_refptr<Config> config_ptr = target_->configs()[0].ptr;
 //    //if (!config_ptr) {
 //     //  Err err(
 //     //   target_->defined_from(),
 //     //   "NinjaBinaryTargetWriter::WriteCompilerVars: failed getting config ptr");
 //     // g_scheduler->FailWithError(err);
 //    //  *err_ = Err(
 //    //    target_->defined_from(),
 //    //    "NinjaBinaryTargetWriter::WriteCompilerVars: failed getting config ptr");
      
 //    //  return false;
 //    //}
 //    for (const auto& pair : target_->private_deps()) {//target_->GetDeps(Target::DEPS_ALL)) {
 //      scoped_refptr<Target> dep_target = pair.ptr;
 //      if (!dep_target) {
 //        DLOG(ERROR) << "bad: dependency(target) " << pair.label.name() << " is coming out null";
 //        continue;
 //      }
 //      std::string middle_path;
 //      if (dep_target->sources().size() > 0) {
 //        middle_path = dep_target->sources()[0].GetDir().value();
 //        auto off = middle_path.find("Sources");
 //        if (off != std::string::npos) {
 //          middle_path = middle_path.substr(1, off-2);
 //        } else {
 //          middle_path = middle_path.substr(1, middle_path.size()-2);
 //        }
 //      }
 //      std::string fullpath = out_dir + "obj" + middle_path;
 //      //config_ptr->own_values().include_dirs().push_back(SourceDir(fullpath));
 //      target_->config_values().include_dirs().push_back(SourceDir(fullpath));

 //      if (dep_target->has_module_map()) { 
 //        module_maps.push_back(dep_target->module_map());
 //      }
 //    }
 //  //}

 //  // 2 - generate output map
 //  // DLOG(INFO) << "generating output map..";

 //  // 3 - add output map path
  
 //  // output map
  
 //  // resolve deps and see if there's a dep with module map 
 // // for (const auto& dep : target_->GetDeps(Target::DEPS_ALL)) {
 // //   scoped_refptr<Target> dep_target = dep.ptr;
 // //   if (dep_target->has_module_map()) { 
 // //     module_maps.push_back(dep_target->module_map());
 // //   }
 // // }
  
 //  // add the module maps found to the cflags_swift
 //  for (const auto& source : module_maps) {
 //    std::string out = "-fmodule-map-file=";
 //    out.append(target_->settings()->build_settings()->root_path_utf8());
    
 //    const std::string& source_str = source.value();
    
 //    if (source_str.size() > 1 && source_str[1] == '/') {
 //      out.append(source_str.substr(1));
 //    } else {
 //      out.append(source_str);
 //    }

 //    target_->config_values().cflags_swift().push_back("-Xcc");
 //    target_->config_values().cflags_swift().push_back(out);
 //  }

  return true;
}
