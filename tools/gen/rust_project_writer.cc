// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "gn/rust_project_writer.h"

#include <fstream>
#include <optional>
#include <sstream>
#include <tuple>

#include "base/json/string_escape.h"
#include "gn/builder.h"
#include "gn/deps_iterator.h"
#include "gn/filesystem_utils.h"
#include "gn/ninja_target_command_util.h"
#include "gn/rust_project_writer_helpers.h"
#include "gn/rust_tool.h"
#include "gn/source_file.h"
#include "gn/string_output_buffer.h"
#include "gn/tool.h"

#if defined(OS_WINDOWS)
#define NEWLINE "\r\n"
#else
#define NEWLINE "\n"
#endif

// Current structure of rust-project.json output file
//
// {
//    "roots": [
//      "some/source/root"  // each crate's source root
//    ],
//    "crates": [
//        {
//            "deps": [
//                {
//                    "crate": 1, // index into crate array
//                    "name": "alloc" // extern name of dependency
//                },
//            ],
//            "edition": "2018", // edition of crate
//            "cfg": [
//              "unix", // "atomic" value config options
//              "rust_panic=\"abort\""", // key="value" config options
//            ]
//            "root_module": "absolute path to crate",
//            "label": "//path/target:value", // GN target for the crate
//            "target": "x86_64-unknown-linux" // optional rustc target
//        },
// }
//

bool RustProjectWriter::RunAndWriteFiles(const BuildSettings* build_settings,
                                         const Builder& builder,
                                         const std::string& file_name,
                                         bool quiet,
                                         Err* err) {
  SourceFile output_file = build_settings->build_dir().ResolveRelativeFile(
      Value(nullptr, file_name), err);
  if (output_file.is_null())
    return false;

  base::FilePath output_path = build_settings->GetFullPath(output_file);

  std::vector<const Target*> all_targets = builder.GetAllResolvedTargets();

  StringOutputBuffer out_buffer;
  std::ostream out(&out_buffer);

  RenderJSON(build_settings, all_targets, out);

  if (out_buffer.ContentsEqual(output_path)) {
    return true;
  }

  return out_buffer.WriteToFile(output_path, err);
}

// Map of Targets to their index in the crates list (for linking dependencies to
// their indexes).
using TargetIndexMap = std::unordered_map<const Target*, uint32_t>;

// A collection of Targets.
using TargetsVector = UniqueVector<const Target*>;

// Get the Rust deps for a target, recursively expanding OutputType::GROUPS
// that are present in the GN structure.  This will return a flattened list of
// deps from the groups, but will not expand a Rust lib dependency to find any
// transitive Rust dependencies.
void GetRustDeps(const Target* target, TargetsVector* rust_deps) {
  for (const auto& pair : target->GetDeps(Target::DEPS_LINKED)) {
    const Target* dep = pair.ptr;

    if (dep->source_types_used().RustSourceUsed()) {
      // Include any Rust dep.
      rust_deps->push_back(dep);
    } else if (dep->output_type() == Target::OutputType::GROUP) {
      // Inspect (recursively) any group to see if it contains Rust deps.
      GetRustDeps(dep, rust_deps);
    }
  }
}
TargetsVector GetRustDeps(const Target* target) {
  TargetsVector deps;
  GetRustDeps(target, &deps);
  return deps;
}

std::vector<std::string> ExtractCompilerArgs(const Target* target) {
  std::vector<std::string> args;
  for (ConfigValuesIterator iter(target); !iter.done(); iter.Next()) {
    auto rustflags = iter.cur().rustflags();
    for (auto flag_iter = rustflags.begin(); flag_iter != rustflags.end();
         flag_iter++) {
      args.push_back(*flag_iter);
    }
  }
  return args;
}

std::optional<std::string> FindArgValue(const char* arg,
                                        const std::vector<std::string>& args) {
  for (auto current = args.begin(); current != args.end();) {
    // capture the current value
    auto previous = *current;
    // and increment
    current++;

    // if the previous argument matches `arg`, and after the above increment the
    // end hasn't been reached, this current argument is the desired value.
    if (previous == arg && current != args.end()) {
      return std::make_optional(*current);
    }
  }
  return std::nullopt;
}

std::optional<std::string> FindArgValueAfterPrefix(
    const std::string& prefix,
    const std::vector<std::string>& args) {
  for (auto arg : args) {
    if (!arg.compare(0, prefix.size(), prefix)) {
      auto value = arg.substr(prefix.size());
      return std::make_optional(value);
    }
  }
  return std::nullopt;
}

std::vector<std::string> FindAllArgValuesAfterPrefix(
    const std::string& prefix,
    const std::vector<std::string>& args) {
  std::vector<std::string> values;
  for (auto arg : args) {
    if (!arg.compare(0, prefix.size(), prefix)) {
      auto value = arg.substr(prefix.size());
      values.push_back(value);
    }
  }
  return values;
}

// TODO(bwb) Parse sysroot structure from toml files. This is fragile and
// might break if upstream changes the dependency structure.
const std::string_view sysroot_crates[] = {"std",
                                           "core",
                                           "alloc",
                                           "panic_unwind",
                                           "proc_macro",
                                           "test",
                                           "panic_abort",
                                           "unwind"};

// Multiple sysroot crates have dependenices on each other.  This provides a
// mechanism for specifying that in an extendible manner.
const std::unordered_map<std::string_view, std::vector<std::string_view>>
    sysroot_deps_map = {{"alloc", {"core"}},
                        {"std", {"alloc", "core", "panic_abort", "unwind"}}};

// Add each of the crates a sysroot has, including their dependencies.
void AddSysrootCrate(const BuildSettings* build_settings,
                     const std::string_view crate,
                     const std::string_view current_sysroot,
                     SysrootCrateIndexMap& sysroot_crate_lookup,
                     CrateList& crate_list) {
  if (sysroot_crate_lookup.find(crate) != sysroot_crate_lookup.end()) {
    // If this sysroot crate is already in the lookup, we don't add it again.
    return;
  }

  // Add any crates that this sysroot crate depends on.
  auto deps_lookup = sysroot_deps_map.find(crate);
  if (deps_lookup != sysroot_deps_map.end()) {
    auto deps = (*deps_lookup).second;
    for (auto dep : deps) {
      AddSysrootCrate(build_settings, dep, current_sysroot,
                      sysroot_crate_lookup, crate_list);
    }
  }

  size_t crate_index = crate_list.size();
  sysroot_crate_lookup.insert(std::make_pair(crate, crate_index));

  base::FilePath rebased_out_dir =
      build_settings->GetFullPath(build_settings->build_dir());
  auto crate_path =
      FilePathToUTF8(rebased_out_dir) + std::string(current_sysroot) +
      "/lib/rustlib/src/rust/library/" + std::string(crate) + "/src/lib.rs";

  Crate sysroot_crate =
      Crate(SourceFile(crate_path), crate_index, std::string(crate), "2018");

  sysroot_crate.AddConfigItem("debug_assertions");

  if (deps_lookup != sysroot_deps_map.end()) {
    auto deps = (*deps_lookup).second;
    for (auto dep : deps) {
      auto idx = sysroot_crate_lookup[dep];
      sysroot_crate.AddDependency(idx, std::string(dep));
    }
  }

  crate_list.push_back(sysroot_crate);
}

// Add the given sysroot to the project, if it hasn't already been added.
void AddSysroot(const BuildSettings* build_settings,
                const std::string_view sysroot,
                SysrootIndexMap& sysroot_lookup,
                CrateList& crate_list) {
  // If this sysroot is already in the lookup, we don't add it again.
  if (sysroot_lookup.find(sysroot) != sysroot_lookup.end()) {
    return;
  }

  // Otherwise, add all of its crates
  for (auto crate : sysroot_crates) {
    AddSysrootCrate(build_settings, crate, sysroot, sysroot_lookup[sysroot],
                    crate_list);
  }
}

void AddSysrootDependencyToCrate(Crate* crate,
                                 const SysrootCrateIndexMap& sysroot,
                                 const std::string_view crate_name) {
  if (const auto crate_idx = sysroot.find(crate_name);
      crate_idx != sysroot.end()) {
    crate->AddDependency(crate_idx->second, std::string(crate_name));
  }
}

void AddTarget(const BuildSettings* build_settings,
               const Target* target,
               TargetIndexMap& lookup,
               SysrootIndexMap& sysroot_lookup,
               CrateList& crate_list) {
  if (lookup.find(target) != lookup.end()) {
    // If target is already in the lookup, we don't add it again.
    return;
  }

  auto compiler_args = ExtractCompilerArgs(target);
  auto compiler_target = FindArgValue("--target", compiler_args);

  // Check what sysroot this target needs.  Add it to the crate list if it
  // hasn't already been added.
  auto rust_tool =
      target->toolchain()->GetToolForTargetFinalOutputAsRust(target);
  auto current_sysroot = rust_tool->GetSysroot();
  if (current_sysroot != "" && sysroot_lookup.count(current_sysroot) == 0) {
    AddSysroot(build_settings, current_sysroot, sysroot_lookup, crate_list);
  }

  auto crate_deps = GetRustDeps(target);

  // Add all dependencies of this crate, before this crate.
  for (const auto& dep : crate_deps) {
    AddTarget(build_settings, dep, lookup, sysroot_lookup, crate_list);
  }

  // The index of a crate is its position (0-based) in the list of crates.
  size_t crate_id = crate_list.size();

  // Add the target to the crate lookup.
  lookup.insert(std::make_pair(target, crate_id));

  SourceFile crate_root = target->rust_values().crate_root();
  std::string crate_label = target->label().GetUserVisibleName(false);

  auto edition =
      FindArgValueAfterPrefix(std::string("--edition="), compiler_args);
  if (!edition.has_value()) {
    edition = FindArgValue("--edition", compiler_args);
  }

  Crate crate =
      Crate(crate_root, crate_id, crate_label, edition.value_or("2015"));

  crate.SetCompilerArgs(compiler_args);
  if (compiler_target.has_value())
    crate.SetCompilerTarget(compiler_target.value());

  ConfigList cfgs =
      FindAllArgValuesAfterPrefix(std::string("--cfg="), compiler_args);

  crate.AddConfigItem("test");
  crate.AddConfigItem("debug_assertions");

  for (auto& cfg : cfgs) {
    crate.AddConfigItem(cfg);
  }

  // Add the sysroot dependencies, if there is one.
  if (current_sysroot != "") {
    const auto& sysroot = sysroot_lookup[current_sysroot];
    AddSysrootDependencyToCrate(&crate, sysroot, "core");
    AddSysrootDependencyToCrate(&crate, sysroot, "alloc");
    AddSysrootDependencyToCrate(&crate, sysroot, "std");

    // Proc macros have the proc_macro crate as a direct dependency
    if (std::string_view(rust_tool->name()) ==
        std::string_view(RustTool::kRsToolMacro)) {
      AddSysrootDependencyToCrate(&crate, sysroot, "proc_macro");
    }
  }

  // Add the rest of the crate dependencies.
  for (const auto& dep : crate_deps) {
    auto idx = lookup[dep];
    crate.AddDependency(idx, dep->rust_values().crate_name());
  }

  crate_list.push_back(crate);
}

void WriteCrates(const BuildSettings* build_settings,
                 CrateList& crate_list,
                 std::ostream& rust_project) {
  // produce a de-duplicated set of source roots:
  std::set<std::string> roots;
  for (auto& crate : crate_list) {
    roots.insert(
        FilePathToUTF8(build_settings->GetFullPath(crate.root().GetDir())));
  }

  rust_project << "{" NEWLINE;
  rust_project << "  \"roots\": [";
  bool first_root = true;
  for (auto& root : roots) {
    if (!first_root)
      rust_project << ",";
    first_root = false;

    rust_project << NEWLINE "    \"" << root << "\"";
  }
  rust_project << NEWLINE "  ]," NEWLINE;
  rust_project << "  \"crates\": [";
  bool first_crate = true;
  for (auto& crate : crate_list) {
    if (!first_crate)
      rust_project << ",";
    first_crate = false;

    auto crate_module =
        FilePathToUTF8(build_settings->GetFullPath(crate.root()));

    rust_project << NEWLINE << "    {" NEWLINE
                 << "      \"crate_id\": " << crate.index() << "," NEWLINE
                 << "      \"root_module\": \"" << crate_module << "\"," NEWLINE
                 << "      \"label\": \"" << crate.label() << "\"," NEWLINE;

    auto compiler_target = crate.CompilerTarget();
    if (compiler_target.has_value()) {
      rust_project << "      \"target\": \"" << compiler_target.value()
                   << "\"," NEWLINE;
    }

    auto compiler_args = crate.CompilerArgs();
    if (!compiler_args.empty()) {
      rust_project << "      \"compiler_args\": [";
      bool first_arg = true;
      for (auto& arg : crate.CompilerArgs()) {
        if (!first_arg)
          rust_project << ", ";
        first_arg = false;

        std::string escaped_arg;
        base::EscapeJSONString(arg, false, &escaped_arg);

        rust_project << "\"" << escaped_arg << "\"";
      }
      rust_project << "]," << NEWLINE;
    }

    rust_project << "      \"deps\": [";
    bool first_dep = true;
    for (auto& dep : crate.dependencies()) {
      if (!first_dep)
        rust_project << ",";
      first_dep = false;

      rust_project << NEWLINE << "        {" NEWLINE
                   << "          \"crate\": " << dep.first << "," NEWLINE
                   << "          \"name\": \"" << dep.second << "\"" NEWLINE
                   << "        }";
    }
    rust_project << NEWLINE "      ]," NEWLINE;  // end dep list

    rust_project << "      \"edition\": \"" << crate.edition() << "\"," NEWLINE;

    rust_project << "      \"cfg\": [";
    bool first_cfg = true;
    for (const auto& cfg : crate.configs()) {
      if (!first_cfg)
        rust_project << ",";
      first_cfg = false;

      std::string escaped_config;
      base::EscapeJSONString(cfg, false, &escaped_config);

      rust_project << NEWLINE;
      rust_project << "        \"" << escaped_config << "\"";
    }
    rust_project << NEWLINE;
    rust_project << "      ]" NEWLINE;  // end cfgs

    rust_project << "    }";  // end crate
  }
  rust_project << NEWLINE "  ]" NEWLINE;  // end crate list
  rust_project << "}" NEWLINE;
}

void RustProjectWriter::RenderJSON(const BuildSettings* build_settings,
                                   std::vector<const Target*>& all_targets,
                                   std::ostream& rust_project) {
  TargetIndexMap lookup;
  SysrootIndexMap sysroot_lookup;
  CrateList crate_list;

  // All the crates defined in the project.
  for (const auto* target : all_targets) {
    if (!target->IsBinary() || !target->source_types_used().RustSourceUsed())
      continue;

    AddTarget(build_settings, target, lookup, sysroot_lookup, crate_list);
  }

  WriteCrates(build_settings, crate_list, rust_project);
}
