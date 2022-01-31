// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TOOLS_GN_RUST_PROJECT_WRITER_HELPERS_H_
#define TOOLS_GN_RUST_PROJECT_WRITER_HELPERS_H_

#include <fstream>
#include <optional>
#include <sstream>
#include <string>
#include <tuple>
#include <unordered_map>
#include <vector>

#include "build_settings.h"
#include "gn/source_file.h"
#include "gn/target.h"

// These are internal types and helper functions for RustProjectWriter that have
// been extracted for easier testability.

// Crate Index in the generated file
using CrateIndex = size_t;

using ConfigList = std::vector<std::string>;
using Dependency = std::pair<CrateIndex, std::string>;
using DependencyList = std::vector<Dependency>;

// This class represents a crate to be serialized out as part of the
// rust-project.json file.  This is used to separate the generating
// of the data that needs to be in the file, from the file itself.
class Crate {
 public:
  Crate(SourceFile root,
        CrateIndex index,
        std::string label,
        std::string edition)
      : root_(root), index_(index), label_(label), edition_(edition) {}

  ~Crate() = default;

  // Add a config item to the crate.
  void AddConfigItem(std::string cfg_item) { configs_.push_back(cfg_item); }

  // Add another crate as a dependency of this one.
  void AddDependency(CrateIndex index, std::string name) {
    deps_.push_back(std::make_pair(index, name));
  }

  // Set the compiler arguments used to invoke the compilation of this crate
  void SetCompilerArgs(std::vector<std::string> args) { compiler_args_ = args; }

  // Set the compiler target ("e.g. x86_64-linux-kernel")
  void SetCompilerTarget(std::string target) { compiler_target_ = target; }

  // Returns the root file for the crate.
  SourceFile& root() { return root_; }

  // Returns the crate index.
  CrateIndex index() { return index_; };

  // Returns the displayable crate label.
  const std::string& label() { return label_; }

  // Returns the Rust Edition this crate uses.
  const std::string& edition() { return edition_; }

  // Return the set of config items for this crate.
  ConfigList& configs() { return configs_; }

  // Return the set of dependencies for this crate.
  DependencyList& dependencies() { return deps_; }

  // Return the compiler arguments used to invoke the compilation of this crate
  const std::vector<std::string>& CompilerArgs() { return compiler_args_; }

  // Return the compiler target "triple" from the compiler args
  const std::optional<std::string>& CompilerTarget() {
    return compiler_target_;
  }

 private:
  SourceFile root_;
  CrateIndex index_;
  std::string label_;
  std::string edition_;
  ConfigList configs_;
  DependencyList deps_;
  std::optional<std::string> compiler_target_;
  std::vector<std::string> compiler_args_;
};

using CrateList = std::vector<Crate>;

// Mapping of a sysroot crate (path) to it's index in the crates list.
using SysrootCrateIndexMap = std::unordered_map<std::string_view, CrateIndex>;

// Mapping of a sysroot (path) to the mapping of each of the sysroot crates to
// their index in the crates list.
using SysrootIndexMap =
    std::unordered_map<std::string_view, SysrootCrateIndexMap>;

// Add all of the crates for a sysroot (path) to the rust_project ostream.
// Add the given sysroot to the project, if it hasn't already been added.
void AddSysroot(const BuildSettings* build_settings,
                const std::string_view sysroot,
                SysrootIndexMap& sysroot_lookup,
                CrateList& crate_list);

// Write the entire rust-project.json file contents into the given stream, based
// on the the given crates list.
void WriteCrates(const BuildSettings* build_settings,
                 CrateList& crate_list,
                 std::ostream& rust_project);

// Assemble the compiler arguments for the given GN Target.
std::vector<std::string> ExtractCompilerArgs(const Target* target);

// Find the value of an argument that's passed to the compiler as two
// consecutive strings in the list of arguments:  ["arg", "value"]
std::optional<std::string> FindArgValue(const char* arg,
                                        const std::vector<std::string>& args);

// Find the first argument that matches the prefix, returning the value after
// the prefix.  e.g. ˝--arg=value", is returned as "value" if the prefix
// "--arg=" is used.
std::optional<std::string> FindArgValueAfterPrefix(
    const std::string& prefix,
    const std::vector<std::string>& args);

// Find all arguments that match the given prefix, returning the value after
// the prefix for each one.  e.g. "--cfg=value" is returned as "value" if the
// prefix "--cfg=" is used.
std::vector<std::string> FindAllArgValuesAfterPrefix(
    const std::string& prefix,
    const std::vector<std::string>& args);


#endif  // TOOLS_GN_RUST_PROJECT_WRITER_HELPERS_H_
