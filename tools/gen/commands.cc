// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "gen/commands.h"

#include "base/command_line.h"
#include "base/environment.h"
#include "base/strings/string_split.h"
#include "base/values.h"
#include "build/build_config.h"
#include "gen/builder.h"
#include "gen/filesystem_utils.h"
#include "gen/config.h"
#include "gen/item.h"
#include "gen/label.h"
#include "gen/label_pattern.h"
#include "gen/setup.h"
#include "gen/standard_out.h"
#include "gen/target.h"

namespace commands {

namespace {

// Like above but the input string can be a pattern that matches multiple
// targets. If the input does not parse as a pattern, prints and error and
// returns false. If the pattern is valid, fills the vector (which might be
// empty if there are no matches) and returns true.
//
// If all_toolchains is false, a pattern with an unspecified toolchain will
// match the default toolchain only. If true, all toolchains will be matched.
bool ResolveTargetsFromCommandLinePattern(
    Setup* setup,
    const std::string& label_pattern,
    bool all_toolchains,
    std::vector<Target*>* matches) {
  Value pattern_value(nullptr, label_pattern);

  Err err;
  LabelPattern pattern = LabelPattern::GetPattern(
      SourceDirForCurrentDirectory(setup->build_settings().root_path()),
      pattern_value,
      &err);
  if (err.has_error()) {
    err.PrintToStdout();
    return false;
  }

  if (!all_toolchains) {
    // By default a pattern with an empty toolchain will match all toolchains.
    // If the caller wants to default to the main toolchain only, set it
    // explicitly.
    if (pattern.toolchain().is_null()) {
      // No explicit toolchain set.
      pattern.set_toolchain(setup->loader()->default_toolchain_label());
    }
  }

  std::vector<LabelPattern> pattern_vector;
  pattern_vector.push_back(pattern);
  FilterTargetsByPatterns(setup->builder().GetAllResolvedTargets(),
                          pattern_vector, matches);
  return true;
}


// If there's an error, it will be printed and false will be returned.
bool ResolveStringFromCommandLineInput(
    Setup* setup,
    const SourceDir& current_dir,
    const std::string& input,
    bool all_toolchains,
    UniqueVector<Target*>* target_matches,
    UniqueVector<Config*>* config_matches,
    UniqueVector<Toolchain*>* toolchain_matches,
    UniqueVector<SourceFile>* file_matches) {
  if (LabelPattern::HasWildcard(input)) {
    // For now, only match patterns against targets. It might be nice in the
    // future to allow the user to specify which types of things they want to
    // match, but it should probably only match targets by default.
    std::vector<Target*> target_match_vector;
    if (!ResolveTargetsFromCommandLinePattern(setup, input, all_toolchains,
                                              &target_match_vector))
      return false;
    for (Target* target : target_match_vector)
      target_matches->push_back(target);
    return true;
  }

  // Try to figure out what this thing is.
  Err err;
  Label label = Label::Resolve(current_dir,
                               setup->loader()->default_toolchain_label(),
                               Value(nullptr, input), &err);
  if (err.has_error()) {
    // Not a valid label, assume this must be a file.
    err = Err();
    file_matches->push_back(current_dir.ResolveRelativeFile(
        Value(nullptr, input), &err, setup->build_settings().root_path_utf8()));
    if (err.has_error()) {
      err.PrintToStdout();
      return false;
    }
    return true;
  }

  scoped_refptr<Item> item = setup->builder().GetItem(label);
  if (item) {
    if (scoped_refptr<Config> as_config = item->AsConfig())
      config_matches->push_back(as_config.get());
    else if (scoped_refptr<Target> as_target = item->AsTarget())
      target_matches->push_back(as_target.get());
    else if (scoped_refptr<Toolchain> as_toolchain = item->AsToolchain())
      toolchain_matches->push_back(as_toolchain.get());
  } else {
    // Not an item, assume this must be a file.
    file_matches->push_back(current_dir.ResolveRelativeFile(
        Value(nullptr, input), &err, setup->build_settings().root_path_utf8()));
    if (err.has_error()) {
      err.PrintToStdout();
      return false;
    }
  }

  return true;
}

enum TargetPrintingMode {
  TARGET_PRINT_BUILDFILE,
  TARGET_PRINT_LABEL,
  TARGET_PRINT_OUTPUT,
};

// Retrieves the target printing mode based on the command line flags for the
// current process. Returns true on success. On error, prints a message to the
// console and returns false.
bool GetTargetPrintingMode(TargetPrintingMode* mode) {
  std::string switch_key = "as";
  const base::CommandLine* cmdline = base::CommandLine::ForCurrentProcess();

  if (!cmdline->HasSwitch(switch_key)) {
    // Default to labels.
    *mode = TARGET_PRINT_LABEL;
    return true;
  }

  std::string value = cmdline->GetSwitchValueASCII(switch_key);
  if (value == "buildfile") {
    *mode = TARGET_PRINT_BUILDFILE;
    return true;
  }
  if (value == "label") {
    *mode = TARGET_PRINT_LABEL;
    return true;
  }
  if (value == "output") {
    *mode = TARGET_PRINT_OUTPUT;
    return true;
  }

  Err(Location(), "Invalid value for \"--as\".",
      "I was expecting \"buildfile\", \"label\", or \"output\" but you\n"
      "said \"" + value + "\".").PrintToStdout();
  return false;
}

// Returns the target type filter based on the command line flags for the
// current process. Returns true on success. On error, prints a message to the
// console and returns false.
//
// Target::UNKNOWN will be set if there is no filter. Target::ACTION_FOREACH
// will never be returned. Code applying the filters should apply Target::ACTION
// to both ACTION and ACTION_FOREACH.
bool GetTargetTypeFilter(Target::OutputType* type) {
  std::string switch_key = "type";
  const base::CommandLine* cmdline = base::CommandLine::ForCurrentProcess();

  if (!cmdline->HasSwitch(switch_key)) {
    // Default to unknown -> no filtering.
    *type = Target::UNKNOWN;
    return true;
  }

  std::string value = cmdline->GetSwitchValueASCII(switch_key);
  if (value == "group") {
    *type = Target::GROUP;
    return true;
  }
  if (value == "executable") {
    *type = Target::EXECUTABLE;
    return true;
  }
  if (value == "shared_library") {
    *type = Target::SHARED_LIBRARY;
    return true;
  }
  if (value == "loadable_module") {
    *type = Target::LOADABLE_MODULE;
    return true;
  }
  if (value == "static_library") {
    *type = Target::STATIC_LIBRARY;
    return true;
  }
  if (value == "source_set") {
    *type = Target::SOURCE_SET;
    return true;
  }
  if (value == "copy") {
    *type = Target::COPY_FILES;
    return true;
  }
  if (value == "action") {
    *type = Target::ACTION;
    return true;
  }

  Err(Location(), "Invalid value for \"--type\".").PrintToStdout();
  return false;
}


// Applies any testonly filtering specified on the command line to the given
// target set. On failure, prints an error and returns false.
bool ApplyTestonlyFilter(std::vector<Target*>* targets) {
  const base::CommandLine* cmdline = base::CommandLine::ForCurrentProcess();
  std::string testonly_key = "testonly";

  if (targets->empty() || !cmdline->HasSwitch(testonly_key))
    return true;

  std::string testonly_value = cmdline->GetSwitchValueASCII(testonly_key);
  bool testonly = false;
  if (testonly_value == "true") {
    testonly = true;
  } else if (testonly_value != "false") {
    Err(Location(), "Bad value for --testonly.",
        "I was expecting --testonly=true or --testonly=false.")
        .PrintToStdout();
    return false;
  }

  // Filter into a copy of the vector, then swap to output.
  std::vector<Target*> result;
  result.reserve(targets->size());

  for (Target* target : *targets) {
    if (target->testonly() == testonly)
      result.push_back(target);
  }

  targets->swap(result);
  return true;
}

// Applies any target type filtering specified on the command line to the given
// target set. On failure, prints an error and returns false.
bool ApplyTypeFilter(std::vector<Target*>* targets) {
  Target::OutputType type = Target::UNKNOWN;
  if (!GetTargetTypeFilter(&type))
    return false;
  if (targets->empty() || type == Target::UNKNOWN)
    return true;  // Nothing to filter out.

  // Filter into a copy of the vector, then swap to output.
  std::vector<Target*> result;
  result.reserve(targets->size());

  for (Target* target : *targets) {
    // Make "action" also apply to ACTION_FOREACH.
    if (target->output_type() == type ||
        (type == Target::ACTION &&
         target->output_type() == Target::ACTION_FOREACH))
      result.push_back(target);
  }

  targets->swap(result);
  return true;
}

// Returns the file path generating this item.
base::FilePath BuildFileForItem(Item* item) {
  return item->defined_from()->GetRange().begin().file()->physical_name();
}

void PrintTargetsAsBuildfiles(const std::vector<Target*>& targets,
                              base::ListValue* out) {
  // Output the set of unique source files.
  std::set<std::string> unique_files;
  for (Target* target : targets)
    unique_files.insert(FilePathToUTF8(BuildFileForItem(target)));

  for (const std::string& file : unique_files) {
    out->AppendString(file);
  }
}

void PrintTargetsAsLabels(const std::vector<Target*>& targets,
                          base::ListValue* out) {
  // Putting the labels into a set automatically sorts them for us.
  std::set<Label> unique_labels;
  for (auto* target : targets)
    unique_labels.insert(target->label());

  // Grab the label of the default toolchain from the first target.
  Label default_tc_label =
      targets[0]->settings()->default_toolchain_label();

  for (const Label& label : unique_labels) {
    // Print toolchain only for ones not in the default toolchain.
    out->AppendString(label.GetUserVisibleName(label.GetToolchainLabel() !=
                                               default_tc_label));
  }
}

void PrintTargetsAsOutputs(const std::vector<Target*>& targets,
                           base::ListValue* out) {
  if (targets.empty())
    return;

  // Grab the build settings from a random target.
  const BuildSettings* build_settings =
      targets[0]->settings()->build_settings();

  for (const Target* target : targets) {
    // Use the link output file if there is one, otherwise fall back to the
    // dependency output file (for actions, for example).
    OutputFile output_file = target->link_output_file();
    if (output_file.value().empty())
      output_file = target->dependency_output_file();

    SourceFile output_as_source =
        output_file.AsSourceFile(build_settings);
    std::string result = RebasePath(output_as_source.value(),
                                    build_settings->build_dir(),
                                    build_settings->root_path_utf8());
    out->AppendString(result);
  }
}

#if defined(OS_WIN)
// Git bash will remove the first "/" in "//" paths
// This also happens for labels assigned to command line parameters, e.g.
// --filters
// Fix "//" paths, but not absolute and relative paths
inline std::string FixGitBashLabelEdit(const std::string& label) {
  static std::unique_ptr<base::Environment> git_bash_env;
  if (!git_bash_env)
    git_bash_env = base::Environment::Create();

  std::string temp_label(label);

  if (git_bash_env->HasVar(
          "MSYSTEM") &&        // Only for MinGW based shells like Git Bash
      temp_label[0] == '/' &&  // Only fix for //foo paths, not /f:oo paths
      (temp_label.length() < 2 ||
       (temp_label[1] != '/' &&
        (temp_label.length() < 3 || temp_label[1] != ':'))))
    temp_label.insert(0, "/");
  return temp_label;
}
#else
// Only repair on Windows
inline std::string FixGitBashLabelEdit(const std::string& label) {
  return label;
}
#endif


}  // namespace

CommandInfo::CommandInfo()
    : help_short(nullptr),
      help(nullptr),
      runner(nullptr) {
}

CommandInfo::CommandInfo(const char* in_help_short,
                         const char* in_help,
                         CommandRunner in_runner)
    : help_short(in_help_short),
      help(in_help),
      runner(in_runner) {
}

const CommandInfoMap& GetCommands() {
  static CommandInfoMap info_map;
  if (info_map.empty()) {
    #define INSERT_COMMAND(cmd) \
        info_map[k##cmd] = CommandInfo(k##cmd##_HelpShort, \
                                       k##cmd##_Help, \
                                       &Run##cmd);

    INSERT_COMMAND(Analyze)
    INSERT_COMMAND(Args)
    INSERT_COMMAND(Check)
    INSERT_COMMAND(Clean)
    INSERT_COMMAND(Desc)
    INSERT_COMMAND(Gen)
    INSERT_COMMAND(Format)
    INSERT_COMMAND(Help)
    INSERT_COMMAND(Ls)
    INSERT_COMMAND(Path)
    INSERT_COMMAND(Refs)

    #undef INSERT_COMMAND
  }
  return info_map;
}

scoped_refptr<Target> ResolveTargetFromCommandLineString(
    Setup* setup,
    const std::string& label_string) {
  // Need to resolve the label after we know the default toolchain.
  Label default_toolchain = setup->loader()->default_toolchain_label();
  Value arg_value(nullptr, FixGitBashLabelEdit(label_string));
  Err err;
  Label label = Label::Resolve(SourceDirForCurrentDirectory(
                                   setup->build_settings().root_path()),
                               default_toolchain, arg_value, &err);
  if (err.has_error()) {
    err.PrintToStdout();
    return nullptr;
  }

  scoped_refptr<Item> item = setup->builder().GetItem(label);
  if (!item) {
    Err(Location(), "Label not found.",
        label.GetUserVisibleName(false) + " not found.").PrintToStdout();
    return nullptr;
  }

  scoped_refptr<Target> target = item->AsTarget();
  if (!target) {
    Err(Location(), "Not a target.",
        "The \"" + label.GetUserVisibleName(false) + "\" thing\n"
        "is not a target. Somebody should probably implement this command for "
        "other\nitem types.").PrintToStdout();
    return nullptr;
  }

  return target;
}

bool ResolveFromCommandLineInput(
    Setup* setup,
    const std::vector<std::string>& input,
    bool all_toolchains,
    UniqueVector<Target*>* target_matches,
    UniqueVector<Config*>* config_matches,
    UniqueVector<Toolchain*>* toolchain_matches,
    UniqueVector<SourceFile>* file_matches) {
  if (input.empty()) {
    Err(Location(), "You need to specify a label, file, or pattern.")
        .PrintToStdout();
    return false;
  }

  SourceDir cur_dir =
      SourceDirForCurrentDirectory(setup->build_settings().root_path());
  for (const auto& cur : input) {
    if (!ResolveStringFromCommandLineInput(setup, cur_dir, cur,
                                           all_toolchains, target_matches,
                                           config_matches, toolchain_matches,
                                           file_matches))
      return false;
  }
  return true;
}

void FilterTargetsByPatterns(const std::vector<Target*>& input,
                             const std::vector<LabelPattern>& filter,
                             std::vector<Target*>* output) {
  for (auto* target : input) {
    for (const auto& pattern : filter) {
      if (pattern.Matches(target->label())) {
        output->push_back(target);
        break;
      }
    }
  }
}

void FilterTargetsByPatterns(const std::vector<Target*>& input,
                             const std::vector<LabelPattern>& filter,
                             UniqueVector<Target*>* output) {
  for (auto* target : input) {
    for (const auto& pattern : filter) {
      if (pattern.Matches(target->label())) {
        output->push_back(target);
        break;
      }
    }
  }
}

bool FilterPatternsFromString(const BuildSettings* build_settings,
                              const std::string& label_list_string,
                              std::vector<LabelPattern>* filters,
                              Err* err) {
  std::vector<std::string> tokens = base::SplitString(
      label_list_string, ";", base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY);
  SourceDir root_dir("//");

  filters->reserve(tokens.size());
  for (const std::string& token : tokens) {
    LabelPattern pattern = LabelPattern::GetPattern(
        root_dir, Value(nullptr, FixGitBashLabelEdit(token)), err);
    if (err->has_error())
      return false;
    filters->push_back(pattern);
  }

  return true;
}

void FilterAndPrintTargets(std::vector<Target*>* targets,
                           base::ListValue* out) {
  if (targets->empty())
    return;

  if (!ApplyTestonlyFilter(targets))
    return;
  if (!ApplyTypeFilter(targets))
    return;

  TargetPrintingMode printing_mode = TARGET_PRINT_LABEL;
  if (targets->empty() || !GetTargetPrintingMode(&printing_mode))
    return;
  switch (printing_mode) {
    case TARGET_PRINT_BUILDFILE:
      PrintTargetsAsBuildfiles(*targets, out);
      break;
    case TARGET_PRINT_LABEL:
      PrintTargetsAsLabels(*targets, out);
      break;
    case TARGET_PRINT_OUTPUT:
      PrintTargetsAsOutputs(*targets, out);
      break;
  }
}

void FilterAndPrintTargets(bool indent, std::vector<Target*>* targets) {
  base::ListValue tmp;
  FilterAndPrintTargets(targets, &tmp);
  for (const auto& value : tmp) {
    std::string string;
    value.GetAsString(&string);
    if (indent)
      OutputString("  ");
    OutputString(string);
    OutputString("\n");
  }
}

void FilterAndPrintTargetSet(bool indent,
                             const std::set<Target*>& targets) {
  std::vector<Target*> target_vector(targets.begin(), targets.end());
  FilterAndPrintTargets(indent, &target_vector);
}

void FilterAndPrintTargetSet(const std::set<Target*>& targets,
                             base::ListValue* out) {
  std::vector<Target*> target_vector(targets.begin(), targets.end());
  FilterAndPrintTargets(&target_vector, out);
}

}  // namespace commands
