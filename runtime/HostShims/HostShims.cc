// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "HostShims.h"

#include <stdio.h>

#include "ProcessMainRunner.h"
#include "base/process/launch.h"
#include "base/files/file_util.h"
#include "base/at_exit.h"
#include "base/path_service.h"
#include "base/base_paths.h"
#include "base/strings/utf_string_conversions.h"
#include "mumba_service_manager_main_delegate.h"
#include "core/common/main_params.h"
#include "services/service_manager/embedder/main.h"

// int _mumba_main(int argc, char** argv) {
//   ProcessMainRunner main_runner;
  
//   int exit_code = main_runner.Initialize(argc, argv);
//   if (exit_code > 0)
//    return exit_code;
  
//   exit_code = main_runner.Run();

//   main_runner.Shutdown();

//   return exit_code;
// }

const char kPackToolName[] = "pack";
const char kPackToolExe[] = "mumba_pack";

const char kBuildToolName[] = "build";
const char kBuildToolExe[] = "mumba_build";

const char kGenToolName[] = "gen";
const char kGenToolExe[] = "mumba_gen";

const char kReplToolName[] = "repl";
const char kReplToolExe[] = "mumba_repl";

const char kInstallToolName[] = "install";
const char kInstallToolExe[] = "mumba_install";

struct Tool {
  const char* name;
  const char* executable;
  std::vector<base::CommandLine::StringType> args;
};

const Tool kTOOLS[] = {
  {kPackToolName, kPackToolExe, {}},
  {kBuildToolName, kBuildToolExe, {}},
  {kGenToolName, kGenToolExe, {}},
  {kReplToolName, kReplToolExe, {}},
  {kInstallToolName, kInstallToolExe, {}}
};

//const base::CommandLine::CharType kSwitchTerminator[] = FILE_PATH_LITERAL("--");
const base::CommandLine::CharType kSwitchValueSeparator[] = FILE_PATH_LITERAL("=");

// Since we use a lazy match, make sure that longer versions (like "--") are
// listed before shorter versions (like "-") of similar prefixes.
#if defined(OS_WIN)
// By putting slash last, we can control whether it is treaded as a switch
// value by changing the value of switch_prefix_count to be one less than
// the array size.
const base::CommandLine::CharType* const kSwitchPrefixes[] = {L"--", L"-", L"/"};
#elif defined(OS_POSIX)
// Unixes don't use slash as a switch.
const base::CommandLine::CharType* const kSwitchPrefixes[] = {"--", "-"};
#endif
size_t switch_prefix_count = arraysize(kSwitchPrefixes);

size_t GetSwitchPrefixLength(const base::CommandLine::StringType& string) {
  for (size_t i = 0; i < switch_prefix_count; ++i) {
    base::CommandLine::StringType prefix(kSwitchPrefixes[i]);
    if (string.compare(0, prefix.length(), prefix) == 0)
      return prefix.length();
  }
  return 0;
}

bool HostIsSwitch(const base::CommandLine::StringType& string,
              base::CommandLine::StringType* switch_string,
              base::CommandLine::StringType* switch_value) {
  switch_string->clear();
  switch_value->clear();
  size_t prefix_length = GetSwitchPrefixLength(string);
  if (prefix_length == 0 || prefix_length == string.length())
    return false;

  const size_t equals_position = string.find(kSwitchValueSeparator);
  *switch_string = string.substr(0, equals_position);
  if (equals_position != base::CommandLine::StringType::npos)
    *switch_value = string.substr(equals_position + 1);
  return true;
}

// Append switches and arguments, keeping switches before arguments.
void HostAppendSwitchesAndArguments(base::CommandLine* command_line,
                                    const base::CommandLine::StringVector& argv) {
  for (size_t i = 1; i < argv.size(); ++i) {
    base::CommandLine::StringType arg = argv[i];
#if defined(OS_WIN)
    base::TrimWhitespace(arg, base::TRIM_ALL, &arg);
#else
    base::TrimWhitespaceASCII(arg, base::TRIM_ALL, &arg);
#endif

    base::CommandLine::StringType switch_string;
    base::CommandLine::StringType switch_value;
    if (HostIsSwitch(arg, &switch_string, &switch_value)) {
#if defined(OS_WIN)
      command_line->AppendSwitchNative(base::UTF16ToASCII(switch_string),
                                       switch_value);
#elif defined(OS_POSIX)
      command_line->AppendSwitchNative(switch_string, switch_value);
#endif
    } else {
      command_line->AppendArgNative(arg);
    }
  }
}


bool HostIsTool(const std::string& tool_cmd, Tool* tool) {
  for (size_t i = 0; i < arraysize(kTOOLS); i++) {
    if (strncmp(tool_cmd.c_str(), kTOOLS[i].name, tool_cmd.size()) == 0) {
      *tool = kTOOLS[i];
      return true;
    } 
  }
  return false;
}

int HostRunTool(const base::CommandLine* original, const Tool& tool) {
  int exit_code = 0;
  base::LaunchOptions options;
  base::FilePath exe_dir;

  base::PathService::Get(base::DIR_EXE, &exe_dir);
  
  options.wait = true;
#if defined(OS_POSIX)
  options.real_path = exe_dir.AppendASCII(tool.executable);
  base::CommandLine cmd(options.real_path);
#else
  base::FilePath real_path = exe_dir.AppendASCII(tool.executable);
  base::CommandLine cmd(real_path);
#endif
  
  HostAppendSwitchesAndArguments(&cmd, original->argv());

  base::Process tool_process = base::LaunchProcess(cmd, options);
  //tool_process.WaitForExit(&exit_code);
  return exit_code;
}

int _mumba_main(int argc, char** argv) {
 //std::unique_ptr<base::AtExitManager> at_exit = std::make_unique<base::AtExitManager>();
#if defined(OS_WIN)
  // The process should crash when going through abnormal termination, but we
  // must be sure to reset this setting when ChromeMain returns normally.
 // auto crash_on_detach_resetter = base::ScopedClosureRunner(
 //     base::Bind(&base::win::SetShouldCrashOnProcessDetach,
 //                base::win::ShouldCrashOnProcessDetach()));
 // base::win::SetShouldCrashOnProcessDetach(true);
 // base::win::SetAbortBehaviorForCrashReporting();
  
  // TODO i guess at least instance is important for the UI
  //params.instance = instance;
  //params.sandbox_info = sandbox_info;

  // Pass chrome_elf's copy of DumpProcessWithoutCrash resolved via load-time
  // dynamic linking.
  //base::debug::SetDumpWithoutCrashingFunction(&DumpProcessWithoutCrash);

  // Verify that chrome_elf and this module (chrome.dll and chrome_child.dll)
  // have the same version.
  //if (install_static::InstallDetails::Get().VersionMismatch())
 //   base::debug::DumpWithoutCrashing();
#else
  base::CommandLine::Init(argc, argv);
#endif  // defined(OS_WIN)
  base::CommandLine::Init(0, nullptr);
  const base::CommandLine* command_line(base::CommandLine::ForCurrentProcess());
  ALLOW_UNUSED_LOCAL(command_line);

  auto args = command_line->GetArgs();

  Tool tool;
#if defined(OS_POSIX)
  if (args.size() > 0 && HostIsTool(args[0], &tool)) {
#elif defined(OS_WIN)
  if (args.size() > 0 && HostIsTool(base::UTF16ToASCII(args[0]), &tool)) {
#endif
    tool.args = args;
    return HostRunTool(command_line, tool);
  }

  common::MainParams params(*command_line);

  MumbaServiceManagerMainDelegate delegate(params);
  service_manager::MainParams main_params(&delegate);
#if defined(OS_POSIX) && !defined(OS_ANDROID)
  main_params.argc = argc;
  main_params.argv = const_cast<const char **>(argv);
#endif
  int result = service_manager::Main(main_params);
  return result;
}
