
#include <memory>
#include <string>

#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/files/file_enumerator.h"
#include "base/command_line.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/utf_string_conversions.h"
#include "base/sys_info.h"
#include "base/at_exit.h"
#include "base/run_loop.h"
#include "base/message_loop/message_loop.h"
#include "base/task_scheduler/task_scheduler.h"
#include "storage/cmd/commands.h"

namespace {

std::vector<std::string> GetArgs(const base::CommandLine& cmdline) {
  base::CommandLine::StringVector in_args = cmdline.GetArgs();
#if defined(OS_WIN)
  std::vector<std::string> out_args;
  for (const auto& arg : in_args)
    out_args.push_back(base::WideToUTF8(arg));
  return out_args;
#else
  return in_args;
#endif
}

int GetThreadCount() {
  int num_cores = base::SysInfo::NumberOfProcessors() / 2;
  return std::max(num_cores - 1, 8);
}

void StartTaskScheduler() {
  constexpr base::TimeDelta kSuggestedReclaimTime =
      base::TimeDelta::FromSeconds(30);

  constexpr int kBackgroundMaxThreads = 1;
  constexpr int kBackgroundBlockingMaxThreads = 2;
  const int kForegroundMaxThreads =
      std::max(1, base::SysInfo::NumberOfProcessors());
  const int foreground_blocking_max_threads = GetThreadCount();

  base::TaskScheduler::Create("net_koden");
  base::TaskScheduler::GetInstance()->Start(
      {{kBackgroundMaxThreads, kSuggestedReclaimTime},
       {kBackgroundBlockingMaxThreads, kSuggestedReclaimTime},
       {kForegroundMaxThreads, kSuggestedReclaimTime},
       {foreground_blocking_max_threads, kSuggestedReclaimTime}});
}

}  // namespace



int main(int argc, char** argv) {
  base::AtExitManager exit_manager;
  base::CommandLine::Init(argc, argv);
  const base::CommandLine& cmdline = *base::CommandLine::ForCurrentProcess();
  std::vector<std::string> args = GetArgs(cmdline);

  std::string command;

  if (cmdline.HasSwitch("help") || cmdline.HasSwitch("h")) {
    // Make "-h" and "--help" default to help command.
    command = net::kHelp;
  } else if (args.empty()) {
    // No command, print error and exit.
    printf("No command specified.\n");
    return 1;
  } else {
    command = args[0];
    args.erase(args.begin());
  }

  const net::CommandInfoMap& command_map = net::GetCommands();
  net::CommandInfoMap::const_iterator found_command =
      command_map.find(command);

  int retval;
  if (found_command != command_map.end()) {
    base::MessageLoop message_loop;
    // if we are working over command line
    // we need to instantiate this
    StartTaskScheduler();
    retval = found_command->second.runner(args);
    base::TaskScheduler::GetInstance()->Shutdown();
  } else {
    printf("Command \"%s\" unknown.\n", command.c_str());
    for (const auto& cmd : net::GetCommands())
      printf("%s\n", cmd.second.help_short);

    retval = 1;
  }

  exit(retval);
}