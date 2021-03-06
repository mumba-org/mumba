// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_NET_CONFIG_FILE_WATCHER_H_
#define MUMBA_HOST_NET_CONFIG_FILE_WATCHER_H_

#include "base/compiler_specific.h"
#include "base/files/file_path.h"
#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "core/host/net/config_watcher.h"

namespace base {
class SingleThreadTaskRunner;
}  // namespace base

namespace host {

extern const char kHostConfigSwitchName[];
extern const base::FilePath::CharType kDefaultHostConfigFile[];

class ConfigFileWatcherImpl;

class ConfigFileWatcher : public ConfigWatcher {
 public:
  // Creates a configuration file watcher that lives at the |io_task_runner|
  // thread but posts config file updates on on |main_task_runner|.
  ConfigFileWatcher(
      scoped_refptr<base::SingleThreadTaskRunner> main_task_runner,
      scoped_refptr<base::SingleThreadTaskRunner> io_task_runner,
      const base::FilePath& config_path);
  ~ConfigFileWatcher() override;

  // Inherited from ConfigWatcher.
  void Watch(Delegate* delegate) override;

 private:
  scoped_refptr<ConfigFileWatcherImpl> impl_;

  DISALLOW_COPY_AND_ASSIGN(ConfigFileWatcher);
};

}

#endif  // REMOTING_HOST_CONFIG_FILE_WATCHER_H_
