// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/ui/platform_util.h"

#include "base/files/file.h"
#include "base/files/file_util.h"
#include "base/logging.h"
#include "base/task_scheduler/post_task.h"
#include "core/host/ui/platform_util_internal.h"
#include "core/host/host_thread.h"

using host::HostThread;

namespace platform_util {

namespace {

bool domain_operations_allowed = true;

void VerifyAndOpenItemOnBlockingThread(const base::FilePath& path,
                                       OpenItemType type,
                                       const OpenOperationCallback& callback) {
  base::File target_item(path, base::File::FLAG_OPEN | base::File::FLAG_READ);
  if (!base::PathExists(path)) {
    if (!callback.is_null())
      HostThread::PostTask(
          HostThread::UI, FROM_HERE,
          base::BindOnce(callback, OPEN_FAILED_PATH_NOT_FOUND));
    return;
  }
  if (base::DirectoryExists(path) != (type == OPEN_FOLDER)) {
    if (!callback.is_null())
      HostThread::PostTask(
          HostThread::UI, FROM_HERE,
          base::BindOnce(callback, OPEN_FAILED_INVALID_TYPE));
    return;
  }

  if (domain_operations_allowed)
    internal::PlatformOpenVerifiedItem(path, type);
  if (!callback.is_null())
    HostThread::PostTask(HostThread::UI, FROM_HERE,
                         base::BindOnce(callback, OPEN_SUCCEEDED));
}

}  // namespace

namespace internal {

void DisableDomainOperationsForTesting() {
  domain_operations_allowed = false;
}

}  // namespace internal

void OpenItem(scoped_refptr<host::Workspace> workspace,
              const base::FilePath& full_path,
              OpenItemType item_type,
              const OpenOperationCallback& callback) {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  base::PostTaskWithTraits(FROM_HERE,
                           {base::MayBlock(), base::TaskPriority::BACKGROUND},
                           base::BindOnce(&VerifyAndOpenItemOnBlockingThread,
                                          full_path, item_type, callback));
}

}  // namespace platform_util
