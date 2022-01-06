// Copyright 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_ROUTE_ROUTE_RESPONSE_BODY_CONSUMER_H_
#define MUMBA_HOST_ROUTE_ROUTE_RESPONSE_BODY_CONSUMER_H_

#include <stddef.h>
#include <stdint.h>

#include <utility>
#include <vector>

#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/memory/weak_ptr.h"
#include "base/single_thread_task_runner.h"
#include "core/shared/common/content_export.h"
#include "mojo/public/cpp/system/data_pipe.h"
#include "mojo/public/cpp/system/simple_watcher.h"
#include "core/shared/common/mojom/route.mojom.h"
#include "services/network/public/cpp/url_loader_completion_status.h"

namespace host {
class RouteRequestPeer;

// This class pulls data from a data pipe and dispatches it to the
// ResourceDispatcher. This class is used only for mojo-enabled requests.
class CONTENT_EXPORT RouteResponseBodyConsumer final
    : public base::RefCounted<RouteResponseBodyConsumer>,
      public base::SupportsWeakPtr<RouteResponseBodyConsumer> {
 public:
  RouteResponseBodyConsumer(
      int request_id,
      RouteRequestPeer* peer,
      mojo::ScopedDataPipeConsumerHandle handle,
      scoped_refptr<base::SingleThreadTaskRunner> task_runner);

  // Sets the completion status. The completion status is dispatched to the
  // ResourceDispatcher when the both following conditions hold:
  //  1) This function has been called and the completion status is set, and
  //  2) All data is read from the handle.
  void OnComplete(const network::URLLoaderCompletionStatus& status);

  // Cancels watching the handle and dispatches an error to the
  // ResourceDispatcher. This function does nothing if the reading is already
  // cancelled or done.
  void Cancel();

  void SetDefersLoading();
  void UnsetDefersLoading();

  // Reads data and dispatches messages synchronously.
  void OnReadable(MojoResult unused);

  void ArmOrNotify();

  // The maximal number of bytes consumed in a task. When there are more bytes
  // in the data pipe, they will be consumed in following tasks. Setting a too
  // small number will generate ton of tasks but setting a too large number will
  // lead to thread janks. Also, some clients cannot handle too large chunks
  // (512k for example).
  static constexpr uint32_t kMaxNumConsumedBytesInTask = 512 * 1024;

 private:
  friend class base::RefCounted<RouteResponseBodyConsumer>;
  ~RouteResponseBodyConsumer();

  class ReceivedData;
  void Reclaim(uint32_t size);

  void NotifyCompletionIfAppropriate();

  const int request_id_;
  RouteRequestPeer* peer_;
  mojo::ScopedDataPipeConsumerHandle handle_;
  mojo::SimpleWatcher handle_watcher_;
  network::URLLoaderCompletionStatus status_;
  scoped_refptr<base::SingleThreadTaskRunner> task_runner_;

  bool has_received_completion_ = false;
  bool has_been_cancelled_ = false;
  bool has_seen_end_of_data_;
  bool is_deferred_ = false;
  bool is_in_on_readable_ = false;

  DISALLOW_COPY_AND_ASSIGN(RouteResponseBodyConsumer);
};

}  // namespace host

#endif
