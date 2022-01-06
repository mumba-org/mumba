// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/histogram_controller.h"

#include "base/bind.h"
#include "base/metrics/histogram_macros.h"
#include "base/process/process_handle.h"
#include "core/host/histogram_subscriber.h"
#include "core/shared/common/histogram_fetcher.mojom.h"
#include "core/host/host_child_process_host_iterator.h"
#include "core/host/host_thread.h"
#include "core/host/child_process_data.h"
//#include "core/host/render_process_host.h"
#include "core/shared/common/bind_interface_helpers.h"
#include "core/shared/common/child_process_host.h"
#include "core/common/process_type.h"
#include "mojo/public/cpp/bindings/callback_helpers.h"

namespace host {

HistogramController* HistogramController::GetInstance() {
  return base::Singleton<HistogramController, base::LeakySingletonTraits<
                                                  HistogramController>>::get();
}

HistogramController::HistogramController() : subscriber_(nullptr) {}

HistogramController::~HistogramController() {
}

void HistogramController::OnPendingProcesses(int sequence_number,
                                             int pending_processes,
                                             bool end) {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  if (subscriber_)
    subscriber_->OnPendingProcesses(sequence_number, pending_processes, end);
}

void HistogramController::OnHistogramDataCollected(
    int sequence_number,
    const std::vector<std::string>& pickled_histograms) {
  if (!HostThread::CurrentlyOn(HostThread::UI)) {
    HostThread::PostTask(
        HostThread::UI, FROM_HERE,
        base::BindOnce(&HistogramController::OnHistogramDataCollected,
                       base::Unretained(this), sequence_number,
                       pickled_histograms));
    return;
  }
  DCHECK_CURRENTLY_ON(HostThread::UI);
  if (subscriber_) {
    subscriber_->OnHistogramDataCollected(sequence_number,
                                          pickled_histograms);
  }
}

void HistogramController::Register(HistogramSubscriber* subscriber) {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  DCHECK(!subscriber_);
  subscriber_ = subscriber;
}

void HistogramController::Unregister(
    const HistogramSubscriber* subscriber) {
  DCHECK_EQ(subscriber_, subscriber);
  subscriber_ = nullptr;
}

template <class T>
void HistogramController::NotifyChildDied(T* host) {
  RemoveChildHistogramFetcherInterface(host);
}

//template void HistogramController::NotifyChildDied(RenderProcessHost* host);

template <>
HistogramController::ChildHistogramFetcherMap<common::ChildProcessHost>&
HistogramController::GetChildHistogramFetcherMap() {
  return child_histogram_fetchers_;
}

// template <>
// HistogramController::ChildHistogramFetcherMap<RenderProcessHost>&
// HistogramController::GetChildHistogramFetcherMap() {
//   return renderer_histogram_fetchers_;
// }

template void HistogramController::SetHistogramMemory(
    common::ChildProcessHost* host,
    mojo::ScopedSharedBufferHandle shared_buffer);

// template void HistogramController::SetHistogramMemory(
//     RenderProcessHost* host,
//     mojo::ScopedSharedBufferHandle shared_buffer);

template <class T>
void HistogramController::SetHistogramMemory(
    T* host,
    mojo::ScopedSharedBufferHandle shared_buffer) {
  common::mojom::ChildHistogramFetcherFactoryPtr
      child_histogram_fetcher_factory;
  common::mojom::ChildHistogramFetcherPtr child_histogram_fetcher;
  common::BindInterface(host, &child_histogram_fetcher_factory);
  child_histogram_fetcher_factory->CreateFetcher(
      std::move(shared_buffer), mojo::MakeRequest(&child_histogram_fetcher));
  InsertChildHistogramFetcherInterface(host,
                                       std::move(child_histogram_fetcher));
}

template <class T>
void HistogramController::InsertChildHistogramFetcherInterface(
    T* host,
    common::mojom::ChildHistogramFetcherPtr child_histogram_fetcher) {
  // Broken pipe means remove this from the map. The map size is a proxy for
  // the number of known processes
  child_histogram_fetcher.set_connection_error_handler(base::BindOnce(
      &HistogramController::RemoveChildHistogramFetcherInterface<T>,
      base::Unretained(this), base::Unretained(host)));
  GetChildHistogramFetcherMap<T>()[host] = std::move(child_histogram_fetcher);
}

template <class T>
common::mojom::ChildHistogramFetcher*
HistogramController::GetChildHistogramFetcherInterface(T* host) {
  auto it = GetChildHistogramFetcherMap<T>().find(host);
  if (it != GetChildHistogramFetcherMap<T>().end()) {
    return (it->second).get();
  }
  return nullptr;
}

template <class T>
void HistogramController::RemoveChildHistogramFetcherInterface(T* host) {
  GetChildHistogramFetcherMap<T>().erase(host);
}

void HistogramController::GetHistogramDataFromChildProcesses(
    int sequence_number) {
  DCHECK_CURRENTLY_ON(HostThread::IO);

  int pending_processes = 0;
  for (HostChildProcessHostIterator iter; !iter.Done(); ++iter) {
    const ChildProcessData& data = iter.GetData();

    // Only get histograms from content process types; skip "embedder" process
    // types.
    if (data.process_type >= common::PROCESS_TYPE_END)
      continue;

    // In some cases, there may be no child process of the given type (for
    // example, the GPU process may not exist and there may instead just be a
    // GPU thread in the host process). If that's the case, then the process
    // handle will be base::kNullProcessHandle and we shouldn't ask it for data.
    if (data.handle == base::kNullProcessHandle)
      continue;

    if (auto* child_histogram_fetcher =
            GetChildHistogramFetcherInterface(iter.GetHost())) {
      child_histogram_fetcher->GetChildNonPersistentHistogramData(
          mojo::WrapCallbackWithDefaultInvokeIfNotRun(
              base::BindOnce(&HistogramController::OnHistogramDataCollected,
                             base::Unretained(this), sequence_number),
              std::vector<std::string>()));
      ++pending_processes;
    }
  }
  HostThread::PostTask(
      HostThread::UI, FROM_HERE,
      base::BindOnce(&HistogramController::OnPendingProcesses,
                     base::Unretained(this), sequence_number, pending_processes,
                     true));
}

void HistogramController::GetHistogramData(int sequence_number) {
  DCHECK_CURRENTLY_ON(HostThread::UI);

  int pending_processes = 0;
  // for (RenderProcessHost::iterator it(RenderProcessHost::AllHostsIterator());
  //      !it.IsAtEnd() && it.GetCurrentValue()->IsReady(); it.Advance()) {
  //   if (auto* child_histogram_fetcher =
  //           GetChildHistogramFetcherInterface(it.GetCurrentValue())) {
  //     child_histogram_fetcher->GetChildNonPersistentHistogramData(
  //         mojo::WrapCallbackWithDefaultInvokeIfNotRun(
  //             base::BindOnce(&HistogramController::OnHistogramDataCollected,
  //                            base::Unretained(this), sequence_number),
  //             std::vector<std::string>()));
  //     ++pending_processes;
  //   }
  // }
  OnPendingProcesses(sequence_number, pending_processes, false);

  HostThread::PostTask(
      HostThread::IO, FROM_HERE,
      base::BindOnce(&HistogramController::GetHistogramDataFromChildProcesses,
                     base::Unretained(this), sequence_number));
}

}  // namespace host
