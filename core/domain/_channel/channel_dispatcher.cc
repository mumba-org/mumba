// Copyright 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/domain/channel/channel_dispatcher.h"

#include "base/uuid.h"
#include "base/files/file_path.h"
#include "base/task_scheduler/post_task.h"
#include "core/domain/domain_process.h"
#include "core/domain/domain_context.h"
#include "core/domain/domain_main_thread.h"

namespace domain {

class ChannelDispatcher::Handler : public base::RefCountedThreadSafe<Handler> {
public:
  Handler() {}

  std::vector<common::mojom::ChannelHandlePtr> ListChannels(scoped_refptr<DomainContext> shell) {
    return std::vector<common::mojom::ChannelHandlePtr>();
  }

  common::mojom::ChannelHandlePtr GetChannelInfo(scoped_refptr<DomainContext> shell, const std::string& url) {
    return nullptr;
  }

  bool AddChannel(scoped_refptr<DomainContext> shell, const std::string& url, common::mojom::ChannelHandlePtr channel) {
    return true;
  }

  bool RemoveChannel(scoped_refptr<DomainContext> shell, const std::string& url) {
    return true;
  }

  bool SubscribeChannel(scoped_refptr<DomainContext> shell, const std::string& url) {
    return true;
  }

  bool UnsubscribeChannel(scoped_refptr<DomainContext> shell, const std::string& url) {
    return true;
  }

private:
  friend class base::RefCountedThreadSafe<Handler>;

  ~Handler() {}
};

ChannelDispatcher::ChannelDispatcher():
 binding_(this),
 handler_(new Handler()),
 weak_factory_(this) {}
 
ChannelDispatcher::~ChannelDispatcher() {

}

void ChannelDispatcher::Bind(common::mojom::ChannelDispatcherAssociatedRequest request) {
  binding_.Bind(std::move(request));
}

void ChannelDispatcher::GetChannelInfo(const std::string& url, GetChannelInfoCallback callback) {
  DomainMainThread* main_thread = DomainMainThread::current();
  base::PostTaskWithTraitsAndReplyWithResult(
    FROM_HERE,
    { base::MayBlock(),
      base::TaskPriority::USER_BLOCKING},
     base::Bind(
       &Handler::GetChannelInfo,
       handler_,
       main_thread->domain_context(),
       url),
     base::Bind(&ChannelDispatcher::ReplyGetChannelInfo,
      weak_factory_.GetWeakPtr(),
      base::Passed(std::move(callback))));
}

void ChannelDispatcher::ListChannels(ListChannelsCallback callback) {
  DomainMainThread* main_thread = DomainMainThread::current();
  base::PostTaskWithTraitsAndReplyWithResult(
    FROM_HERE,
    { base::MayBlock(),
      base::TaskPriority::USER_BLOCKING},
     base::Bind(
       &Handler::ListChannels,
       handler_,
       main_thread->domain_context()),
     base::Bind(&ChannelDispatcher::ReplyListChannels,
      weak_factory_.GetWeakPtr(),
      base::Passed(std::move(callback))));
}

void ChannelDispatcher::AddChannel(const std::string& url, common::mojom::ChannelHandlePtr node, AddChannelCallback callback) {
  DomainMainThread* main_thread = DomainMainThread::current();
  base::PostTaskWithTraitsAndReplyWithResult(
    FROM_HERE,
    { base::MayBlock(),
      base::TaskPriority::USER_BLOCKING},
     base::Bind(
       &Handler::AddChannel,
       handler_,
       main_thread->domain_context(),
       url,
       base::Passed(std::move(node))),
     base::Bind(&ChannelDispatcher::ReplyAddChannel,
      weak_factory_.GetWeakPtr(),
      base::Passed(std::move(callback))));
}

void ChannelDispatcher::RemoveChannel(const std::string& url, RemoveChannelCallback callback) {
  DomainMainThread* main_thread = DomainMainThread::current();
  base::PostTaskWithTraitsAndReplyWithResult(
    FROM_HERE,
    { base::MayBlock(),
      base::TaskPriority::USER_BLOCKING},
     base::Bind(
       &Handler::RemoveChannel,
       handler_,
       main_thread->domain_context(),
       url),
     base::Bind(&ChannelDispatcher::ReplyRemoveChannel,
      weak_factory_.GetWeakPtr(),
      base::Passed(std::move(callback))));
}

void ChannelDispatcher::SubscribeChannel(const std::string& url, SubscribeChannelCallback callback) {
  DomainMainThread* main_thread = DomainMainThread::current();
  base::PostTaskWithTraitsAndReplyWithResult(
    FROM_HERE,
    { base::MayBlock(),
      base::TaskPriority::USER_BLOCKING},
     base::Bind(
       &Handler::SubscribeChannel,
       handler_,
       main_thread->domain_context(),
       url),
     base::Bind(&ChannelDispatcher::ReplySubscribeChannel,
      weak_factory_.GetWeakPtr(),
      base::Passed(std::move(callback))));
}

void ChannelDispatcher::UnsubscribeChannel(const std::string& url, UnsubscribeChannelCallback callback) {
  DomainMainThread* main_thread = DomainMainThread::current();
  base::PostTaskWithTraitsAndReplyWithResult(
    FROM_HERE,
    { base::MayBlock(),
      base::TaskPriority::USER_BLOCKING},
     base::Bind(
       &Handler::UnsubscribeChannel,
       handler_,
       main_thread->domain_context(),
       url),
     base::Bind(&ChannelDispatcher::ReplyUnsubscribeChannel,
      weak_factory_.GetWeakPtr(),
      base::Passed(std::move(callback))));
}
 
void ChannelDispatcher::ReplyGetChannelInfo(GetChannelInfoCallback callback, common::mojom::ChannelHandlePtr info) {
  std::move(callback).Run(std::move(info));
}

void ChannelDispatcher::ReplyListChannels(ListChannelsCallback callback, std::vector<common::mojom::ChannelHandlePtr> infos) {
  std::move(callback).Run(std::move(infos));
}

void ChannelDispatcher::ReplyAddChannel(AddChannelCallback callback, bool result) {
  common::mojom::DomainStatus status = result ? common::mojom::DomainStatus::kOk : common::mojom::DomainStatus::kError;
  std::move(callback).Run(std::move(status));
}

void ChannelDispatcher::ReplyRemoveChannel(RemoveChannelCallback callback, bool result) {
  common::mojom::DomainStatus status = result ? common::mojom::DomainStatus::kOk : common::mojom::DomainStatus::kError;
  std::move(callback).Run(std::move(status));
}

void ChannelDispatcher::ReplySubscribeChannel(SubscribeChannelCallback callback, bool result) {
  common::mojom::DomainStatus status = result ? common::mojom::DomainStatus::kOk : common::mojom::DomainStatus::kError;
  std::move(callback).Run(std::move(status));
}

void ChannelDispatcher::ReplyUnsubscribeChannel(UnsubscribeChannelCallback callback, bool result) {
  common::mojom::DomainStatus status = result ? common::mojom::DomainStatus::kOk : common::mojom::DomainStatus::kError;
  std::move(callback).Run(std::move(status));
}

}