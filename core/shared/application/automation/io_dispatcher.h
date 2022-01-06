// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_APPLICATION_IO_DISPATCHER_H_
#define MUMBA_APPLICATION_IO_DISPATCHER_H_

#include "core/shared/common/mojom/automation.mojom.h"

#include "mojo/public/cpp/bindings/binding.h"
#include "mojo/public/cpp/bindings/associated_binding.h"

namespace service_manager {
class InterfaceProvider;
}

namespace blink {
class WebLocalFrame;  
}

namespace IPC {
class SyncChannel;
}

namespace application {
class PageInstance;

class IODispatcher : public automation::IO {
public:
  
  static void Create(automation::IORequest request, PageInstance* page_instance);

  IODispatcher(automation::IORequest request, PageInstance* page_instance);
  IODispatcher(PageInstance* page_instance);
  ~IODispatcher() override;

  void Init(IPC::SyncChannel* channel);
  void Bind(automation::IOAssociatedRequest request);

  void Register(int32_t application_id) override;
  void Close(const std::string& handl) override;
  void Read(const std::string& handl, int32_t offset, int32_t size, ReadCallback callback) override;
  void ResolveBlob(const std::string& object_id, ResolveBlobCallback callback) override;

  PageInstance* page_instance() const {
    return page_instance_;
  }

  void OnWebFrameCreated(blink::WebLocalFrame* web_frame);
  
private:
  int32_t application_id_;
  PageInstance* page_instance_;
  mojo::AssociatedBinding<automation::IO> binding_;

  DISALLOW_COPY_AND_ASSIGN(IODispatcher); 
};

}

#endif