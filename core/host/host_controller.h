// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_HOST_CONTROLLER_H_
#define MUMBA_HOST_HOST_CONTROLLER_H_

#include <map>

#include "base/macros.h"
#include "base/command_line.h"
#include "base/atomic_sequence_num.h"
#include <memory>
#include "base/memory/weak_ptr.h"
#include "ipc/ipc_channel_proxy.h"
#include "core/common/process_launcher_delegate.h"
#include "core/common/query_code.h"
#include "core/host/child_process_launcher.h"
#include "net/base/io_buffer.h"
#include "core/host/waitable_task.h"
#include "url/gurl.h"

namespace host {
class Host;
class Volume;
class Domain;
class Workspace;
class IOThread;

class HostController : public base::RefCountedThreadSafe<HostController> {
public:
  // if its ref counted.. why to depend of a singleton ?
  static scoped_refptr<HostController> Instance();
  static int GetNextReplyId();
 
  HostController(Host* host);
  
  void Init();
  void Shutdown();

  IOThread* io_thread();
  //Workspace* current_workspace();

  void ProcessHostClient(const std::string& message);
  
  void ShutdownHost();
    
  void ExecuteShutdown();

  void LaunchDomain(const std::string& name);

  void OnDomainAdded(Domain* domain);
  void OnDomainRemoved(Domain* domain);

  // to be used with the Host handle
  void lock();
  void unlock();

  Host* host();
 
private:
 friend class base::RefCountedThreadSafe<HostController>;
 ~HostController();
 
 void ProcessHostClientOnFileThread(const std::string& message);

 void PerformShutdown();

 base::Lock host_lock_;

 Host* host_;
   
 std::map<int, int> req_to_sess_idx_;
  
 DISALLOW_COPY_AND_ASSIGN(HostController);
};

  
}

#endif