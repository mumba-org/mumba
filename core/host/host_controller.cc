// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/host_controller.h"

#include "base/files/file_util.h"
#include "base/strings/string_util.h"
#include "base/threading/thread_restrictions.h"
#include "base/task_scheduler/post_task.h"
#include "base/stl_util.h"
#include "core/host/host.h"
#include "core/host/host_thread.h"
#include "core/host/io_thread.h"
#include "core/host/volume/volume_manager.h"
#include "core/host/volume/volume_model.h"
#include "core/host/volume/volume.h"
#include "core/host/application/domain_manager.h"
#include "core/host/application/domain.h"
#include "core/shared/common/child_process_host.h"
#include "core/shared/common/switches.h"
#include "core/common/proto/control.pb.h"
#include "core/common/proto/internal.pb.h"
#include "core/common/protocol/message_serialization.h"
#include "third_party/protobuf/src/google/protobuf/message_lite.h"

namespace host {

// static
scoped_refptr<HostController> HostController::Instance() {
	base::Lock lock;
	lock.Acquire();
	scoped_refptr<HostController> instance = Host::Instance()->controller();
	lock.Release();
	return instance;
}

// static 
int HostController::GetNextReplyId() {
  //scoped_refptr<HostController> controller = HostController::Instance();
  //return controller->reply_next_id_.GetNext() + 1;
  DCHECK(false);
  return 0;
}

HostController::HostController(Host* host): 
  host_(host) {}

HostController::~HostController() {
  
}

void HostController::Init() {

}

IOThread* HostController::io_thread() {
  base::AutoLock lock(host_lock_);
  return host_->io_thread();
}

// Workspace* HostController::current_workspace() {
//   base::AutoLock lock(host_lock_);
//   return host_->current_workspace();
// }

void HostController::Shutdown() {
 
}

void HostController::ShutdownHost() {
  base::AutoLock lock(host_lock_);
  host_->Shutdown();
}

void HostController::lock() {
  host_lock_.Acquire();
}

void HostController::unlock() {
  host_lock_.Release();
}

Host* HostController::host() {
  return host_;
}

void HostController::ProcessHostClient(const std::string& message) {
	//HostThread::PostTask(HostThread::FILE,
  base::PostTask(
                 FROM_HERE,
                 base::Bind(&HostController::ProcessHostClientOnFileThread,
                            this,
                            message));
}

void HostController::ProcessHostClientOnFileThread(const std::string& message) {
  //DCHECK(HostThread::CurrentlyOn(HostThread::FILE));		
  // TODO: find a profissional way to do this
  // eg. wapping it up in a "HostClient"
  // also we need to be able to control WaitableEvents here
  // where the Host instance can signal the client instance
  // when something is ready.. the host would use Request::Done()
  // or Request::More()
  if (!message.empty())
   printf("%s\n", message.c_str());
}
  
void HostController::ExecuteShutdown() {
  //DCHECK(HostThread::CurrentlyOn(HostThread::DISPATCHER));
   HostThread::PostTask(HostThread::UI,
        FROM_HERE,
        base::Bind(&HostController::PerformShutdown, this));
}

void HostController::PerformShutdown() {
  DCHECK(HostThread::CurrentlyOn(HostThread::UI));
  ShutdownHost();
}

void HostController::LaunchDomain(const std::string& name) {
  base::AutoLock lock(host_lock_);
  //Domain* shell = host_->domain_manager()->GetDomain(name);
  host_->current_workspace()->LaunchDomain(name, base::Callback<void(int)>());
}

void HostController::OnDomainAdded(Domain* domain) {
  base::AutoLock lock(host_lock_);
  // on installation from volume is alredy there.. otherwise
  // if recovered from db this is null, so we need to set up
  if (!domain->main_volume()) {
    VolumeManager* volume_manager = host_->current_workspace()->volume_manager();
    Volume* volume = volume_manager->volumes()->GetVolumeByName(domain->name());
    DCHECK(volume);
    domain->AddVolume(volume, true /* is_main */);
  }
  if (domain->ShouldLaunchOnInit()) {
    host_->current_workspace()->LaunchDomain(domain, base::Callback<void(int)>());
  }
}

void HostController::OnDomainRemoved(Domain* domain) {
  //base::AutoLock lock(host_lock_);
  //LOG(INFO) << "HostController::OnDomainRemoved";
}

}