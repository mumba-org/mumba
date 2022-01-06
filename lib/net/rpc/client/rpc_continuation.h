// Copyright (c) 2017 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_RPC_CLIENT_RPC_CONTINUATION_H_
#define NET_RPC_CLIENT_RPC_CONTINUATION_H_

#include "base/macros.h"
#include "rpc/grpc.h"
#include "net/rpc/client/rpc_stream.h"

namespace net {
class RpcCall;

class NET_EXPORT RpcContinuation {
public:
  class Delegate {
  public:
    virtual ~Delegate() {}
    virtual const scoped_refptr<base::SequencedTaskRunner>& io_task_runner() const = 0;
    virtual void OnContinue(bool ok, RpcCall*) = 0;
    virtual void OnTimeout() = 0;
    virtual void OnShutdown() = 0;
  };

  virtual ~RpcContinuation() {}
  virtual grpc_completion_queue* c_completion_queue() const = 0;
  //virtual Delegate* delegate() const = 0;
  virtual void Schedule(base::WeakPtr<Delegate> delegate) = 0;
  virtual void Shutdown() = 0;
  virtual void ShutdownOnIO() = 0;
  virtual void ShutdownLoop() = 0;
  virtual base::WeakPtr<RpcContinuation> GetWeakPtr() = 0;
};

class NET_EXPORT RpcPluckContinuation : public RpcContinuation {
public:
  RpcPluckContinuation(
    const scoped_refptr<base::SequencedTaskRunner>& io_task_runner);
  ~RpcPluckContinuation() override;

  grpc_completion_queue* c_completion_queue() const override;
  //Delegate* delegate() const override;
    
  void Schedule(base::WeakPtr<Delegate> delegate) override;
  void Shutdown() override;
  void ShutdownOnIO() override;

  void ShutdownLoop() override {
    //shutdown_loop_ = true;
  }

  base::WeakPtr<RpcContinuation> GetWeakPtr() override;

private:
  
  //base::WeakPtr<Delegate> delegate_;
  
  grpc_completion_queue* completion_queue_;

  mutable bool shutting_down_;

  //bool shutdown_loop_;

  scoped_refptr<base::SequencedTaskRunner> io_task_runner_;

  base::WaitableEvent shutdown_event_;

  std::unique_ptr<base::WeakPtrFactory<RpcContinuation>> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(RpcPluckContinuation);
};

class NET_EXPORT RpcNextContinuation : public RpcContinuation {
public:
  RpcNextContinuation(
    const scoped_refptr<base::SequencedTaskRunner>& io_task_runner);
  ~RpcNextContinuation() override;

  grpc_completion_queue* c_completion_queue() const override;
  //Delegate* delegate() const override;

  base::WeakPtr<RpcContinuation> GetWeakPtr() override;

  void Schedule(base::WeakPtr<Delegate> delegate) override;
  void Shutdown() override;
  void ShutdownOnIO() override;

  void ShutdownLoop() override {
    //shutdown_loop_ = true;
  }
  
private:
  
  //base::WeakPtr<Delegate> delegate_;

  grpc_completion_queue* completion_queue_;

  mutable bool shutting_down_;

  //bool shutdown_loop_;

  scoped_refptr<base::SequencedTaskRunner> io_task_runner_;

  base::WaitableEvent shutdown_event_;

  std::unique_ptr<base::WeakPtrFactory<RpcContinuation>> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(RpcNextContinuation);
};

}

#endif