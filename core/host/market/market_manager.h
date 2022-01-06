// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_MARKET_MARKET_MANAGER_H_
#define MUMBA_HOST_MARKET_MARKET_MANAGER_H_

#include <memory>

#include "base/macros.h"
#include "base/uuid.h"
#include "base/synchronization/waitable_event.h"
#include "base/task_scheduler/task.h"
#include "base/task_scheduler/post_task.h"
#include "third_party/stellar/src/ledger/LedgerManager.h"

namespace stellar {
class Application;  
}

namespace host {
class AccountManager;
class LedgerManager;
class PaymentManager;
class TransactionManager;
class TrustlineManager;

/*
 *  MarketManager is the main entry point to the 'financial live' of a node
 *  its the manager of the managers: 
 *    account manager, ledger manager, payment manager, transaction_manager, trustline_manager etc ...
 *  besides that, its the main controller point to all financial activities
 *    create account, create transaction, etc..
 */

class MarketManager {
public:
  MarketManager();
  ~MarketManager();

  void Init();
  void Shutdown(base::WaitableEvent* shutdown_event);

  AccountManager* account_manager() const {
    return account_manager_.get();
  }

  LedgerManager* ledger_manager() const {
    return ledger_manager_.get();
  }

  PaymentManager* payment_manager() const {
    return payment_manager_.get();
  }

  TransactionManager* transaction_manager() const {
    return transaction_manager_.get();
  }

  TrustlineManager* trustline_manager() const {
    return trustline_manager_.get();
  }

private:
  friend class LedgerManager;

  void InitNetwork();
  void ShutdownNetwork(base::WaitableEvent* shutdown_event);

  // route stellar managers back to the other managers
  stellar::LedgerManager& GetLedgerManager();

  // heavy IO going on here, we dont want them on the main thread
  scoped_refptr<base::SingleThreadTaskRunner> task_runner_;

  std::shared_ptr<stellar::Application> application_;

  std::unique_ptr<AccountManager> account_manager_;
  std::unique_ptr<LedgerManager> ledger_manager_;
  std::unique_ptr<PaymentManager> payment_manager_;
  std::unique_ptr<TransactionManager> transaction_manager_;
  std::unique_ptr<TrustlineManager> trustline_manager_;

  bool shutting_down_;

  
  DISALLOW_COPY_AND_ASSIGN(MarketManager);
};

}

#endif