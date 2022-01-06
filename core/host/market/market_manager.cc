
// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/market/market_manager.h"

#include "base/strings/string_util.h"
#include "core/host/market/ledger.h"
#include "core/host/market/account_manager.h"
#include "core/host/market/ledger_manager.h"
#include "core/host/market/market_manager.h"
#include "core/host/market/payment_manager.h"
#include "core/host/market/transaction_manager.h"
#include "core/host/market/trustline_manager.h"
#include "third_party/stellar/src/ledger/LedgerManager.h"
#include "third_party/stellar/src/crypto/ShortHash.h"
#include "third_party/stellar/src/util/RandHasher.h"
#include "third_party/stellar/src/util/Logging.h"
#include "third_party/stellar/src/main/ApplicationImpl.h"
#include "third_party/stellar/src/main/ApplicationUtils.h"
#include "third_party/stellar/src/history/HistoryArchiveManager.h"
#include "third_party/stellar/src/main/Config.h"
#include "third_party/xdrpp/xdrpp/marshal.h"

namespace host {

namespace {

const char config_file_str[] = "HTTP_PORT=11626\nPUBLIC_HTTP_PORT=false\n\nNETWORK_PASSPHRASE=\"Test SDF Network ; September 2015\"\n\nDATABASE=\"sqlite3://stellar.db\"\n\n# Stellar Testnet validators\n[[HOME_DOMAINS]]\nHOME_DOMAIN=\"testnet.stellar.org\"\nQUALITY=\"HIGH\"\n\n[[VALIDATORS]]\nNAME=\"sdftest1\"\nHOME_DOMAIN=\"testnet.stellar.org\"\nPUBLIC_KEY=\"GDKXE2OZMJIPOSLNA6N6F2BVCI3O777I2OOC4BV7VOYUEHYX7RTRYA7Y\"\nADDRESS=\"core-testnet1.stellar.org\"\nHISTORY=\"curl -sf http://history.stellar.org/prd/core-testnet/core_testnet_001/{0} -o {1}\"\n\n[[VALIDATORS]]\nNAME=\"sdftest2\"\nHOME_DOMAIN=\"testnet.stellar.org\"\nPUBLIC_KEY=\"GCUCJTIYXSOXKBSNFGNFWW5MUQ54HKRPGJUTQFJ5RQXZXNOLNXYDHRAP\"\nADDRESS=\"core-testnet2.stellar.org\"\nHISTORY=\"curl -sf http://history.stellar.org/prd/core-testnet/core_testnet_002/{0} -o {1}\"\n\n[[VALIDATORS]]\nNAME=\"sdftest3\"\nHOME_DOMAIN=\"testnet.stellar.org\"\nPUBLIC_KEY=\"GC2V2EFSXN6SQTWVYA5EPJPBWWIMSD2XQNKUOHGEKB535AQE2I6IXV2Z\"\nADDRESS=\"core-testnet3.stellar.org\"\nHISTORY=\"curl -sf http://history.stellar.org/prd/core-testnet/core_testnet_003/{0} -o {1}\"\n";

}

MarketManager::MarketManager(): 
  task_runner_(
    base::CreateSingleThreadTaskRunnerWithTraits(
     {base::MayBlock(), 
      base::WithBaseSyncPrimitives(), 
      base::TaskPriority::USER_BLOCKING},
      //base::TaskShutdownBehavior::SKIP_ON_SHUTDOWN},
      base::SingleThreadTaskRunnerThreadMode::DEDICATED)),
  shutting_down_(false) {
} 

MarketManager::~MarketManager() {

}

void MarketManager::Init() {
  account_manager_ = std::make_unique<AccountManager>(this);
  ledger_manager_ = std::make_unique<LedgerManager>(this);
  payment_manager_ = std::make_unique<PaymentManager>(this);
  transaction_manager_ = std::make_unique<TransactionManager>(this);
  trustline_manager_ = std::make_unique<TrustlineManager>(this);

  task_runner_->PostTask(
    FROM_HERE,
    base::BindOnce(&MarketManager::InitNetwork, 
                   base::Unretained(this)));
}

void MarketManager::Shutdown(base::WaitableEvent* shutdown_event) {
  shutting_down_ = true;
  task_runner_->PostTask(
   FROM_HERE,
   base::BindOnce(&MarketManager::ShutdownNetwork, 
                  base::Unretained(this),
                  base::Unretained(shutdown_event)));
}

stellar::LedgerManager& MarketManager::GetLedgerManager() {
  return application_->getLedgerManager();
}

void MarketManager::InitNetwork() {
  DLOG(INFO) << "MarketManager::InitNetwork";
  //auto disable_bucket_gc = false;
  std::string stream;
  bool in_memory = false;
  //bool wait_for_consensus = false;
  //uint32_t start_at_ledger = 0;
  std::string start_at_hash;
  std::string archive;
  stellar::Config config;

  DLOG(INFO) << "stellar::Logging::init()";
  stellar::Logging::init();
  DLOG(INFO) << "stellar::shortHash::initialize()";
  stellar::shortHash::initialize();
  DLOG(INFO) << "stellar::randHash::initialize()";
  stellar::randHash::initialize();
  xdr::marshaling_stack_limit = 1000;
  
  stellar::VirtualClock clock(stellar::VirtualClock::REAL_TIME);

  // FIXME: use the ResourceLoader/ pack file
  std::istringstream istr(config_file_str);

  DLOG(INFO) << "config.load(istr)";
  config.load(istr);
  
  DLOG(INFO) << "application_ = stellar::Application::create(clock, config, in_memory)";
  application_ = stellar::Application::create(clock, config, in_memory);
  DLOG(INFO) << "application_->getHistoryArchiveManager()";
  auto const& ham = application_->getHistoryArchiveManager();
  DLOG(INFO) << "ham.getHistoryArchive(archive)";
  auto archivePtr = ham.getHistoryArchive(archive);
  if (base::EqualsCaseInsensitiveASCII(archive, "any")){
    archivePtr = ham.selectRandomReadableHistoryArchive();
  }
  
  stellar::CatchupConfiguration cc(
    0 /* toLedger */, 
    0 /* uint32_t count */, 
    //stellar::CatchupConfiguration::Mode::ONLINE);
    stellar::CatchupConfiguration::Mode::OFFLINE_BASIC);
  Json::Value catchupInfo;
  
  DLOG(INFO) << "stellar::catchup(application_, cc, catchupInfo, archivePtr)";
  bool result = stellar::catchup(application_, cc, catchupInfo, archivePtr);
  if (!result) {
    printf("ledger catchup failed. not running..\n");
  }
  DLOG(INFO) << "MarketManager::InitImpl: stellar::runApp(application_)";
  stellar::runApp(application_);

  // if (!catchupInfo.isNull()) {
  //     writeCatchupInfo(catchupInfo, outputFile);
  // }
  // create_db: bool, force_rebuild: bool 
  //application_->initialize(false, true);
  //impl_ = stellar::MarketManager::Create(*application_);
  DLOG(INFO) << "MarketManager::InitImpl END";
}

void MarketManager::ShutdownNetwork(base::WaitableEvent* shutdown_event) {
  application_->gracefulStop();
  application_.reset();
  if (shutdown_event) {
    shutdown_event->Signal();
  }
}

}