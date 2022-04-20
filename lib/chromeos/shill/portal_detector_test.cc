// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/portal_detector.h"

#include <memory>
#include <set>
#include <string>
#include <vector>

#include <base/bind.h>
#include <base/time/time.h>
#include <brillo/http/http_request.h>
#include <brillo/http/mock_connection.h>
#include <brillo/http/mock_transport.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "shill/manager.h"
#include "shill/mock_event_dispatcher.h"
#include "shill/mock_metrics.h"

using testing::_;
using testing::Mock;
using testing::NiceMock;
using testing::Return;
using testing::ReturnRef;
using testing::StrictMock;
using testing::Test;

namespace shill {

namespace {
const char kBadURL[] = "badurl";
const char kInterfaceName[] = "int0";
const char kHttpUrl[] = "http://www.chromium.org";
const char kHttpsUrl[] = "https://www.google.com";
const std::vector<std::string> kFallbackHttpUrls{
    "http://www.google.com/gen_204",
    "http://play.googleapis.com/generate_204",
};
const IPAddress kIpAddress = IPAddress("1.2.3.4");
const char kDNSServer0[] = "8.8.8.8";
const char kDNSServer1[] = "8.8.4.4";
const char* const kDNSServers[] = {kDNSServer0, kDNSServer1};

class MockHttpRequest : public HttpRequest {
 public:
  MockHttpRequest()
      : HttpRequest(nullptr,
                    kInterfaceName,
                    IPAddress(IPAddress::kFamilyIPv4),
                    {kDNSServer0, kDNSServer1},
                    true) {}
  MockHttpRequest(const MockHttpRequest&) = delete;
  MockHttpRequest& operator=(const MockHttpRequest&) = delete;
  ~MockHttpRequest() = default;

  MOCK_METHOD(
      HttpRequest::Result,
      Start,
      (const std::string&,
       const std::string&,
       const brillo::http::HeaderList&,
       const base::Callback<void(std::shared_ptr<brillo::http::Response>)>&,
       const base::Callback<void(Result)>&),
      (override));
  MOCK_METHOD(void, Stop, (), (override));
};

}  // namespace

MATCHER_P(IsResult, result, "") {
  return (result.http_phase == arg.http_phase &&
          result.http_status == arg.http_status &&
          result.https_phase == arg.https_phase &&
          result.https_status == arg.https_status &&
          result.redirect_url_string == arg.redirect_url_string &&
          result.probe_url_string == arg.probe_url_string);
}

class PortalDetectorTest : public Test {
 public:
  PortalDetectorTest()
      : transport_(std::make_shared<brillo::http::MockTransport>()),
        brillo_connection_(
            std::make_shared<brillo::http::MockConnection>(transport_)),
        portal_detector_(new PortalDetector(
            &dispatcher_, &metrics_, callback_target_.result_callback())),
        interface_name_(kInterfaceName),
        dns_servers_(kDNSServers, kDNSServers + 2),
        http_request_(nullptr),
        https_request_(nullptr) {}

  void SetUp() override { EXPECT_EQ(nullptr, portal_detector_->http_request_); }

  void TearDown() override {
    Mock::VerifyAndClearExpectations(&http_request_);
    if (portal_detector()->http_request_) {
      EXPECT_CALL(*http_request(), Stop());
      EXPECT_CALL(*https_request(), Stop());

      // Delete the portal detector while expectations still exist.
      portal_detector_.reset();
    }
    testing::Mock::VerifyAndClearExpectations(brillo_connection_.get());
    brillo_connection_.reset();
    testing::Mock::VerifyAndClearExpectations(transport_.get());
    transport_.reset();
  }

 protected:
  static const int kNumAttempts;

  class CallbackTarget {
   public:
    CallbackTarget()
        : result_callback_(base::Bind(&CallbackTarget::ResultCallback,
                                      base::Unretained(this))) {}

    MOCK_METHOD(void, ResultCallback, (const PortalDetector::Result&));

    base::Callback<void(const PortalDetector::Result&)>& result_callback() {
      return result_callback_;
    }

   private:
    base::Callback<void(const PortalDetector::Result&)> result_callback_;
  };

  void AssignHttpRequest() {
    http_request_ = new StrictMock<MockHttpRequest>();
    https_request_ = new StrictMock<MockHttpRequest>();
    portal_detector_->http_request_.reset(http_request_);
    portal_detector_->https_request_.reset(
        https_request_);  // Passes ownership.
  }

  static ManagerProperties MakePortalProperties() {
    ManagerProperties props;
    props.portal_http_url = kHttpUrl;
    props.portal_https_url = kHttpsUrl;
    props.portal_fallback_http_urls = kFallbackHttpUrls;
    return props;
  }

  bool StartPortalRequest(const ManagerProperties& props,
                          base::TimeDelta delay = base::TimeDelta()) {
    bool ret = portal_detector_->Start(props, kInterfaceName, kIpAddress,
                                       {kDNSServer0, kDNSServer1}, delay);
    if (ret) {
      AssignHttpRequest();
    }
    return ret;
  }

  void StartTrialTask() {
    EXPECT_CALL(*http_request(), Start(_, _, _, _, _))
        .WillOnce(Return(HttpRequest::kResultInProgress));
    EXPECT_CALL(*https_request(), Start(_, _, _, _, _))
        .WillOnce(Return(HttpRequest::kResultInProgress));
    portal_detector()->StartTrialTask();
  }

  MockHttpRequest* http_request() { return http_request_; }
  MockHttpRequest* https_request() { return https_request_; }
  PortalDetector* portal_detector() { return portal_detector_.get(); }
  MockEventDispatcher& dispatcher() { return dispatcher_; }
  CallbackTarget& callback_target() { return callback_target_; }
  MockMetrics& metrics() { return metrics_; }
  brillo::http::MockConnection* brillo_connection() {
    return brillo_connection_.get();
  }

  void ExpectReset() {
    EXPECT_FALSE(portal_detector_->attempt_count_);
    EXPECT_TRUE(callback_target_.result_callback() ==
                portal_detector_->portal_result_callback_);
    EXPECT_EQ(nullptr, portal_detector_->http_request_);
    EXPECT_EQ(nullptr, portal_detector_->https_request_);
  }

  void StartAttempt() {
    EXPECT_CALL(dispatcher(), PostDelayedTask(_, _, base::TimeDelta()));
    ManagerProperties props = MakePortalProperties();
    EXPECT_TRUE(StartPortalRequest(props));
    StartTrialTask();
  }

  void ExpectRequestSuccessWithStatus(int status_code, bool is_http) {
    EXPECT_CALL(*brillo_connection_, GetResponseStatusCode())
        .WillOnce(Return(status_code));

    auto response =
        std::make_shared<brillo::http::Response>(brillo_connection_);
    if (is_http)
      portal_detector_->HttpRequestSuccessCallback(response);
    else
      portal_detector_->HttpsRequestSuccessCallback(response);
  }

 protected:
  StrictMock<MockEventDispatcher> dispatcher_;
  std::shared_ptr<brillo::http::MockTransport> transport_;
  NiceMock<MockMetrics> metrics_;
  std::shared_ptr<brillo::http::MockConnection> brillo_connection_;
  CallbackTarget callback_target_;
  std::unique_ptr<PortalDetector> portal_detector_;
  const std::string interface_name_;
  std::vector<std::string> dns_servers_;
  MockHttpRequest* http_request_;
  MockHttpRequest* https_request_;
};

// static
const int PortalDetectorTest::kNumAttempts = 0;

TEST_F(PortalDetectorTest, Constructor) {
  ExpectReset();
}

TEST_F(PortalDetectorTest, InvalidURL) {
  EXPECT_FALSE(portal_detector()->IsInProgress());
  EXPECT_CALL(dispatcher(), PostDelayedTask(_, _, base::TimeDelta())).Times(0);
  ManagerProperties props = MakePortalProperties();
  props.portal_http_url = kBadURL;
  EXPECT_FALSE(StartPortalRequest(props));
  ExpectReset();

  EXPECT_FALSE(portal_detector()->IsInProgress());
}

TEST_F(PortalDetectorTest, IsInProgress) {
  // Before the trial is started, should not be active.
  EXPECT_FALSE(portal_detector()->IsInProgress());

  // Once the trial is started, IsInProgress should return true.
  EXPECT_CALL(dispatcher(), PostDelayedTask(_, _, base::TimeDelta()));
  ManagerProperties props = MakePortalProperties();
  EXPECT_TRUE(StartPortalRequest(props));

  StartTrialTask();
  EXPECT_TRUE(portal_detector()->IsInProgress());

  // Finish the trial, IsInProgress should return false.
  EXPECT_CALL(*http_request(), Stop()).Times(1);
  EXPECT_CALL(*https_request(), Stop()).Times(1);
  PortalDetector::Result result;
  result.http_phase = PortalDetector::Phase::kContent,
  result.http_status = PortalDetector::Status::kFailure;
  result.https_phase = PortalDetector::Phase::kContent;
  result.https_status = PortalDetector::Status::kSuccess;
  portal_detector()->CompleteTrial(result);
  EXPECT_FALSE(portal_detector()->IsInProgress());
}

TEST_F(PortalDetectorTest, StartAttemptFailed) {
  EXPECT_CALL(dispatcher(), PostDelayedTask(_, _, base::TimeDelta()));
  ManagerProperties props = MakePortalProperties();
  EXPECT_TRUE(StartPortalRequest(props));

  // Expect that the request will be started -- return failure.
  EXPECT_CALL(*http_request(), Start(_, _, _, _, _))
      .WillOnce(Return(HttpRequest::kResultDNSFailure));

  EXPECT_CALL(dispatcher(), PostDelayedTask(_, _, base::TimeDelta())).Times(0);
  EXPECT_CALL(*http_request(), Stop()).Times(1);
  EXPECT_CALL(*https_request(), Stop()).Times(1);

  // Expect a non-final failure to be relayed to the caller.
  PortalDetector::Result result;
  result.http_phase = PortalDetector::Phase::kDNS,
  result.http_status = PortalDetector::Status::kFailure;
  result.https_phase = PortalDetector::Phase::kContent;
  result.https_status = PortalDetector::Status::kFailure;
  result.num_attempts = kNumAttempts;
  EXPECT_CALL(callback_target(), ResultCallback(IsResult(result)));

  portal_detector()->StartTrialTask();
}

TEST_F(PortalDetectorTest, GetNextAttemptDelay) {
  EXPECT_EQ(portal_detector()->GetNextAttemptDelay(), base::TimeDelta());

  ManagerProperties props = MakePortalProperties();
  EXPECT_CALL(dispatcher(), PostDelayedTask(_, _, base::TimeDelta()));
  EXPECT_TRUE(StartPortalRequest(props));

  EXPECT_TRUE(base::TimeDelta() < portal_detector()->GetNextAttemptDelay());
}

TEST_F(PortalDetectorTest, DelayedAttempt) {
  const auto delay = base::Seconds(123);
  ManagerProperties props = MakePortalProperties();
  EXPECT_CALL(dispatcher(), PostDelayedTask(_, _, delay)).Times(1);
  EXPECT_TRUE(StartPortalRequest(props, delay));
}

TEST_F(PortalDetectorTest, StartRepeated) {
  EXPECT_CALL(dispatcher(), PostDelayedTask(_, _, base::TimeDelta())).Times(1);
  ManagerProperties props = MakePortalProperties();
  EXPECT_TRUE(StartPortalRequest(props));

  // A second  should cancel the existing trial and set up the new one.
  const auto delay = base::Seconds(10);
  EXPECT_CALL(*http_request(), Stop());
  EXPECT_CALL(*https_request(), Stop());
  EXPECT_CALL(dispatcher(), PostDelayedTask(_, _, delay)).Times(1);
  EXPECT_TRUE(StartPortalRequest(props, delay));
}

TEST_F(PortalDetectorTest, AttemptCount) {
  EXPECT_FALSE(portal_detector()->IsInProgress());
  // Expect the PortalDetector to immediately post a task for the each attempt.
  EXPECT_CALL(dispatcher(), PostDelayedTask(_, _, _)).Times(4);
  ManagerProperties props = MakePortalProperties();
  EXPECT_TRUE(StartPortalRequest(props));
  EXPECT_EQ(portal_detector()->http_url_string_, props.portal_http_url);

  PortalDetector::Result result;
  result.http_phase = PortalDetector::Phase::kDNS,
  result.http_status = PortalDetector::Status::kFailure;
  result.https_phase = PortalDetector::Phase::kContent;
  result.https_status = PortalDetector::Status::kFailure;
  result.num_attempts = kNumAttempts;
  EXPECT_CALL(callback_target(), ResultCallback(IsResult(result))).Times(3);

  // Expect the PortalDetector to stop the trial after
  // the final attempt.
  EXPECT_CALL(*http_request(), Stop()).Times(7);
  EXPECT_CALL(*https_request(), Stop()).Times(7);

  std::set<std::string> expected_retry_http_urls(
      props.portal_fallback_http_urls.begin(),
      props.portal_fallback_http_urls.end());
  expected_retry_http_urls.insert(props.portal_http_url);

  std::set<std::string> expected_retry_https_urls(
      props.portal_fallback_https_urls.begin(),
      props.portal_fallback_https_urls.end());
  expected_retry_https_urls.insert(props.portal_https_url);

  auto last_delay = base::TimeDelta();
  for (int i = 0; i < 3; i++) {
    const auto delay = portal_detector()->GetNextAttemptDelay();
    EXPECT_TRUE(last_delay < delay);
    last_delay = delay;
    portal_detector()->Start(props, kInterfaceName, kIpAddress,
                             {kDNSServer0, kDNSServer1});

    EXPECT_NE(
        expected_retry_http_urls.find(portal_detector()->http_url_string_),
        expected_retry_http_urls.end());
    EXPECT_NE(
        expected_retry_https_urls.find(portal_detector()->https_url_string_),
        expected_retry_https_urls.end());

    portal_detector()->CompleteTrial(result);
  }
  portal_detector()->Stop();
  ExpectReset();
}

TEST_F(PortalDetectorTest, RequestSuccess) {
  StartAttempt();

  // HTTPS probe does not trigger anything (for now)
  PortalDetector::Result result;
  result.http_phase = PortalDetector::Phase::kContent,
  result.http_status = PortalDetector::Status::kSuccess;
  result.https_phase = PortalDetector::Phase::kContent;
  result.https_status = PortalDetector::Status::kSuccess;
  result.num_attempts = kNumAttempts;
  EXPECT_CALL(callback_target(), ResultCallback(IsResult(result))).Times(0);
  EXPECT_CALL(*http_request(), Stop()).Times(0);
  EXPECT_CALL(*https_request(), Stop()).Times(0);
  ExpectRequestSuccessWithStatus(204, false);

  EXPECT_CALL(callback_target(), ResultCallback(IsResult(result)));
  EXPECT_CALL(*http_request(), Stop()).Times(1);
  EXPECT_CALL(*https_request(), Stop()).Times(1);
  EXPECT_CALL(metrics(), NotifyPortalDetectionMultiProbeResult(_));
  ExpectRequestSuccessWithStatus(204, true);
}

TEST_F(PortalDetectorTest, RequestHTTPFailureHTTPSSuccess) {
  StartAttempt();

  // HTTPS probe does not trigger anything (for now)
  PortalDetector::Result result;
  result.http_phase = PortalDetector::Phase::kContent,
  result.http_status = PortalDetector::Status::kFailure;
  result.https_phase = PortalDetector::Phase::kContent;
  result.https_status = PortalDetector::Status::kSuccess;
  result.num_attempts = kNumAttempts;
  EXPECT_CALL(callback_target(), ResultCallback(IsResult(result))).Times(0);
  EXPECT_CALL(*http_request(), Stop()).Times(0);
  EXPECT_CALL(*https_request(), Stop()).Times(0);
  ExpectRequestSuccessWithStatus(123, true);

  EXPECT_CALL(callback_target(), ResultCallback(IsResult(result)));
  EXPECT_CALL(*http_request(), Stop()).Times(1);
  EXPECT_CALL(*https_request(), Stop()).Times(1);
  EXPECT_CALL(metrics(), NotifyPortalDetectionMultiProbeResult(_));
  ExpectRequestSuccessWithStatus(204, false);
}

TEST_F(PortalDetectorTest, RequestFail) {
  StartAttempt();

  // HTTPS probe does not trigger anything (for now)
  PortalDetector::Result result;
  result.http_phase = PortalDetector::Phase::kContent,
  result.http_status = PortalDetector::Status::kFailure;
  result.https_phase = PortalDetector::Phase::kContent;
  result.https_status = PortalDetector::Status::kFailure;
  result.num_attempts = kNumAttempts;
  EXPECT_CALL(callback_target(), ResultCallback(IsResult(result))).Times(0);
  EXPECT_CALL(*http_request(), Stop()).Times(0);
  EXPECT_CALL(*https_request(), Stop()).Times(0);
  ExpectRequestSuccessWithStatus(123, false);

  EXPECT_CALL(callback_target(), ResultCallback(IsResult(result)));
  EXPECT_CALL(*http_request(), Stop()).Times(1);
  EXPECT_CALL(*https_request(), Stop()).Times(1);
  EXPECT_CALL(metrics(), NotifyPortalDetectionMultiProbeResult(_));
  ExpectRequestSuccessWithStatus(123, true);
}

TEST_F(PortalDetectorTest, RequestRedirect) {
  StartAttempt();

  PortalDetector::Result result;
  result.http_phase = PortalDetector::Phase::kContent,
  result.http_status = PortalDetector::Status::kRedirect;
  result.https_phase = PortalDetector::Phase::kContent;
  result.https_status = PortalDetector::Status::kFailure;
  result.redirect_url_string = kHttpUrl;
  result.probe_url_string = kHttpUrl;
  EXPECT_CALL(callback_target(), ResultCallback(IsResult(result))).Times(0);
  EXPECT_CALL(*http_request(), Stop()).Times(0);
  EXPECT_CALL(*https_request(), Stop()).Times(0);
  ExpectRequestSuccessWithStatus(123, false);

  EXPECT_CALL(callback_target(), ResultCallback(IsResult(result)));
  EXPECT_CALL(*http_request(), Stop()).Times(1);
  EXPECT_CALL(*https_request(), Stop()).Times(1);
  EXPECT_CALL(*brillo_connection(), GetResponseHeader("Location"))
      .WillOnce(Return(kHttpUrl));
  EXPECT_CALL(metrics(), NotifyPortalDetectionMultiProbeResult(_));
  ExpectRequestSuccessWithStatus(302, true);
}

TEST_F(PortalDetectorTest, PhaseToString) {
  struct {
    PortalDetector::Phase phase;
    std::string expected_name;
  } test_cases[] = {
      {PortalDetector::Phase::kConnection, "Connection"},
      {PortalDetector::Phase::kDNS, "DNS"},
      {PortalDetector::Phase::kHTTP, "HTTP"},
      {PortalDetector::Phase::kContent, "Content"},
      {PortalDetector::Phase::kUnknown, "Unknown"},
  };

  for (const auto& t : test_cases) {
    EXPECT_EQ(t.expected_name, PortalDetector::PhaseToString(t.phase));
  }
}

TEST_F(PortalDetectorTest, StatusToString) {
  struct {
    PortalDetector::Status status;
    std::string expected_name;
  } test_cases[] = {
      {PortalDetector::Status::kSuccess, "Success"},
      {PortalDetector::Status::kTimeout, "Timeout"},
      {PortalDetector::Status::kRedirect, "Redirect"},
      {PortalDetector::Status::kFailure, "Failure"},
  };

  for (const auto& t : test_cases) {
    EXPECT_EQ(t.expected_name, PortalDetector::StatusToString(t.status));
  }
}

TEST_F(PortalDetectorTest, PickProbeUrlTest) {
  const std::string url1 = "http://www.url1.com";
  const std::string url2 = "http://www.url2.com";
  const std::string url3 = "http://www.url3.com";
  const std::set<std::string> all_urls = {url1, url2, url3};
  std::set<std::string> all_found_urls;

  EXPECT_EQ(url1, portal_detector_->PickProbeUrl(url1, {}));
  EXPECT_EQ(url1, portal_detector_->PickProbeUrl(url1, {url2, url3}));

  // The loop index starts at 1 to force a non-zero |attempt_count_| and to
  // force using the fallback list.
  for (int i = 1; i < 100; i++) {
    portal_detector_->attempt_count_ = i;
    EXPECT_EQ(portal_detector_->PickProbeUrl(url1, {}), url1);

    const auto found = portal_detector_->PickProbeUrl(url1, {url2, url3});
    all_found_urls.insert(found);
    EXPECT_NE(all_urls.find(found), all_urls.end());
  }
  // Probability this assert fails = 3 * 1/3 ^ 99 + 3 * 2/3 ^ 99
  EXPECT_EQ(all_urls, all_found_urls);
}

}  // namespace shill
