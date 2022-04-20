// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_VPN_OPENVPN_MANAGEMENT_SERVER_H_
#define SHILL_VPN_OPENVPN_MANAGEMENT_SERVER_H_

#include <memory>
#include <string>
#include <vector>

#include <gtest/gtest_prod.h>  // for FRIEND_TEST

#include "shill/data_types.h"
#include "shill/mockable.h"

namespace shill {

struct InputData;
class IOHandler;
class IOHandlerFactory;
class OpenVPNDriver;
class Sockets;

class OpenVPNManagementServer {
 public:
  static const char kStateAuth[];
  static const char kStateConnected[];
  static const char kStateReconnecting[];
  static const char kStateResolve[];

  explicit OpenVPNManagementServer(OpenVPNDriver* driver);
  OpenVPNManagementServer(const OpenVPNManagementServer&) = delete;
  OpenVPNManagementServer& operator=(const OpenVPNManagementServer&) = delete;

  virtual ~OpenVPNManagementServer();

  // Returns false on failure. On success, returns true and appends management
  // interface openvpn options to |options|.
  virtual bool Start(Sockets* sockets,
                     std::vector<std::vector<std::string>>* options);

  virtual void Stop();

  // Releases openvpn's hold if it's waiting for a hold release (i.e., if
  // |hold_waiting_| is true). Otherwise, sets |hold_release_| to true
  // indicating that the hold can be released as soon as openvpn requests.
  virtual void ReleaseHold();

  // Holds openvpn so that it doesn't connect or reconnect automatically (i.e.,
  // sets |hold_release_| to false). Note that this method neither drops an
  // existing connection, nor sends any commands to the openvpn client.
  virtual void Hold();

  // Restarts openvpn causing a disconnect followed by a reconnect attempt.
  virtual void Restart();

  // OpenVPN client state.
  const std::string& state() const { return state_; }

  // If Start() was called and no Stop() after that.
  mockable bool IsStarted() const { return sockets_ != nullptr; }

 private:
  friend class OpenVPNDriverTest;
  friend class OpenVPNManagementServerFuzzer;
  friend class OpenVPNManagementServerTest;
  FRIEND_TEST(OpenVPNManagementServerTest, EscapeToQuote);
  FRIEND_TEST(OpenVPNManagementServerTest, Hold);
  FRIEND_TEST(OpenVPNManagementServerTest, OnInputStop);
  FRIEND_TEST(OpenVPNManagementServerTest, OnReady);
  FRIEND_TEST(OpenVPNManagementServerTest, OnReadyAcceptFail);
  FRIEND_TEST(OpenVPNManagementServerTest, PerformAuthentication);
  FRIEND_TEST(OpenVPNManagementServerTest, PerformAuthenticationNoCreds);
  FRIEND_TEST(OpenVPNManagementServerTest, PerformStaticChallengeNoCreds);
  FRIEND_TEST(OpenVPNManagementServerTest, PerformStaticChallengeOTP);
  FRIEND_TEST(OpenVPNManagementServerTest, PerformStaticChallengeToken);
  FRIEND_TEST(OpenVPNManagementServerTest, ProcessFailedPasswordMessage);
  FRIEND_TEST(OpenVPNManagementServerTest, ProcessHoldMessage);
  FRIEND_TEST(OpenVPNManagementServerTest, ProcessInfoMessage);
  FRIEND_TEST(OpenVPNManagementServerTest, ProcessNeedPasswordMessageAuth);
  FRIEND_TEST(OpenVPNManagementServerTest, ProcessNeedPasswordMessageAuthSC);
  FRIEND_TEST(OpenVPNManagementServerTest, ProcessNeedPasswordMessageTPMToken);
  FRIEND_TEST(OpenVPNManagementServerTest, ProcessNeedPasswordMessageUnknown);
  FRIEND_TEST(OpenVPNManagementServerTest, Send);
  FRIEND_TEST(OpenVPNManagementServerTest, SendHoldRelease);
  FRIEND_TEST(OpenVPNManagementServerTest, SendPassword);
  FRIEND_TEST(OpenVPNManagementServerTest, SendPasswordWithSpecialCharacters);
  FRIEND_TEST(OpenVPNManagementServerTest, SendState);
  FRIEND_TEST(OpenVPNManagementServerTest, SendUsername);
  FRIEND_TEST(OpenVPNManagementServerTest, SendUsernameWithSpecialCharacters);
  FRIEND_TEST(OpenVPNManagementServerTest, Start);
  FRIEND_TEST(OpenVPNManagementServerTest, Stop);
  FRIEND_TEST(OpenVPNManagementServerTest, SupplyTPMToken);
  FRIEND_TEST(OpenVPNManagementServerTest, SupplyTPMTokenNoPin);

  // IO handler callbacks.
  void OnReady(int fd);
  void OnInput(InputData* data);
  void OnInputError(const std::string& error_msg);

  void Send(const std::string& data);
  void SendState(const std::string& state);
  void SendUsername(const std::string& tag, const std::string& username);
  void SendPassword(const std::string& tag, const std::string& password);
  void SendHoldRelease();
  void SendSignal(const std::string& signal);
  void SendStatus();

  void ProcessMessage(const std::string& message);
  bool ProcessInfoMessage(const std::string& message);
  bool ProcessNeedPasswordMessage(const std::string& message);
  bool ProcessFailedPasswordMessage(const std::string& message);
  bool ProcessAuthTokenMessage(const std::string& message);
  bool ProcessStateMessage(const std::string& message);
  bool ProcessHoldMessage(const std::string& message);
  bool ProcessSuccessMessage(const std::string& message);
  bool ProcessStatusMessage(const std::string& message);

  void PerformStaticChallenge(const std::string& tag);
  void PerformAuthentication(const std::string& tag);
  void SupplyTPMToken(const std::string& tag);

  // Returns the first substring in |message| enclosed by the |start| and |end|
  // substrings. Note that the first |end| substring after the position of
  // |start| is matched.
  static std::string ParseSubstring(const std::string& message,
                                    const std::string& start,
                                    const std::string& end);

  // Password messages come in two forms:
  //
  // >PASSWORD:Need 'AUTH_TYPE' ...
  // >PASSWORD:Verification Failed: 'AUTH_TYPE' ['REASON_STRING']
  //
  // ParsePasswordTag parses AUTH_TYPE out of a password |message| and returns
  // it. ParsePasswordFailedReason parses REASON_STRING, if any, out of a
  // password |message| and returns it.
  static std::string ParsePasswordTag(const std::string& message);
  static std::string ParsePasswordFailedReason(const std::string& message);

  // Escapes |str| per OpenVPN's command parsing rules assuming |str| will be
  // sent over the management interface quoted (i.e., whitespace is not
  // escaped).
  static std::string EscapeToQuote(const std::string& str);

  OpenVPNDriver* driver_;

  Sockets* sockets_;
  int socket_;
  IOHandlerFactory* io_handler_factory_;
  std::unique_ptr<IOHandler> ready_handler_;
  int connected_socket_;
  std::unique_ptr<IOHandler> input_handler_;

  std::string state_;

  bool hold_waiting_;
  bool hold_release_;
};

}  // namespace shill

#endif  // SHILL_VPN_OPENVPN_MANAGEMENT_SERVER_H_
