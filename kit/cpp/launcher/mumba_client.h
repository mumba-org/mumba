// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_KIT_CPP_LAUNCHER_MUMBA_CLIENT_H_
#define MUMBA_KIT_CPP_LAUNCHER_MUMBA_CLIENT_H_

#include <string>

// A gRPC client to the mumba control service
class MumbaClient {
public:
 MumbaClient();
 ~MumbaClient();
 
 // Application control ops
 void LaunchApplication(const std::string& url);
 void CloseApplication(const std::string& url);
 void InstallApplication(const std::string& url);
 void StartApplication(const std::string& app_name);
 void StopApplication(const std::string& app_name);
 void UninstallApplication(const std::string& app_name);
 void UpdateApplication(const std::string& app_name);
 void PinApplication(const std::string& app_name);
 void UnpinApplication(const std::string& app_name);
 void ApplicationStatus(const std::string& app_name);
 
 // Application common denominator ops
 void ApplicationCall(const std::string& app_name, const std::string& method_name, const std::vector<std::string>& args);
 void ApplicationGo(const std::string& app_name, const std::string& url);

private:
  
};

#endif