// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_STORAGE_COMMANDS_H_
#define MUMBA_STORAGE_COMMANDS_H_

#include <map>
#include <set>
#include <string>
#include <vector>

#include "base/strings/string_piece.h"
#include "base/values.h"
#include "base/macros.h"
#include "storage/storage_export.h"

// Note; this is exactly like the gn command interface
namespace storage {

typedef int (*CommandRunner)(const std::vector<std::string>&);

/*
 * Info - try to understand what a disk is
 *        by reading its manifest
 */
extern const char kInfo[];
extern const char kInfo_HelpShort[];
extern const char kInfo_Help[];
int STORAGE_EXPORT RunInfo(const std::vector<std::string>& args);

/*
 * Create - create a new disk
 */
extern const char kCreate[];
extern const char kCreate_HelpShort[];
extern const char kCreate_Help[];
int STORAGE_EXPORT RunCreate(const std::vector<std::string>& args);

/*
 * Clone - clone a disk
 */
extern const char kClone[];
extern const char kClone_HelpShort[];
extern const char kClone_Help[];
int STORAGE_EXPORT RunClone(const std::vector<std::string>& args);

/*
 * Copy - copy a file
 */
// extern const char kCopy[];
// extern const char kCopy_HelpShort[];
// extern const char kCopy_Help[];
// int STORAGE_EXPORT RunCopy(const std::vector<std::string>& args);

/*
 * Start - start a disk
 */
extern const char kStart[];
extern const char kStart_HelpShort[];
extern const char kStart_Help[];
int STORAGE_EXPORT RunStart(const std::vector<std::string>& args);

/*
 * Stop - stop a disk
 */
extern const char kStop[];
extern const char kStop_HelpShort[];
extern const char kStop_Help[];
int STORAGE_EXPORT RunStop(const std::vector<std::string>& args);

/*
 * List - list disks
 */
extern const char kList[];
extern const char kList_HelpShort[];
extern const char kList_Help[];
int STORAGE_EXPORT RunList(const std::vector<std::string>& args);


/*
 * Blob - manage files on disk
 */
extern const char kBlob[];
extern const char kBlob_HelpShort[];
extern const char kBlob_Help[];
int STORAGE_EXPORT RunBlob(const std::vector<std::string>& args);

/*
 * Ls - list the files added to the disk
 */
extern const char kLs[];
extern const char kLs_HelpShort[];
extern const char kLs_Help[];
int STORAGE_EXPORT RunLs(const std::vector<std::string>& args);

/*
 * Sign - public signature management commands
 */
extern const char kSign[];
extern const char kSign_HelpShort[];
extern const char kSign_Help[];
int STORAGE_EXPORT RunSign(const std::vector<std::string>& args);


/*
 * App - commands to manage an application in a disk
 */
//extern const char kApp[];
//extern const char kApp_HelpShort[];
//extern const char kApp_Help[];
//int RunApp(const std::vector<std::string>& args);

/*
 * Help - show help
 */
extern const char kHelp[];
extern const char kHelp_HelpShort[];
extern const char kHelp_Help[];
int STORAGE_EXPORT RunHelp(const std::vector<std::string>& args);

/*
 * Db - db
 */
extern const char kDatabase[];
extern const char kDatabase_HelpShort[];
extern const char kDatabase_Help[];
int STORAGE_EXPORT RunDatabase(const std::vector<std::string>& args);

/*
 * Query
 */
//extern const char kQuery[];
//extern const char kQuery_HelpShort[];
//extern const char kQuery_Help[];
//int RunQuery(const std::vector<std::string>& args);

/*
 * Session - start a koden DHT session
 */
extern const char kSession[];
extern const char kSession_HelpShort[];
extern const char kSession_Help[];
int STORAGE_EXPORT RunSession(const std::vector<std::string>& args);

/*
 * Put - put a entry on DHT
 */
extern const char kPut[];
extern const char kPut_HelpShort[];
extern const char kPut_Help[];
int STORAGE_EXPORT RunPut(const std::vector<std::string>& args);

/*
 * Get - get a entry on DHT
 */
extern const char kGet[];
extern const char kGet_HelpShort[];
extern const char kGet_Help[];
int STORAGE_EXPORT RunGet(const std::vector<std::string>& args);

/*
 * Sample - a sample of a disk
 */
extern const char kSample[];
extern const char kSample_HelpShort[];
extern const char kSample_Help[];
int STORAGE_EXPORT RunSample(const std::vector<std::string>& args);

/*
 * Client
 */
extern const char kClient[];
extern const char kClient_HelpShort[];
extern const char kClient_Help[];
int STORAGE_EXPORT RunClient(const std::vector<std::string>& args);

/*
 * Server
 */
extern const char kServer[];
extern const char kServer_HelpShort[];
extern const char kServer_Help[];
int STORAGE_EXPORT RunServer(const std::vector<std::string>& args);

/*
 * Torrent
 */
extern const char kTorrent[];
extern const char kTorrent_HelpShort[];
extern const char kTorrent_Help[];
int STORAGE_EXPORT RunTorrent(const std::vector<std::string>& args);

struct CommandInfo {
  CommandInfo();
  CommandInfo(const char* in_help_short,
              const char* in_help,
              CommandRunner in_runner);

  const char* help_short;
  const char* help;
  CommandRunner runner;
};

typedef std::map<base::StringPiece, CommandInfo> CommandInfoMap;

const CommandInfoMap& GetCommands();

}

#endif