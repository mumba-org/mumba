// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_KIT_CPP_LAUNCHER_INDEXED_DB_CLEAR_OBJECT_STORE_COMMAND_H_
#define MUMBA_KIT_CPP_LAUNCHER_INDEXED_DB_CLEAR_OBJECT_STORE_COMMAND_H_

#include "launcher/command.h"

class IndexedDBClearObjectStoreCommand : public Command {
public:
 static std::unique_ptr<IndexedDBClearObjectStoreCommand> Create();

 IndexedDBClearObjectStoreCommand();
 ~IndexedDBClearObjectStoreCommand() override;
 
 std::string GetCommandMethod() const override;
 int Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) override;
};

#endif