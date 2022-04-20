// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_NET_MOCK_IO_HANDLER_FACTORY_H_
#define SHILL_NET_MOCK_IO_HANDLER_FACTORY_H_

#include <gmock/gmock.h>

#include "shill/net/io_handler_factory.h"

namespace shill {

class MockIOHandlerFactory : public IOHandlerFactory {
 public:
  MockIOHandlerFactory() = default;
  MockIOHandlerFactory(const MockIOHandlerFactory&) = delete;
  MockIOHandlerFactory& operator=(const MockIOHandlerFactory&) = delete;

  ~MockIOHandlerFactory() override = default;

  MOCK_METHOD(IOHandler*,
              CreateIOInputHandler,
              (int,
               const IOHandler::InputCallback&,
               const IOHandler::ErrorCallback&),
              (override));
  MOCK_METHOD(IOHandler*,
              CreateIOReadyHandler,
              (int, IOHandler::ReadyMode, const IOHandler::ReadyCallback&),
              (override));
};

}  // namespace shill

#endif  // SHILL_NET_MOCK_IO_HANDLER_FACTORY_H_
