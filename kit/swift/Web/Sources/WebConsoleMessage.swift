// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public struct WebConsoleMessage {
    
    public enum Level : Int {
      case Debug = 4
      case Log = 1
      case Info = 5
      case Warning = 2
      case Error = 3
      case RevokedError = 6
    }

    public var level: Level
    public var text: String
}