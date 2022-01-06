// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Value type command line
public struct Command {

  public var argCount: Int { return Int(CommandLine.argc) }
  public let arguments: [String]
  // fullpath of the executable being called
  public let path: FilePath

  public var stringValue: String? {
    return arguments.joined(separator: " ")
  }

  public static func isFlag(arg: String) -> Bool {

    guard !arg.isEmpty else {
      return false
    }

    if arg[arg.startIndex] == "-" {
      return true
    }

    return false
  }
  
  public static func isUrl(arg: String) -> Bool {
   // very simple and stupid.. fix! with a real url class testing this
   for ch in arg {
     if ch == ":" {
       return true
     }
   }
   return false
  }

  public init(args: [String]) {
    arguments = args
    path = FilePath.from(string: args[0])
  }

  public init() {
    self.init(args: CommandLine.arguments)
  }
}
