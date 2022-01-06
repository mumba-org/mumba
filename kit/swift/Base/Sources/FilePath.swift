// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public struct FilePath {

  public var pathString: String

  public var isEmpty: Bool {
    return pathString.isEmpty
  }

  // individual items separated by the separator
  public var items: [String] {
    return [String]()
  }

  public var dirname: FilePath {
    return FilePath(path: pathString)
  }

  public var basename: FilePath {
    return FilePath(path: pathString)
  }

  public var fileExtension: String {
    return ""
  }

  public var isAbsolute: Bool {
    return false
  }

  public var endsWithSeparator: Bool {
    return false
  }

  public static func isSeparator(ch: Character) -> Bool {
    return false
  }

  public static func from(string str: String) -> FilePath {
    return FilePath(path: str)
  }

  public init(path: String) {
    pathString = path
  }

  public mutating func reset() {
    pathString.removeAll()
  }

  public func isParent(of child: FilePath) -> Bool {
    return false
  }

  public func append(path p: FilePath) -> FilePath {
    return FilePath(path: "")
  }

  public func append(string str: String) -> FilePath {
    return FilePath(path: "")
  }

  public func appendRelativePath(child: FilePath, path: inout FilePath) {

  }

}

public func == (left: FilePath, right: FilePath) -> Bool {
  // TODO: implementar ignorando case
  return left.pathString == right.pathString
}

public func != (left: FilePath, right: FilePath) -> Bool {
  return left.pathString != right.pathString
}

extension FilePath : Equatable {}
