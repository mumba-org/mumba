// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public enum ShareInfoKind : Int {
  case raw = 0
  case data
  case file
}

public enum ShareInfoState : Int {
  case none = 0
  case checking
  case downloadingMeta
  case downloading
  case finished
  case seeding
  case error
}

public struct ShareEntry {
  public var name: String = String()
  public var path: String = String()
  public var contentType: String = String()
  public var offset: Int = -1
  public var size: Int64 = -1
  public var blocks: Int = -1
  public var startBlock: Int = -1
  public var endBlock: Int = -1
  public var createdTime: Int64 = -1

  public init() {}
}

public class ShareInfo {
  public var uuid: String = String()
  public var path: String = String()
  public var kind: ShareInfoKind = .raw
  public var state: ShareInfoState = .none
  public var rootHash: String = String()
  public var size: Int64 = -1
  public var blocks: Int = -1
  public var blockSize: Int = -1
  public var createdTime: Int64 = -1
  public var entryCount: Int = -1
  public var entries: ContiguousArray<ShareEntry> = ContiguousArray<ShareEntry>()

  public init() {}
}
