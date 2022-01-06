// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public struct WebFindOptions {

    public var forward: Bool = false
    public var matchCase: Bool = false
    public var findNext: Bool = false
    public var wordStart: Bool = false
    public var medialCapitalAsWordStart: Bool = false
    public var force: Bool = false

    public init() {}
    
    public init(
      forward: Bool,
      matchCase: Bool,
      findNext: Bool,
      wordStart: Bool,
      medialCapitalAsWordStart: Bool,
      force: Bool) {
      self.forward = forward
      self.matchCase = matchCase
      self.findNext = findNext
      self.wordStart = wordStart
      self.medialCapitalAsWordStart = medialCapitalAsWordStart
      self.force = force
    }
}