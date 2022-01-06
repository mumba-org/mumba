// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base

public class ApplicationEntry : ApplicationInstanceObserver {
  // subclasses of ApplicationEntry are/should be well-known
  public enum Kind {
    case Page
  }

  public var isPage: Bool {
    return kind == .Page
  }

  public let kind: Kind
  public let uuid: String
  public private(set) weak var instance: ApplicationInstance?

  init(instance: ApplicationInstance?, uuid: String, kind: Kind) {
    self.instance = instance
    self.uuid = uuid
    self.kind = kind

    self.instance!.addObserver(self)
  }

  deinit {
    self.instance!.removeObserver(self) 
  }

}