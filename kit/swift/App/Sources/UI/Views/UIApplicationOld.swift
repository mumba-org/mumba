// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Application

public protocol UIApplicationOldDelegate: ApplicationDelegate {
  var widget: UIWidget? { get }
}

public class UIApplicationOld : Application {
  
  public override init(delegate: ApplicationDelegate?) {
    super.init(delegate: delegate)
  }
  
  public func initialize(contextFactory: UIContextFactory) throws {
    //try initialize(contextFactory: contextFactory)
    try super.initialize()
  }
  
}