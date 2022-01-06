// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public class ViewStorage {

  static var _instance: ViewStorage?

  public static var instance: ViewStorage {
    if ViewStorage._instance == nil {
      ViewStorage._instance = ViewStorage()
    }
    return ViewStorage._instance!
  }

  init() {}

  public func createStorageID() -> Int {
    return 0
  }

  public func removeView(storageId: Int) {

  }

  public func viewRemoved(view: View) {

  }

  public func storeView(storageId: Int, view: View) {}

  public func retrieveView(storageId: Int) -> View? {
    return nil
  }

}
