// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public class AtomCache {
  let display: XDisplayHandle
  var cache: [String: Atom]
  var uncachedAtomsAllowed: Bool

  public init(_ display: XDisplayHandle, _ cache: [String]) {
    self.display = display
    self.cache = [String: Atom]()

    for name in cache {
      let atom: Atom = XInternAtom(display, name, 0)
      self.cache[name] = atom
    }
    uncachedAtomsAllowed = false
  }

  public func getAtom(name: String) -> Atom? {
    let found: Atom? = cache[name]

    if uncachedAtomsAllowed && found == nil {
      let atom: Atom = XInternAtom(display, name, 0)
      cache[name] = atom
      return atom
    }

    return found
  }

  public func allowUncachedAtoms() {
    uncachedAtomsAllowed = true
  }

}