// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public class Location {

  public var `protocol`: String { 
    if _proto == nil {
      var len: CInt = 0
      let str = LocationGetProtocol(reference, &len)
      _proto = String(bytesNoCopy: str!, length: Int(len), encoding: String.Encoding.utf8, freeWhenDone: true)!
    }
    return _proto!
  }

  public var host: String {
    if _host == nil {
      var len: CInt = 0
      let str = LocationGetHost(reference, &len)
      _host = String(bytesNoCopy: str!, length: Int(len), encoding: String.Encoding.utf8, freeWhenDone: true)!
    }
    return _host!
  }

  public var hostname: String {
    if _hostname == nil {
      var len: CInt = 0
      let str = LocationGetHostname(reference, &len)
      _hostname = String(bytesNoCopy: str!, length: Int(len), encoding: String.Encoding.utf8, freeWhenDone: true)!
    }
    return _hostname!
  }

  public var port: String {
    if _port == nil {
      var len: CInt = 0
      let str = LocationGetPort(reference, &len)
      _port = String(bytesNoCopy: str!, length: Int(len), encoding: String.Encoding.utf8, freeWhenDone: true)!
    }
    return _port!
  }

  public var pathname: String {
    if _pathname == nil {
      var len: CInt = 0
      let str = LocationGetPathname(reference, &len)
      _pathname = String(bytesNoCopy: str!, length: Int(len), encoding: String.Encoding.utf8, freeWhenDone: true)!
    }
    return _pathname!
  }

  public var search: String {
    if _search == nil {
      var len: CInt = 0
      let str = LocationGetSearch(reference, &len)
      _search = String(bytesNoCopy: str!, length: Int(len), encoding: String.Encoding.utf8, freeWhenDone: true)!
    }
    return _search!
  }

  public var hash: String {
    if _hash == nil {
      var len: CInt = 0
      let str = LocationGetHash(reference, &len)
      _hash = String(bytesNoCopy: str!, length: Int(len), encoding: String.Encoding.utf8, freeWhenDone: true)!
    }
    return _hash!
  }

  public var origin: String {
    if _origin == nil {
      var len: CInt = 0
      let str = LocationGetOrigin(reference, &len)
      _origin = String(bytesNoCopy: str!, length: Int(len), encoding: String.Encoding.utf8, freeWhenDone: true)!
    }
    return _origin!
  }

  private var _proto: String?
  private var _host: String?
  private var _hostname: String?
  private var _port: String?
  private var _pathname: String?
  private var _search: String?
  private var _hash: String?
  private var _origin: String?
  internal var reference: LocationRef

  init(reference: LocationRef) {
    self.reference = reference
  }
}