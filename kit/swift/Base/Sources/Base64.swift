// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims
import Foundation

public func base64Decode(string input: String) -> String {
  var out: UnsafeMutablePointer<CChar>?
  var outputSize: Int = 0
  let len = modp_b64_decode_len(input.count)
  input.withCString {
    out = malloc(len).bindMemory(to: CChar.self, capacity: len)
    outputSize = modp_b64_decode(out, $0, input.count)
  }
  print("\nbase64Decode: input len = \(input.count) modp_b64_decode_len = \(len) outputLen = \(outputSize)")
  guard outputSize > 0 else {
    return String()
  }
  return String(bytesNoCopy: out!, length: outputSize, encoding: String.Encoding.utf8, freeWhenDone: true)!
}

public func base64Decode(data input: Data) -> String {
  var out: UnsafeMutablePointer<CChar>?
  var outputSize: Int = 0
  let len = modp_b64_decode_len(input.count)
  print("\nbase64Decode: input len = \(input.count) modp_b64_decode_len = \(len)")
  input.withUnsafeBytes {
    out = malloc(len).bindMemory(to: CChar.self, capacity: len)
    outputSize = modp_b64_decode(out, $0.bindMemory(to: CChar.self).baseAddress, input.count)
  }
  guard outputSize > 0 else {
    return String()
  }
  return String(bytesNoCopy: out!, length: outputSize, encoding: String.Encoding.utf8, freeWhenDone: true)!
}

public func base64UrlDecode(string input: String) -> String {
  var outputSize: CInt = 0
  let ref = input.withCString {
    return Base64UrlDecode($0, CInt(input.count), &outputSize)
  }
  return ref == nil ? String() : String(bytesNoCopy: ref!, length: Int(outputSize), encoding: String.Encoding.utf8, freeWhenDone: true)!
}

public func base64UrlDecode(data input: Data) -> String {
  var outputSize: CInt = 0
  let ref = input.withUnsafeBytes {
    return Base64UrlDecode($0, CInt(input.count), &outputSize)
  }
  return ref == nil ? String() : String(bytesNoCopy: ref!, length: Int(outputSize), encoding: String.Encoding.utf8, freeWhenDone: true)!
}

fileprivate func modp_b64_decode_len(_ len: Int) -> Int { return (len / 4 * 3 + 2) }