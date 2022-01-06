// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base
import Foundation
import ProtocolBuffers

let magic: UInt32 = 0x6d328498
let version: UInt32 = 0x01

public enum CloseStatus : Int {
  case ok = 0
  case error = 1
}

@dynamicCallable
public class RouteCompletion {
  
  private var callback: (_: Int) -> Void
  private let doneSignal: WaitableEvent = WaitableEvent(resetPolicy: .manual, initialState: .notSignaled)
  private var waiting: Bool = false

  public init(_ callback: @escaping (_: Int) -> Void) {
    self.callback = callback
  }

  deinit {
    if waiting {
      doneSignal.signal()
    }
  }

  public func wait() {
    waiting = true
    doneSignal.timedWait(waitDelta: TimeDelta.from(seconds: 10))
    waiting = false
  }

  public func dynamicallyCall(withArguments args: [Int] = []) {
    call(args[0])
  }

  private func call(_ r: Int) {
    callback(r)
    doneSignal.signal()
  }

}

public protocol RouteHandler {
  
  typealias WriteCompletion = (_: Int, _: UnsafeRawPointer?, _: Int) -> Void
  typealias WriteRawCompletion = (_: Int, _: UnsafeRawPointer?, _: Int) -> Void
  typealias CloseCompletion = (_: Int, _: CloseStatus) -> Void
  
  var entry: RouteEntry { get set }
  var type: RouteEntryType { get set }
  var transportType: RouteTransportType { get set }
  var rpcTransportMode: RouteRpcTransportMode { get set }
  var scheme: String { get set }
  var name: String { get set }
  var url: String { get set }
  var path: String { get set }
  var title: String { get set }
  var contentType: String { get set }
  var iconData: Data { get set }
  var bufferSize: Int { get }
  var lastCallId: Int { get set }
  var writeCompletion: WriteCompletion? { get set }
  var writeRawCompletion: WriteRawCompletion? { get set }
  var closeCompletion: CloseCompletion? { get set }
  
  mutating func onResponseStarted(request: RouteRequest, info: RouteResponseInfo, completion: RouteCompletion?)
  mutating func onReadCompleted(request: RouteRequest, info: RouteResponseInfo, buffer: RouteBuffer, bytesRead: UInt64)
  mutating func onSucceeded(request: RouteRequest, info: RouteResponseInfo)
  mutating func onFailed(request: RouteRequest, info: RouteResponseInfo, error: RouteRequestError)
  mutating func onCanceled(request: RouteRequest, info: RouteResponseInfo)
  mutating func read(request: RouteRequest, buffer: UnsafeMutableRawPointer?, maxBytes: Int, completion: RouteCompletion)

  mutating func getRawBodyBytes(url: String) -> Int64
  mutating func getExpectedContentSize(url: String) -> Int64
  mutating func getResponseHeaders(url: String) -> String
  
}

extension RouteHandler {

  public var type: RouteEntryType {
    get {
     return entry.type
    }
    set {
      entry.type = newValue
    }
  }

  public var transportType: RouteTransportType {
    get {
      return entry.transportType
    }
    set {
      entry.transportType = newValue
    }
  }

  public var rpcTransportMode: RouteRpcTransportMode {
    get {
      return entry.rpcTransportMode
    }
    set {
      entry.rpcTransportMode = newValue
    }
  }

  public var scheme: String {
    get {
      return entry.scheme
    }
    set {
      entry.scheme = newValue
    }
  }

  public var name: String {
    get {
      return entry.name
    }
    set {
      entry.name = newValue
    }
  }

  public var url: String {
    get {
      return entry.url
    }
    set {
      entry.url = newValue
    }
  }

  public var path: String {
    get {
      return entry.path
    }
    set {
      entry.path = newValue
    }
  }

  public var title: String {
    get {
      return entry.title
    }
    set {
      entry.title = newValue
    }
  }

  public var contentType: String {
    get {
      return entry.contentType
    }
    set {
      entry.contentType = newValue
    }
  }

  public var iconData: Data {
    get {
      return entry.iconData 
    }
    set {
      entry.iconData = newValue
    }
  }

  public var bufferSize: Int {
    return 16378
  }

  public func write(call: Int, bytes: UnsafeRawPointer?, count: Int) {
    writeHeader(call, bytes, count)
    writeCompletion?(call, bytes, count) 
  }

  public func write(call: Int, data: Data) {
    let size = data.count
    writeHeader(call, data)
    data.withUnsafeBytes {
      writeCompletion?(call, $0.baseAddress, size)  
    }
  }

  public func write(call: Int, string: String) {
    let size = string.count
    let data = Data(bytes: string, count: size)
    writeHeader(call, data)
    writeBody(call, data)
  }

  public func write(data: Data) {
    write(call: lastCallId, data: data)
  }

  public func write(string: String) {
    write(call: lastCallId, string: string)
  }

  public func writeRaw(call: Int, bytes: UnsafeRawPointer?, count: Int) {
    writeHeader(call, bytes, count, encoded: false, encoding: "none")
    writeRawCompletion?(call, bytes, count) 
  }

  public func writeRaw(call: Int, data: Data) {
    let size = data.count
    data.withUnsafeBytes {
      writeHeader(call, $0.baseAddress, size, encoded: false, encoding: "none")
      writeRawCompletion?(call, $0.baseAddress, size)
    }
  }

  public func writeRaw(call: Int, string: String) {
    let encoded = encodeHeader(string, encoded: false, encoding: "none")
    encoded.withUnsafeBytes {
      writeRawCompletion?(call, $0.baseAddress, encoded.count)
    }
    string.withCString {
      writeRawCompletion?(call, $0, string.count)
    }
  }

  public func writeRaw(data: Data) {
    writeRaw(call: lastCallId, data: data)
  }

  public func writeRaw(string: String) {
    let encoded = encodeHeader(string, encoded: false, encoding: "none")
    encoded.withUnsafeBytes {
      writeRawCompletion?(lastCallId, $0.baseAddress, encoded.count)
    }
    string.withCString {
      writeRawCompletion?(lastCallId, $0, string.count)
    }
  }

  public func writeHeader(_ callId: Int, _ bytes: UnsafeRawPointer?, _ count: Int, encoded: Bool = true, encoding: String = "protobuf") {
    let encoded = encodeHeader(bytes, count, encoded: encoded, encoding: encoding)
    writeEncodedHeader(callId: callId, data: encoded)
  }

  public func writeHeader(_ callId: Int, _ data: Data, encoded: Bool = true, encoding: String = "protobuf") {
    let encoded = encodeHeader(data, encoded: encoded, encoding: encoding)
    writeEncodedHeader(callId: callId, data: encoded)
  }

  public func writeHeader(_ callId: Int, _ string: String, encoded: Bool = true, encoding: String = "protobuf") {
    let encoded = encodeHeader(string, encoded: encoded, encoding: encoding)
    writeEncodedHeader(callId: callId, data: encoded)
  }
  
  public func writeEncodedHeader(callId: Int, data: Data) {
    let size = data.count
    data.withUnsafeBytes {
      writeRawCompletion?(callId, $0.baseAddress, size)
    }
  }

  public func writeBody(_ callId: Int, _ data: Data) {
    let encoded = encodeBody(data)
    writeEncodedBody(callId: callId, data: encoded)
  }

  public func writeBody(_ callId: Int, _ string: String) {
    let encoded = encodeBody(string)
    writeEncodedBody(callId: callId, data: encoded)
  }

  public func writeEncodedBody(callId: Int, data: Data) {
    let size = data.count
    data.withUnsafeBytes {
      writeRawCompletion?(callId, $0.baseAddress, size)
    }
  }

  public func close(call: Int, status: CloseStatus) {
    closeCompletion?(call, status)
  }

  public func close(call: Int, status: CloseStatus, completion: (() -> Void)?) {
    closeCompletion?(call, status)
  }

  public func close(status: CloseStatus) {
    closeCompletion?(lastCallId, status)
  }

  public func close(status: CloseStatus, completion: (() -> Void)?) {
    closeCompletion?(lastCallId, status)
  }

  public func encodeHeader(_ string: String, encoded: Bool, encoding: String) -> Data {
    return encodeHeaderInternal(size: UInt64(string.count), bufferSize: UInt64(bufferSize), encoded: encoded, encoding: encoding)
  }

  public func encodeHeader(_ data: Data, encoded: Bool, encoding: String) -> Data {
    return encodeHeaderInternal(size: UInt64(data.count), bufferSize: UInt64(bufferSize), encoded: encoded, encoding: encoding)
  }

  public func encodeHeader(_ bytes: UnsafeRawPointer?, _ count: Int, encoded: Bool, encoding: String) -> Data {
    return encodeHeaderInternal(size: UInt64(count), bufferSize: UInt64(bufferSize), encoded: encoded, encoding: encoding)
  }

  private func encodeHeaderInternal(size: UInt64, bufferSize: UInt64, encoded: Bool, encoding: String) -> Data {
    let encodingData = encoding.utf8ToData()
    let stream = CodedOutputStream(bufferSize: 256)
    try! stream.writeRawLittleEndian32(value: Int32(magic))
    try! stream.writeRawLittleEndian32(value: Int32(version))
    try! stream.writeRawVarint32(value: Int32(size))
    try! stream.writeRawVarint32(value: Int32(bufferSize))
    try! stream.writeRawVarint32(value: Int32(encoded ? 1 : 0))
    try! stream.writeRawVarint32(value: Int32(encoding.count))
    try! stream.writeRawData(data: encodingData)
    return stream.flushToData()
  }

  private func encodeBody(_ string: String) -> Data {
    let data = Data(bytes: string, count: string.count)
    let encSize = encodedSize(data: data)
    let stream = CodedOutputStream(bufferSize: encSize)
    try! stream.writeInt64(fieldNumber: 1, value: Int64(string.count))
    try! stream.writeData(fieldNumber: 2, value: data)
    return stream.flushToData()
  }

  private func encodeBody(_ data: Data) -> Data {
    let encSize = encodedSize(data: data)
    let stream = CodedOutputStream(bufferSize: encSize)
    try! stream.writeInt64(fieldNumber: 1, value: Int64(data.count))
    try! stream.writeData(fieldNumber: 2, value: data)
    return stream.flushToData()
  }

  private func encodedSize(data: Data) -> Int {
    let size = Int64(data.count)
    var serializedSize: Int32 = 0
    serializedSize += size.computeInt64Size(fieldNumber: 1)
    serializedSize += data.computeDataSize(fieldNumber: 2)
    return Int(serializedSize)
  }

  // private func encodeHeaderInternal(size: UInt64, bufferSize: UInt64) -> Data {
  //   let size = csqliteVarintLen(1249) + csqliteVarintLen(UInt64(data.count)) + csqliteVarintLen(UInt64(bufferSize))
  //   let ptr: UnsafeMutablePointer<UInt8> = malloc(Int(size)).bindMemory(to: UInt8.self, capacity: Int(size))
  //   var d = ptr
  //   var allocated = 0
  //   allocated = Int(csqlitePutVarint(d, 1249))
  //   d = d + allocated
  //   allocated = Int(csqlitePutVarint(d, UInt64(data.count)))
  //   d = d + allocated
  //   allocated = Int(csqlitePutVarint(d, UInt64(bufferSize)))
  //   d = d + allocated
  //   return Data(bytesNoCopy: ptr, count: Int(size), deallocator: .free)
  // }

}