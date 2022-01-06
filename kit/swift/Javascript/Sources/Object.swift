// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims
import Foundation

public protocol JavascriptConvertible {
  var javascriptValue: JavascriptValue { get }
}

//fileprivate extension JavascriptConvertible {
//  var reference: JavascriptDataRef {
//    return javascriptValue.reference
//  }
//  var context: JavascriptContext {
//    return javascriptValue.context
//  }
//}

public protocol ConvertibleFromJavascript {
  init?(_ value: JavascriptValue)
}

public class JavascriptData {

  public var reference: JavascriptDataRef!

  init(reference: JavascriptDataRef?) {
    self.reference = reference
  }

  deinit {
    // TODO: fix destruction
    //       it might have something to do with thread affinity
    //_JavascriptDataDestroy(reference)
  }

}

// extension JavascriptValue : ExpressibleByArrayLiteral, ExpressibleByDictionaryLiteral {
//     public init(arrayLiteral elements: JavascriptValue...) {
//         self.init(elements)
//     }
//     public typealias Key = JavascriptValue
//     public typealias Value = JavascriptValue
//     public init(dictionaryLiteral elements: (JavascriptValue, JavascriptValue)...) {
//         self.init(Dictionary(elements, uniquingKeysWith: { lhs, _ in lhs }))
//     }
// }

@dynamicMemberLookup
@dynamicCallable
public class JavascriptValue : JavascriptData,
                               ExpressibleByBooleanLiteral, 
                               ExpressibleByIntegerLiteral,
                               ExpressibleByFloatLiteral, 
                               ExpressibleByStringLiteral,
                               ExpressibleByStringInterpolation {//,
                               //ExpressibleByArrayLiteral, 
                               //ExpressibleByDictionaryLiteral {

  public var isUndefined:  Bool {
    return _JavascriptValueIsUndefined(context.reference, reference) == 1
  }

  public var isNull: Bool {
    return _JavascriptValueIsNull(context.reference, reference) == 1
  }

  public var isTrue: Bool {
    return _JavascriptValueIsTrue(context.reference, reference) == 1
  }

  public var isFalse: Bool {
    return _JavascriptValueIsFalse(context.reference, reference) == 1
  }

  public var isName: Bool {
    return _JavascriptValueIsName(context.reference, reference) == 1
  }

  public var isSymbol: Bool {
    return _JavascriptValueIsSymbol(context.reference, reference) == 1
  }

  public var isString: Bool {
    return _JavascriptValueIsString(context.reference, reference) == 1
  }

  public var isFunction: Bool {
    return _JavascriptValueIsFunction(context.reference, reference) == 1
  }

  public var isArray: Bool {
    return _JavascriptValueIsArray(context.reference, reference) == 1
  }

  public var isObject: Bool {
    return _JavascriptValueIsObject(context.reference, reference) == 1
  }

  public var isBool: Bool {
    return _JavascriptValueIsBool(context.reference, reference) == 1
  }

  public var isNumber: Bool {
    return _JavascriptValueIsNumber(context.reference, reference) == 1
  }

  public var isInt32: Bool {
    return _JavascriptValueIsInt32(context.reference, reference) == 1
  }

  public var isUInt32: Bool {
    return _JavascriptValueIsUInt32(context.reference, reference) == 1
  }

  public var isDate: Bool {
    return _JavascriptValueIsDate(context.reference, reference) == 1
  }

  public var isMap: Bool {
    return _JavascriptValueIsMap(context.reference, reference) == 1
  }

  public var isSet: Bool {
    return _JavascriptValueIsSet(context.reference, reference) == 1
  }

  public var isArgumentsObject: Bool {
    return _JavascriptValueIsArgumentsObject(context.reference, reference) == 1
  }

  public var isBooleanObject: Bool {
    return _JavascriptValueIsBooleanObject(context.reference, reference) == 1
  }

  public var isNumberObject: Bool {
    return _JavascriptValueIsNumberObject(context.reference, reference) == 1
  }

  public var isStringObject: Bool {
    return _JavascriptValueIsStringObject(context.reference, reference) == 1
  }

  public var isSymbolObject: Bool {
    return _JavascriptValueIsSymbolObject(context.reference, reference) == 1
  }

  public var isNativeError: Bool {
    return _JavascriptValueIsNativeError(context.reference, reference) == 1
  }

  public var isRegExp: Bool {
    return _JavascriptValueIsRegExp(context.reference, reference) == 1
  }

  public var isGeneratorFunction: Bool {
    return _JavascriptValueIsGeneratorFunction(context.reference, reference) == 1
  }

  public var isGeneratorObject: Bool {
    return _JavascriptValueIsGeneratorObject(context.reference, reference) == 1
  }

  public var isPromise: Bool {
    return _JavascriptValueIsPromise(context.reference, reference) == 1
  }

  public var isMapIterator: Bool {
    return _JavascriptValueIsMapIterator(context.reference, reference) == 1
  }

  public var isSetIterator: Bool {
    return _JavascriptValueIsSetIterator(context.reference, reference) == 1
  }

  public var isWeakMap: Bool {
    return _JavascriptValueIsWeakMap(context.reference, reference) == 1
  }

  public var isWeakSet: Bool {
    return _JavascriptValueIsWeakSet(context.reference, reference) == 1
  }

  public var isArrayBuffer: Bool {
    return _JavascriptValueIsArrayBuffer(context.reference, reference) == 1
  }

  public var isArrayBufferView: Bool {
    return _JavascriptValueIsArrayBufferView(context.reference, reference) == 1
  }

  public var isTypedArray: Bool {
    return _JavascriptValueIsTypedArray(context.reference, reference) == 1
  }

  public var isUInt8Array: Bool {
    return _JavascriptValueIsUInt8Array(context.reference, reference) == 1
  }

  public var isUInt8ClampedArray: Bool {
    return _JavascriptValueIsUInt8ClampedArray(context.reference, reference) == 1
  }

  public var isInt8Array: Bool {
    return _JavascriptValueIsInt8Array(context.reference, reference) == 1
  }

  public var isUInt16Array: Bool {
    return _JavascriptValueIsUInt32Array(context.reference, reference) == 1
  }

  public var isInt16Array: Bool {
    return _JavascriptValueIsInt16Array(context.reference, reference) == 1
  }

  public var isUInt32Array: Bool {
    return _JavascriptValueIsUInt32Array(context.reference, reference) == 1
  }

  public var isInt32Array: Bool {
    return _JavascriptValueIsInt32Array(context.reference, reference) == 1
  }

  public var isFloat32Array: Bool {
    return _JavascriptValueIsFloat32Array(context.reference, reference) == 1
  }

  public var isFloat64Array: Bool {
    return _JavascriptValueIsFloat64Array(context.reference, reference) == 1
  }

  public var isDataView: Bool {
    return _JavascriptValueIsDataView(context.reference, reference) == 1
  }

  public var isSharedArrayBuffer: Bool {
    return _JavascriptValueIsSharedArrayBuffer(context.reference, reference) == 1
  }
  
  // create a null js value
  public static func Null(context: JavascriptContext) -> JavascriptValue {
    let ref = _JavascriptValueCreateNull(context.reference)
    return JavascriptValue(context: context, reference: ref!)
  }

  // create a undefined js value
  public static func Undefined(context: JavascriptContext) -> JavascriptValue {
    let ref = _JavascriptValueCreateUndefined(context.reference)
    return JavascriptValue(context: context, reference: ref!)
  }

  // the idea here is to be overrided
  // we cant use a protocol for this, because theres
  // a need to be overrided, when the object is a child of JavascriptObject
  public class func cast(context: JavascriptContext, from value: JavascriptValue) -> Self? {
    return nil
  }

  public let context: JavascriptContext
  internal var parent: JavascriptValue?

  public required init(context: JavascriptContext, reference: JavascriptDataRef) {
    self.context = context
    super.init(reference: reference)
  }

  public convenience required init<T : JavascriptConvertible>(_ value: T) {
    self.init(value.javascriptValue)
  }

  public convenience required init(_ value: JavascriptValue) {
    self.init(context: value.context, reference: value.reference)
  }

  public init(_ strValue: String) {
    let ctx = JavascriptContext.current
    let ref = strValue.withCString {
      return _JavascriptStringCreateFromCString(ctx.reference, $0, CInt(strValue.count))
    }
    self.context = ctx
    super.init(reference: ref)
  }

  public init(_ boolValue: Bool) {
    let ctx = JavascriptContext.current
    let ref = _JavascriptBooleanNew(ctx.reference, boolValue ? 1 : 0)
    self.context = ctx
    super.init(reference: ref)
  }

  public init(_ intValue: Int) {
    let ctx = JavascriptContext.current
    let ref = _JavascriptIntegerNew(ctx.reference, Int64(intValue))
    self.context = ctx
    super.init(reference: ref)
  }

  public init(_ floatValue: Double) {
    let ctx = JavascriptContext.current
    let ref = _JavascriptNumberNew(ctx.reference, floatValue)
    self.context = ctx
    super.init(reference: ref)
  }

  public required convenience init(booleanLiteral value: Bool) {
    self.init(value)
  }
  
  public required convenience init(integerLiteral value: Int) {
    self.init(value)
  }
  
  public required convenience init(floatLiteral value: Double) {
    self.init(value)
  }
    
  public required convenience init(stringLiteral value: String) {
    self.init(value)
  }

  internal init(context: JavascriptContext) {
    self.context = context
    super.init(reference: nil)
  }

  public func isEqual(other: JavascriptValue) -> Bool {
    return _JavascriptValueIsEqual(context.reference, reference, other.reference) == 1
  }

  public func cast<T: JavascriptValue>(to type: T.Type) -> T? {
    return T.cast(context: context, from: self)
  }

  public subscript(dynamicMember name: String) -> JavascriptValue {
    get {
      guard let obj = self.cast(to: JavascriptObject.self) else {
        return JavascriptValue.Undefined(context: self.context)
      }
      guard let result = obj.get(key: name) else {
        return JavascriptValue.Undefined(context: self.context)
      }
      // this is a trick to allow function call
      // as in a.b() to have 'a' as 'recv' parameter
      // or 'this' of 'b'
      result.parent = self
      return result
    }
    set {
      guard let obj = self.cast(to: JavascriptObject.self) else {
        return
      }
      let _ = obj.set(key: JavascriptString(context: context, string: name), value: newValue)
    }
  }
    
  public subscript(key: [JavascriptConvertible]) -> JavascriptValue {
    get {
      guard let obj = self.cast(to: JavascriptObject.self) else {
        return JavascriptValue.Undefined(context: self.context)
      }
      let keyValue = flattenedSubscriptIndices(self.context, key)
      guard let result = obj.get(key: keyValue) else {
        return JavascriptValue.Undefined(context: self.context)
      }
      result.parent = self
      return result
    }
    set {
      guard let obj = self.cast(to: JavascriptObject.self) else {
        return
      }
      let keyObject = flattenedSubscriptIndices(self.context, key)
      let _ = obj.set(key: keyObject, value: newValue)
    }
  }

  public subscript(key: JavascriptConvertible...) -> JavascriptValue {
    get {
      return self[key]
    }
    set {
      self[key] = newValue
    }
  }

  @discardableResult
  public func dynamicallyCall(
    withArguments args: JavascriptConvertible...) -> JavascriptValue {
    if let fn = self.cast(to: JavascriptFunction.self) {
      let argArray = args.map { $0.javascriptValue }
      return fn.call(recv: self.parent ?? context.global, argc: args.count, argv: argArray) ?? JavascriptValue.Undefined(context: self.context)
    }
    return JavascriptValue.Undefined(context: self.context)
  }

  @discardableResult
  public func dynamicallyCall(
    withArguments args: [JavascriptConvertible] = []) -> JavascriptValue {
    if let fn = self.cast(to: JavascriptFunction.self) {
      let argsArray = args.map { $0.javascriptValue }
      return fn.call(recv: self.parent ?? context.global, argc: args.count, argv: argsArray) ?? JavascriptValue.Undefined(context: self.context)
    }
    return JavascriptValue.Undefined(context: self.context)
  }

  @discardableResult
  public func dynamicallyCall(
      withKeywordArguments args:
      KeyValuePairs<String, JavascriptConvertible> = [:]) -> JavascriptValue {
    if let fn = self.cast(to: JavascriptFunction.self) {
      let argArray = args.map { $0.1.javascriptValue }
      return fn.call(recv: self.parent ?? context.global, argc: args.count, argv: argArray) ?? JavascriptValue.Undefined(context: self.context)
    }
    return JavascriptValue.Undefined(context: self.context)
  }

  public func toString() -> String {
    var len: CInt = 0
    let strbuf = _JavascriptValueToString(context.reference, reference, &len)
    return String(bytesNoCopy: strbuf!, length: Int(len), encoding: String.Encoding.utf8, freeWhenDone: true)!
  }

}

extension JavascriptValue : CustomStringConvertible {

  public var description: String {
    return self.toString()
  }

}

extension JavascriptValue : JavascriptConvertible, ConvertibleFromJavascript {
    
    public var javascriptValue: JavascriptValue { 
      return self 
    }

}

//extension JavascriptValue : Equatable {}

//public func ==(left: JavascriptValue, right: JavascriptValue) -> Bool {
//  return left.isEqual(other: right)
//}

public class JavascriptBoolean : JavascriptValue {

  public var value: Bool {
    return _JavascriptBooleanGetValue(context.reference, reference) == 1
  }

  public override class func cast(context: JavascriptContext, from value: JavascriptValue) -> JavascriptBoolean? {
    if _JavascriptBooleanCanCast(context.reference, value.reference) == 0 {
      return nil
    }
    return JavascriptBoolean(context: context, reference: value.reference)
  }

  public init(context: JavascriptContext, value: Bool) {
    let ref = _JavascriptBooleanNew(context.reference, value ? 1 : 0)
    super.init(context: context, reference: ref!)
  }

  public required init(context: JavascriptContext, reference: JavascriptDataRef) {
    super.init(context: context, reference: reference)
  }

  public convenience required init<T : JavascriptConvertible>(_ value: T) {
    self.init(value.javascriptValue)
  }

  public convenience required init(_ value: JavascriptValue) {
    self.init(context: value.context, reference: value.reference)
  }

  public required init(booleanLiteral value: Bool) {
    super.init(value)
  }
  
  public required init(integerLiteral value: Int) {
    super.init(value)
  }
  
  public required init(floatLiteral value: Double) {
    super.init(value)
  }
    
  public required init(stringLiteral value: String) {
    super.init(value)
  }

}

public class JavascriptName : JavascriptValue {
  
  public var identityHash: Int {
    return Int(_JavascriptNameGetIdentityHash(context.reference, reference))
  }

  public override class func cast(context: JavascriptContext, from value: JavascriptValue) -> JavascriptName? {
    if _JavascriptNameCanCast(context.reference, value.reference) == 0 {
      return nil
    }
    return JavascriptName(context: context, reference: value.reference)
  }

  public convenience required init<T : JavascriptConvertible>(_ value: T) {
    self.init(value.javascriptValue)
  }

  public convenience required init(_ value: JavascriptValue) {
    self.init(context: value.context, reference: value.reference)
  }

  public required init(context: JavascriptContext, reference: JavascriptDataRef) {
    super.init(context: context, reference: reference)
  }
  
  public required init(booleanLiteral value: Bool) {
    super.init(value)
  }
  
  public required init(integerLiteral value: Int) {
    super.init(value)
  }
  
  public required init(floatLiteral value: Double) {
    super.init(value)
  }
    
  public required init(stringLiteral value: String) {
    super.init(value)
  }

}

public class JavascriptString : JavascriptValue {
  
  public var value: String {
    let len = length
    let mem = malloc(len)
    let bytes = mem!.bindMemory(to: Int8.self, capacity: len)
    let _ = writeUTF8(buffer: bytes, length: len)
    return String(bytesNoCopy: bytes, length: len, encoding: String.Encoding.utf8, freeWhenDone: true)!
  }

  public var length: Int {
    return Int(_JavascriptStringGetLenght(context.reference, reference))
  }
 
  public var utf8Length: Int {
    return Int(_JavascriptStringUTF8Length(context.reference, reference))
  }

  public var isOneByte: Bool {
    return _JavascriptStringIsOneByte(context.reference, reference) == 1
  }

  public var containsOnlyOneByte: Bool {
    return _JavascriptStringContainsOnlyOneByte(context.reference, reference) == 1
  }

  public init(context: JavascriptContext, string: String) {
    var ref: JavascriptDataRef? = nil
    string.withCString { ptr in
      ref = _JavascriptStringCreateFromCString(context.reference, ptr, Int32(string.count))
    }
    // fix it: its actually failable on the C side
    super.init(context: context, reference: ref!)
  }

  public required init(context: JavascriptContext, reference: JavascriptDataRef) {
    super.init(context: context, reference: reference)
  }

  public convenience required init<T : JavascriptConvertible>(_ value: T) {
    self.init(value.javascriptValue)
  }

  public convenience required init(_ value: JavascriptValue) {
    self.init(context: value.context, reference: value.reference)
  }

  public convenience override init(_ string: String) {
    self.init(context: JavascriptContext.current, string: string)
  }

  public required init(booleanLiteral value: Bool) {
    super.init(value)
  }
  
  public required init(integerLiteral value: Int) {
    super.init(value)
  }
  
  public required init(floatLiteral value: Double) {
    super.init(value)
  }
    
  public required init(stringLiteral value: String) {
    super.init(value)
  }

  public override class func cast(context: JavascriptContext, from value: JavascriptValue) -> JavascriptString? {
    if _JavascriptStringCanCast(context.reference, value.reference) == 0 {
      return nil
    }
    return JavascriptString(context: context, reference: value.reference)
  }

  public func write(buffer: inout [UInt16],
                    start: Int,
                    length: Int) -> Int {
    var result = -1
    buffer.withUnsafeMutableBufferPointer { buf in
      result = Int(_JavascriptStringWrite(context.reference, reference, buf.baseAddress, Int32(start), Int32(length)))  
    }
    return result
  }

  public func writeOneByte(buffer: inout [UInt8],
                           start: Int,
                           length: Int) -> Int {
    var result = -1
    buffer.withUnsafeMutableBufferPointer { buf in                          
      result = Int(_JavascriptStringWriteOneByte(context.reference, reference, buf.baseAddress, Int32(start), Int32(length)))
    }
    return result
  }
  
  public func writeUTF8(buffer: inout [Int8], length: Int) -> Int {
    var result = -1
    buffer.withUnsafeMutableBufferPointer { buf in
      result = Int(_JavascriptStringWriteUTF8(context.reference, reference, buf.baseAddress, Int32(length)))
    }
    return result
  }

  public func writeUTF8(buffer: UnsafeMutablePointer<Int8>, length: Int) -> Int {
    var result = -1
    result = Int(_JavascriptStringWriteUTF8(context.reference, reference, &buffer.pointee, Int32(length)))
    return result
  }

}

public class JavascriptNumber : JavascriptValue {
  
  public var value: Double {
    return _JavascriptNumberGetValue(context.reference, reference)
  }

  public override class func cast(context: JavascriptContext, from value: JavascriptValue) -> JavascriptNumber? {
    if _JavascriptNumberCanCast(context.reference, value.reference) == 0 {
      return nil
    }
    return JavascriptNumber(context: context, reference: value.reference)
  }

  public required init(context: JavascriptContext, reference: JavascriptDataRef) {
    super.init(context: context, reference: reference)
  }

  public convenience required init<T : JavascriptConvertible>(_ value: T) {
    self.init(value.javascriptValue)
  }

  public convenience required init(_ value: JavascriptValue) {
    self.init(context: value.context, reference: value.reference)
  }

  public required init(booleanLiteral value: Bool) {
    super.init(value)
  }
  
  public required init(integerLiteral value: Int) {
    super.init(value)
  }
  
  public required init(floatLiteral value: Double) {
    super.init(value)
  }
    
  public required init(stringLiteral value: String) {
    super.init(value)
  }

}

public class JavascriptInteger : JavascriptValue {
  
  public var value: Int64 {
    return _JavascriptIntegerGetValue(context.reference, reference)
  }

  public override class func cast(context: JavascriptContext, from value: JavascriptValue) -> JavascriptInteger? {
    if _JavascriptIntegerCanCast(context.reference, value.reference) == 0 {
      return nil
    }
    return JavascriptInteger(context: context, reference: value.reference)
  }

  public required init(context: JavascriptContext, reference: JavascriptDataRef) {
    super.init(context: context, reference: reference)
  }

  public convenience required init<T : JavascriptConvertible>(_ value: T) {
    self.init(value.javascriptValue)
  }

  public convenience required init(_ value: JavascriptValue) {
    self.init(context: value.context, reference: value.reference)
  }

  public required init(booleanLiteral value: Bool) {
    super.init(value)
  }
  
  public required init(integerLiteral value: Int) {
    super.init(value)
  }
  
  public required init(floatLiteral value: Double) {
    super.init(value)
  }
    
  public required init(stringLiteral value: String) {
    super.init(value)
  }

}

public class JavascriptInt32: JavascriptValue {
  
  public var value: Int32 {
    return _JavascriptInt32GetValue(context.reference, reference)
  }

  public override class func cast(context: JavascriptContext, from value: JavascriptValue) -> JavascriptInt32? {
    if _JavascriptInt32CanCast(context.reference, value.reference) == 0 {
      return nil
    }
    return JavascriptInt32(context: context, reference: value.reference)
  }

  public required init(context: JavascriptContext, reference: JavascriptDataRef) {
    super.init(context: context, reference: reference)
  }

  public convenience required init<T : JavascriptConvertible>(_ value: T) {
    self.init(value.javascriptValue)
  }
  
  public convenience required init(_ value: JavascriptValue) {
    self.init(context: value.context, reference: value.reference)
  }

  public required init(booleanLiteral value: Bool) {
    super.init(value)
  }
  
  public required init(integerLiteral value: Int) {
    super.init(value)
  }
  
  public required init(floatLiteral value: Double) {
    super.init(value)
  }
    
  public required init(stringLiteral value: String) {
    super.init(value)
  }

}

public class JavascriptUInt32: JavascriptValue {
  
  public func getValue(context: JavascriptContext) -> UInt32 {
    return _JavascriptUInt32GetValue(context.reference, reference)
  }

  public override class func cast(context: JavascriptContext, from value: JavascriptValue) -> JavascriptUInt32? {
    if _JavascriptUInt32CanCast(context.reference, value.reference) == 0 {
      return nil
    }
    return JavascriptUInt32(context: context, reference: value.reference)
  }

  public required init(context: JavascriptContext, reference: JavascriptDataRef) {
    super.init(context: context, reference: reference)
  }
  
  public convenience required init<T : JavascriptConvertible>(_ value: T) {
    self.init(value.javascriptValue)
  }

  public convenience required init(_ value: JavascriptValue) {
    self.init(context: value.context, reference: value.reference)
  }

  public required init(booleanLiteral value: Bool) {
    super.init(value)
  }
  
  public required init(integerLiteral value: Int) {
    super.init(value)
  }
  
  public required init(floatLiteral value: Double) {
    super.init(value)
  }
    
  public required init(stringLiteral value: String) {
    super.init(value)
  }

}

// info actually is info: PropertyCallbackInfo<JavascriptValue>
public typealias JavascriptAccessorGetterCallback = (_: JavascriptString, _: JavascriptValue) -> Void

//@dynamicCallable
public class JavascriptObject : JavascriptValue {

  public var identityHash: Int {
    return Int(_JavascriptObjectGetIdentityHash(context.reference, reference))  
  }

  public var isCallable: Bool {
    return _JavascriptObjectIsCallable(context.reference, reference) == 0 ? false : true
  }

  public var propertyNames: JavascriptArray {
    let ref = _JavascriptObjectGetPropertyNames(context.reference, reference)
    return JavascriptArray(context: context, reference: ref!)
  }

  public var prototype: JavascriptValue {
    let ref = _JavascriptObjectGetPrototype(context.reference, reference)
    return JavascriptValue(context: context, reference: ref!)
  }

  public var objectProtoToString: JavascriptString {
    let ref = _JavascriptObjectGetObjectProtoString(context.reference, reference)
    return JavascriptString(context: context, reference: ref!)
  }

  public var constructorName: JavascriptString {
    let ref = _JavascriptObjectGetConstructorName(context.reference, reference)
    return JavascriptString(context: context, reference: ref!)
  }

  public var internalFieldCount: Int {
    return Int(_JavascriptObjectGetInternalFieldCount(context.reference, reference))
  }

  public var hasNamedLookupInterceptor: Bool {
    return _JavascriptObjectHasNamedLookupInterceptor(context.reference, reference) == 0 ? false : true
  }

  public var hasIndexedLookupInterceptor: Bool {
    return _JavascriptObjectHasIndexedLookupInterceptor(context.reference, reference) == 0 ? false : true
  }

  public override class func cast(context: JavascriptContext, from value: JavascriptValue) -> JavascriptObject? {
    if _JavascriptObjectCanCast(context.reference, value.reference) == 0 {
      return nil
    }
    return JavascriptObject(context: context, reference: value.reference)
  }
  
  public required init(context: JavascriptContext, reference: JavascriptDataRef) {
    super.init(context: context, reference: reference)
  }

  public convenience required init<T : JavascriptConvertible>(_ value: T) {
    self.init(value.javascriptValue)
  }

  public convenience required init(_ value: JavascriptValue) {
    self.init(context: value.context, reference: value.reference)
  }

  public required init(booleanLiteral value: Bool) {
    super.init(value)
  }
  
  public required init(integerLiteral value: Int) {
    super.init(value)
  }
  
  public required init(floatLiteral value: Double) {
    super.init(value)
  }
    
  public required init(stringLiteral value: String) {
    super.init(value)
  }

  internal override init(context: JavascriptContext) {
    super.init(context: context)
  }

  public func getInternalField(index: Int) -> JavascriptValue? {
    let ref = _JavascriptObjectGetInternalField(context.reference, reference, Int32(index))
    if ref == nil {
      return nil
    }
    return JavascriptValue(context: context, reference: ref!)
  }

  public func setInternalField(index: Int, value: JavascriptValue) {
    _JavascriptObjectSetInternalField(context.reference, reference, Int32(index), value.reference)
  }

  public func createDataProperty(key: JavascriptName, value: JavascriptValue) -> Bool {
    // TODO: the native function may return -1 in case of error
    return _JavascriptObjectCreateDataProperty(context.reference, reference, key.reference, value.reference) == 0 ? false : true
  }

  public func createDataProperty(index: Int, value: JavascriptValue) -> Bool {
    // TODO: the native function may return -1 in case of error
    return _JavascriptObjectCreateDataPropertyByIndex(context.reference, reference, Int32(index), value.reference) == 0 ? false : true
  }

  public func get(key: String) -> JavascriptValue? {
    return get(key: JavascriptString(context: self.context, string: key))
  }

  public func get(key: JavascriptValue) -> JavascriptValue? {
    let ref =  _JavascriptObjectGetProperty(context.reference, reference, key.reference)
    if ref == nil {
      return nil
    }
    return JavascriptValue(context: context, reference: ref!)
  }

  public func get(index: Int) -> JavascriptValue? {
    let ref =  _JavascriptObjectGetPropertyByIndex(context.reference, reference, Int32(index))
    if ref == nil {
      return nil
    }
    return JavascriptValue(context: context, reference: ref!)
  }

  public func set(key: JavascriptValue, value: JavascriptValue) -> Bool {
    let retval = _JavascriptObjectSetProperty(context.reference, reference, key.reference, value.reference)
    if retval == -1 { // what?
      
    }
    return retval == 0 ? false : true
  }

  public func set(index: Int, value: JavascriptValue) -> Bool {
    return _JavascriptObjectSetPropertyByIndex(context.reference, reference, Int32(index), value.reference) == 0 ? false : true
  }

  public func has(key: JavascriptValue) -> Bool {
    return _JavascriptObjectHasProperty(context.reference, reference, key.reference) == 0 ? false : true
  }

  public func delete(key: JavascriptValue) -> Bool {
    return _JavascriptObjectDeleteProperty(context.reference, reference, key.reference) == 0 ? false : true
  }

  public func delete(index: Int) -> Bool {
    return _JavascriptObjectDeletePropertyByIndex(context.reference, reference, Int32(index)) == 0 ? false : true
  }

  public func setAccessor(getter: JavascriptAccessorGetterCallback) {
    assert(false)
  }

  public func findInstanceInPrototypeChain(template: JavascriptFunctionTemplate) -> JavascriptObject? {
    // FIXIT: see why we are asking for the context on some and not on others
    // and why this is particular to objects and not other values
    // maybe the ideal would be to pass always and relly in the isolate pointed by it
    // instead of relying on the Isolate::GetCurrent(), so we can deal with multiple isolates
    // without much hasless
    let ref =  _JavascriptObjectFindInstanceInPrototypeChain(context.reference, reference, template.reference)
    if ref == nil {
      return nil
    }
    return JavascriptObject(context: context, reference: ref!)
  }

  public func hasOwnProperty(key: JavascriptString) -> Bool {
    return _JavascriptObjectHasOwnProperty(context.reference, reference, key.reference) == 0 ? false : true
  }

  public func hasRealNamedProperty(key: JavascriptString) -> Bool {
    return _JavascriptObjectHasRealNamedProperty(context.reference, reference, key.reference) == 0 ? false : true
  }

  public func hasRealIndexedProperty(index: Int) -> Bool {
    return _JavascriptObjectHasRealIndexedProperty(context.reference, reference, Int32(index)) == 0 ? false : true
  }

  public func hasRealNamedCallbackProperty(key: JavascriptString) -> Bool {
    return _JavascriptObjectHasRealNamedCallbackProperty(context.reference, reference, key.reference) == 0 ? false : true
  }

  public func getRealNamedPropertyInPrototypeChain(key: JavascriptString) -> JavascriptValue? {
    let ref =  _JavascriptObjectGetRealNamedPropertyInPrototypeChain(context.reference, reference, key.reference)
    if ref == nil {
      return nil
    }
    return JavascriptValue(context: context, reference: ref!)
  }

  public func getRealNamedProperty(key: JavascriptString) -> JavascriptValue? {
    let ref =  _JavascriptObjectGetRealNamedProperty(context.reference, reference, key.reference)
    if ref == nil {
      return nil
    }
    return JavascriptValue(context: context, reference: ref!)
  }

  public func clone() -> JavascriptObject {
    let ref =  _JavascriptObjectClone(context.reference, reference)
    return JavascriptObject(context: context, reference: ref!)
  }

  public func callAsFunction(recv: JavascriptValue, args: [JavascriptValue]) -> JavascriptValue {
    var handles: [JavascriptDataRef?] = []
    var result: JavascriptValue? = nil

    for arg in args {
      handles.append(arg.reference)
    }

    handles.withUnsafeMutableBufferPointer { (arrayBuffer: inout UnsafeMutableBufferPointer<JavascriptDataRef?>) -> Void in
      let ref =  _JavascriptObjectCallAsFunction(context.reference, reference, recv.reference, Int32(args.count), arrayBuffer.baseAddress)
      result = JavascriptValue(context: context, reference: ref!)
    }

    return result!
  }

  public func callAsConstructor(args: [JavascriptValue]) -> JavascriptValue {
    var handles: [JavascriptDataRef?] = []
    var result: JavascriptValue? = nil
    
    for arg in args {
      handles.append(arg.reference)
    }

    handles.withUnsafeMutableBufferPointer { (arrayBuffer: inout UnsafeMutableBufferPointer<JavascriptDataRef?>) -> Void in
      let ref =  _JavascriptObjectCallAsConstructor(context.reference, reference, Int32(args.count), arrayBuffer.baseAddress)
      result = JavascriptValue(context: context, reference: ref!)
    }

    return result!
  }

  // public override subscript(dynamicMember name: String) -> JavascriptValue {
  //   get {
  //     guard let result = self.get(key: name) else {
  //       return JavascriptValue.Undefined(context: self.context)
  //     }
  //     // this is a trick to allow function call
  //     // as in a.b() to have 'a' as 'recv' parameter
  //     // or 'this' of 'b'
  //     result.parent = self
  //     return result
  //   }
  // }
    
  // public override subscript(key: [JavascriptConvertible]) -> JavascriptValue {
  //   get {
  //       let keyValue = flattenedSubscriptIndices(self.context, key)
  //       guard let result = self.get(key: keyValue) else {
  //         return JavascriptValue.Undefined(context: self.context)
  //       }
  //       result.parent = self
  //       return result
  //   }
  //   set {
  //       let keyObject = flattenedSubscriptIndices(self.context, key)
  //       //if let newValue = newValue {
  //         let _ = self.set(key: keyObject, value: newValue)
  //       //} else {
  //       //  let _ = self.delete(key: keyObject)
  //       //}
  //   }
  // }
    
  // public override subscript(key: JavascriptConvertible...) -> JavascriptValue {
  //   get {
  //     return self[key]
  //   }
  //   set {
  //     self[key] = newValue
  //   }
  // }

  // @discardableResult
  // public func dynamicallyCall(
  //   withArguments args: JavascriptConvertible...) -> JavascriptValue {
  //   if let fn = self.cast(to: JavascriptFunction.self) {
  //     let argArray = args.map { $0.javascriptValue }
  //     return fn.call(recv: self.parent ?? context.global, argc: args.count, argv: argArray) ?? JavascriptValue.Undefined(context: self.context)
  //   }
  //   return JavascriptValue.Undefined(context: self.context)
  // }

  // @discardableResult
  // public func dynamicallyCall(
  //   withArguments args: [JavascriptConvertible] = []) -> JavascriptValue {
  //   if let fn = self.cast(to: JavascriptFunction.self) {
  //     let argsArray = args.map { $0.javascriptValue }
  //     return fn.call(recv: self.parent ?? context.global, argc: args.count, argv: argsArray) ?? JavascriptValue.Undefined(context: self.context)
  //   }
  //   return JavascriptValue.Undefined(context: self.context)
  // }

  // @discardableResult
  // public func dynamicallyCall(
  //     withKeywordArguments args:
  //     KeyValuePairs<String, JavascriptConvertible> = [:]) -> JavascriptValue {
  //   if let fn = self.cast(to: JavascriptFunction.self) {
  //     let argArray = args.map { $0.1.javascriptValue }
  //     return fn.call(recv: self.parent ?? context.global, argc: args.count, argv: argArray) ?? JavascriptValue.Undefined(context: self.context)
  //   }
  //   return JavascriptValue.Undefined(context: self.context)
  // }

}

public class JavascriptArray : JavascriptObject {
  
  public var count: Int {
    return Int(_JavascriptArrayCount(context.reference, reference))
  }

  public override class func cast(context: JavascriptContext, from value: JavascriptValue) -> JavascriptArray? {
    if _JavascriptArrayCanCast(context.reference, value.reference) == 0 {
      return nil
    }
    return JavascriptArray(context: context, reference: value.reference)
  }

  public required init(context: JavascriptContext, reference: JavascriptDataRef) {
    super.init(context: context, reference: reference)
  }

  public convenience required init<T : JavascriptConvertible>(_ value: T) {
    self.init(value.javascriptValue)
  }

  public convenience required init(_ value: JavascriptValue) {
    self.init(context: value.context, reference: value.reference)
  }

  public required init(booleanLiteral value: Bool) {
    super.init(booleanLiteral: value)
  }
  
  public required init(integerLiteral value: Int) {
    super.init(integerLiteral: value)
  }
  
  public required init(floatLiteral value: Double) {
    super.init(floatLiteral: value)
  }
    
  public required init(stringLiteral value: String) {
    super.init(stringLiteral: value)
  }

}

public class JavascriptMap : JavascriptObject {
  
  public var count: Int {
    return Int(_JavascriptMapCount(context.reference, reference))
  }

  public override class func cast(context: JavascriptContext, from value: JavascriptValue) -> JavascriptMap? {
    if _JavascriptMapCanCast(context.reference, value.reference) == 0 {
      return nil
    }
    return JavascriptMap(context: context, reference: value.reference)
  }

  public required init(context: JavascriptContext, reference: JavascriptDataRef) {
    super.init(context: context, reference: reference)
  }

  public convenience required init<T : JavascriptConvertible>(_ value: T) {
    self.init(value.javascriptValue)
  }

  public convenience required init(_ value: JavascriptValue) {
    self.init(context: value.context, reference: value.reference)
  }

  public required init(booleanLiteral value: Bool) {
    super.init(booleanLiteral: value)
  }
  
  public required init(integerLiteral value: Int) {
    super.init(integerLiteral: value)
  }
  
  public required init(floatLiteral value: Double) {
    super.init(floatLiteral: value)
  }
    
  public required init(stringLiteral value: String) {
    super.init(stringLiteral: value)
  }

  public override func get(key: JavascriptValue) -> JavascriptValue? {
    let ref =  _JavascriptMapGetProperty(context.reference, reference, key.reference)
    if ref == nil {
      return nil
    }
    return JavascriptValue(context: context, reference: ref!)
  }

  public func set(key: JavascriptValue, value: JavascriptValue) -> JavascriptMap? {
    let ref = _JavascriptMapSetProperty(context.reference, reference, key.reference, value.reference)
    if ref == nil {
      return nil
    }
    return JavascriptMap(context: context, reference: ref!)
  }

  public override func has(key: JavascriptValue) -> Bool {
    return _JavascriptMapHasProperty(context.reference, reference, key.reference) == 0 ? false : true
  }

  public override func delete(key: JavascriptValue) -> Bool {
    return _JavascriptMapDeleteProperty(context.reference, reference, key.reference) == 0 ? false : true
  }

  public func clear() {
    _JavascriptMapClear(context.reference, reference)
  }

  public func asArray() -> JavascriptArray {
    let ref = _JavascriptMapAsArray(context.reference, reference)
    return JavascriptArray(context: context, reference: ref!)
  }

}

public class JavascriptSet : JavascriptObject {
  
  public var count: Int {
    return Int(_JavascriptSetCount(context.reference, reference))
  }

  public override class func cast(context: JavascriptContext, from value: JavascriptValue) -> JavascriptSet? {
    if _JavascriptSetCanCast(context.reference, value.reference) == 0 {
      return nil
    }
    return JavascriptSet(context: context, reference: value.reference)
  }

  public required init(context: JavascriptContext, reference: JavascriptDataRef) {
    super.init(context: context, reference: reference)
  }

  public convenience required init<T : JavascriptConvertible>(_ value: T) {
    self.init(value.javascriptValue)
  }

  public convenience required init(_ value: JavascriptValue) {
    self.init(context: value.context, reference: value.reference)
  }

  public required init(booleanLiteral value: Bool) {
    super.init(booleanLiteral: value)
  }
  
  public required init(integerLiteral value: Int) {
    super.init(integerLiteral: value)
  }
  
  public required init(floatLiteral value: Double) {
    super.init(floatLiteral: value)
  }
    
  public required init(stringLiteral value: String) {
    super.init(stringLiteral: value)
  }

  public func add(key: JavascriptValue) {
    _JavascriptSetAdd(context.reference, reference, key.reference)
  }
  
  public override func has(key: JavascriptValue) -> Bool {
    return _JavascriptSetHasProperty(context.reference, reference, key.reference) == 0 ? false : true
  }

  public override func delete(key: JavascriptValue) -> Bool {
    return _JavascriptSetDeleteProperty(context.reference, reference, key.reference) == 0 ? false : true
  }

  public func clear() {
    _JavascriptSetClear(context.reference, reference)
  }

  public func asArray() -> JavascriptArray {
    let ref = _JavascriptSetAsArray(context.reference, reference)
    return JavascriptArray(context: context, reference: ref!)
  }

}

public struct JavascriptFunctionCallbackInfo {
  
  public var length: Int {
    return Int(_JavascriptFunctionCallbackInfoGetLength(context.reference, reference))
  }

  public var this: JavascriptObject {
    let ref = _JavascriptFunctionCallbackInfoGetThis(context.reference, reference)
    return JavascriptFunction(context: context, reference: ref!)
  }

  public var holder: JavascriptObject {
    let ref = _JavascriptFunctionCallbackInfoGetHolder(context.reference, reference)
    return JavascriptFunction(context: context, reference: ref!)
  }

  public var isConstructorCall: Bool {
    return _JavascriptFunctionCallbackInfoIsConstructorCall(context.reference, reference) == 0 ? false : true
  }

  public var data: JavascriptValue {
    let ref = _JavascriptFunctionCallbackInfoGetData(context.reference, reference)
    return JavascriptValue(context: context, reference: ref!)
  }

  let reference: JavascriptFunctionCallbackInfoRef
  let context: JavascriptContext

  public init(context: JavascriptContext, reference: JavascriptFunctionCallbackInfoRef) {
    self.context = context
    self.reference = reference
  }

  public subscript(_ index: Int) -> JavascriptValue? {
    return getValue(at: index)
  }

  public func getValue(at: Int) -> JavascriptValue? {
    let ref = _JavascriptFunctionCallbackInfoGetValueAt(context.reference, reference, Int32(at))
    if ref == nil {
      return nil
    }
    return JavascriptValue(context: context, reference: ref!)
  }

  public func returnValue<T: JavascriptValue>() -> T {
    let ref = _JavascriptFunctionCallbackInfoGetReturnValue(context.reference, reference)
    return T(context: context, reference: ref!)
  }

}

public typealias JavascriptFunctionCallback = (_: JavascriptFunctionCallbackInfo) -> Void

protocol FunctionCallbackStateOwner : class {
  func onFunctionCallbackCreate(_ state: FunctionCallbackState)
  func onFunctionCallbackDispose(_ state: FunctionCallbackState)
}

public class FunctionCallbackState {
  
  let callback: JavascriptFunctionCallback
  weak var owner: FunctionCallbackStateOwner?
  
  init(_ owner: FunctionCallbackStateOwner, _ callback: @escaping JavascriptFunctionCallback) {
    self.owner = owner
    self.callback = callback
    self.owner!.onFunctionCallbackCreate(self)
  }

  func dispose() {
    owner!.onFunctionCallbackDispose(self)
  } 
}

public class JavascriptFunction: JavascriptObject,
                                 FunctionCallbackStateOwner {

  public var name: JavascriptString {
    get {
      let ref = _JavascriptFunctionGetName(context.reference, reference)
      return JavascriptString(context: context, reference: ref!)
    }
    set {
      _JavascriptFunctionSetName(context.reference, reference, newValue.reference)
    }
  }

  public var inferredName: JavascriptValue {
    let ref = _JavascriptFunctionGetInferredName(context.reference, reference)
    return JavascriptValue(context: context, reference: ref!)
  }

  public var scriptLineNumber: Int {
    return Int(_JavascriptFunctionGetScriptLineNumber(context.reference, reference)) 
  }

  public var scriptColumnNumber: Int {
    return Int(_JavascriptFunctionGetScriptColumnNumber(context.reference, reference))
  }

  public var scriptId: Int {
    return Int(_JavascriptFunctionGetScriptId(context.reference, reference))
  }

  public var displayName: JavascriptValue {
    let ref = _JavascriptFunctionGetDisplayName(context.reference, reference)
    return JavascriptValue(context: context, reference: ref!)
  }

  public var boundFunction: JavascriptValue {
    let ref = _JavascriptFunctionGetBoundFunction(context.reference, reference)
    return JavascriptValue(context: context, reference: ref!)
  }

  public var scriptOrigin: JavascriptScriptOrigin {
    let ref = _JavascriptFunctionGetScriptOrigin(context.reference, reference)
    return JavascriptScriptOrigin(reference: ref!)
  }

  public override class func cast(context: JavascriptContext, from value: JavascriptValue) -> JavascriptFunction? {
    if _JavascriptFunctionCanCast(context.reference, value.reference) == 0 {
      return nil
    }
    return JavascriptFunction(context: context, reference: value.reference)
  }

  private var callbackStates: ContiguousArray<FunctionCallbackState> = ContiguousArray<FunctionCallbackState>()

  public init(context: JavascriptContext, name: String, callback: @escaping JavascriptFunctionCallback) {
    super.init(context: context)
    let state = FunctionCallbackState(self, callback)
    let stateRef = unsafeBitCast(Unmanaged.passUnretained(state).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    let ref = name.utf8CString.withUnsafeBufferPointer {
      return _JavascriptFunctionCreate(context.reference, $0.baseAddress, CInt($0.count-1), stateRef, { (handle: UnsafeMutableRawPointer?, info: UnsafeMutableRawPointer?) in 
        print("JavascriptFunction: callback called()")
        let funcState = unsafeBitCast(handle, to: FunctionCallbackState.self)
        let infoState = JavascriptFunctionCallbackInfo(context: JavascriptContext.current, reference: info!)
        funcState.callback(infoState)
        funcState.dispose()
      })
    }
    self.reference = ref!
  }

  public required init(context: JavascriptContext, reference: JavascriptDataRef) {
    super.init(context: context, reference: reference)
  }

  public convenience required init<T : JavascriptConvertible>(_ value: T) {
    self.init(value.javascriptValue)
  }

  public convenience required init(_ value: JavascriptValue) {
    self.init(context: value.context, reference: value.reference)
  }

  public required init(booleanLiteral value: Bool) {
    super.init(booleanLiteral: value)
  }
  
  public required init(integerLiteral value: Int) {
    super.init(integerLiteral: value)
  }
  
  public required init(floatLiteral value: Double) {
    super.init(floatLiteral: value)
  }
    
  public required init(stringLiteral value: String) {
    super.init(stringLiteral: value)
  }

  public func onFunctionCallbackCreate(_ state: FunctionCallbackState) {
    callbackStates.append(state)
  }

  public func onFunctionCallbackDispose(_ state: FunctionCallbackState) {
    // for (i, cur) in callbackStates.enumerated() {
    //   if cur === state { 
    //     callbackStates.remove(at: i)
    //     return
    //   }
    // }
  }

  public func newInstance(argc: Int, argv: [JavascriptValue]) -> JavascriptObject? {
    var handles: [JavascriptDataRef?] = []
    var result: JavascriptObject? = nil
    
    for arg in argv {
      handles.append(arg.reference)
    }

    handles.withUnsafeMutableBufferPointer { (arrayBuffer: inout UnsafeMutableBufferPointer<JavascriptDataRef?>) -> Void in
      let ref = _JavascriptFunctionCreateInstance(context.reference, reference, Int32(argc), arrayBuffer.baseAddress)
      if ref != nil {
        result = JavascriptObject(context: context, reference: ref!)
      }
    }

    return result
  }

  public func call(recv: JavascriptValue, argc: Int, argv: [JavascriptValue]) -> JavascriptValue? {
    var handles: [JavascriptDataRef?] = []
    var result: JavascriptValue? = nil
    
    for arg in argv {
      handles.append(arg.reference)
    }

    handles.withUnsafeMutableBufferPointer { (arrayBuffer: inout UnsafeMutableBufferPointer<JavascriptDataRef?>) -> Void in
      let ref = _JavascriptFunctionCall(context.reference, reference, recv.reference, Int32(argc), arrayBuffer.baseAddress)
      if ref != nil {
        result = JavascriptValue(context: context, reference: ref!)
      }
    }

    return result
  }

}

public class JavascriptPromise : JavascriptObject {

  public var hasHandler: Bool {
    assert(false)
    // FIXIT: implement this
    //return _JavascriptPromisseHasHandler(reference) == 0 ? false : true
    return false
  }

  public override class func cast(context: JavascriptContext, from value: JavascriptValue) -> JavascriptPromise? {
    if _JavascriptPromiseCanCast(context.reference, value.reference) == 0 {
      return nil
    }
    return JavascriptPromise(context: context, reference: value.reference)
  }

  public required init(context: JavascriptContext, reference: JavascriptDataRef) {
    super.init(context: context, reference: reference)
  }

  public convenience required init<T : JavascriptConvertible>(_ value: T) {
    self.init(value.javascriptValue)
  }

  public convenience required init(_ value: JavascriptValue) {
    self.init(context: value.context, reference: value.reference)
  }

  public required init(booleanLiteral value: Bool) {
    super.init(booleanLiteral: value)
  }
  
  public required init(integerLiteral value: Int) {
    super.init(integerLiteral: value)
  }
  
  public required init(floatLiteral value: Double) {
    super.init(floatLiteral: value)
  }
    
  public required init(stringLiteral value: String) {
    super.init(stringLiteral: value)
  }

  public func chain(handler: JavascriptFunction) -> JavascriptPromise {
    // temporary hack.. remove
    let nullValue = _JavascriptValueCreateNull(context.reference)
    return JavascriptPromise(context: context, reference: nullValue!)
  }

  public func `catch`(handler: JavascriptFunction) -> JavascriptPromise {
    // temporary hack.. remove
    let nullValue = _JavascriptValueCreateNull(context.reference)
    return JavascriptPromise(context: context, reference: nullValue!)
  }

  public func then(handler: JavascriptFunction) -> JavascriptPromise {
    // temporary hack.. remove
    let nullValue = _JavascriptValueCreateNull(context.reference)
    return JavascriptPromise(context: context, reference: nullValue!)
  }

}

public class JavascriptArrayBuffer : JavascriptObject {

  public var isExternal: Bool {
    assert(false)
    return false
  }

  public var isNeuterable: Bool {
    assert(false)
    return false
  }

  public override class func cast(context: JavascriptContext, from value: JavascriptValue) -> JavascriptArrayBuffer? {
    if _JavascriptArrayCanCast(context.reference, value.reference) == 0 {
      return nil
    }
    return JavascriptArrayBuffer(context: context, reference: value.reference)
  }

  public init(context: JavascriptContext, byteLenght: Int) {
    // temporary hack: remove once implemented
    let nullValue = _JavascriptValueCreateNull(context.reference)
    super.init(context: context, reference: nullValue!)
  }

  public init(context: JavascriptContext, data: UnsafePointer<UInt8>, byteLenght: Int) {
    // temporary hack: remove once implemented
    let nullValue = _JavascriptValueCreateNull(context.reference)
    super.init(context: context, reference: nullValue!)
  }

  public required init(context: JavascriptContext, reference: JavascriptDataRef) {
    super.init(context: context, reference: reference)
  }

  public convenience required init<T : JavascriptConvertible>(_ value: T) {
    self.init(value.javascriptValue)
  }

  public convenience required init(_ value: JavascriptValue) {
    self.init(context: value.context, reference: value.reference)
  }

  public required init(booleanLiteral value: Bool) {
    super.init(booleanLiteral: value)
  }
  
  public required init(integerLiteral value: Int) {
    super.init(integerLiteral: value)
  }
  
  public required init(floatLiteral value: Double) {
    super.init(floatLiteral: value)
  }
    
  public required init(stringLiteral value: String) {
    super.init(stringLiteral: value)
  }

  public func neuter(context: JavascriptContext) {

  }

}

public class JavascriptArrayBufferView : JavascriptObject {

  public var buffer: JavascriptArrayBuffer? {
    //assert(false)
    return nil
  }

  public var byteOffset: Int {
    //assert(false)
    return -1
  }

  public var byteLenght: Int {
    //assert(false)
    return -1
  }

  public var hasBuffer: Bool {
    //assert(false)
    return false
  }

  public override class func cast(context: JavascriptContext, from value: JavascriptValue) -> JavascriptArrayBufferView? {
    if _JavascriptArrayBufferCanCast(context.reference, value.reference) == 0 {
      return nil
    }
    return JavascriptArrayBufferView(context: context, reference: value.reference)
  }

  public required init(context: JavascriptContext, reference: JavascriptDataRef) {
    super.init(context: context, reference: reference)
  }

  public convenience required init<T : JavascriptConvertible>(_ value: T) {
    self.init(value.javascriptValue)
  }

  public convenience required init(_ value: JavascriptValue) {
    self.init(context: value.context, reference: value.reference)
  }

  public required init(booleanLiteral value: Bool) {
    super.init(booleanLiteral: value)
  }
  
  public required init(integerLiteral value: Int) {
    super.init(integerLiteral: value)
  }
  
  public required init(floatLiteral value: Double) {
    super.init(floatLiteral: value)
  }
    
  public required init(stringLiteral value: String) {
    super.init(stringLiteral: value)
  }

  public func copyContents(dest: inout UnsafeMutablePointer<UInt8>, lenght: Int) -> Int {
    return 0  
  }

}

public class JavascriptTypedArray : JavascriptArrayBufferView {
  
  public var count: Int {
    assert(false)
    return 0
  }

  public override class func cast(context: JavascriptContext, from value: JavascriptValue) -> JavascriptTypedArray? {
    if _JavascriptTypedArrayCanCast(context.reference, value.reference) == 0 {
      return nil
    }
    return JavascriptTypedArray(context: context, reference: value.reference)
  }

  public required init(context: JavascriptContext, reference: JavascriptDataRef) {
    super.init(context: context, reference: reference)
  }

  public convenience required init<T : JavascriptConvertible>(_ value: T) {
    self.init(value.javascriptValue)
  }

  public convenience required init(_ value: JavascriptValue) {
    self.init(context: value.context, reference: value.reference)
  }

  public required init(booleanLiteral value: Bool) {
    super.init(booleanLiteral: value)
  }
  
  public required init(integerLiteral value: Int) {
    super.init(integerLiteral: value)
  }
  
  public required init(floatLiteral value: Double) {
    super.init(floatLiteral: value)
  }
    
  public required init(stringLiteral value: String) {
    super.init(stringLiteral: value)
  }

}

public class JavascriptUInt8Array : JavascriptTypedArray {
  
  public override class func cast(context: JavascriptContext, from value: JavascriptValue) -> JavascriptUInt8Array? {
    if _JavascriptUInt8ArrayCanCast(context.reference, value.reference) == 0 {
      return nil
    }
    return JavascriptUInt8Array(context: context, reference: value.reference)
  }

  public init(context: JavascriptContext, buffer: JavascriptArrayBuffer, offset: Int, length: Int) {
    // temporary hack: remove once implemented
    let nullValue = _JavascriptValueCreateNull(context.reference)
    super.init(context: context, reference: nullValue!)
  }

  public required init(context: JavascriptContext, reference: JavascriptDataRef) {
    super.init(context: context, reference: reference)
  }

  public convenience required init<T : JavascriptConvertible>(_ value: T) {
    self.init(value.javascriptValue)
  }

  public convenience required init(_ value: JavascriptValue) {
    self.init(context: value.context, reference: value.reference)
  }

  public required init(booleanLiteral value: Bool) {
    super.init(booleanLiteral: value)
  }
  
  public required init(integerLiteral value: Int) {
    super.init(integerLiteral: value)
  }
  
  public required init(floatLiteral value: Double) {
    super.init(floatLiteral: value)
  }
    
  public required init(stringLiteral value: String) {
    super.init(stringLiteral: value)
  }

}

public class JavascriptUInt8ClampedArray : JavascriptTypedArray {

  public override class func cast(context: JavascriptContext, from value: JavascriptValue) -> JavascriptUInt8ClampedArray? {
    if _JavascriptUInt8ClampedArrayCanCast(context.reference, value.reference) == 0 {
      return nil
    }
    return JavascriptUInt8ClampedArray(context: context, reference: value.reference)
  }

  public init(context: JavascriptContext, buffer: JavascriptArrayBuffer, offset: Int, length: Int) {
    // temporary hack: remove once implemented
    let nullValue = _JavascriptValueCreateNull(context.reference)
    super.init(context: context, reference: nullValue!)
  }

  public required init(context: JavascriptContext, reference: JavascriptDataRef) {
    super.init(context: context, reference: reference)
  }

  public convenience required init<T : JavascriptConvertible>(_ value: T) {
    self.init(value.javascriptValue)
  }

  public convenience required init(_ value: JavascriptValue) {
    self.init(context: value.context, reference: value.reference)
  }

  public required init(booleanLiteral value: Bool) {
    super.init(booleanLiteral: value)
  }
  
  public required init(integerLiteral value: Int) {
    super.init(integerLiteral: value)
  }
  
  public required init(floatLiteral value: Double) {
    super.init(floatLiteral: value)
  }
    
  public required init(stringLiteral value: String) {
    super.init(stringLiteral: value)
  }

}

public class JavascriptInt8Array : JavascriptTypedArray {

  public init(context: JavascriptContext, buffer: JavascriptArrayBuffer, offset: Int, length: Int) {
    // temporary hack: remove once implemented
    let nullValue = _JavascriptValueCreateNull(context.reference)
    super.init(context: context, reference: nullValue!)
  }

  public override class func cast(context: JavascriptContext, from value: JavascriptValue) -> JavascriptInt8Array? {
    if _JavascriptInt8ArrayCanCast(context.reference, value.reference) == 0 {
      return nil
    }
    return JavascriptInt8Array(context: context, reference: value.reference)
  }

  public required init(context: JavascriptContext, reference: JavascriptDataRef) {
    super.init(context: context, reference: reference)
  }

  public convenience required init<T : JavascriptConvertible>(_ value: T) {
    self.init(value.javascriptValue)
  }

  public convenience required init(_ value: JavascriptValue) {
    self.init(context: value.context, reference: value.reference)
  }

  public required init(booleanLiteral value: Bool) {
    super.init(booleanLiteral: value)
  }
  
  public required init(integerLiteral value: Int) {
    super.init(integerLiteral: value)
  }
  
  public required init(floatLiteral value: Double) {
    super.init(floatLiteral: value)
  }
    
  public required init(stringLiteral value: String) {
    super.init(stringLiteral: value)
  }

}

public class JavascriptUInt16Array : JavascriptTypedArray {

  public init(context: JavascriptContext, buffer: JavascriptArrayBuffer, offset: Int, length: Int) {
    // temporary hack: remove once implemented
    let nullValue = _JavascriptValueCreateNull(context.reference)
    super.init(context: context, reference: nullValue!)  
  }
  
  public override class func cast(context: JavascriptContext, from value: JavascriptValue) -> JavascriptUInt16Array? {
    if _JavascriptUInt16ArrayCanCast(context.reference, value.reference) == 0 {
      return nil
    }
    return JavascriptUInt16Array(context: context, reference: value.reference)
  }

  public required init(context: JavascriptContext, reference: JavascriptDataRef) {
    super.init(context: context, reference: reference)
  }

  public convenience required init<T : JavascriptConvertible>(_ value: T) {
    self.init(value.javascriptValue)
  }

  public convenience required init(_ value: JavascriptValue) {
    self.init(context: value.context, reference: value.reference)
  }

  public required init(booleanLiteral value: Bool) {
    super.init(booleanLiteral: value)
  }
  
  public required init(integerLiteral value: Int) {
    super.init(integerLiteral: value)
  }
  
  public required init(floatLiteral value: Double) {
    super.init(floatLiteral: value)
  }
    
  public required init(stringLiteral value: String) {
    super.init(stringLiteral: value)
  }

}

public class JavascriptInt16Array : JavascriptTypedArray {

  public override class func cast(context: JavascriptContext, from value: JavascriptValue) -> JavascriptInt16Array? {
    if _JavascriptInt16ArrayCanCast(context.reference, value.reference) == 0 {
      return nil
    }
    return JavascriptInt16Array(context: context, reference: value.reference)
  }

  public init(context: JavascriptContext, buffer: JavascriptArrayBuffer, offset: Int, length: Int) {
    // temporary hack: remove once implemented
    let nullValue = _JavascriptValueCreateNull(context.reference)
    super.init(context: context, reference: nullValue!)
  }

  public required init(context: JavascriptContext, reference: JavascriptDataRef) {
    super.init(context: context, reference: reference)
  }

  public convenience required init<T : JavascriptConvertible>(_ value: T) {
    self.init(value.javascriptValue)
  }

  public convenience required init(_ value: JavascriptValue) {
    self.init(context: value.context, reference: value.reference)
  }

  public required init(booleanLiteral value: Bool) {
    super.init(booleanLiteral: value)
  }
  
  public required init(integerLiteral value: Int) {
    super.init(integerLiteral: value)
  }
  
  public required init(floatLiteral value: Double) {
    super.init(floatLiteral: value)
  }
    
  public required init(stringLiteral value: String) {
    super.init(stringLiteral: value)
  }

}

public class JavascriptUInt32Array : JavascriptTypedArray {
  
  public override class func cast(context: JavascriptContext, from value: JavascriptValue) -> JavascriptUInt32Array? {
    if _JavascriptUInt32ArrayCanCast(context.reference, value.reference) == 0 {
      return nil
    }
    return JavascriptUInt32Array(context: context, reference: value.reference)
  }

  public init(context: JavascriptContext, buffer: JavascriptArrayBuffer, offset: Int, length: Int) {
    // temporary hack: remove once implemented
    let nullValue = _JavascriptValueCreateNull(context.reference)
    super.init(context: context, reference: nullValue!)
  }

  public required init(context: JavascriptContext, reference: JavascriptDataRef) {
    super.init(context: context, reference: reference) 
  }

  public convenience required init<T : JavascriptConvertible>(_ value: T) {
    self.init(value.javascriptValue)
  }

  public convenience required init(_ value: JavascriptValue) {
    self.init(context: value.context, reference: value.reference)
  }

  public required init(booleanLiteral value: Bool) {
    super.init(booleanLiteral: value)
  }
  
  public required init(integerLiteral value: Int) {
    super.init(integerLiteral: value)
  }
  
  public required init(floatLiteral value: Double) {
    super.init(floatLiteral: value)
  }
    
  public required init(stringLiteral value: String) {
    super.init(stringLiteral: value)
  }

}

public class JavascriptInt32Array : JavascriptTypedArray {

  public override class func cast(context: JavascriptContext, from value: JavascriptValue) -> JavascriptInt32Array? {
    if _JavascriptInt32ArrayCanCast(context.reference, value.reference) == 0 {
      return nil
    }
    return JavascriptInt32Array(context: context, reference: value.reference)
  }

  public init(context: JavascriptContext, buffer: JavascriptArrayBuffer, offset: Int, length: Int) {
    // temporary hack: remove once implemented
    let nullValue = _JavascriptValueCreateNull(context.reference)
    super.init(context: context, reference: nullValue!)
  }

  public required init(context: JavascriptContext, reference: JavascriptDataRef) {
    super.init(context: context, reference: reference)
  }

  public convenience required init<T : JavascriptConvertible>(_ value: T) {
    self.init(value.javascriptValue)
  }

  public convenience required init(_ value: JavascriptValue) {
    self.init(context: value.context, reference: value.reference)
  }

  public required init(booleanLiteral value: Bool) {
    super.init(booleanLiteral: value)
  }
  
  public required init(integerLiteral value: Int) {
    super.init(integerLiteral: value)
  }
  
  public required init(floatLiteral value: Double) {
    super.init(floatLiteral: value)
  }
    
  public required init(stringLiteral value: String) {
    super.init(stringLiteral: value)
  }

}

public class JavascriptFloat32Array : JavascriptTypedArray {

  public override class func cast(context: JavascriptContext, from value: JavascriptValue) -> JavascriptFloat32Array? {
    if _JavascriptFloat32ArrayCanCast(context.reference, value.reference) == 0 {
      return nil
    }
    return JavascriptFloat32Array(context: context, reference: value.reference)
  }

  public init(context: JavascriptContext, buffer: JavascriptArrayBuffer, offset: Int, length: Int) {
    // temporary hack: remove once implemented
    let nullValue = _JavascriptValueCreateNull(context.reference)
    super.init(context: context, reference: nullValue!)
  }

  public required init(context: JavascriptContext, reference: JavascriptDataRef) {
    super.init(context: context, reference: reference)
  }

  public convenience required init<T : JavascriptConvertible>(_ value: T) {
    self.init(value.javascriptValue)
  }

  public convenience required init(_ value: JavascriptValue) {
    self.init(context: value.context, reference: value.reference)
  }

  public required init(booleanLiteral value: Bool) {
    super.init(booleanLiteral: value)
  }
  
  public required init(integerLiteral value: Int) {
    super.init(integerLiteral: value)
  }
  
  public required init(floatLiteral value: Double) {
    super.init(floatLiteral: value)
  }
    
  public required init(stringLiteral value: String) {
    super.init(stringLiteral: value)
  }

}

public class JavascriptFloat64Array : JavascriptTypedArray {

  public override class func cast(context: JavascriptContext, from value: JavascriptValue) -> JavascriptFloat64Array? {
    if _JavascriptFloat64ArrayCanCast(context.reference, value.reference) == 0 {
      return nil
    }
    return JavascriptFloat64Array(context: context, reference: value.reference)
  }

  public init(context: JavascriptContext, buffer: JavascriptArrayBuffer, offset: Int, length: Int) {
    // temporary hack: remove once implemented
    let nullValue = _JavascriptValueCreateNull(context.reference)
    super.init(context: context, reference: nullValue!)
  }

  public required init(context: JavascriptContext, reference: JavascriptDataRef) {
    super.init(context: context, reference: reference)
  }

  public convenience required init<T : JavascriptConvertible>(_ value: T) {
    self.init(value.javascriptValue)
  }

  public convenience required init(_ value: JavascriptValue) {
    self.init(context: value.context, reference: value.reference)
  }

  public required init(booleanLiteral value: Bool) {
    super.init(booleanLiteral: value)
  }
  
  public required init(integerLiteral value: Int) {
    super.init(integerLiteral: value)
  }
  
  public required init(floatLiteral value: Double) {
    super.init(floatLiteral: value)
  }
    
  public required init(stringLiteral value: String) {
    super.init(stringLiteral: value)
  }

}

public class JavascriptDataView : JavascriptArrayBufferView {

  public override class func cast(context: JavascriptContext, from value: JavascriptValue) -> JavascriptDataView? {
    if _JavascriptDataViewCanCast(context.reference, value.reference) == 0 {
      return nil
    }
    return JavascriptDataView(context: context, reference: value.reference)
  }

  public init(context: JavascriptContext, buffer: JavascriptArrayBuffer, offset: Int, length: Int) {
    // temporary hack: remove once implemented
    let nullValue = _JavascriptValueCreateNull(context.reference)
    super.init(context: context, reference: nullValue!)
  }

  public required init(context: JavascriptContext, reference: JavascriptDataRef) {
    super.init(context: context, reference: reference)
  }

  public convenience required init<T : JavascriptConvertible>(_ value: T) {
    self.init(value.javascriptValue)
  }

  public convenience required init(_ value: JavascriptValue) {
    self.init(context: value.context, reference: value.reference)
  }

  public required init(booleanLiteral value: Bool) {
    super.init(booleanLiteral: value)
  }
  
  public required init(integerLiteral value: Int) {
    super.init(integerLiteral: value)
  }
  
  public required init(floatLiteral value: Double) {
    super.init(floatLiteral: value)
  }
    
  public required init(stringLiteral value: String) {
    super.init(stringLiteral: value)
  }

}

public class JavascriptDate : JavascriptObject {
  
  public var value: Double {
    return _JavascriptDateGetValue(context.reference, reference)
  }

  public override class func cast(context: JavascriptContext, from value: JavascriptValue) -> JavascriptDate? {
    if _JavascriptDateCanCast(context.reference, value.reference) == 0 {
      return nil
    }
    return JavascriptDate(context: context, reference: value.reference)
  }

  public init(context: JavascriptContext, time: Double) {
    let ref = _JavascriptDateCreate(context.reference, time)
    super.init(context: context, reference: ref!)
  }

  public required init(context: JavascriptContext, reference: JavascriptDataRef) {
    super.init(context: context, reference: reference)
  }

  public convenience required init<T : JavascriptConvertible>(_ value: T) {
    self.init(value.javascriptValue)
  }

  public convenience required init(_ value: JavascriptValue) {
    self.init(context: value.context, reference: value.reference)
  }

  public required init(booleanLiteral value: Bool) {
    super.init(booleanLiteral: value)
  }
  
  public required init(integerLiteral value: Int) {
    super.init(integerLiteral: value)
  }
  
  public required init(floatLiteral value: Double) {
    super.init(floatLiteral: value)
  }
    
  public required init(stringLiteral value: String) {
    super.init(stringLiteral: value)
  }

}

public class JavascriptNumberObject : JavascriptObject {
  
  public var value: Double {
    return _JavascriptNumberObjectGetValue(context.reference, reference)
  }

  public override class func cast(context: JavascriptContext, from value: JavascriptValue) -> JavascriptNumberObject? {
    if _JavascriptNumberObjectCanCast(context.reference, value.reference) == 0 {
      return nil
    }
    return JavascriptNumberObject(context: context, reference: value.reference)
  }

  public init(context: JavascriptContext, value: Double) {
    let ref = _JavascriptNumberObjectCreate(context.reference, value)
    super.init(context: context, reference: ref!)
  }

  public required init(context: JavascriptContext, reference: JavascriptDataRef) {
    super.init(context: context, reference: reference)
  }

  public convenience required init<T : JavascriptConvertible>(_ value: T) {
    self.init(value.javascriptValue)
  }

  public convenience required init(_ value: JavascriptValue) {
    self.init(context: value.context, reference: value.reference)
  }

  public required init(booleanLiteral value: Bool) {
    super.init(booleanLiteral: value)
  }
  
  public required init(integerLiteral value: Int) {
    super.init(integerLiteral: value)
  }
  
  public required init(floatLiteral value: Double) {
    super.init(floatLiteral: value)
  }
    
  public required init(stringLiteral value: String) {
    super.init(stringLiteral: value)
  }

}

public class JavascriptBooleanObject : JavascriptObject {
  
  public var value: Bool {
    return _JavascriptBooleanObjectGetValue(context.reference, reference) == 1
  }

  public override class func cast(context: JavascriptContext, from value: JavascriptValue) -> JavascriptBooleanObject? {
    if _JavascriptBooleanObjectCanCast(context.reference, value.reference) == 0 {
      return nil
    }
    return JavascriptBooleanObject(context: context, reference: value.reference)
  }

  public init(context: JavascriptContext, value: Bool) {
    let ref = _JavascriptBooleanObjectCreate(context.reference, value ? 1 : 0)
    super.init(context: context, reference: ref!)
  }

  public required init(context: JavascriptContext, reference: JavascriptDataRef) {
    super.init(context: context, reference: reference)
  }

  public convenience required init<T : JavascriptConvertible>(_ value: T) {
    self.init(value.javascriptValue)
  }

  public convenience required init(_ value: JavascriptValue) {
    self.init(context: value.context, reference: value.reference)
  }

  public required init(booleanLiteral value: Bool) {
    super.init(booleanLiteral: value)
  }
  
  public required init(integerLiteral value: Int) {
    super.init(integerLiteral: value)
  }
  
  public required init(floatLiteral value: Double) {
    super.init(floatLiteral: value)
  }
    
  public required init(stringLiteral value: String) {
    super.init(stringLiteral: value)
  }

}

public class JavascriptStringObject : JavascriptObject {
  
  public var value: JavascriptString {
    let ref = _JavascriptStringObjectGetValue(context.reference, reference)
    return JavascriptString(context: context, reference: ref!)
  }

  public override class func cast(context: JavascriptContext, from value: JavascriptValue) -> JavascriptStringObject? {
    if _JavascriptStringObjectCanCast(context.reference, value.reference) == 0 {
      return nil
    }
    return JavascriptStringObject(context: context, reference: value.reference)
  }

  public init(context: JavascriptContext, value: JavascriptString) {
    let ref = _JavascriptStringObjectCreate(context.reference, value.reference)
    super.init(context: context, reference: ref!)
  }

  public init(context: JavascriptContext, string: String) {
    var ref: JavascriptDataRef? = nil
    string.withCString { buf in
      ref = _JavascriptStringObjectCreateFromString(context.reference, buf, Int32(string.count))
    }
    super.init(context: context, reference: ref!)
  }

  public required init(context: JavascriptContext, reference: JavascriptDataRef) {
    super.init(context: context, reference: reference)
  }

  public convenience required init<T : JavascriptConvertible>(_ value: T) {
    self.init(value.javascriptValue)
  }

  public convenience required init(_ value: JavascriptValue) {
    self.init(context: value.context, reference: value.reference)
  }

  public required init(booleanLiteral value: Bool) {
    super.init(booleanLiteral: value)
  }
  
  public required init(integerLiteral value: Int) {
    super.init(integerLiteral: value)
  }
  
  public required init(floatLiteral value: Double) {
    super.init(floatLiteral: value)
  }
    
  public required init(stringLiteral value: String) {
    super.init(stringLiteral: value)
  }

}

public class JavascriptRegExp : JavascriptObject {

  public var source: JavascriptString {
    let ref = _JavascriptRegExpGetSource(context.reference, reference)
    return JavascriptString(context: context, reference: ref!)
  }

  public override class func cast(context: JavascriptContext, from value: JavascriptValue) -> JavascriptRegExp? {
    if _JavascriptRegExpCanCast(context.reference, value.reference) == 0 {
      return nil
    }
    return JavascriptRegExp(context: context, reference: value.reference)
  }

  public init(context: JavascriptContext, pattern: JavascriptString) {
    let ref = _JavascriptRegExpCreate(context.reference, pattern.reference)
    super.init(context: context, reference: ref!)
  }

  public required init(context: JavascriptContext, reference: JavascriptDataRef) {
    super.init(context: context, reference: reference)
  }

  public convenience required init<T : JavascriptConvertible>(_ value: T) {
    self.init(value.javascriptValue)
  }

  public convenience required init(_ value: JavascriptValue) {
    self.init(context: value.context, reference: value.reference)
  }

  public required init(booleanLiteral value: Bool) {
    super.init(booleanLiteral: value)
  }
  
  public required init(integerLiteral value: Int) {
    super.init(integerLiteral: value)
  }
  
  public required init(floatLiteral value: Double) {
    super.init(floatLiteral: value)
  }
    
  public required init(stringLiteral value: String) {
    super.init(stringLiteral: value)
  }

}

public typealias JavascriptAccessorSetterCallback = Int

public protocol JavascriptTemplate {
 func set(context: JavascriptContext, name: String, value: JavascriptData)
 func setNativeDataProperty(context: JavascriptContext, name: JavascriptString, getter: JavascriptAccessorGetterCallback, setter: JavascriptAccessorSetterCallback?)
}

public class JavascriptFunctionTemplate {
  
  public var function: JavascriptFunction? {
    let ref = _JavascriptFunctionTemplateGetFunction(context.reference, reference)
    if ref == nil {
      return nil
    }
    return JavascriptFunction(context: context, reference: ref!)
  }

  public var prototypeTemplate: JavascriptObjectTemplate {
    let ref = _JavascriptFunctionTemplateGetPrototypeTemplate(context.reference, reference)
    return JavascriptObjectTemplate(context: context, reference: ref!)
  }

  public var instanceTemplate: JavascriptObjectTemplate {
    let ref = _JavascriptFunctionTemplateGetInstanceTemplate(context.reference, reference)
    return JavascriptObjectTemplate(context: context, reference: ref!)
  }

  public init(context: JavascriptContext,
              callback: JavascriptFunctionCallback? = nil,
              data: JavascriptValue? = nil) {
    self.context = context
    reference =  _JavascriptFunctionTemplateCreate(context.reference)
  }

  public convenience init(context: JavascriptContext) {
    self.init(context: context, callback: nil, data: nil)
  }

  var reference: JavascriptFunctionTemplateRef
  let context: JavascriptContext 

  // internal constructor
  init(context: JavascriptContext, reference: JavascriptFunctionTemplateRef) {
    self.context = context
    self.reference = reference
  }

  deinit {
    _JavascriptFunctionTemplateDestroy(reference)
  }

  public func setCallHandler(callback: @escaping JavascriptFunctionCallback, data: JavascriptValue?) {
    //_JavascriptFunctionTemplateSetCallHandler(reference, callback, data != nil ? data.reference : nil)
  }

  public func setLength(lenght: Int) {
    _JavascriptFunctionTemplateSetLength(context.reference, reference, Int32(lenght))
  }

  public func inherit(parent: JavascriptFunctionTemplate) {
    _JavascriptFunctionTemplateInherit(context.reference, reference, parent.reference)
  }

  public func setClassName(name: JavascriptString) {
    _JavascriptFunctionTemplateSetClassName(context.reference, reference, name.reference)
  }

  public func setAcceptAnyReceiver(value: Bool) {
    _JavascriptFunctionTemplateSetAcceptAnyReceiver(context.reference, reference, value ? 1 : 0)
  }

  public func setHiddenPrototype(value: Bool) {
    _JavascriptFunctionTemplateSetHiddenPrototype(context.reference, reference, value ? 1 : 0)
  }

  public func setReadOnlyPrototype() {
    _JavascriptFunctionTemplateSetReadOnlyPrototype(context.reference, reference)
  }

  public func removePrototype() {
    _JavascriptFunctionTemplateRemovePrototype(context.reference, reference)
  }

  public func hasInstance(object: JavascriptValue) -> Bool {
    return _JavascriptFunctionTemplateHasInstance(context.reference, reference, object.reference) == 0 ? false : true
  }

}

extension JavascriptFunctionTemplate : JavascriptTemplate {
  
  public func set(context: JavascriptContext, name: String, value: JavascriptData) {

  }

  public func setNativeDataProperty(context: JavascriptContext, name: JavascriptString, getter: JavascriptAccessorGetterCallback, setter: JavascriptAccessorSetterCallback?) {

  }

}

public class JavascriptObjectTemplate {
  
  public func getInternalFieldCount(context: JavascriptContext) -> Int {
    return Int(_JavascriptObjectTemplateGetInternalFieldCount(context.reference, reference))
  }

  public func setInternalFieldCount(context: JavascriptContext, count: Int) {
    _JavascriptObjectTemplateSetInternalFieldCount(context.reference, reference, Int32(count))
  }
  
  var reference: JavascriptObjectTemplateRef
  let context: JavascriptContext
  
  public init(context: JavascriptContext, constructor: JavascriptFunctionTemplate?) {
    self.context = context
    reference = _JavascriptObjectTemplateCreate(context.reference)
  }

  public convenience init(context: JavascriptContext) {
    self.init(context: context, constructor: nil)
  }

  init(context: JavascriptContext, reference: JavascriptObjectTemplateRef) {
    self.context = context
    self.reference = reference
  }

  deinit {
    _JavascriptObjectTemplateDestroy(reference)
  }

  public func setAccessor() {
    _JavascriptObjectTemplateSetAccessor(context.reference, reference)
  }
  
  public func setHandler() {
    _JavascriptObjectTemplateSetHandler(context.reference, reference)
  }

  public func setCallAsFunctionHandler(callback: JavascriptFunctionCallback, data: JavascriptValue?) {
    _JavascriptObjectTemplateSetCallAsFunctionHandler(context.reference, reference)
  }

  public func markAsUndetectable() {
    _JavascriptObjectTemplateMarkAsUndetectable(context.reference, reference)
  }

  public func setAccessCheckCallback() {
    _JavascriptObjectTemplateSetAccessCheckCallback(context.reference, reference)
  }
}

extension JavascriptObjectTemplate : JavascriptTemplate {
  
  public func set(context: JavascriptContext, name: String, value: JavascriptData) {

  }

  public func setNativeDataProperty(context: JavascriptContext, name: JavascriptString, getter: JavascriptAccessorGetterCallback, setter: JavascriptAccessorSetterCallback?) {
    
  }

}

public class JavascriptSignature {
  
  public init(context: JavascriptContext, receiver: JavascriptFunctionTemplate? = nil) {
    
  }

}

public class WasmCompiledModule : JavascriptObject {
  
  static func deserialize(context: JavascriptContext, data: Data) -> WasmCompiledModule? {
    let ref = data.withUnsafeBytes {
      return _WasmCompiledModuleDeserializeOrCompile(context.reference, $0, CInt(data.count), nil, 0)
    }
    guard let module = ref else {
      return nil
    }
    return WasmCompiledModule(context: context, reference: module)
  }

  static func compile(context: JavascriptContext, data: Data) -> WasmCompiledModule? {
    let ref = data.withUnsafeBytes {
      return _WasmCompiledModuleDeserializeOrCompile(context.reference, nil, 0, $0, CInt(data.count))
    }
    guard let module = ref else {
      return nil
    }
    return WasmCompiledModule(context: context, reference: module)
  }

  public required init(context: JavascriptContext, reference: JavascriptDataRef) {
    super.init(context: context, reference: reference)
  }

  public convenience required init<T : JavascriptConvertible>(_ value: T) {
    self.init(value.javascriptValue)
  }

  public convenience required init(_ value: JavascriptValue) {
    self.init(context: value.context, reference: value.reference)
  }

  public required init(booleanLiteral value: Bool) {
    super.init(booleanLiteral: value)
  }
  
  public required init(integerLiteral value: Int) {
    super.init(integerLiteral: value)
  }
  
  public required init(floatLiteral value: Double) {
    super.init(floatLiteral: value)
  }
    
  public required init(stringLiteral value: String) {
    super.init(stringLiteral: value)
  }

}

public func flattenedSubscriptIndices(
    _ context: JavascriptContext,
    _ indices: [JavascriptConvertible]) -> JavascriptValue {
  if indices.count == 1 {
    return indices[0].javascriptValue
  }
  //return JavascriptArray(indices.map { $0.javascriptValue })
  return JavascriptValue.Undefined(context: context)
}

extension String : JavascriptConvertible, ConvertibleFromJavascript {

    public init?(_ javascriptValue: JavascriptValue) {
      let cstr = _JavascriptStringGetValue(javascriptValue.context.reference, javascriptValue.reference)
      self.init(cString: cstr!)
    }
    
    public var javascriptValue: JavascriptValue {
      let context = JavascriptContext.current
      let v = utf8CString.withUnsafeBufferPointer {
        return _JavascriptStringCreateFromCString(context.reference, $0.baseAddress, CInt($0.count-1))
      }
      return JavascriptString(context: context, reference: v!)
    }

}