// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims
import Foundation

public class JsData {

  var reference: JavascriptDataRef

  init(reference: JavascriptDataRef) {
    self.reference = reference
  }
  deinit {
    _JavascriptDataDestroy(reference)
  }

}

public class JavascriptValue {

  public func isUndefined(context: JsContext) ->  Bool {
    return _JavascriptValueIsUndefined(context.reference, reference) == 1
  }

  public func isNull(context: JsContext) -> Bool {
    return _JavascriptValueIsNull(context.reference, reference) == 1
  }

  public func isTrue(context: JsContext) -> Bool {
    return _JavascriptValueIsTrue(context.reference, reference) == 1
  }

  public func isFalse(context: JsContext) -> Bool {
    return _JavascriptValueIsFalse(context.reference, reference) == 1
  }

  public func isName(context: JsContext) -> Bool {
    return _JavascriptValueIsName(context.reference, reference) == 1
  }

  public func isSymbol(context: JsContext) -> Bool {
    return _JavascriptValueIsSymbol(context.reference, reference) == 1
  }

  public func isString(context: JsContext) -> Bool {
    return _JavascriptValueIsString(context.reference, reference) == 1
  }

  public func isFunction(context: JsContext) -> Bool {
    return _JavascriptValueIsFunction(context.reference, reference) == 1
  }

  public func isArray(context: JsContext) -> Bool {
    return _JavascriptValueIsArray(context.reference, reference) == 1
  }

  public func isObject(context: JsContext) -> Bool {
    return _JavascriptValueIsObject(context.reference, reference) == 1
  }

  public func isBool(context: JsContext) -> Bool {
    return _JavascriptValueIsBool(context.reference, reference) == 1
  }

  public func isNumber(context: JsContext) -> Bool {
    return _JavascriptValueIsNumber(context.reference, reference) == 1
  }

  public func isInt32(context: JsContext) -> Bool {
    return _JavascriptValueIsInt32(context.reference, reference) == 1
  }

  public func isUInt32(context: JsContext) -> Bool {
    return _JavascriptValueIsUInt32(context.reference, reference) == 1
  }

  public func isDate(context: JsContext) -> Bool {
    return _JavascriptValueIsDate(context.reference, reference) == 1
  }

  public func isMap(context: JsContext) -> Bool {
    return _JavascriptValueIsMap(context.reference, reference) == 1
  }

  public func isSet(context: JsContext) -> Bool {
    return _JavascriptValueIsSet(context.reference, reference) == 1
  }

  public func isArgumentsObject(context: JsContext) -> Bool {
    return _JavascriptValueIsArgumentsObject(context.reference, reference) == 1
  }

  public func isBooleanObject(context: JsContext) -> Bool {
    return _JavascriptValueIsBooleanObject(context.reference, reference) == 1
  }

  public func isNumberObject(context: JsContext) -> Bool {
    return _JavascriptValueIsNumberObject(context.reference, reference) == 1
  }

  public func isStringObject(context: JsContext) -> Bool {
    return _JavascriptValueIsStringObject(context.reference, reference) == 1
  }

  public func isSymbolObject(context: JsContext) -> Bool {
    return _JavascriptValueIsSymbolObject(context.reference, reference) == 1
  }

  public func isNativeError(context: JsContext) -> Bool {
    return _JavascriptValueIsNativeError(context.reference, reference) == 1
  }

  public func isRegExp(context: JsContext) -> Bool {
    return _JavascriptValueIsRegExp(context.reference, reference) == 1
  }

  public func isGeneratorFunction(context: JsContext) -> Bool {
    return _JavascriptValueIsGeneratorFunction(context.reference, reference) == 1
  }

  public func isGeneratorObject(context: JsContext) -> Bool {
    return _JavascriptValueIsGeneratorObject(context.reference, reference) == 1
  }

  public func isPromise(context: JsContext) -> Bool {
    return _JavascriptValueIsPromise(context.reference, reference) == 1
  }

  public func isMapIterator(context: JsContext) -> Bool {
    return _JavascriptValueIsMapIterator(context.reference, reference) == 1
  }

  public func isSetIterator(context: JsContext) -> Bool {
    return _JavascriptValueIsSetIterator(context.reference, reference) == 1
  }

  public func isWeakMap(context: JsContext) -> Bool {
    return _JavascriptValueIsWeakMap(context.reference, reference) == 1
  }

  public func isWeakSet(context: JsContext) -> Bool {
    return _JavascriptValueIsWeakSet(context.reference, reference) == 1
  }

  public func isArrayBuffer(context: JsContext) -> Bool {
    return _JavascriptValueIsArrayBuffer(context.reference, reference) == 1
  }

  public func isArrayBufferView(context: JsContext) -> Bool {
    return _JavascriptValueIsArrayBufferView(context.reference, reference) == 1
  }

  public func isTypedArray(context: JsContext) -> Bool {
    return _JavascriptValueIsTypedArray(context.reference, reference) == 1
  }

  public func isUInt8Array(context: JsContext) -> Bool {
    return _JavascriptValueIsUInt8Array(context.reference, reference) == 1
  }

  public func isUInt8ClampedArray(context: JsContext) -> Bool {
    return _JavascriptValueIsUInt8ClampedArray(context.reference, reference) == 1
  }

  public func isInt8Array(context: JsContext) -> Bool {
    return _JavascriptValueIsInt8Array(context.reference, reference) == 1
  }

  public func isUInt16Array(context: JsContext) -> Bool {
    return _JavascriptValueIsUInt32Array(context.reference, reference) == 1
  }

  public func isInt16Array(context: JsContext) -> Bool {
    return _JavascriptValueIsInt16Array(context.reference, reference) == 1
  }

  public func isUInt32Array(context: JsContext) -> Bool {
    return _JavascriptValueIsUInt32Array(context.reference, reference) == 1
  }

  public func isInt32Array(context: JsContext) -> Bool {
    return _JavascriptValueIsInt32Array(context.reference, reference) == 1
  }

  public func isFloat32Array(context: JsContext) -> Bool {
    return _JavascriptValueIsFloat32Array(context.reference, reference) == 1
  }

  public func isFloat64Array(context: JsContext) -> Bool {
    return _JavascriptValueIsFloat64Array(context.reference, reference) == 1
  }

  public func isDataView(context: JsContext) -> Bool {
    return _JavascriptValueIsDataView(context.reference, reference) == 1
  }

  public func isSharedArrayBuffer(context: JsContext) -> Bool {
    return _JavascriptValueIsSharedArrayBuffer(context.reference, reference) == 1
  }
  
  // public so Web can access
  public var reference: JavascriptValueRef

  // create a null js value
  public static func Null(context: JsContext) -> JavascriptValue {
    let ref = _JavascriptValueCreateNull(context.reference)
    return JavascriptValue(reference: ref!)
  }

  // create a undefined js value
  public static func Undefined(context: JsContext) -> JavascriptValue {
    let ref = _JavascriptValueCreateUndefined(context.reference)
    return JavascriptValue(reference: ref!)
  }

  // the idea here is to be overrided
  // we cant use a protocol for this, because theres
  // a need to be overrided, when the object is a child of JsObject
  public class func cast(context: JsContext, from value: JavascriptValue) -> Self? {
    return nil
  }

  public required init(reference: JavascriptValueRef) {
    self.reference = reference
  }

  public func isEqual(context: JsContext, other: JavascriptValue) -> Bool {
    return _JavascriptValueIsEqual(context.reference, reference, other.reference) == 1
  }

  public func castAs<To: JavascriptValue>(context: JsContext) -> To? {
    return To.cast(context: context, from: self)
    //switch To.self {
    //  case is JsBoolean:
    //    return JsBoolean.cast(value: self) as! To
    //  case is JsName:
    //    return JsName.cast(value: self) as! To
    //}
  }

}

//extension JavascriptValue : Equatable {}

//public func ==(left: JavascriptValue, right: JavascriptValue) -> Bool {
//  return left.isEqual(other: right)
//}

public class JsBoolean : JavascriptValue {

  public override class func cast(context: JsContext, from value: JavascriptValue) -> JsBoolean? {
    if _JavascriptBooleanCanCast(context.reference, value.reference) == 0 {
      return nil
    }
    return JsBoolean(reference: value.reference)
  }

  public init(context: JsContext, value: Bool) {
    let ref = _JavascriptBooleanNew(context.reference, value ? 1 : 0)
    super.init(reference: ref!)
  }

  public required init(reference: JavascriptValueRef) {
    super.init(reference: reference)
  }

  public func getValue(context: JsContext) -> Bool {
    return _JavascriptBooleanGetValue(context.reference, reference) == 1
  }

}

public class JsName : JavascriptValue {
  
  public func getIdentityHash(context: JsContext) -> Int {
    return Int(_JavascriptNameGetIdentityHash(context.reference, reference))
  }

  public override class func cast(context: JsContext, from value: JavascriptValue) -> JsName? {
    if _JavascriptNameCanCast(context.reference, value.reference) == 0 {
      return nil
    }
    return JsName(reference: value.reference)
  }

}

public class JsString : JavascriptValue {
  
  public func getValue(context: JsContext) -> String {
    let len = getUTF8Length(context: context)
    let mem = malloc(len)
    let bytes = mem!.bindMemory(to: Int8.self, capacity: len)
    let _ = writeUTF8(context: context, buffer: bytes, length: len)
    return String(bytesNoCopy: bytes, length: len, encoding: String.Encoding.utf8, freeWhenDone: true)!
  }

  public func getLength(context: JsContext) -> Int {
    return Int(_JavascriptStringGetLenght(context.reference, reference))
  }
 
  public func getUTF8Length(context: JsContext) -> Int {
    return Int(_JavascriptStringUTF8Length(context.reference, reference))
  }

  public func isOneByte(context: JsContext) -> Bool {
    return _JavascriptStringIsOneByte(context.reference, reference) == 1
  }

  public func containsOnlyOneByte(context: JsContext) -> Bool {
    return _JavascriptStringContainsOnlyOneByte(context.reference, reference) == 1
  }

  public init(context: JsContext, string: String) {
    var ref: JavascriptValueRef? = nil
    string.withCString { ptr in
      ref = _JavascriptStringCreateFromCString(context.reference, ptr, Int32(string.count))
    }
    // fix it: its actually failable on the C side
    super.init(reference: ref!)
  }

  public required init(reference: JavascriptValueRef) {
    super.init(reference: reference)
  }

  public override class func cast(context: JsContext, from value: JavascriptValue) -> JsString? {
    if _JavascriptStringCanCast(context.reference, value.reference) == 0 {
      return nil
    }
    return JsString(reference: value.reference)
  }

  public func write(context: JsContext,
                    buffer: inout [UInt16],
                    start: Int,
                    length: Int) -> Int {
    var result = -1
    buffer.withUnsafeMutableBufferPointer { buf in
      result = Int(_JavascriptStringWrite(context.reference, reference, buf.baseAddress, Int32(start), Int32(length)))  
    }
    return result
  }

  public func writeOneByte(context: JsContext,
                           buffer: inout [UInt8],
                           start: Int,
                           length: Int) -> Int {
    var result = -1
    buffer.withUnsafeMutableBufferPointer { buf in                          
      result = Int(_JavascriptStringWriteOneByte(context.reference, reference, buf.baseAddress, Int32(start), Int32(length)))
    }
    return result
  }
  
  public func writeUTF8(context: JsContext, buffer: inout [Int8], length: Int) -> Int {
    var result = -1
    buffer.withUnsafeMutableBufferPointer { buf in
      result = Int(_JavascriptStringWriteUTF8(context.reference, reference, buf.baseAddress, Int32(length)))
    }
    return result
  }

  public func writeUTF8(context: JsContext, buffer: UnsafeMutablePointer<Int8>, length: Int) -> Int {
    var result = -1
    result = Int(_JavascriptStringWriteUTF8(context.reference, reference, &buffer.pointee, Int32(length)))
    return result
  }

}

public class JsNumber : JavascriptValue {
  
  public func getValue(context: JsContext) -> Double {
    return _JavascriptNumberGetValue(context.reference, reference)
  }

  public override class func cast(context: JsContext, from value: JavascriptValue) -> JsNumber? {
    if _JavascriptNumberCanCast(context.reference, value.reference) == 0 {
      return nil
    }
    return JsNumber(reference: value.reference)
  }

  public required init(reference: JavascriptValueRef) {
    super.init(reference: reference)
  }

}

public class JsInteger : JavascriptValue {
  
  public func getValue(context: JsContext) -> Int64 {
    return _JavascriptIntegerGetValue(context.reference, reference)
  }

  public override class func cast(context: JsContext, from value: JavascriptValue) -> JsInteger? {
    if _JavascriptIntegerCanCast(context.reference, value.reference) == 0 {
      return nil
    }
    return JsInteger(reference: value.reference)
  }

  public required init(reference: JavascriptValueRef) {
    super.init(reference: reference)
  }

}

public class JsInt32: JavascriptValue {
  
  public func getValue(context: JsContext) -> Int32 {
    return _JavascriptInt32GetValue(context.reference, reference)
  }

  public override class func cast(context: JsContext, from value: JavascriptValue) -> JsInt32? {
    if _JavascriptInt32CanCast(context.reference, value.reference) == 0 {
      return nil
    }
    return JsInt32(reference: value.reference)
  }

  public required init(reference: JavascriptValueRef) {
    super.init(reference: reference)
  }

}

public class JsUInt32: JavascriptValue {
  
  public func getValue(context: JsContext) -> UInt32 {
    return _JavascriptUInt32GetValue(context.reference, reference)
  }

  public override class func cast(context: JsContext, from value: JavascriptValue) -> JsUInt32? {
    if _JavascriptUInt32CanCast(context.reference, value.reference) == 0 {
      return nil
    }
    return JsUInt32(reference: value.reference)
  }

  public required init(reference: JavascriptValueRef) {
    super.init(reference: reference)
  }

}

// info actually is info: PropertyCallbackInfo<JavascriptValue>
public typealias JsAccessorGetterCallback = (_: JsString, _: JavascriptValue) -> Void

public class JsObject : JavascriptValue {

  public func getIdentityHash(context: JsContext) -> Int {
    return Int(_JavascriptObjectGetIdentityHash(context.reference, reference))  
  }

  public func isCallable(context: JsContext) -> Bool {
    return _JavascriptObjectIsCallable(context.reference, reference) == 0 ? false : true
  }

  public func getPropertyNames(context: JsContext) -> JsArray {
    let ref = _JavascriptObjectGetPropertyNames(context.reference, reference)
    return JsArray(reference: ref!)
  }

  public func getPrototype(context: JsContext) -> JavascriptValue {
    let ref = _JavascriptObjectGetPrototype(context.reference, reference)
    return JavascriptValue(reference: ref!)
  }

  public func getObjectProtoToString(context: JsContext) -> JsString {
    let ref = _JavascriptObjectGetObjectProtoString(context.reference, reference)
    return JsString(reference: ref!)
  }

  public func getConstructorName(context: JsContext) -> JsString {
    let ref = _JavascriptObjectGetConstructorName(context.reference, reference)
    return JsString(reference: ref!)
  }

  public func getInternalFieldCount(context: JsContext) -> Int {
    return Int(_JavascriptObjectGetInternalFieldCount(context.reference, reference))
  }

  public override class func cast(context: JsContext, from value: JavascriptValue) -> JsObject? {
    if _JavascriptObjectCanCast(context.reference, value.reference) == 0 {
      return nil
    }
    return JsObject(reference: value.reference)
  }
  
  public required init(reference: JavascriptValueRef) {
    super.init(reference: reference)
  }

  public func getInternalField(context: JsContext, index: Int) -> JavascriptValue? {
    let ref = _JavascriptObjectGetInternalField(context.reference, reference, Int32(index))
    if ref == nil {
      return nil
    }
    return JavascriptValue(reference: ref!)
  }

  public func setInternalField(context: JsContext, index: Int, value: JavascriptValue) {
    _JavascriptObjectSetInternalField(context.reference, reference, Int32(index), value.reference)
  }

  public func createDataProperty(context: JsContext, key: JsName, value: JavascriptValue) -> Bool {
    // TODO: the native function may return -1 in case of error
    return _JavascriptObjectCreateDataProperty(context.reference, reference, key.reference, value.reference) == 0 ? false : true
  }

  public func createDataProperty(context: JsContext, index: Int, value: JavascriptValue) -> Bool {
    // TODO: the native function may return -1 in case of error
    return _JavascriptObjectCreateDataPropertyByIndex(context.reference, reference, Int32(index), value.reference) == 0 ? false : true
  }

  public func getProperty(context: JsContext, key: JavascriptValue) -> JavascriptValue? {
    let ref =  _JavascriptObjectGetProperty(context.reference, reference, key.reference)
    if ref == nil {
      return nil
    }
    return JavascriptValue(reference: ref!)
  }

  public func getProperty(context: JsContext, index: Int) -> JavascriptValue? {
    let ref =  _JavascriptObjectGetPropertyByIndex(context.reference, reference, Int32(index))
    if ref == nil {
      return nil
    }
    return JavascriptValue(reference: ref!)
  }

  public func setProperty(context: JsContext, key: JavascriptValue, value: JavascriptValue) -> Bool {
    let retval = _JavascriptObjectSetProperty(context.reference, reference, key.reference, value.reference)
    if retval == -1 { // what?
      
    }
    return retval == 0 ? false : true
  }

  public func setProperty(context: JsContext, index: Int, value: JavascriptValue) -> Bool {
    return _JavascriptObjectSetPropertyByIndex(context.reference, reference, Int32(index), value.reference) == 0 ? false : true
  }

  public func hasProperty(context: JsContext, key: JavascriptValue) -> Bool {
    return _JavascriptObjectHasProperty(context.reference, reference, key.reference) == 0 ? false : true
  }

  public func deleteProperty(context: JsContext, key: JavascriptValue) -> Bool {
    return _JavascriptObjectDeleteProperty(context.reference, reference, key.reference) == 0 ? false : true
  }

  public func deleteProperty(context: JsContext, index: Int) -> Bool {
    return _JavascriptObjectDeletePropertyByIndex(context.reference, reference, Int32(index)) == 0 ? false : true
  }

  public func setAccessor(getter: JsAccessorGetterCallback) {
    assert(false)
  }

  public func findInstanceInPrototypeChain(context: JsContext, template: JsFunctionTemplate) -> JsObject? {
    // FIXIT: see why we are asking for the context on some and not on others
    // and why this is particular to objects and not other values
    // maybe the ideal would be to pass always and relly in the isolate pointed by it
    // instead of relying on the Isolate::GetCurrent(), so we can deal with multiple isolates
    // without much hasless
    let ref =  _JavascriptObjectFindInstanceInPrototypeChain(context.reference, reference, template.reference)
    if ref == nil {
      return nil
    }
    return JsObject(reference: ref!)
  }

  public func hasOwnProperty(context: JsContext, key: JsString) -> Bool {
    return _JavascriptObjectHasOwnProperty(context.reference, reference, key.reference) == 0 ? false : true
  }

  public func hasRealNamedProperty(context: JsContext, key: JsString) -> Bool {
    return _JavascriptObjectHasRealNamedProperty(context.reference, reference, key.reference) == 0 ? false : true
  }

  public func hasRealIndexedProperty(context: JsContext, index: Int) -> Bool {
    return _JavascriptObjectHasRealIndexedProperty(context.reference, reference, Int32(index)) == 0 ? false : true
  }

  public func hasRealNamedCallbackProperty(context: JsContext, key: JsString) -> Bool {
    return _JavascriptObjectHasRealNamedCallbackProperty(context.reference, reference, key.reference) == 0 ? false : true
  }

  public func getRealNamedPropertyInPrototypeChain(context: JsContext, key: JsString) -> JavascriptValue? {
    let ref =  _JavascriptObjectGetRealNamedPropertyInPrototypeChain(context.reference, reference, key.reference)
    if ref == nil {
      return nil
    }
    return JavascriptValue(reference: ref!)
  }

  public func getRealNamedProperty(context: JsContext, key: JsString) -> JavascriptValue? {
    let ref =  _JavascriptObjectGetRealNamedProperty(context.reference, reference, key.reference)
    if ref == nil {
      return nil
    }
    return JavascriptValue(reference: ref!)
  }

  public func hasNamedLookupInterceptor(context: JsContext) -> Bool {
    return _JavascriptObjectHasNamedLookupInterceptor(context.reference, reference) == 0 ? false : true
  }

  public func hasIndexedLookupInterceptor(context: JsContext) -> Bool {
    return _JavascriptObjectHasIndexedLookupInterceptor(context.reference, reference) == 0 ? false : true
  }

  public func clone(context: JsContext) -> JsObject {
    let ref =  _JavascriptObjectClone(context.reference, reference)
    return JsObject(reference: ref!)
  }

  public func callAsFunction(context: JsContext, recv: JavascriptValue, args: [JavascriptValue]) -> JavascriptValue {
    var handles: [JavascriptValueRef?] = []
    var result: JavascriptValue? = nil

    for arg in args {
      handles.append(arg.reference)
    }

    handles.withUnsafeMutableBufferPointer { (arrayBuffer: inout UnsafeMutableBufferPointer<JavascriptValueRef?>) -> Void in
      let ref =  _JavascriptObjectCallAsFunction(context.reference, reference, recv.reference, Int32(args.count), arrayBuffer.baseAddress)
      result = JavascriptValue(reference: ref!)
    }

    return result!
  }

  public func callAsConstructor(context: JsContext, args: [JavascriptValue]) -> JavascriptValue {
    var handles: [JavascriptValueRef?] = []
    var result: JavascriptValue? = nil
    
    for arg in args {
      handles.append(arg.reference)
    }

    handles.withUnsafeMutableBufferPointer { (arrayBuffer: inout UnsafeMutableBufferPointer<JavascriptValueRef?>) -> Void in
      let ref =  _JavascriptObjectCallAsConstructor(context.reference, reference, Int32(args.count), arrayBuffer.baseAddress)
      result = JavascriptValue(reference: ref!)
    }

    return result!
  }

}

public class JsArray : JsObject {
  
  public func getCount(context: JsContext) -> Int {
    return Int(_JavascriptArrayCount(context.reference, reference))
  }

  public override class func cast(context: JsContext, from value: JavascriptValue) -> JsArray? {
    if _JavascriptArrayCanCast(context.reference, value.reference) == 0 {
      return nil
    }
    return JsArray(reference: value.reference)
  }

  public required init(reference: JavascriptValueRef) {
    super.init(reference: reference)
  }

}

public class JsMap : JsObject {
  
  public func getCount(context: JsContext) -> Int {
    return Int(_JavascriptMapCount(context.reference, reference))
  }

  public override class func cast(context: JsContext, from value: JavascriptValue) -> JsMap? {
    if _JavascriptMapCanCast(context.reference, value.reference) == 0 {
      return nil
    }
    return JsMap(reference: value.reference)
  }

  public required init(reference: JavascriptValueRef) {
    super.init(reference: reference)
  }

  public func get(context: JsContext, key: JavascriptValue) -> JavascriptValue? {
    let ref =  _JavascriptMapGetProperty(context.reference, reference, key.reference)
    if ref == nil {
      return nil
    }
    return JavascriptValue(reference: ref!)
  }

  public func set(context: JsContext, key: JavascriptValue, value: JavascriptValue) -> JsMap? {
    let ref = _JavascriptMapSetProperty(context.reference, reference, key.reference, value.reference)
    if ref == nil {
      return nil
    }
    return JsMap(reference: ref!)
  }

  public func has(context: JsContext, key: JavascriptValue) -> Bool {
    return _JavascriptMapHasProperty(context.reference, reference, key.reference) == 0 ? false : true
  }

  public func delete(context: JsContext, key: JavascriptValue) -> Bool {
    return _JavascriptMapDeleteProperty(context.reference, reference, key.reference) == 0 ? false : true
  }

  public func clear(context: JsContext) {
    _JavascriptMapClear(context.reference, reference)
  }

  public func asArray(context: JsContext) -> JsArray {
    let ref = _JavascriptMapAsArray(context.reference, reference)
    return JsArray(reference: ref!)
  }

}

public class JsSet : JsObject {
  
  public func getCount(context: JsContext) -> Int {
    return Int(_JavascriptSetCount(context.reference, reference))
  }

  public override class func cast(context: JsContext, from value: JavascriptValue) -> JsSet? {
    if _JavascriptSetCanCast(context.reference, value.reference) == 0 {
      return nil
    }
    return JsSet(reference: value.reference)
  }

  public required init(reference: JavascriptValueRef) {
    super.init(reference: reference)
  }

  public func add(context: JsContext, key: JavascriptValue) {
    _JavascriptSetAdd(context.reference, reference, key.reference)
  }
  
  public func has(context: JsContext, key: JavascriptValue) -> Bool {
    return _JavascriptSetHasProperty(context.reference, reference, key.reference) == 0 ? false : true
  }

  public func delete(context: JsContext, key: JavascriptValue) -> Bool {
    return _JavascriptSetDeleteProperty(context.reference, reference, key.reference) == 0 ? false : true
  }

  public func clear(context: JsContext) {
    _JavascriptSetClear(context.reference, reference)
  }

  public func asArray(context: JsContext) -> JsArray {
    let ref = _JavascriptSetAsArray(context.reference, reference)
    return JsArray(reference: ref!)
  }

}

public struct JsFunctionCallbackInfo {
  
  public func getLength(context: JsContext) -> Int {
    return Int(_JavascriptFunctionCallbackInfoGetLength(context.reference, reference))
  }

  public func getCallee(context: JsContext) -> JsFunction {
    let ref = _JavascriptFunctionCallbackInfoGetCallee(context.reference, reference)
    return JsFunction(reference: ref!)
  }

  public func this(context: JsContext) -> JsObject {
    let ref = _JavascriptFunctionCallbackInfoGetThis(context.reference, reference)
    return JsFunction(reference: ref!)
  }

  public func getHolder(context: JsContext) -> JsObject {
    let ref = _JavascriptFunctionCallbackInfoGetHolder(context.reference, reference)
    return JsFunction(reference: ref!)
  }

  public func isConstructorCall(context: JsContext) -> Bool {
    return _JavascriptFunctionCallbackInfoIsConstructorCall(context.reference, reference) == 0 ? false : true
  }

  public func getData(context: JsContext) -> JavascriptValue {
    let ref = _JavascriptFunctionCallbackInfoGetData(context.reference, reference)
    return JavascriptValue(reference: ref!)
  }

  let reference: JsFunctionCallbackInfoRef

  public func getValue(context: JsContext, at: Int) -> JavascriptValue? {
    let ref = _JavascriptFunctionCallbackInfoGetValueAt(context.reference, reference, Int32(at))
    if ref == nil {
      return nil
    }
    return JavascriptValue(reference: ref!)
  }

  public func returnValue<T: JavascriptValue>(context: JsContext) -> T {
    let ref = _JavascriptFunctionCallbackInfoGetReturnValue(context.reference, reference)
    return T(reference: ref!)
  }

}

public typealias JsFunctionCallback = (_: JsFunctionCallbackInfo) -> Void

func localFunctionHandler(info: JsFunctionCallbackInfoRef?) -> Void {
  guard info != nil else {
    return
  }
}

public class JsFunction: JsObject {

  public func getName(context: JsContext) -> JavascriptValue {
    let ref = _JavascriptFunctionGetName(context.reference, reference)
    return JavascriptValue(reference: ref!)
  }

  public func getInferredName(context: JsContext) -> JavascriptValue {
    let ref = _JavascriptFunctionGetInferredName(context.reference, reference)
    return JavascriptValue(reference: ref!)
  }

  public func getScriptLineNumber(context: JsContext) -> Int {
    return Int(_JavascriptFunctionGetScriptLineNumber(context.reference, reference)) 
  }

  public func getScriptColumnNumber(context: JsContext) -> Int {
    return Int(_JavascriptFunctionGetScriptColumnNumber(context.reference, reference))
  }

  public func getScriptId(context: JsContext) -> Int {
    return Int(_JavascriptFunctionGetScriptId(context.reference, reference))
  }

  public func getDisplayName(context: JsContext) -> JavascriptValue {
    let ref = _JavascriptFunctionGetDisplayName(context.reference, reference)
    return JavascriptValue(reference: ref!)
  }

  public func getBoundFunction(context: JsContext) -> JavascriptValue {
    let ref = _JavascriptFunctionGetBoundFunction(context.reference, reference)
    return JavascriptValue(reference: ref!)
  }

  public func getScriptOrigin(context: JsContext) -> JsScriptOrigin {
    let ref = _JavascriptFunctionGetScriptOrigin(context.reference, reference)
    return JsScriptOrigin(reference: ref!)
  }

  public override class func cast(context: JsContext, from value: JavascriptValue) -> JsFunction? {
    if _JavascriptFunctionCanCast(context.reference, value.reference) == 0 {
      return nil
    }
    return JsFunction(reference: value.reference)
  }

  public init(context: JsContext, callback: @escaping JsFunctionCallback, data: JavascriptValue? = nil, len: Int) {
    let ref = _JavascriptFunctionCreate(context.reference, localFunctionHandler, data != nil ? data!.reference : nil, Int32(len))
    super.init(reference: ref!)
  }

  public required init(reference: JavascriptValueRef) {
    super.init(reference: reference)
  }

  public func newInstance(context: JsContext, argc: Int, argv: [JavascriptValue]) -> JsObject? {
    var handles: [JavascriptValueRef?] = []
    var result: JsObject? = nil
    
    for arg in argv {
      handles.append(arg.reference)
    }

    handles.withUnsafeMutableBufferPointer { (arrayBuffer: inout UnsafeMutableBufferPointer<JavascriptValueRef?>) -> Void in
      let ref = _JavascriptFunctionCreateInstance(context.reference, reference, Int32(argc), arrayBuffer.baseAddress)
      if ref != nil {
        result = JsObject(reference: ref!)
      }
    }

    return result
  }

  public func call(context: JsContext, recv: JavascriptValue, argc: Int, argv: [JavascriptValue]) -> JavascriptValue? {
    var handles: [JavascriptValueRef?] = []
    var result: JavascriptValue? = nil
    
    for arg in argv {
      handles.append(arg.reference)
    }

    handles.withUnsafeMutableBufferPointer { (arrayBuffer: inout UnsafeMutableBufferPointer<JavascriptValueRef?>) -> Void in
      let ref = _JavascriptFunctionCall(context.reference, reference, recv.reference, Int32(argc), arrayBuffer.baseAddress)
      if ref != nil {
        result = JavascriptValue(reference: ref!)
      }
    }

    return result
  }

  public func setName(context: JsContext, name: JsString) {
    _JavascriptFunctionSetName(context.reference, reference, name.reference)
  }

}

public class JsPromise : JsObject {

  public var hasHandler: Bool {
    assert(false)
    // FIXIT: implement this
    //return _JavascriptPromisseHasHandler(reference) == 0 ? false : true
    return false
  }

  public override class func cast(context: JsContext, from value: JavascriptValue) -> JsPromise? {
    if _JavascriptPromiseCanCast(context.reference, value.reference) == 0 {
      return nil
    }
    return JsPromise(reference: value.reference)
  }

  public required init(reference: JavascriptValueRef) {
    super.init(reference: reference)
  }

  public func chain(context: JsContext, handler: JsFunction) -> JsPromise {
    // temporary hack.. remove
    let nullValue = _JavascriptValueCreateNull(context.reference)
    return JsPromise(reference: nullValue!)
  }

  public func `catch`(context: JsContext, handler: JsFunction) -> JsPromise {
    // temporary hack.. remove
    let nullValue = _JavascriptValueCreateNull(context.reference)
    return JsPromise(reference: nullValue!)
  }

  public func then(context: JsContext, handler: JsFunction) -> JsPromise {
    // temporary hack.. remove
    let nullValue = _JavascriptValueCreateNull(context.reference)
    return JsPromise(reference: nullValue!)
  }

}

public class JsArrayBuffer : JsObject {

  public func isExternal(context: JsContext) -> Bool {
    assert(false)
    return false
  }

  public func isNeuterable(context: JsContext) -> Bool {
    assert(false)
    return false
  }

  public override class func cast(context: JsContext, from value: JavascriptValue) -> JsArrayBuffer? {
    if _JavascriptArrayCanCast(context.reference, value.reference) == 0 {
      return nil
    }
    return JsArrayBuffer(reference: value.reference)
  }

  public init(context: JsContext, byteLenght: Int) {
    // temporary hack: remove once implemented
    let nullValue = _JavascriptValueCreateNull(context.reference)
    super.init(reference: nullValue!)
  }

  public init(context: JsContext, data: UnsafePointer<UInt8>, byteLenght: Int) {
    // temporary hack: remove once implemented
    let nullValue = _JavascriptValueCreateNull(context.reference)
    super.init(reference: nullValue!)
  }

  public required init(reference: JavascriptValueRef) {
    super.init(reference: reference)
  }

  public func neuter(context: JsContext) {

  }

}

public class JsArrayBufferView : JsObject {

  public func getBuffer(context: JsContext) -> JsArrayBuffer? {
    //assert(false)
    return nil
  }

  public func getByteOffset(context: JsContext) -> Int {
    //assert(false)
    return -1
  }

  public func getByteLenght(context: JsContext) -> Int {
    //assert(false)
    return -1
  }

  public func hasBuffer(context: JsContext) -> Bool {
    //assert(false)
    return false
  }

  public override class func cast(context: JsContext, from value: JavascriptValue) -> JsArrayBufferView? {
    if _JavascriptArrayBufferCanCast(context.reference, value.reference) == 0 {
      return nil
    }
    return JsArrayBufferView(reference: value.reference)
  }

  public required init(reference: JavascriptValueRef) {
    super.init(reference: reference)
  }

  public func copyContents(context: JsContext, dest: inout UnsafeMutablePointer<UInt8>, lenght: Int) -> Int {
    return 0  
  }

}

public class JsTypedArray : JsArrayBufferView {
  
  public func getCount(context: JsContext) -> Int {
    assert(false)
    return 0
  }

  public override class func cast(context: JsContext, from value: JavascriptValue) -> JsTypedArray? {
    if _JavascriptTypedArrayCanCast(context.reference, value.reference) == 0 {
      return nil
    }
    return JsTypedArray(reference: value.reference)
  }

  public required init(reference: JavascriptValueRef) {
    super.init(reference: reference)
  }

}

public class JsUInt8Array : JsTypedArray {
  
  public override class func cast(context: JsContext, from value: JavascriptValue) -> JsUInt8Array? {
    if _JavascriptUInt8ArrayCanCast(context.reference, value.reference) == 0 {
      return nil
    }
    return JsUInt8Array(reference: value.reference)
  }

  public init(context: JsContext, buffer: JsArrayBuffer, offset: Int, length: Int) {
    // temporary hack: remove once implemented
    let nullValue = _JavascriptValueCreateNull(context.reference)
    super.init(reference: nullValue!)
  }

  public required init(reference: JavascriptValueRef) {
    super.init(reference: reference)
  }

}

public class JsUInt8ClampedArray : JsTypedArray {

  public override class func cast(context: JsContext, from value: JavascriptValue) -> JsUInt8ClampedArray? {
    if _JavascriptUInt8ClampedArrayCanCast(context.reference, value.reference) == 0 {
      return nil
    }
    return JsUInt8ClampedArray(reference: value.reference)
  }

  public init(context: JsContext, buffer: JsArrayBuffer, offset: Int, length: Int) {
    // temporary hack: remove once implemented
    let nullValue = _JavascriptValueCreateNull(context.reference)
    super.init(reference: nullValue!)
  }

  public required init(reference: JavascriptValueRef) {
    super.init(reference: reference)
  }

}

public class JsInt8Array : JsTypedArray {

  public init(context: JsContext, buffer: JsArrayBuffer, offset: Int, length: Int) {
    // temporary hack: remove once implemented
    let nullValue = _JavascriptValueCreateNull(context.reference)
    super.init(reference: nullValue!)
  }

  public override class func cast(context: JsContext, from value: JavascriptValue) -> JsInt8Array? {
    if _JavascriptInt8ArrayCanCast(context.reference, value.reference) == 0 {
      return nil
    }
    return JsInt8Array(reference: value.reference)
  }

  public required init(reference: JavascriptValueRef) {
    super.init(reference: reference)
  }

}

public class JsUInt16Array : JsTypedArray {

  public init(context: JsContext, buffer: JsArrayBuffer, offset: Int, length: Int) {
    // temporary hack: remove once implemented
    let nullValue = _JavascriptValueCreateNull(context.reference)
    super.init(reference: nullValue!)  
  }
  
  public override class func cast(context: JsContext, from value: JavascriptValue) -> JsUInt16Array? {
    if _JavascriptUInt16ArrayCanCast(context.reference, value.reference) == 0 {
      return nil
    }
    return JsUInt16Array(reference: value.reference)
  }

  public required init(reference: JavascriptValueRef) {
    super.init(reference: reference)
  }

}

public class JsInt16Array : JsTypedArray {

  public override class func cast(context: JsContext, from value: JavascriptValue) -> JsInt16Array? {
    if _JavascriptInt16ArrayCanCast(context.reference, value.reference) == 0 {
      return nil
    }
    return JsInt16Array(reference: value.reference)
  }

  public init(context: JsContext, buffer: JsArrayBuffer, offset: Int, length: Int) {
    // temporary hack: remove once implemented
    let nullValue = _JavascriptValueCreateNull(context.reference)
    super.init(reference: nullValue!)
  }

  public required init(reference: JavascriptValueRef) {
    super.init(reference: reference)
  }

}

public class JsUInt32Array : JsTypedArray {
  
  public override class func cast(context: JsContext, from value: JavascriptValue) -> JsUInt32Array? {
    if _JavascriptUInt32ArrayCanCast(context.reference, value.reference) == 0 {
      return nil
    }
    return JsUInt32Array(reference: value.reference)
  }

  public init(context: JsContext, buffer: JsArrayBuffer, offset: Int, length: Int) {
    // temporary hack: remove once implemented
    let nullValue = _JavascriptValueCreateNull(context.reference)
    super.init(reference: nullValue!)
  }

  public required init(reference: JavascriptValueRef) {
    super.init(reference: reference) 
  }

}

public class JsInt32Array : JsTypedArray {

  public override class func cast(context: JsContext, from value: JavascriptValue) -> JsInt32Array? {
    if _JavascriptInt32ArrayCanCast(context.reference, value.reference) == 0 {
      return nil
    }
    return JsInt32Array(reference: value.reference)
  }

  public init(context: JsContext, buffer: JsArrayBuffer, offset: Int, length: Int) {
    // temporary hack: remove once implemented
    let nullValue = _JavascriptValueCreateNull(context.reference)
    super.init(reference: nullValue!)
  }

  public required init(reference: JavascriptValueRef) {
    super.init(reference: reference)
  }

}

public class JsFloat32Array : JsTypedArray {

  public override class func cast(context: JsContext, from value: JavascriptValue) -> JsFloat32Array? {
    if _JavascriptFloat32ArrayCanCast(context.reference, value.reference) == 0 {
      return nil
    }
    return JsFloat32Array(reference: value.reference)
  }

  public init(context: JsContext, buffer: JsArrayBuffer, offset: Int, length: Int) {
    // temporary hack: remove once implemented
    let nullValue = _JavascriptValueCreateNull(context.reference)
    super.init(reference: nullValue!)
  }

  public required init(reference: JavascriptValueRef) {
    super.init(reference: reference)
  }

}

public class JsFloat64Array : JsTypedArray {

  public override class func cast(context: JsContext, from value: JavascriptValue) -> JsFloat64Array? {
    if _JavascriptFloat64ArrayCanCast(context.reference, value.reference) == 0 {
      return nil
    }
    return JsFloat64Array(reference: value.reference)
  }

  public init(context: JsContext, buffer: JsArrayBuffer, offset: Int, length: Int) {
    // temporary hack: remove once implemented
    let nullValue = _JavascriptValueCreateNull(context.reference)
    super.init(reference: nullValue!)
  }

  public required init(reference: JavascriptValueRef) {
    super.init(reference: reference)
  }

}

public class JsDataView : JsArrayBufferView {

  public override class func cast(context: JsContext, from value: JavascriptValue) -> JsDataView? {
    if _JavascriptDataViewCanCast(context.reference, value.reference) == 0 {
      return nil
    }
    return JsDataView(reference: value.reference)
  }

  public init(context: JsContext, buffer: JsArrayBuffer, offset: Int, length: Int) {
    // temporary hack: remove once implemented
    let nullValue = _JavascriptValueCreateNull(context.reference)
    super.init(reference: nullValue!)
  }

  public required init(reference: JavascriptValueRef) {
    super.init(reference: reference)
  }

}

public class JsDate : JsObject {
  
  public func getValue(context: JsContext) -> Double {
    return _JavascriptDateGetValue(context.reference, reference)
  }

  public override class func cast(context: JsContext, from value: JavascriptValue) -> JsDate? {
    if _JavascriptDateCanCast(context.reference, value.reference) == 0 {
      return nil
    }
    return JsDate(reference: value.reference)
  }

  public init(context: JsContext, time: Double) {
    let ref = _JavascriptDateCreate(context.reference, time)
    super.init(reference: ref!)
  }

  public required init(reference: JavascriptValueRef) {
    super.init(reference: reference)
  }

}

public class JsNumberObject : JsObject {
  
  public func getValue(context: JsContext) -> Double {
    return _JavascriptNumberObjectGetValue(context.reference, reference)
  }

  public override class func cast(context: JsContext, from value: JavascriptValue) -> JsNumberObject? {
    if _JavascriptNumberObjectCanCast(context.reference, value.reference) == 0 {
      return nil
    }
    return JsNumberObject(reference: value.reference)
  }

  public init(context: JsContext, value: Double) {
    let ref = _JavascriptNumberObjectCreate(context.reference, value)
    super.init(reference: ref!)
  }

  public required init(reference: JavascriptValueRef) {
    super.init(reference: reference)
  }

}

public class JsBooleanObject : JsObject {
  
  public func getValue(context: JsContext) -> Bool {
    return _JavascriptBooleanObjectGetValue(context.reference, reference) == 1
  }

  public override class func cast(context: JsContext, from value: JavascriptValue) -> JsBooleanObject? {
    if _JavascriptBooleanObjectCanCast(context.reference, value.reference) == 0 {
      return nil
    }
    return JsBooleanObject(reference: value.reference)
  }

  public init(context: JsContext, value: Bool) {
    let ref = _JavascriptBooleanObjectCreate(context.reference, value ? 1 : 0)
    super.init(reference: ref!)
  }

  public required init(reference: JavascriptValueRef) {
    super.init(reference: reference)
  }

}

public class JsStringObject : JsObject {
  
  public func getValue(context: JsContext) -> JsString {
    let ref = _JavascriptStringObjectGetValue(context.reference, reference)
    return JsString(reference: ref!)
  }

  public override class func cast(context: JsContext, from value: JavascriptValue) -> JsStringObject? {
    if _JavascriptStringObjectCanCast(context.reference, value.reference) == 0 {
      return nil
    }
    return JsStringObject(reference: value.reference)
  }

  public init(context: JsContext, value: JsString) {
    let ref = _JavascriptStringObjectCreate(context.reference, value.reference)
    super.init(reference: ref!)
  }

  public init(context: JsContext, string: String) {
    var ref: JavascriptValueRef? = nil
    string.withCString { buf in
      ref = _JavascriptStringObjectCreateFromString(context.reference, buf, Int32(string.count))
    }
    super.init(reference: ref!)
  }

  public required init(reference: JavascriptValueRef) {
    super.init(reference: reference)
  }

}

public class JsRegExp : JsObject {

  public func getSource(context: JsContext) -> JsString {
    let ref = _JavascriptRegExpGetSource(context.reference, reference)
    return JsString(reference: ref!)
  }

  public override class func cast(context: JsContext, from value: JavascriptValue) -> JsRegExp? {
    if _JavascriptRegExpCanCast(context.reference, value.reference) == 0 {
      return nil
    }
    return JsRegExp(reference: value.reference)
  }

  public init(context: JsContext, pattern: JsString) {
    let ref = _JavascriptRegExpCreate(context.reference, pattern.reference)
    super.init(reference: ref!)
  }

  public required init(reference: JavascriptValueRef) {
    super.init(reference: reference)
  }

}

public typealias JsAccessorSetterCallback = Int

public protocol JsTemplate {
 func set(context: JsContext, name: String, value: JsData)
 func setNativeDataProperty(context: JsContext, name: JsString, getter: JsAccessorGetterCallback, setter: JsAccessorSetterCallback?)
}

public class JsFunctionTemplate {
  
  public func getFunction(context: JsContext) -> JsFunction? {
    let ref = _JavascriptFunctionTemplateGetFunction(context.reference, reference)
    if ref == nil {
      return nil
    }
    return JsFunction(reference: ref!)
  }

  public func getPrototypeTemplate(context: JsContext) -> JsObjectTemplate {
    let ref = _JavascriptFunctionTemplateGetPrototypeTemplate(context.reference, reference)
    return JsObjectTemplate(reference: ref!)
  }

  public func getInstanceTemplate(context: JsContext) -> JsObjectTemplate {
    let ref = _JavascriptFunctionTemplateGetInstanceTemplate(context.reference, reference)
    return JsObjectTemplate(reference: ref!)
  }

  public init(context: JsContext,
              callback: JsFunctionCallback? = nil,
              data: JavascriptValue? = nil) {
    reference =  _JavascriptFunctionTemplateCreate(context.reference)
  }

  public convenience init(context: JsContext) {
    self.init(context: context, callback: nil, data: nil)
  }

  var reference: JsFunctionTemplateRef

  // internal constructor
  init(reference: JsFunctionTemplateRef) {
    self.reference = reference
  }

  deinit {
    _JavascriptFunctionTemplateDestroy(reference)
  }

  public func setCallHandler(context: JsContext, callback: @escaping JsFunctionCallback, data: JavascriptValue?) {
    //_JavascriptFunctionTemplateSetCallHandler(reference, callback, data != nil ? data.reference : nil)
  }

  public func setLength(context: JsContext, lenght: Int) {
    _JavascriptFunctionTemplateSetLength(context.reference, reference, Int32(lenght))
  }

  public func inherit(context: JsContext, parent: JsFunctionTemplate) {
    _JavascriptFunctionTemplateInherit(context.reference, reference, parent.reference)
  }

  public func setClassName(context: JsContext, name: JsString) {
    _JavascriptFunctionTemplateSetClassName(context.reference, reference, name.reference)
  }

  public func setAcceptAnyReceiver(context: JsContext, value: Bool) {
    _JavascriptFunctionTemplateSetAcceptAnyReceiver(context.reference, reference, value ? 1 : 0)
  }

  public func setHiddenPrototype(context: JsContext, value: Bool) {
    _JavascriptFunctionTemplateSetHiddenPrototype(context.reference, reference, value ? 1 : 0)
  }

  public func setReadOnlyPrototype(context: JsContext) {
    _JavascriptFunctionTemplateSetReadOnlyPrototype(context.reference, reference)
  }

  public func removePrototype(context: JsContext) {
    _JavascriptFunctionTemplateRemovePrototype(context.reference, reference)
  }

  public func hasInstance(context: JsContext, object: JavascriptValue) -> Bool {
    return _JavascriptFunctionTemplateHasInstance(context.reference, reference, object.reference) == 0 ? false : true
  }

}

extension JsFunctionTemplate : JsTemplate {
  
  public func set(context: JsContext, name: String, value: JsData) {

  }

  public func setNativeDataProperty(context: JsContext, name: JsString, getter: JsAccessorGetterCallback, setter: JsAccessorSetterCallback?) {

  }

}

public class JsObjectTemplate {
  
  public func getInternalFieldCount(context: JsContext) -> Int {
    return Int(_JavascriptObjectTemplateGetInternalFieldCount(context.reference, reference))
  }

  public func setInternalFieldCount(context: JsContext, count: Int) {
    _JavascriptObjectTemplateSetInternalFieldCount(context.reference, reference, Int32(count))
  }
  
  var reference: JsObjectTemplateRef
  
  public init(context: JsContext, constructor: JsFunctionTemplate?) {
    reference = _JavascriptObjectTemplateCreate(context.reference)
  }

  public convenience init(context: JsContext) {
    self.init(context: context, constructor: nil)
  }

  init(reference: JsObjectTemplateRef) {
    self.reference = reference
  }

  deinit {
    _JavascriptObjectTemplateDestroy(reference)
  }

  public func setAccessor(context: JsContext) {
    _JavascriptObjectTemplateSetAccessor(context.reference, reference)
  }
  
  public func setHandler(context: JsContext) {
    _JavascriptObjectTemplateSetHandler(context.reference, reference)
  }

  public func setCallAsFunctionHandler(context: JsContext, callback: JsFunctionCallback, data: JavascriptValue?) {
    _JavascriptObjectTemplateSetCallAsFunctionHandler(context.reference, reference)
  }

  public func markAsUndetectable(context: JsContext) {
    _JavascriptObjectTemplateMarkAsUndetectable(context.reference, reference)
  }

  public func setAccessCheckCallback(context: JsContext) {
    _JavascriptObjectTemplateSetAccessCheckCallback(context.reference, reference)
  }
}

extension JsObjectTemplate : JsTemplate {
  
  public func set(context: JsContext, name: String, value: JsData) {

  }

  public func setNativeDataProperty(context: JsContext, name: JsString, getter: JsAccessorGetterCallback, setter: JsAccessorSetterCallback?) {
    
  }

}

public class JsSignature {
  
  public init(context: JsContext, receiver: JsFunctionTemplate? = nil) {
    
  }

}