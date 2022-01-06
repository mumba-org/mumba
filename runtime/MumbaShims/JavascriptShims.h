// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_RUNTIME_MUMBA_SHIMS_Javascript_SHIMS_H_
#define MUMBA_RUNTIME_MUMBA_SHIMS_Javascript_SHIMS_H_

#include "Globals.h"
#include "EngineShims.h"

typedef void* JavascriptContextRef;
typedef void* JavascriptScriptRef;
typedef void* JavascriptScriptOriginRef;
typedef void* JavascriptSourceScriptRef;
typedef void* JavascriptDataRef;
typedef void* JavascriptFunctionTemplateRef;
typedef void* JavascriptObjectTemplateRef;
typedef void* JavascriptFunctionCallbackInfoRef;

typedef void(*CJsAccessorGetterCallback)(JavascriptDataRef);
typedef void(*CJsAccessorSetterCallback)(JavascriptDataRef, JavascriptDataRef);
typedef void(*CJsFunctionCallback)(JavascriptFunctionCallbackInfoRef info);

// JsEngine
// EXPORT JsEngineRef _JavascriptEngineCreate();
// EXPORT int _JavascriptEngineInit(JsEngineRef engine);
// EXPORT void _JavascriptEngineShutdown(JsEngineRef engine);
// EXPORT JavascriptContextRef _JavascriptEngineCreateContext(JsEngineRef engine);
// EXPORT JsEngineRef _JavascriptEngineGetCurrent();

// JsContext
EXPORT JavascriptContextRef _JavascriptContextGetCurrent();
// no runtime dependable (external runtime)
//EXPORT JavascriptContextRef _JavascriptContextCreateFromModuleContext(ModuleContextRef module);
EXPORT void _JavascriptContextDestroy(JavascriptContextRef context);
EXPORT JavascriptDataRef _JavascriptContextGetGlobal(JavascriptContextRef context);
//EXPORT JavascriptScriptRef _JavascriptContextParseScriptUTF8(JavascriptContextRef context, const char* source);
//EXPORT JavascriptDataRef _JavascriptContextExecuteScript(JavascriptContextRef context, JavascriptScriptRef source);
EXPORT JavascriptDataRef _JavascriptContextParseAndRunUTF8(JavascriptContextRef context, const char* source, int len);

// JsData
EXPORT void _JavascriptDataDestroy(JavascriptDataRef handle);

// JsValue
EXPORT int _JavascriptValueIsUndefined(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT int _JavascriptValueIsNull(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT int _JavascriptValueIsTrue(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT int _JavascriptValueIsFalse(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT int _JavascriptValueIsName(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT int _JavascriptValueIsSymbol(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT int _JavascriptValueIsString(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT int _JavascriptValueIsFunction(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT int _JavascriptValueIsArray(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT int _JavascriptValueIsObject(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT int _JavascriptValueIsBool(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT int _JavascriptValueIsNumber(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT int _JavascriptValueIsInt32(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT int _JavascriptValueIsUInt32(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT int _JavascriptValueIsDate(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT int _JavascriptValueIsMap(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT int _JavascriptValueIsSet(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT int _JavascriptValueIsArgumentsObject(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT int _JavascriptValueIsBooleanObject(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT int _JavascriptValueIsNumberObject(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT int _JavascriptValueIsStringObject(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT int _JavascriptValueIsSymbolObject(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT int _JavascriptValueIsNativeError(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT int _JavascriptValueIsRegExp(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT int _JavascriptValueIsGeneratorFunction(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT int _JavascriptValueIsGeneratorObject(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT int _JavascriptValueIsPromise(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT int _JavascriptValueIsMapIterator(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT int _JavascriptValueIsSetIterator(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT int _JavascriptValueIsWeakMap(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT int _JavascriptValueIsWeakSet(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT int _JavascriptValueIsArrayBuffer(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT int _JavascriptValueIsArrayBufferView(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT int _JavascriptValueIsTypedArray(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT int _JavascriptValueIsUInt8Array(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT int _JavascriptValueIsUInt8ClampedArray(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT int _JavascriptValueIsInt8Array(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT int _JavascriptValueIsUInt16Array(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT int _JavascriptValueIsInt16Array(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT int _JavascriptValueIsUInt32Array(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT int _JavascriptValueIsInt32Array(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT int _JavascriptValueIsFloat32Array(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT int _JavascriptValueIsFloat64Array(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT int _JavascriptValueIsDataView(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT int _JavascriptValueIsSharedArrayBuffer(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT int _JavascriptValueIsEqual(JavascriptContextRef context, JavascriptDataRef left, JavascriptDataRef right);
EXPORT JavascriptDataRef _JavascriptValueCreateNull(JavascriptContextRef context);
EXPORT JavascriptDataRef _JavascriptValueCreateUndefined(JavascriptContextRef context);
// NOTE: is the caller responsabilty to free the returned buffer
EXPORT char* _JavascriptValueToString(JavascriptContextRef context, JavascriptDataRef handle, int* out_len);

// JsBoolean
EXPORT int _JavascriptBooleanCanCast(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT int _JavascriptBooleanGetValue(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT JavascriptDataRef _JavascriptBooleanNew(JavascriptContextRef context, int value);

// JsName
EXPORT int _JavascriptNameGetIdentityHash(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT int _JavascriptNameCanCast(JavascriptContextRef context, JavascriptDataRef handle);

// JsString
EXPORT const char* _JavascriptStringGetValue(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT int _JavascriptStringGetLenght(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT int _JavascriptStringUTF8Length(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT int _JavascriptStringIsOneByte(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT int _JavascriptStringContainsOnlyOneByte(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT int _JavascriptStringCanCast(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT JavascriptDataRef _JavascriptStringCreateFromCString(JavascriptContextRef context, const char* string, int lenght);
EXPORT int _JavascriptStringWrite(JavascriptContextRef context, JavascriptDataRef handle, uint16_t* buffer, int start, int length);
EXPORT int _JavascriptStringWriteOneByte(JavascriptContextRef context, JavascriptDataRef handle, uint8_t* buffer, int start, int length);
EXPORT int _JavascriptStringWriteUTF8(JavascriptContextRef context, JavascriptDataRef handle, char* buffer, int length);
     
// JsNumber
EXPORT double _JavascriptNumberGetValue(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT int _JavascriptNumberCanCast(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT JavascriptDataRef _JavascriptNumberNew(JavascriptContextRef context, double value);

// JsInteger
EXPORT int64_t _JavascriptIntegerGetValue(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT int _JavascriptIntegerCanCast(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT JavascriptDataRef _JavascriptIntegerNew(JavascriptContextRef context, int64_t value);

// JsInt32
EXPORT int _JavascriptInt32GetValue(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT int _JavascriptInt32CanCast(JavascriptContextRef context, JavascriptDataRef handle);

// JsUInt32
EXPORT uint32_t _JavascriptUInt32GetValue(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT int _JavascriptUInt32CanCast(JavascriptContextRef context, JavascriptDataRef handle);

// JsObject
EXPORT int _JavascriptObjectGetIdentityHash(JavascriptContextRef context, JavascriptDataRef handle); 
EXPORT int _JavascriptObjectIsCallable(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT JavascriptDataRef _JavascriptObjectGetPropertyNames(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT JavascriptDataRef _JavascriptObjectGetPrototype(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT JavascriptDataRef _JavascriptObjectGetObjectProtoString(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT JavascriptDataRef _JavascriptObjectGetConstructorName(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT int _JavascriptObjectGetInternalFieldCount(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT int _JavascriptObjectCanCast(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT int _JavascriptObjectCreateDataProperty(JavascriptContextRef context, JavascriptDataRef handle, JavascriptDataRef key, JavascriptDataRef value);
EXPORT int _JavascriptObjectCreateDataPropertyByIndex(JavascriptContextRef context, JavascriptDataRef handle, int index, JavascriptDataRef value);
EXPORT JavascriptDataRef _JavascriptObjectGetProperty(JavascriptContextRef context, JavascriptDataRef handle, JavascriptDataRef key);
EXPORT JavascriptDataRef _JavascriptObjectGetPropertyByIndex(JavascriptContextRef context, JavascriptDataRef handle, int index);
EXPORT int _JavascriptObjectSetProperty(JavascriptDataRef context, JavascriptDataRef handle, JavascriptDataRef key, JavascriptDataRef value);
EXPORT int _JavascriptObjectSetPropertyByIndex(JavascriptContextRef context, JavascriptDataRef handle, int index, JavascriptDataRef value);
EXPORT int _JavascriptObjectHasProperty(JavascriptContextRef context, JavascriptDataRef handle, JavascriptDataRef key);
EXPORT int _JavascriptObjectHasPropertyByIndex(JavascriptContextRef context, JavascriptDataRef handle, int index);
EXPORT int _JavascriptObjectDeleteProperty(JavascriptContextRef context, JavascriptDataRef handle, JavascriptDataRef key);
EXPORT int _JavascriptObjectDeletePropertyByIndex(JavascriptContextRef context, JavascriptDataRef handle, int index);
EXPORT JavascriptDataRef _JavascriptObjectFindInstanceInPrototypeChain(JavascriptContextRef context, JavascriptDataRef handle, JavascriptFunctionTemplateRef templ);
EXPORT JavascriptDataRef _JavascriptObjectGetInternalField(JavascriptContextRef context, JavascriptDataRef handle, int index);
EXPORT void _JavascriptObjectSetInternalField(JavascriptContextRef context, JavascriptDataRef handle, int index, JavascriptDataRef value);
EXPORT int _JavascriptObjectHasOwnProperty(JavascriptContextRef context, JavascriptDataRef handle, JavascriptDataRef key);
EXPORT int _JavascriptObjectHasRealNamedProperty(JavascriptContextRef context, JavascriptDataRef handle, JavascriptDataRef key);
EXPORT int _JavascriptObjectHasRealIndexedProperty(JavascriptContextRef context, JavascriptDataRef handle, int index);
EXPORT int _JavascriptObjectHasRealNamedCallbackProperty(JavascriptContextRef context, JavascriptDataRef handle, JavascriptDataRef key);
EXPORT JavascriptDataRef _JavascriptObjectGetRealNamedPropertyInPrototypeChain(JavascriptContextRef context, JavascriptDataRef handle, JavascriptDataRef key);
EXPORT JavascriptDataRef _JavascriptObjectGetRealNamedProperty(JavascriptContextRef context, JavascriptDataRef handle, JavascriptDataRef key);
EXPORT int _JavascriptObjectHasNamedLookupInterceptor(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT int _JavascriptObjectHasIndexedLookupInterceptor(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT JavascriptDataRef _JavascriptObjectCallAsFunction(JavascriptContextRef context, JavascriptDataRef handle, JavascriptDataRef recv, int argc, JavascriptDataRef* argv);
EXPORT JavascriptDataRef _JavascriptObjectCallAsConstructor(JavascriptContextRef context, JavascriptDataRef handle, int argc, JavascriptDataRef* argv);
EXPORT JavascriptDataRef _JavascriptObjectClone(JavascriptContextRef context, JavascriptDataRef handle);

// JsMap
EXPORT int _JavascriptArrayCount(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT int _JavascriptArrayCanCast(JavascriptContextRef context, JavascriptDataRef handle);
//EXPORT JavascriptDataRef _JavascriptArrayCloneElementAt(JavascriptDataRef context, JavascriptDataRef handle, int index);

// JsMap
EXPORT int _JavascriptMapCount(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT int _JavascriptMapCanCast(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT JavascriptDataRef _JavascriptMapGetProperty(JavascriptContextRef context, JavascriptDataRef handle, JavascriptDataRef key);
EXPORT JavascriptDataRef _JavascriptMapSetProperty(JavascriptContextRef context, JavascriptDataRef handle, JavascriptDataRef key, JavascriptDataRef value);
EXPORT int _JavascriptMapHasProperty(JavascriptContextRef context, JavascriptDataRef handle, JavascriptDataRef key);
EXPORT int _JavascriptMapDeleteProperty(JavascriptContextRef context, JavascriptDataRef handle, JavascriptDataRef key);
EXPORT void _JavascriptMapClear(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT JavascriptDataRef _JavascriptMapAsArray(JavascriptContextRef context, JavascriptDataRef handle);

// JsSet
EXPORT int _JavascriptSetCount(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT int _JavascriptSetCanCast(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT JavascriptDataRef _JavascriptSetAdd(JavascriptContextRef context,  JavascriptDataRef handle, JavascriptDataRef key);
EXPORT int _JavascriptSetHasProperty(JavascriptContextRef context,  JavascriptDataRef handle, JavascriptDataRef key);
EXPORT int _JavascriptSetDeleteProperty(JavascriptContextRef context,  JavascriptDataRef handle, JavascriptDataRef key);
EXPORT void _JavascriptSetClear(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT JavascriptDataRef _JavascriptSetAsArray(JavascriptContextRef context, JavascriptDataRef handle);

EXPORT int _JavascriptFunctionCallbackInfoGetLength(JavascriptContextRef context, JavascriptFunctionCallbackInfoRef handle);
EXPORT JavascriptDataRef _JavascriptFunctionCallbackInfoGetThis(JavascriptContextRef context, JavascriptFunctionCallbackInfoRef handle);
EXPORT JavascriptDataRef _JavascriptFunctionCallbackInfoGetHolder(JavascriptContextRef context, JavascriptFunctionCallbackInfoRef handle);
EXPORT int _JavascriptFunctionCallbackInfoIsConstructorCall(JavascriptContextRef context, JavascriptFunctionCallbackInfoRef handle);
EXPORT JavascriptDataRef _JavascriptFunctionCallbackInfoGetData(JavascriptContextRef context, JavascriptFunctionCallbackInfoRef handle);
EXPORT JavascriptDataRef _JavascriptFunctionCallbackInfoGetReturnValue(JavascriptContextRef context, JavascriptFunctionCallbackInfoRef handle);
EXPORT JavascriptDataRef _JavascriptFunctionCallbackInfoGetValueAt(JavascriptContextRef context, JavascriptFunctionCallbackInfoRef handle, int index);

// JsFunction
EXPORT JavascriptDataRef _JavascriptFunctionCreate(JavascriptContextRef context, const char* name, int name_len, void* state, void(*callback)(void*, JavascriptFunctionCallbackInfoRef));
EXPORT JavascriptDataRef _JavascriptFunctionCreateInstance(JavascriptContextRef context, JavascriptDataRef handle, int argc, JavascriptDataRef* argv);
EXPORT JavascriptDataRef _JavascriptFunctionGetName(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT JavascriptDataRef _JavascriptFunctionGetInferredName(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT int _JavascriptFunctionGetScriptLineNumber(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT int _JavascriptFunctionGetScriptColumnNumber(JavascriptContextRef context, JavascriptDataRef handle);
//EXPORT int _JavascriptFunctionIsBuiltin(JavascriptDataRef handle);
EXPORT int _JavascriptFunctionGetScriptId(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT JavascriptDataRef _JavascriptFunctionGetDisplayName(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT JavascriptDataRef _JavascriptFunctionGetBoundFunction(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT int _JavascriptFunctionCanCast(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT JavascriptDataRef _JavascriptFunctionCall(JavascriptContextRef context, JavascriptDataRef handle, JavascriptDataRef recv, int argc, JavascriptDataRef* argv);
EXPORT void _JavascriptFunctionSetName(JavascriptContextRef context, JavascriptDataRef handle, JavascriptDataRef name);
EXPORT JavascriptScriptOriginRef _JavascriptFunctionGetScriptOrigin(JavascriptContextRef context, JavascriptDataRef handle);

// JsPromisse
EXPORT int _JavascriptPromiseCanCast(JavascriptContextRef context, JavascriptDataRef handle);

// JsArrayBuffer
EXPORT int _JavascriptArrayBufferCanCast(JavascriptContextRef context, JavascriptDataRef handle);

// JsArrayBufferView
EXPORT int _JavascriptArrayBufferViewCanCast(JavascriptContextRef context, JavascriptDataRef handle);

// JsTypedArray
EXPORT int _JavascriptTypedArrayCanCast(JavascriptContextRef context, JavascriptDataRef handle);

// JsUInt8Array
EXPORT int _JavascriptUInt8ArrayCanCast(JavascriptContextRef context, JavascriptDataRef handle);

// JsUInt8ClampedArray
EXPORT int _JavascriptUInt8ClampedArrayCanCast(JavascriptContextRef context, JavascriptDataRef handle);

// JsInt8Array
EXPORT int _JavascriptInt8ArrayCanCast(JavascriptContextRef context, JavascriptDataRef handle);

// JsUInt64Array
EXPORT int _JavascriptUInt16ArrayCanCast(JavascriptContextRef context, JavascriptDataRef handle);

// JsInt64Array
EXPORT int _JavascriptInt16ArrayCanCast(JavascriptContextRef context, JavascriptDataRef handle);

// JsUInt32Array
EXPORT int _JavascriptUInt32ArrayCanCast(JavascriptContextRef context, JavascriptDataRef handle);

// JsInt32
EXPORT int _JavascriptInt32ArrayCanCast(JavascriptContextRef context, JavascriptDataRef handle);

// JsFloat32
EXPORT int _JavascriptFloat32ArrayCanCast(JavascriptContextRef context, JavascriptDataRef handle);

// JsFloat64
EXPORT int _JavascriptFloat64ArrayCanCast(JavascriptContextRef context, JavascriptDataRef handle);

// JsDataView
EXPORT int _JavascriptDataViewCanCast(JavascriptContextRef context, JavascriptDataRef handle);

// JsDate
EXPORT double _JavascriptDateGetValue(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT int _JavascriptDateCanCast(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT JavascriptDataRef _JavascriptDateCreate(JavascriptContextRef context, double value);

// JsNumberObject
EXPORT double _JavascriptNumberObjectGetValue(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT int _JavascriptNumberObjectCanCast(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT JavascriptDataRef _JavascriptNumberObjectCreate(JavascriptContextRef context, double value);

// JsBooleanObject
EXPORT int _JavascriptBooleanObjectGetValue(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT int _JavascriptBooleanObjectCanCast(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT JavascriptDataRef _JavascriptBooleanObjectCreate(JavascriptContextRef context, int value);

// JsStringObject
EXPORT JavascriptDataRef _JavascriptStringObjectGetValue(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT int _JavascriptStringObjectCanCast(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT JavascriptDataRef _JavascriptStringObjectCreate(JavascriptContextRef context, JavascriptDataRef string);
EXPORT JavascriptDataRef _JavascriptStringObjectCreateFromString(JavascriptContextRef context, const char* value, int len);

// JsRegexp
EXPORT JavascriptDataRef _JavascriptRegExpGetSource(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT int _JavascriptRegExpCanCast(JavascriptContextRef context, JavascriptDataRef handle);
EXPORT JavascriptDataRef _JavascriptRegExpCreateFromString(JavascriptContextRef context, const char* pattern, int len);
EXPORT JavascriptDataRef _JavascriptRegExpCreate(JavascriptContextRef context, JavascriptDataRef pattern);

// JsFunctionTemplate
EXPORT JavascriptFunctionTemplateRef _JavascriptFunctionTemplateCreate(JavascriptContextRef context);
EXPORT void _JavascriptFunctionTemplateDestroy(JavascriptFunctionTemplateRef handle);
EXPORT void _JavascriptFunctionTemplateSet(JavascriptContextRef context, JavascriptFunctionTemplateRef handle, const char* name, JavascriptDataRef value);
EXPORT void _JavascriptFunctionTemplateSetNativeDataProperty(JavascriptContextRef context, JavascriptFunctionTemplateRef handle, JavascriptDataRef name, CJsAccessorGetterCallback getter, CJsAccessorSetterCallback setter);

EXPORT JavascriptDataRef _JavascriptFunctionTemplateGetFunction(JavascriptContextRef context, JavascriptFunctionTemplateRef handle);
EXPORT JavascriptObjectTemplateRef _JavascriptFunctionTemplateGetPrototypeTemplate(JavascriptContextRef context, JavascriptFunctionTemplateRef handle);
EXPORT JavascriptObjectTemplateRef _JavascriptFunctionTemplateGetInstanceTemplate(JavascriptContextRef context, JavascriptFunctionTemplateRef handle);
EXPORT void _JavascriptFunctionTemplateSetCallHandler(JavascriptContextRef context, JavascriptFunctionTemplateRef handle, CJsFunctionCallback callback, JavascriptDataRef data);
EXPORT void _JavascriptFunctionTemplateSetLength(JavascriptContextRef context, JavascriptFunctionTemplateRef handle, int lenght);
EXPORT void _JavascriptFunctionTemplateInherit(JavascriptContextRef context, JavascriptFunctionTemplateRef handle, JavascriptFunctionTemplateRef parent);
EXPORT void _JavascriptFunctionTemplateSetClassName(JavascriptContextRef context, JavascriptFunctionTemplateRef handle, JavascriptDataRef name);
EXPORT void _JavascriptFunctionTemplateSetAcceptAnyReceiver(JavascriptContextRef context, JavascriptFunctionTemplateRef handle, int value);
EXPORT void _JavascriptFunctionTemplateSetHiddenPrototype(JavascriptContextRef context, JavascriptFunctionTemplateRef handle, int value);
EXPORT void _JavascriptFunctionTemplateSetReadOnlyPrototype(JavascriptContextRef context, JavascriptFunctionTemplateRef handle);
EXPORT void _JavascriptFunctionTemplateRemovePrototype(JavascriptContextRef context, JavascriptFunctionTemplateRef handle);
EXPORT int _JavascriptFunctionTemplateHasInstance(JavascriptContextRef context, JavascriptFunctionTemplateRef handle, JavascriptDataRef object);

// JsObjectTemplate
EXPORT JavascriptObjectTemplateRef _JavascriptObjectTemplateCreate(JavascriptContextRef context);
EXPORT void _JavascriptObjectTemplateDestroy(JavascriptObjectTemplateRef handle);
EXPORT void _JavascriptObjectTemplateSet(JavascriptContextRef context, JavascriptObjectTemplateRef handle, const char* name, JavascriptDataRef value);
EXPORT void _JavascriptObjectTemplateSetNativeDataProperty(JavascriptContextRef context, JavascriptObjectTemplateRef handle, JavascriptDataRef name, CJsAccessorGetterCallback getter, CJsAccessorSetterCallback setter);

EXPORT int _JavascriptObjectTemplateGetInternalFieldCount(JavascriptContextRef context, JavascriptObjectTemplateRef handle);
EXPORT void _JavascriptObjectTemplateSetInternalFieldCount(JavascriptContextRef context, JavascriptObjectTemplateRef handle, int count);
EXPORT void _JavascriptObjectTemplateSetAccessor(JavascriptContextRef context, JavascriptObjectTemplateRef handle);
EXPORT void _JavascriptObjectTemplateSetHandler(JavascriptContextRef context, JavascriptObjectTemplateRef handle);
EXPORT void _JavascriptObjectTemplateSetCallAsFunctionHandler(JavascriptContextRef context, JavascriptObjectTemplateRef handle);
EXPORT void _JavascriptObjectTemplateMarkAsUndetectable(JavascriptContextRef context, JavascriptObjectTemplateRef handle);
EXPORT void _JavascriptObjectTemplateSetAccessCheckCallback(JavascriptContextRef context, JavascriptObjectTemplateRef handle);

EXPORT JavascriptDataRef _JavascriptModuleImport(JavascriptContextRef context, const char* name);

EXPORT JavascriptDataRef _WasmCompiledModuleDeserializeOrCompile(JavascriptContextRef context, const uint8_t* serialized_bytes, int serialized_bytes_size, const uint8_t* raw_bytes, int raw_bytes_size);
EXPORT int _JavascriptContextExecuteWasm(JavascriptContextRef context, JavascriptDataRef module, const char* func, int argc, char** argv);
EXPORT int _JavascriptContextExecuteWasmMain(JavascriptContextRef context, JavascriptDataRef module);

#endif