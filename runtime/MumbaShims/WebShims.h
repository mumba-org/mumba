// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_RUNTIME_MUMBA_SHIMS_WEB_SHIMS_H_
#define MUMBA_RUNTIME_MUMBA_SHIMS_WEB_SHIMS_H_

//#include <limits.h>

#include "Globals.h"
#include "SkiaShims.h"
#include "JavascriptShims.h"
#include "ApplicationHandler.h"
#include "WebDefinitions.h"
// WebKit api relies a lot on stack allocation
// with inner pointers to the real objects
// so this force us to use a more exoteric approach

typedef void* WebNodeRef;
typedef void* WebFrameRef;
typedef void* WebWidgetRef;
typedef void* WebFrameWidgetRef;
typedef void* WebWidgetClientRef;
typedef void* WebAXObjectRef;
typedef void* WebEventRef;
typedef void* WebInputEventRef;
typedef void* HTMLCollectionRef;
typedef void* WebElementArrayRef;
typedef void* WebHitTestResultRef;
typedef void* WebDragDataRef;
typedef void* WebDataRef;
typedef void* WebPagePopupRef;
typedef void* WebSettingsRef;
typedef void* NPObjectRef;
typedef void* WebPerformanceRef;
typedef void* WebSecurityOriginRef;
typedef void* WebSharedWorkerRepositoryClientRef;
typedef void* WebURLRequestRef;
typedef void* WebURLLoaderRef;
typedef void* WebURLResponseRef;
typedef void* WebHTTPLoadInfoRef;
typedef void* WebHTTPBodyRef;
typedef void* WebRangeRef;
typedef void* WebHistoryItemRef;
typedef void* WebLayerTreeViewRef;
typedef void* WebStorageNamespaceRef;
typedef void* WebFileChooserCompletionRef;
typedef void* WebDateTimeChooserCompletionRef;
//typedef void* WebSpeechRecognizerRef;
typedef void* WebDataSourceRef;
typedef void* WebURLLoaderRef;
typedef void* WebAssociatedURLLoaderRef;
typedef void* WebDataSourceExtraDataRef;
typedef void* WebUSBClientRef;
typedef void* WebBluetoothRef;
typedef void* WebAppBannerClientRef;
typedef void* WebVRClientRef;
typedef void* WebPermissionClientRef;
//typedef void* WebScreenOrientationClientRef;
typedef void* WebMIDIClientRef;
typedef void* WebEncryptedMediaClientRef;
typedef void* WebUserMediaClientRef;
typedef void* WebGeolocationClientRef;
typedef void* WebWakeLockClientRef;
typedef void* WebColorChooserRef;
//typedef void* WebPresentationClientRef;
typedef void* WebPushClientRef;
typedef void* WebCookieJarRef;
typedef void* WebExternalPopupMenuRef;
typedef void* WebWorkerContentSettingsClientProxyRef;
typedef void* WebServiceWorkerProviderRef;
typedef void* WebApplicationCacheHostRef;
typedef void* WebMediaSessionRef;
typedef void* WebMediaPlayerRef;
typedef void* WebPluginRef;
typedef void* WebMediaPlayerEncryptedMediaClientRef;
typedef void* WebApplicationCacheHostClientRef;
typedef void* WebExternalPopupMenuClientRef;
//typedef void* WebColorChooserClientRef;
typedef void* WebSocketHandleRef;
typedef void* WebContextMenuDataRef;
typedef void* WebStorageQuotaCallbacksRef;
typedef void* WebContentDecryptionModuleRef;
typedef void* WebRTCPeerConnectionHandlerRef;
typedef void* WebNotificationPermissionCallbackRef;
typedef void* WebDOMMessageEventRef;
typedef void* WebDOMEventRef;
typedef void* WebFrameClientRef;
typedef void* WebAutofillClientRef;
typedef void* WebAutofillClientRef;
typedef void* WebDevToolsAgentClientRef;
typedef void* WebDevToolsAgentRef;
typedef void* WebScriptExecutionCallbackRef;
typedef void* WebSuspendableTaskRef;
typedef void* WebContentSettingsClientRef;
typedef void* WebAppBannerPromptReplyRef;
typedef void* WebCompositedDisplayListRef;
typedef void* WebPageImportanceSignalsRef;
typedef void* WebPluginContainerRef;
typedef void* WebContentSettingCallbacksRef;
typedef void* WebBlameContextRef;
typedef void* WebInterfaceProviderRef;
typedef void* WebAssociatedInterfaceProviderRef;
typedef void* WebDocumentLoaderRef;
typedef void* WebInterfaceRegistryRef;
typedef void* WebServiceWorkerNetworkProviderRef;
typedef void* WebSelectorQueryRef;
typedef void* CSSStyleSheetRef;
typedef void* CSSRuleListRef;
typedef void* CSSRuleRef;
typedef void* CSSStyleSheetListRef;
typedef void* PaintImageRef;
typedef void* StyleSheetContentsRef;
typedef void* CanvasRenderingContext2dRef;
typedef void* PaintCanvasRenderingContext2dRef;
typedef void* WebImageBitmapRef;
typedef void* XMLHttpRequestRef;
typedef void* DOMArrayBufferRef;
typedef void* BlobRef;
typedef void* BlobDataHandleRef;
typedef void* BlobDataRef;
typedef void* ExecutionContextRef;
typedef void* WebSelectionRef;
typedef void* WebFrameSelectionRef;
typedef void* WebFrameCaretRef;
typedef void* WebInputMethodControllerRef;
typedef void* WebEditorRef;
typedef void* WebMediaPlayerClientRef;
typedef void* WebMediaStreamDescriptorRef;
typedef void* WebMediaStreamComponentRef;
typedef void* MediaSourceRef;
typedef void* SourceBufferRef;

typedef void* AudioTrackRef;
typedef void* VideoTrackRef;
typedef void* TextTrackRef;
typedef void* MediaStreamDescriptorRef;
typedef void* CueTimelineRef;
typedef void* MediaAudioSourceNodeRef;
typedef void* MediaControlsRef;
typedef void* WebMediaPlayerSourceRef;

typedef void* DisplayItemListRef;

typedef void* LayerRef;
typedef void* AnimationHostRef;
typedef void* LayerTreeMutatorRef;
typedef void* LayerTreeHostRef;
typedef void* ImageRef;
typedef void* PaintFlagsRef;
typedef void* PathRef;
typedef void* MatrixRef;
typedef void* PaintTextBlobRef;
typedef void* PaintRecordRef;
typedef void* DOMArrayBufferViewRef;
typedef void* WebGLUniformLocationRef;
typedef void* WebGLProgramRef;
typedef void* WebGLTextureRef;
typedef void* WebGLSamplerRef;
typedef void* WebGLBufferRef;
typedef void* WebGLVertexArrayObjectRef;
typedef void* WebGLShaderRef;
typedef void* WebGLFramebufferRef;
typedef void* WebGLRenderbufferRef;
typedef void* WebGLQueryRef;
typedef void* WebGLSyncRef;
typedef void* WebGLTransformFeedbackRef;
typedef void* WebGLActiveInfoRef;
typedef void* WebGLRenderingContextRef;
typedef void* WebImageDataRef;
typedef void* WebGLShaderPrecisionFormatRef;
typedef void* WebNavigatorRef;
typedef void* WebLocalDomWindowRef;
typedef void* WebServiceWorkerContainerRef;
typedef void* WebServiceWorkerRef;
typedef void* ScriptPromiseRef;
typedef void* WebWorkerRef;
typedef void* WorkletRef;
typedef void* WorkletGlobalScopeRef; 
typedef void* MessageChannelRef;
typedef void* MessagePortRef;
typedef void* OwnedMessagePortRef;
typedef void* SerializedScriptValueRef;
typedef void* OwnedSerializedScriptValueRef;
typedef void* UnpackedSerializedScriptValueRef;
typedef void* WebServiceWorkerRegistrationRef;
typedef void* WebNavigationPreloadManagerRef;
typedef void* ExtendableMessageEventRef;
typedef void* OffscreenCanvasRef;
typedef void* OffscreenCanvasRenderingContext2dRef;
typedef void* FormDataRef;
typedef void* HeadersRef;
typedef void* RequestRef;
typedef void* ResponseRef;
typedef void* ReadableStreamRef;
typedef void* ReadableStreamReaderRef;
typedef void* WritableStreamRef;
typedef void* WritableStreamWriterRef;
typedef void* TransformStreamRef;
typedef void* TransformStreamControllerRef;
// FIXME: convergence with ServiceWorker
typedef void* ServiceWorkerGlobalScopeRef;
typedef void* WebServiceWorkerClientsRef;
typedef void* WebServiceWorkerClientRef;
typedef void* PaintSizeRef;
typedef void* Path2dRef;
typedef void* Path2dOwnedRef;
typedef void* CSSImageValueRef;
typedef void* CanvasGradientRef;
typedef void* CanvasPatternRef;
typedef void* WebImageDataArrayRef;
typedef void* WebImageDataOwnedRef;
typedef void* WebImageBitmapOwnedRef;
typedef void* Uint8ArrayBufferRef;
typedef void* SVGMatrixRef;
typedef void* SVGMatrixOwnedRef;
typedef void* WebSocketRef;
typedef void* LocationRef;

typedef unsigned int   GLenum;
typedef uint8_t        GLboolean;
typedef unsigned int   GLbitfield;
typedef int8_t         GLbyte;
typedef short          GLshort;
typedef int            GLint;
typedef int            GLsizei;
typedef long           GLintptr;
typedef long           GLsizeiptr;
typedef uint8_t        GLubyte;
typedef unsigned short GLushort;
typedef unsigned int  GLuint;
typedef float          GLfloat;
typedef float          GLclampf;
typedef uint64_t       GLuint64;
typedef int64_t        GLint64;

typedef enum {
  WebViewDoNotKeepSelection = 0,
  WebViewKeepSelection = 1,
} WebViewConfirmCompositionBehaviorEnum;

typedef enum {
  WebViewCompositeEvent = 0,
  WebViewRenderEvent = 1,
} WebViewFrameTimingEventEnum;

typedef enum {
  WebEventUndefined = -1,
  WebEventMouseDown,
  WebEventMouseUp,
  WebEventMouseMove,
  WebEventMouseEnter,
  WebEventMouseLeave,
  WebEventContextMenu,
  WebEventMouseWheel,
  WebEventRawKeyDown,
  WebEventKeyDown,
  WebEventKeyUp,
  WebEventChar,
  WebEventGestureScrollBegin,
  WebEventGestureScrollEnd,
  WebEventGestureScrollUpdate,
  WebEventGestureFlingStart,
  WebEventGestureFlingCancel,
  WebEventGestureShowPress,
  WebEventGestureTap,
  WebEventGestureTapUnconfirmed,
  WebEventGestureTapDown,
  WebEventGestureTapCancel,
  WebEventGestureDoubleTap,
  WebEventGestureTwoFingerTap,
  WebEventGestureLongPress,
  WebEventGestureLongTap,
  WebEventGesturePinchBegin,
  WebEventGesturePinchEnd,
  WebEventGesturePinchUpdate,
  WebEventTouchStart,
  WebEventTouchMove,
  WebEventTouchEnd,
  WebEventTouchCancel,
} WebEventEnum;

typedef enum {
  WebEventShiftKey            = 1 << 0,
  WebEventControlKey          = 1 << 1,
  WebEventAltKey              = 1 << 2,
  WebEventMetaKey             = 1 << 3,
  WebEventIsKeyPad            = 1 << 4,
  WebEventIsAutoRepeat        = 1 << 5,
  WebEventLeftButtonDown      = 1 << 6,
  WebEventMiddleButtonDown    = 1 << 7,
  WebEventRightButtonDown     = 1 << 8,
  WebEventCapsLockOn          = 1 << 9,
  WebEventNumLockOn           = 1 << 10,
  WebEventIsLeft              = 1 << 11,
  WebEventIsRight             = 1 << 12,
  WebEventIsTouchAccessibility = 1 << 13,
  WebEventIsComposing         = 1 << 14,
  WebEventAltGrKey            = 1 << 15,
  WebEventOSKey               = 1 << 16,
  WebEventFnKey               = 1 << 17,
  WebEventSymbolKey           = 1 << 18,
  WebEventScrollLockOn        = 1 << 19,
} WebEventModifiersEnum;

typedef enum {
  WebTextDirectionDefault = 0,  // Natural writing direction ("inherit")
  WebTextDirectionLeftToRight = 1,
  WebTextDirectionRightToLeft = 2,
} WebTextDirectionEnum;

typedef enum {
  WebTopControlsShown = 1,
  WebTopControlsHidden = 2,
  WebTopControlsBoth = 3
} WebTopControlsStateEnum;

typedef enum {
  WebDisplayModeUndefined = 0, // User for override setting (ie. not set).
  WebDisplayModeBrowser = 1,
  WebDisplayModeMinimalUi = 2,
  WebDisplayModeStandalone = 3,
  WebDisplayModeFullscreen = 4,
} WebDisplayModeEnum;

typedef enum {
  WebPageVisibilityStateVisible = 0,
  WebPageVisibilityStateHidden = 1,
  WebPageVisibilityStatePrerender = 2,
} WebPageVisibilityStateEnum;

typedef enum {
  WebGestureDeviceUninitialized = 0,
  WebGestureDeviceTouchpad = 1,
  WebGestureDeviceTouchscreen = 2, 
} WebGestureDeviceEnum;

typedef enum {
  WebMediaPlayerActionUnknown = 0,
  WebMediaPlayerActionPlay = 1,
  WebMediaPlayerActionMute = 2,
  WebMediaPlayerActionLoop = 3,
  WebMediaPlayerActionControls = 4
} WebMediaPlayerActionEnum;

typedef enum {
  WebPluginActionUnknown = 0,
  WebPluginActionRotate90Clockwise = 1,
  WebPluginActionRotate90Counterclockwise = 2
} WebPluginActionEnum;

typedef enum {
  WebSelectionBoundTypeCaret = 0, 
  WebSelectionBoundTypeSelectionLeft = 1, 
  WebSelectionBoundTypeSelectionRight = 2
} WebSelectionBoundTypeEnum;

typedef enum {
  WebSelectionTypeNoSelection = 0, 
  WebSelectionTypeCaretSelection = 1, 
  WebSelectionTypeRangeSelection = 2
} WebSelectionTypeEnum;

typedef enum {
  WebDragOperationNone    = 0,
  WebDragOperationCopy    = 1,
  WebDragOperationLink    = 2,
  WebDragOperationGeneric = 4,
  WebDragOperationPrivate = 8,
  WebDragOperationMove    = 16,
  WebDragOperationDelete  = 32,
  WebDragOperationEvery   = UINT_MAX
} WebDragOperationEnum;

typedef enum {
  WebCursorPointer = 0,
  WebCursorCross = 1,
  WebCursorHand = 2,
  WebCursorIBeam = 3,
  WebCursorWait = 4,
  WebCursorHelp = 5,
  WebCursorEastResize = 6,
  WebCursorNorthResize = 7,
  WebCursorNorthEastResize = 8,
  WebCursorNorthWestResize = 9,
  WebCursorSouthResize = 10,
  WebCursorSouthEastResize = 11,
  WebCursorSouthWestResize = 12,
  WebCursorWestResize = 13,
  WebCursorNorthSouthResize = 14,
  WebCursorEastWestResize = 15,
  WebCursorNorthEastSouthWestResize = 16,
  WebCursorNorthWestSouthEastResize = 17,
  WebCursorColumnResize = 18,
  WebCursorRowResize = 19,
  WebCursorMiddlePanning = 20,
  WebCursorEastPanning = 21,
  WebCursorNorthPanning = 22,
  WebCursorNorthEastPanning = 23,
  WebCursorNorthWestPanning = 24,
  WebCursorSouthPanning = 25,
  WebCursorSouthEastPanning = 26,
  WebCursorSouthWestPanning = 27,
  WebCursorWestPanning = 28,
  WebCursorMove = 29,
  WebCursorVerticalText = 30,
  WebCursorCell = 31,
  WebCursorContextMenu = 32,
  WebCursorAlias = 33,
  WebCursorProgress = 34,
  WebCursorNoDrop = 35,
  WebCursorCopy = 36,
  WebCursorNone = 37,
  WebCursorNotAllowed = 38,
  WebCursorZoomIn = 39,
  WebCursorZoomOut = 40,
  WebCursorGrab = 41,
  WebCursorGrabbing = 42,
  WebCursorCustom = 43
} WebCursorEnum;

typedef enum {
    WebTextInputTypeNone = 0,
    WebTextInputTypeText = 1,
    WebTextInputTypePassword = 2,
    WebTextInputTypeSearch = 3,
    WebTextInputTypeEmail = 4,
    WebTextInputTypeNumber = 5,
    WebTextInputTypeTelephone = 6,
    WebTextInputTypeURL = 7,
    WebTextInputTypeDate = 8,
    WebTextInputTypeDateTime = 9,
    WebTextInputTypeDateTimeLocal = 10,
    WebTextInputTypeMonth = 11,
    WebTextInputTypeTime = 12,
    WebTextInputTypeWeek = 13,
    WebTextInputTypeTextArea = 14,
    WebTextInputTypeContentEditable = 15,
    WebTextInputTypeDateTimeField = 16
} WebTextInputTypeEnum;

typedef enum {
    WebSandboxNone = 0,
    WebSandboxNavigation = 1,
    WebSandboxPlugins = 1 << 1,
    WebSandboxOrigin = 1 << 2,
    WebSandboxForms = 1 << 3,
    WebSandboxScripts = 1 << 4,
    WebSandboxTopNavigation = 1 << 5,
    WebSandboxPopups = 1 << 6,
    WebSandboxAutomaticFeatures = 1 << 7,
    WebSandboxPointerLock = 1 << 8,
    WebSandboxDocumentDomain = 1 << 9,
    WebSandboxOrientationLock = 1 << 10,
    WebSandboxPropagatesToAuxiliaryBrowsingContexts = 1 << 11,
    WebSandboxModals = 1 << 12,
    WebSandboxAll = -1
} WebSandboxFlagsEnum;

// from blink::WebFrameOwnerProperties
typedef enum {
  WebScrollingAuto = 0,
  WebScrollingAlwaysOff = 1,
  WebScrollingAlwaysOn = 2
} WebScrollingModeEnum;

typedef enum { 
  WebDetachRemove = 0, 
  WebDetachSwap = 1 
} WebDetachEnum;

typedef enum {
    WebStandardCommit = 0,
    WebBackForwardCommit = 1,
    WebInitialCommitInChildFrame = 2,
    WebHistoryInertCommit = 3
} WebHistoryCommitEnum;

typedef enum {
  WebIconURLInvalid = 0,
  WebIconURLFavicon = 1 << 0,
  WebIconURLTouch = 1 << 1,
  WebIconURLTouchPrecomposed = 1 << 2
} WebIconURLEnum;

typedef enum {
  WebURLRequestUnresolved = -1,
  WebURLRequestVeryLow = 0,
  WebURLRequestLow = 1,
  WebURLRequestMedium = 2,
  WebURLRequestHigh = 3,
  WebURLRequestVeryHigh = 4,
} WebURLRequestPriorityEnum;

typedef enum {
  WebStorageQuotaTypeTemporary = 0,
  WebStorageQuotaTypePersistent = 1,
} WebStorageQuotaTypeEnum;

typedef enum {
  SuddenTerminationBeforeUnloadHandler = 0,
  SuddenTerminationUnloadHandler = 1,
} WebSuddenTerminationDisablerTypeEnum;

typedef enum {
    WebCustomHandlersNew = 0,
    WebCustomHandlersRegistered = 1,
    WebCustomHandlersDeclined = 2
} WebCustomHandlersStateEnum;

typedef enum {
    WebAXEventActiveDescendantChanged = 0,
    WebAXEventAlert,
    WebAXEventAriaAttributeChanged,
    WebAXEventAutocorrectionOccured,
    WebAXEventBlur,
    WebAXEventCheckedStateChanged,
    WebAXEventChildrenChanged,
    WebAXEventDocumentSelectionChanged,
    WebAXEventFocus,
    WebAXEventHide,
    WebAXEventHover,
    WebAXEventInvalidStatusChanged,
    WebAXEventLayoutComplete,
    WebAXEventLiveRegionChanged,
    WebAXEventLoadComplete,
    WebAXEventLocationChanged,
    WebAXEventMenuListItemSelected,
    WebAXEventMenuListItemUnselected,
    WebAXEventMenuListValueChanged,
    WebAXEventRowCollapsed,
    WebAXEventRowCountChanged,
    WebAXEventRowExpanded,
    WebAXEventScrollPositionChanged,
    WebAXEventScrolledToAnchor,
    WebAXEventSelectedChildrenChanged,
    WebAXEventSelectedTextChanged,
    WebAXEventShow,
    WebAXEventTextChanged,
    WebAXEventTextInserted,
    WebAXEventTextRemoved,
    WebAXEventValueChanged
} WebAXEventEnum;

typedef enum {
    WebNavigationTypeLinkClicked = 0,
    WebNavigationTypeFormSubmitted = 1,
    WebNavigationTypeBackForward = 2,
    WebNavigationTypeReload = 3,
    WebNavigationTypeFormResubmitted = 4,
    WebNavigationTypeOther = 5
} WebNavigationTypeEnum;

typedef enum {
    WebHistorySameDocumentLoad = 0,
    WebHistoryDifferentDocumentLoad = 1
} WebHistoryLoadTypeEnum;

typedef enum {
  WebCrossOriginRequestPolicyDeny = 0,
  WebCrossOriginRequestPolicyUseAccessControl = 1,
  WebCrossOriginRequestPolicyAllow = 2
} WebCrossOriginRequestPolicyEnum;

typedef enum {
  WebConsiderPreflight = 0,
  WebForcePreflight = 1,
  WebPreventPreflight = 2
} WebPreflightPolicyEnum;

typedef enum {
  CharacterGranularity = 0,
  WordGranularity = 1
} WebTextGranularityEnum;

typedef enum {
    WebConsoleMessageLevelDebug = 4,
    WebConsoleMessageLevelLog = 1,
    WebConsoleMessageLevelInfo = 5,
    WebConsoleMessageLevelWarning = 2,
    WebConsoleMessageLevelError = 3,
    WebConsoleMessageLevelRevokedError = 6
} WebConsoleMessageLevelEnum;

typedef enum {
    WebPrintScalingOptionNone = 0,
    WebPrintScalingOptionFitToPrintableArea = 1, 
    WebPrintScalingOptionSourceSize = 2
} WebPrintScalingOptionEnum;

typedef enum {
    WebUnknownDuplexMode = -1,
    WebSimplex,
    WebLongEdge,
    WebShortEdge
} WebDuplexModeEnum;

typedef enum {
    WebTreeScopeDocument = 0,
    WebTreeScopeShadow = 1,
} WebTreeScopeEnum;

typedef enum {
    WebFrameLoadStandard = 0,
    WebFrameLoadBackForward = 1,
    WebFrameLoadReload = 2,
    WebFrameLoadSame = 3,
    WebFrameLoadReplaceCurrentItem = 4,
    WebFrameLoadInitialInChildFrame = 5,
    WebFrameLoadInitialHistoryLoad = 6,
    WebFrameLoadReloadBypassingCache = 7, 
} WebFrameLoadEnum;

typedef enum {
  WebURLRequestCachePolicyUseProtocolCachePolicy = 0,
  WebURLRequestCachePolicyReloadIgnoringCacheData = 1,
  WebURLRequestCachePolicyReturnCacheDataElseLoad = 2,
  WebURLRequestCachePolicyReturnCacheDataDontLoad = 3,
  WebURLRequestCachePolicyReloadBypassingCache = 4,
} WebURLRequestCachePolicyEnum;

typedef enum {
    WebDateTimeInputTypeNone,
    WebDateTimeInputTypeDate,
    WebDateTimeInputTypeDateTime,
    WebDateTimeInputTypeDateTimeLocal,
    WebDateTimeInputTypeMonth,
    WebDateTimeInputTypeTime,
    WebDateTimeInputTypeWeek,
} WebDateTimeInputTypeEnum;

typedef enum {
    VisuallyNonEmpty = 0,
    FinishedParsing = 1,
    FinishedLoading = 2
} WebMeaningfulLayoutTypeEnum;

typedef enum {
    WebNavigationPolicyIgnore,
    WebNavigationPolicyDownload,
    WebNavigationPolicyCurrentTab,
    WebNavigationPolicyNewBackgroundTab,
    WebNavigationPolicyNewForegroundTab,
    WebNavigationPolicyNewWindow,
    WebNavigationPolicyNewPopup,
    WebNavigationPolicyHandledByClient,
} WebNavigationPolicyEnum;

typedef enum {
    WebScreenOrientationUndefined = 0,
    WebScreenOrientationPortraitPrimary,
    WebScreenOrientationPortraitSecondary,
    WebScreenOrientationLandscapePrimary,
    WebScreenOrientationLandscapeSecondary
} WebScreenOrientationEnum;

typedef enum {
    WebTouchActionNone = 0x0,
    WebTouchActionPanLeft = 0x1,
    WebTouchActionPanRight = 0x2,
    WebTouchActionPanX = WebTouchActionPanLeft | WebTouchActionPanRight,
    WebTouchActionPanUp = 0x4,
    WebTouchActionPanDown = 0x8,
    WebTouchActionPanY = WebTouchActionPanUp | WebTouchActionPanDown,
    WebTouchActionPan = WebTouchActionPanX | WebTouchActionPanY,
    WebTouchActionPinchZoom = 0x10,
    WebTouchActionManipulation = WebTouchActionPan | WebTouchActionPinchZoom,
    WebTouchActionDoubleTapZoom = 0x20,
    WebTouchActionAuto = WebTouchActionManipulation | WebTouchActionDoubleTapZoom
} WebTouchActionEnum;

typedef enum {
    WebPopupTypeNone = 0,
    WebPopupTypePage = 1
} WebPopupTypeEnum;

typedef enum {
  WebOverscrollBehaviorTypeNone = 0,
  WebOverscrollBehaviorTypeAuto = 1,
  WebOverscrollBehaviorTypeContain = 2
} WebOverscrollBehaviorTypeEnum;

typedef enum {
  WebReferrerPolicyAlways = 0,
  WebReferrerPolicyDefault = 1,
  WebReferrerPolicyNoReferrerWhenDowngrade = 2,
  WebReferrerPolicyNever = 3,
  WebReferrerPolicyOrigin = 4,
  WebReferrerPolicyOriginWhenCrossOrigin = 5,
  WebReferrerPolicyNoReferrerWhenDowngradeOriginWhenCrossOrigin = 6,
  WebReferrerPolicySameOrigin = 7,
  WebReferrerPolicyStrictOrigin = 8
} WebReferrerPolicyEnum;

typedef enum {
  WebEffectiveConnectionTypeUnknown = 0,
  WebEffectiveConnectionTypeOffline = 1,
  WebEffectiveConnectionTypeSlow2G = 2,
  WebEffectiveConnectionType2G = 3,
  WebEffectiveConnectionType3G = 4,
  WebEffectiveConnectionType4G = 5
} WebEffectiveConnectionTypeEnum;

typedef enum {
  WebScriptExecutionTypeSynchronous = 0,
  // Execute script asynchronously.
  WebScriptExecutionTypeAsynchronous = 1,
  // Execute script asynchronously, blocking the window.onload event.
  WebScriptExecutionTypeAsynchronousBlockingOnload = 2
} WebScriptExecutionTypeEnum;

typedef enum {
 WebLifecycleUpdatePrePaint = 0, 
 WebLifecycleUpdateAll = 1
} WebLifecycleUpdateEnum;

typedef enum {
  WebFrameLoadTypeStandard = 0,
  WebFrameLoadTypeBackForward = 1,
  WebFrameLoadTypeReload = 2,
  WebFrameLoadTypeReplaceCurrentItem = 3,
  WebFrameLoadTypeInitialInChildFrame = 4,
  WebFrameLoadTypeInitialHistoryLoad = 5,
  WebFrameLoadTypeReloadBypassingCache = 6,
} WebFrameLoadTypeEnum;

typedef enum { 
  WebClientRedirectNotClientRedirect = 0, 
  WebClientRedirectClientRedirect = 1 
} WebClientRedirectPolicyEnum;

typedef enum {
  WebFocusTypeNone = 0,
  WebFocusTypeForward = 1,
  WebFocusTypeBackward = 2,
  WebFocusTypeUp = 3,
  WebFocusTypeDown = 4,
  WebFocusTypeLeft = 5,
  WebFocusTypeRight = 6,
  WebFocusTypeMouse = 7,
  WebFocusTypePage = 8
} WebFocusTypeEnum;

typedef enum {
  WebEventListenerClassTouchStartOrMove = 0,
  WebEventListenerClassMouseWheel = 1,
  WebEventListenerClassTouchEndOrCancel = 2
} WebEventListenerClassEnum;

typedef enum {
  WebEventListenerPropertiesNothing = 0,
  WebEventListenerPropertiesPassive = 1,
  WebEventListenerPropertiesBlocking = 2,
  WebEventListenerPropertiesBlockingAndPassive = 3
} WebEventListenerPropertiesEnum;

typedef enum {
  WebSwapResultDidSwap = 0,
  WebSwapResultDidNotSwapSwapFails = 1,
  WebSwapResultDidNotSwapCommitFails = 2,
  WebSwapResultDidNotSwapCommitNoUpdate = 3,
  WebSwapResultDidNotSwapActivationFails = 4
} WebSwapResultEnum;

typedef struct {
  void (*SetRootLayer)(void* state, LayerRef web_layer);
  void (*ClearRootLayer)(void* state);
  AnimationHostRef (*CompositorAnimationHost)(void* state);
  LayerTreeHostRef (*GetLayerTreeHost)(void* state);
  void (*GetViewportSize)(void* state, int* w, int* h);
  void (*SetBackgroundColor)(void* state, uint8_t a, uint8_t r, uint8_t g, uint8_t b);
  void (*SetVisible)(void* state, int visible);
  void (*SetPageScaleFactorAndLimits)(void* state, 
                                      float page_scale_factor,
                                      float minimum,
                                      float maximum);
  void (*StartPageScaleAnimation)(void* state,
                                  int px,
                                  int py,
                                  int use_anchor,
                                  float new_page_scale,
                                  double duration_sec);
  int (*HasPendingPageScaleAnimation)(void* state);
  void (*HeuristicsForGpuRasterizationUpdated)(void* state, int);
  void (*SetBrowserControlsShownRatio)(void* state, float);
  void (*UpdateBrowserControlsState)(void* state,
                                     WebTopControlsStateEnum constraints, 
                                     WebTopControlsStateEnum current,
                                     int animate);
  void (*SetBrowserControlsHeight)(void* state,
                                   float top_height,
                                   float bottom_height,
                                   int shrink_viewport);
  void (*SetOverscrollBehavior)(void* state,
    WebOverscrollBehaviorTypeEnum x,
    WebOverscrollBehaviorTypeEnum y);
  void (*SetNeedsBeginFrame)(void* state);
  void (*DidStopFlinging)(void* state);
  void (*LayoutAndPaintAsync)(void* state, void* cb_state, void(*callback)(void*));
  void (*CompositeAndReadbackAsync)(
        void* state,
        void* cb_state,
        void(*callback)(void*, BitmapRef));
  void (*SynchronouslyCompositeNoRasterForTesting)(void* state);
  void (*CompositeWithRasterForTesting)(void* state);
  void (*SetDeferCommits)(void* state, int defer_commits);
  void (*RegisterViewportLayers)(void* state, 
    LayerRef overscroll_elasticity,
    LayerRef page_scale,
    LayerRef inner_viewport_container,
    LayerRef outer_viewport_container,
    LayerRef inner_viewport_scroll,
    LayerRef outer_viewport_scroll);
  void (*ClearViewportLayers)(void* state);
  void (*RegisterSelection)(void* state, 
    WebSelectionTypeEnum type,
    WebSelectionBoundTypeEnum start_bound_type,
    int start_bound_layer_id,
    int start_bound_edge_top_in_layer_x,
    int start_bound_edge_top_in_layer_y,
    int start_bound_edge_bottom_in_layer_x,
    int start_bound_edge_bottom_in_layer_y,
    int start_bound_is_text_direction_rtl,
    int start_bound_hidden,
    WebSelectionBoundTypeEnum end_bound_type,
    int end_bound_layer_id,
    int end_bound_edge_top_in_layer_x,
    int end_bound_edge_top_in_layer_y,
    int end_bound_edge_bottom_in_layer_x,
    int end_bound_edge_bottom_in_layer_y,
    int end_bound_is_text_direction_rtl,
    int end_bound_hidden);
  void (*ClearSelection)(void* state);
  void (*SetMutatorClient)(void* state, LayerTreeMutatorRef mutator);
  void (*ForceRecalculateRasterScales)(void* state);
  void (*SetEventListenerProperties)(void* state, 
                                     WebEventListenerClassEnum,
                                     WebEventListenerPropertiesEnum);
  void (*UpdateEventRectsForSubframeIfNecessary)(void* state);
  void (*SetHaveScrollEventHandlers)(void* state, int);
  void (*GetFrameSinkId)(
    void* state,
    uint32_t* frame_sink_client_id, 
    uint32_t* frame_sink_sink_id);
  WebEventListenerPropertiesEnum (*EventListenerProperties)(
      void* state,
      WebEventListenerClassEnum);
  int (*HaveScrollEventHandlers)(void* state);
  int (*LayerTreeId)(void* state);
  void (*SetShowFPSCounter)(void* state, int);
  void (*SetShowPaintRects)(void* state, int);
  void (*SetShowDebugBorders)(void* state, int);
  void (*SetShowScrollBottleneckRects)(void* state, int);
  void (*NotifySwapTime)(void* state, void* cb_state);
  void (*RequestBeginMainFrameNotExpected)(void* state, int new_state);
  void (*RequestDecode)(void* state,
                        void* cb_state,
                        PaintImageRef image,
                        void(*callback)(void*, int)); 
  void (*GetLayerTreeSettings)(
    void* state,
    int* single_thread_proxy_scheduler,
    int* main_frame_before_activation_enabled,
    int* using_synchronous_renderer_compositor,
    int* enable_early_damage_check,
    int* damaged_frame_limit,
    int* enable_latency_recovery,
    int* can_use_lcd_text,
    int* gpu_rasterization_forced,
    int* gpu_rasterization_msaa_sample_count,
    float* gpu_rasterization_skewport_target_time_in_seconds,
    int* create_low_res_tiling,
    int* use_stream_video_draw_quad,
    int64_t* scrollbar_fade_delay,
    int64_t* scrollbar_fade_duration,
    int64_t* scrollbar_thinning_duration,
    int* scrollbar_flash_after_any_scroll_update,
    int* scrollbar_flash_when_mouse_enter,
    uint8_t* solid_color_scrollbar_color_a,
    uint8_t* solid_color_scrollbar_color_r,
    uint8_t* solid_color_scrollbar_color_g,
    uint8_t* solid_color_scrollbar_color_b,
    int* timeout_and_draw_when_animation_checkerboards,
    int* layer_transforms_should_scale_layer_contents,
    int* layers_always_allowed_lcd_text,
    float* minimum_contents_scale,
    float* low_res_contents_scale_factor,
    float* top_controls_show_threshold,
    float* top_controls_hide_threshold,
    double* background_animation_rate,
    int* default_tile_size_width,
    int* default_tile_size_height,
    int* max_untiled_layer_size_width,
    int* max_untiled_layer_size_height,
    int* max_gpu_raster_tile_size_width,
    int* max_gpu_raster_tile_size_height,
    int* minimum_occlusion_tracking_size_width,
    int* minimum_occlusion_tracking_size_height,
    int* tiling_interest_area_padding,
    float* skewport_target_time_in_seconds,
    int* skewport_extrapolation_limit_in_screen_pixels,
    int* max_memory_for_prepaint_percentage,
    int* use_zero_copy,
    int* use_partial_raster,
    int* enable_elastic_overscroll,
    int* ignore_root_layer_flings,
    int* scheduled_raster_task_limit,
    int* use_occlusion_for_tile_prioritization,
    int* use_layer_lists,
    int* max_staging_buffer_usage_in_bytes,
    int* memory_policy_bytes_limit_when_visible,
    int* memory_policy_priority_cutoff_when_visible,
    int* decoded_image_working_set_budget_bytes,
    int* max_preraster_distance_in_screen_pixels,
    int* use_rgba_4444,
    int* unpremultiply_and_dither_low_bit_depth_tiles,
    int* enable_mask_tiling,
    int* enable_checker_imaging,
    int* min_image_bytes_to_checker,
    int* only_checker_images_with_gpu_raster,
    int* enable_surface_synchronization,
    int* is_layer_tree_for_subframe,
    int* disallow_non_exact_resource_reuse,
    int* wait_for_all_pipeline_stages_before_draw,
    int* commit_to_active_tree,
    int* enable_oop_rasterization,
    int* enable_image_animation_resync,
    int* enable_edge_anti_aliasing,
    int* always_request_presentation_time,
    int* use_painted_device_scale_factor);
} WebLayerTreeViewCbs;

typedef WebDragOperationEnum WebDragOperationsMask;

typedef void (*WebLayoutAndPaintAsyncCallback)();
typedef void (*WebCompositeAndReadbackAsyncCallback)(const void*);

 // WebWidgetClient
 typedef void (*WebViewClientDidInvalidateRectCb)(void* peer, int x, int y, int width, int height);
 typedef void (*WebViewClientDidAutoResizeCb)(void* peer, int width, int height);
 //typedef void (*WebViewClientDidUpdateLayoutSizeCb)(void* peer, int width, int height);
 typedef void (*WebViewClientInitializeLayerTreeViewCb)(void* peer, void** compositor_state_out, WebLayerTreeViewCbs* cbs_out);
 typedef int (*WebViewClientCanHandleGestureEventCb)(void* peer);
 //typedef WebLayerTreeViewRef (*WebViewClientLayerTreeViewCb)(void* peer);
 typedef int (*WebViewClientCanUpdateLayoutCb)(void* peer);
 typedef void (*WebViewClientConvertViewportToWindowCb)(void* peer, int* rx, int* ry, int* rw, int* rh);
 typedef void (*WebViewClientConvertWindowToViewport)(void* peer, float* rx, float* ry, float* rw, float* rh);
 typedef void (*WebViewClientDidOverscrollCb)(void* peer, 
  float overscrollDeltaWidth, float overscrollDeltaHeight, 
  float accumulatedRootOverScrollWidth, float accumulatedRootOverScrollHeight, 
  float posX, float posY, 
  float velocityWidth, float velocityHeight,
  int overscrollBehaviorTypeX, int overscrollBehaviorTypeY);

 typedef void (*WebViewClientScheduleAnimationCb)(void* peer);
 typedef void (*WebViewClientIntrinsicSizingInfoChanged)(void* peer,
   float szw, float szh,
   float arw, float arh,
   int has_width,
   int has_height);
 typedef void (*WebViewClientDidMeaningfulLayoutCb)(void* peer, WebMeaningfulLayoutTypeEnum layout);
 typedef void (*WebViewClientDidFirstLayoutAfterFinishedParsingCb)(void* peer);
 typedef void (*WebViewClientDidFocusCb)(void* peer, WebFrameRef calling_frame);
 //typedef void (*WebViewClientDidBlurCb)(void* peer);
 typedef void (*WebViewClientDidChangeCursorCb)(void* peer, WebCursorEnum type, int hotSpotX, int hotSpotY, float imageScaleFactor, ImageRef customImage);
 typedef void (*WebViewClientCloseWidgetSoonCb)(void* peer);
 typedef void (*WebViewClientShowCb)(void* peer, WebNavigationPolicyEnum policy);
 typedef void (*WebViewClientWindowRectCb)(void* peer, int* rx, int* ry, int* rw, int* rh);
 typedef void (*WebViewClientSetWindowRectCb)(void* peer, int rx, int ry, int rw, int rh);
 typedef void (*WebViewClientSetToolTipTextCb)(void* peer, const char* text, WebTextDirectionEnum hint);
 //typedef void (*WebViewClientWindowResizerRectCb)(void* peer, int* rx, int* ry, int* rw, int* rh);
 typedef void (*WebViewClientRootWindowRectCb)(void* peer, int* rx, int* ry, int* rw, int* rh);
 typedef void (*WebViewClientScreenInfoCb)(void* peer,
  // WebScreenInfo
  float* deviceScaleFactor, 
  int* depth, 
  int* depthPerComponent, 
  int* isMonochrome, 
  int* rx, 
  int* ry, 
  int* rw, 
  int* rh, 
  int* availableX, 
  int* availableY, 
  int* availableW, 
  int* availableH, 
  WebScreenOrientationEnum* orientationType, 
  uint16_t* orientationAngle);
 //typedef void (*WebViewClientResetInputMethodCb)(void* peer);
 typedef int (*WebViewClientRequestPointerLockCb)(void* peer);
 typedef void (*WebViewClientRequestPointerUnlockCb)(void* peer);
 typedef int (*WebViewClientIsPointerLockedCb)(void* peer);
 // TODO: we need to pass WebGesture.data .. have a lot more information
 typedef void (*WebViewClientDidHandleGestureEventCb)(void* peer, WebInputEventRef event, int eventCancelled);
 typedef void (*WebViewClientHasTouchEventHandlersCb)(void* peer, int handlers);
 typedef void (*WebViewClientSetTouchActionCb)(void* peer, WebTouchActionEnum touchAction);
 //typedef void (*WebViewClientDidUpdateTextOfFocusedElementByNonUserInputCb)(void* peer);
 //typedef void (*WebViewClientShowImeIfNeededCb)(void* peer);
 //typedef void (*WebViewClientShowUnhandledTapUIIfNeededCb)(void* peer, int tappedPositionX, int tappedPositionY,  WebNodeRef tappedNode, int pageChanged);
 //typedef void (*WebViewClientOnMouseDownCb)(void* peer, WebNodeRef mouseDownNode);
 typedef WebWidgetRef (*WebViewClientCreateViewCb)(void* peer, 
                    WebFrameRef creator,
                    WebURLRequestRef request,
                    // WindowFeatures
                    float x, 
                    int xSet, 
                    float y, 
                    int ySet, 
                    float width,
                    int widthSet, 
                    float height, 
                    int heightSet, 
                    int menuBarVisible, 
                    int statusBarVisible, 
                    int toolBarVisible, 
                    int scrollbarsVisible, 
                    int resizable, 
                    int noopener, 
                    int background,
                    int persistent,
                    const char* name,
                    WebNavigationPolicyEnum policy,
                    int suppressOpener);
typedef WebWidgetRef (*WebViewClientCreatePopupCb)(void* peer, WebFrameRef frame, WebPopupTypeEnum type);
typedef const char* (*WebViewClientGetSessionStorageNamespaceIdCb)(void* peer);
typedef void (*WebViewClientPrintPageCb)(void* peer, WebFrameRef frame);
typedef int (*WebViewClientEnumerateChosenDirectoryCb)(void* peer, const char* path, WebFileChooserCompletionRef completion);
//typedef void (*WebViewClientSaveImageFromDataURLCb)(void* peer, const char* url);
typedef void (*WebViewClientPageImportanceSignalsChangedCb)(void* peer);
//typedef void (*WebViewClientDidCancelCompositionOnSelectionChangeCb)(void* peer);
//typedef void (*WebViewClientDidChangeContentsCb)(void* peer);
//typedef int (*WebViewClientHandleCurrentKeyboardEventCb)(void* peer);
// typedef int (*WebViewClientRunFileChooserCb)(void* peer, 
//     int multiSelect,
//     int directory,
//     int saveAs,
//     const char* title,
//     const char* initialValue,
//     const char** acceptTypes,
//     const char** selectedFiles,
//     const char* capture,
//     int useMediaCapture,
//     int needLocalPath,
//     const char* requestor, 
//     WebFileChooserCompletionRef completion);

typedef int (*WebViewClientOpenDateTimeChooserCb)(void* peer,
    WebDateTimeInputTypeEnum type,
    int anchorRectInScreenX, 
    int anchorRectInScreenY, 
    int anchorRectInScreenW, 
    int anchorRectInScreenH,
    double doubleValue,
    double minimum,
    double maximum,
    double step,
    double stepBase,
    int isRequired,
    int isAnchorElementRTL, 
    WebDateTimeChooserCompletionRef completion);
// typedef void (*WebViewClientShowValidationMessageCb)(void* peer, 
//   int anchorInViewportX, 
//   int anchorInViewportY, 
//   int anchorInViewportW, 
//   int anchorInViewportH, 
//   const char* mainText, 
//   WebTextDirectionEnum mainTextDir, 
//   const char* supplementalText, 
//   WebTextDirectionEnum supplementalTextDir);
//typedef void (*WebViewClientHideValidationMessageCb)(void* peer);
//typedef void (*WebViewClientMoveValidationMessageCb)(void* peer, int anchorInViewportX, int anchorInViewportY, int anchorInViewportW, int anchorInViewportH);
//typedef void (*WebViewClientSetStatusTextCb)(void* peer, const char* text);
typedef void (*WebViewClientSetMouseOverURLCb)(void* peer, const char* url);
typedef void (*WebViewClientSetKeyboardFocusURLCb)(void* peer, const char* url);
typedef void (*WebViewClientStartDraggingCb)(void* peer, WebReferrerPolicyEnum policy, WebDragDataRef data, WebDragOperationsMask mask, ImageRef image, int dragImageOffsetX, int dragImageOffsetY);
typedef int (*WebViewClientAcceptsLoadDropsCb)(void* peer);
typedef void (*WebViewClientFocusNextCb)(void* peer);
typedef void (*WebViewClientFocusPreviousCb)(void* peer);
typedef void (*WebViewClientFocusedNodeChangedCb)(void* peer, WebNodeRef fromNode, WebNodeRef toNode);
typedef void (*WebViewClientDidUpdateLayoutCb)(void* peer);
typedef int (*WebViewClientDidTapMultipleTargetsCb)(void* peer, int pinchViewportOffsetX, int pinchViewportOffsetY, int tx, int ty, int tw, int th, int* targetX, int* targetY, int* targetW, int* targetH, int targetLen);
typedef const char* (*WebViewClientAcceptLanguagesCb)(void* peer);
typedef void (*WebViewClientNavigateBackForwardSoonCb)(void* peer, int offset);
typedef int (*WebViewClientHistoryBackListCountCb)(void* peer);
typedef int (*WebViewClientHistoryForwardListCountCb)(void* peer);
typedef void (*WebViewClientDidUpdateInspectorSettingsCb)(void* peer);
typedef void (*WebViewClientDidUpdateInspectorSettingCb)(void* peer, const char* key, const char* value);
//typedef WebSpeechRecognizerRef (*WebViewClientSpeechRecognizerCb)(void* peer);
typedef void (*WebViewClientZoomLimitsChangedCb)(void* peer, double minimumLevel, double maximumLevel);
typedef void (*WebViewClientPageScaleFactorChangedCb)(void* peer);
//typedef WebPageVisibilityStateEnum (*WebViewClientVisibilityStateCb)(void* peer);
// typedef void (*WebViewClientDetectContentAroundCb)(void* peer, 
//     WebHitTestResultRef result,
//     WebRangeRef range,
//     const char** string,
//     const char** intent);
// typedef void (*WebViewClientScheduleContentIntentCb)(void* peer, const char* url, int isMainFrame);
// typedef void (*WebViewClientCancelScheduledContentIntentsCb)(void* peer);
//typedef void (*WebViewClientDraggableRegionsChangedCb)(void* peer);
typedef void (*WebViewClientAutoscrollStart)(void* peer, float px, float py);
typedef void (*WebViewClientAutoscrollFling)(void* peer, float velocity_width, float velocity_height);
typedef void (*WebViewClientAutoscrollEnd)(void* peer);


// WebViewClient + WebWidgetClient
typedef struct {
 WebViewClientDidInvalidateRectCb didInvalidateRect;
 WebViewClientDidAutoResizeCb didAutoResize;
 //WebViewClientDidUpdateLayoutSizeCb didUpdateLayoutSize; 
 WebViewClientInitializeLayerTreeViewCb initializeLayerTreeView;
 WebViewClientIntrinsicSizingInfoChanged intrinsicSizingInfoChanged;
 WebViewClientAutoscrollStart autoscrollStart;
 WebViewClientAutoscrollFling autoscrollFling;
 WebViewClientAutoscrollEnd autoscrollEnd;
 WebViewClientCanHandleGestureEventCb canHandleGestureEvent;
 WebViewClientCanUpdateLayoutCb canUpdateLayout;
 WebViewClientConvertViewportToWindowCb convertViewportToWindow;
 WebViewClientConvertWindowToViewport convertWindowToViewport;
 //WebViewClientLayerTreeViewCb layerTreeView;
 WebViewClientScheduleAnimationCb scheduleAnimation;
 WebViewClientDidMeaningfulLayoutCb didMeaningfulLayout;
 WebViewClientDidFirstLayoutAfterFinishedParsingCb didFirstLayoutAfterFinishedParsing;
 WebViewClientDidFocusCb didFocus;
 //WebViewClientDidBlurCb didBlur;
 WebViewClientDidChangeCursorCb didChangeCursor;
 WebViewClientCloseWidgetSoonCb closeWidgetSoon;
 WebViewClientShowCb show;
 WebViewClientWindowRectCb windowRect;
 WebViewClientWindowRectCb viewRect;
 WebViewClientSetWindowRectCb setWindowRect;
 WebViewClientSetToolTipTextCb setToolTipText;
 //WebViewClientWindowResizerRectCb windowResizerRect;
 WebViewClientRootWindowRectCb rootWindowRect;
 WebViewClientScreenInfoCb screenInfo;
 //WebViewClientResetInputMethodCb resetInputMethod;
 WebViewClientRequestPointerLockCb requestPointerLock;
 WebViewClientRequestPointerUnlockCb requestPointerUnlock;
 WebViewClientIsPointerLockedCb isPointerLocked;
 WebViewClientDidHandleGestureEventCb didHandleGestureEvent;
 WebViewClientDidOverscrollCb didOverscroll;
 WebViewClientHasTouchEventHandlersCb hasTouchEventHandlers;
 WebViewClientSetTouchActionCb setTouchAction;
 //WebViewClientDidUpdateTextOfFocusedElementByNonUserInputCb didUpdateTextOfFocusedElementByNonUserInput;
 //WebViewClientShowImeIfNeededCb showImeIfNeeded;
// WebViewClientShowUnhandledTapUIIfNeededCb showUnhandledTapUIIfNeeded;
 //WebViewClientOnMouseDownCb onMouseDown;
 WebViewClientCreateViewCb createView;
 WebViewClientCreatePopupCb createPopup;
 WebViewClientGetSessionStorageNamespaceIdCb getSessionStorageNamespaceId;
 WebViewClientPrintPageCb printPage;
 WebViewClientEnumerateChosenDirectoryCb enumerateChosenDirectory;
 //WebViewClientSaveImageFromDataURLCb saveImageFromDataURL;
 WebViewClientPageImportanceSignalsChangedCb pageImportanceSignalsChanged;
 //WebViewClientDidCancelCompositionOnSelectionChangeCb didCancelCompositionOnSelectionChange;
 //WebViewClientDidChangeContentsCb didChangeContents;
 //WebViewClientHandleCurrentKeyboardEventCb handleCurrentKeyboardEvent;
 //WebViewClientRunFileChooserCb runFileChooser;
 WebViewClientOpenDateTimeChooserCb openDateTimeChooser;
 //WebViewClientShowValidationMessageCb showValidationMessage;
 //WebViewClientHideValidationMessageCb hideValidationMessage;
 //WebViewClientMoveValidationMessageCb moveValidationMessage;
 //WebViewClientSetStatusTextCb setStatusText;
 WebViewClientSetMouseOverURLCb setMouseOverURL;
 WebViewClientSetKeyboardFocusURLCb setKeyboardFocusURL;
 WebViewClientStartDraggingCb startDragging;
 WebViewClientAcceptsLoadDropsCb acceptsLoadDrops;
 WebViewClientFocusNextCb focusNext;
 WebViewClientFocusPreviousCb focusPrevious;
 WebViewClientFocusedNodeChangedCb focusedNodeChanged;
 WebViewClientDidUpdateLayoutCb didUpdateLayout;
 WebViewClientDidTapMultipleTargetsCb didTapMultipleTargets;
 WebViewClientAcceptLanguagesCb acceptLanguages;
 WebViewClientNavigateBackForwardSoonCb navigateBackForwardSoon;
 WebViewClientHistoryBackListCountCb historyBackListCount;
 WebViewClientHistoryForwardListCountCb historyForwardListCount;
 WebViewClientDidUpdateInspectorSettingsCb didUpdateInspectorSettings;
 WebViewClientDidUpdateInspectorSettingCb didUpdateInspectorSetting;
 //WebViewClientSpeechRecognizerCb speechRecognizer;
 WebViewClientZoomLimitsChangedCb zoomLimitsChanged;
 WebViewClientPageScaleFactorChangedCb pageScaleFactorChanged;
 //WebViewClientVisibilityStateCb visibilityState;
 //WebViewClientDetectContentAroundCb detectContentAround;
 //WebViewClientScheduleContentIntentCb scheduleContentIntent;
 //WebViewClientCancelScheduledContentIntentsCb cancelScheduledContentIntents;
 //WebViewClientDraggableRegionsChangedCb draggableRegionsChanged;
} WebViewClientCbs;

typedef struct {
  int (*GetProviderId)(void* state); 
  int (*HasControllerServiceWorker)(void* state);
  int64_t (*GetControllerServiceWorkerId)(void* state);  
  void (*WillSendRequest)(void* state, void* request);
  void* (*CreateURLLoader)(void* state, void* request, struct CBlinkPlatformCallbacks* cbs);
  int (*CountResponseHandler)(void* state);
  void* (*GetResponseHandlerAt)(void* state, int index, struct CResponseHandler* cbs);
} WebServiceWorkerNetworkProviderCbs;

// WebFrameClient Callbacks
typedef void (*WebFrameClientBindToFrameCb)(void* peer, WebFrameRef frame);

typedef WebPluginRef (*WebFrameClientCreatePluginCb)(void* peer, 
    const char* url,
    const char* mimeType,
    const char** attributeNames,
    int attributeNamesLen,
    const char** attributeValues,
    int attributeValuesLen,
    int loadManually);

typedef WebMediaPlayerRef (*WebFrameClientCreateMediaPlayerCb)(void* peer, const char* url, WebMediaPlayerClientRef client, WebMediaPlayerEncryptedMediaClientRef eclient, WebContentDecryptionModuleRef module, const char* sinkId, WebLayerTreeViewRef tree);
typedef WebMediaPlayerRef (*WebFrameClientCreateMediaPlayerStreamCb)(void* peer, WebMediaStreamDescriptorRef descriptor, WebMediaPlayerClientRef client, WebMediaPlayerEncryptedMediaClientRef eclient, WebContentDecryptionModuleRef module, const char* sinkId, WebLayerTreeViewRef tree);
typedef WebMediaSessionRef (*WebFrameClientCreateMediaSessionCb)(void* peer);
typedef WebApplicationCacheHostRef (*WebFrameClientCreateApplicationCacheHostCb)(void* peer, WebApplicationCacheHostClientRef client);
typedef WebServiceWorkerProviderRef (*WebFrameClientCreateServiceWorkerProviderCb)(void* peer);
//typedef WebWorkerContentSettingsClientProxyRef (*WebFrameClientCreateWorkerContentSettingsClientProxyCb)(void* peer);
typedef WebExternalPopupMenuRef (*WebFrameClientCreateExternalPopupMenuCb)(void* peer, 
    int itemHeight,
    int itemFontSize,
    int selectedIndex,
    // FIXME: Theres no easy way to port this.. so this is broken for now
    //WebVector<WebMenuItemInfo> items;
    int rightAligned,
    int allowMultipleSelection, 
    WebExternalPopupMenuClientRef client);

typedef WebCookieJarRef (*WebFrameClientCookieJarCb)(void* peer);
typedef WebBlameContextRef (*WebFrameClientFrameBlameContextCb)(void* peer);
typedef WebInterfaceProviderRef (*WebFrameClientInterfaceProviderCb)(void* peer);
typedef WebAssociatedInterfaceProviderRef (*WebFrameClientRemoteNavigationAssociatedInterfacesCb)(void* peer);
typedef int (*WebFrameClientCanCreatePluginWithoutRendererCb)(void* peer, const char* mimeType);
typedef void (*WebFrameClientDidAccessInitialDocumentCb)(void* peer);
typedef WebFrameRef (*WebFrameClientCreateChildFrameCb)(void* peer, 
  WebFrameRef parent, 
  WebTreeScopeEnum type, 
  const char* frameName,
  const char* fallback_name,
  WebSandboxFlagsEnum sandboxFlags, 
  WebScrollingModeEnum scrollingMode, 
  int marginWidth, 
  int marginHeight,
  int allow_fullscreen,
  int allow_payment_request,
  int is_display_none);
typedef WebFrameRef (*WebFrameClientFindFrameCb)(void* peer, const char* frameName);  
typedef void (*WebFrameClientDidChangeOpenerCb)(void* peer, WebFrameRef frame);
typedef void (*WebFrameClientFrameDetachedCb)(void* peer, WebDetachEnum type);
typedef void (*WebFrameClientFrameFocusedCb)(void* peer);
typedef void (*WebFrameClientWillCommitProvisionalLoadCb)(void* peer);
typedef void (*WebFrameClientDidChangeNameCb)(void* peer, const char* name);
typedef void (*WebFrameClientDidEnforceInsecureRequestPolicyCb)(void* peer);
typedef void (*WebFrameClientDidEnforceInsecureNavigationsSetCb)(void* peer);
typedef void (*WebFrameClientDidChangeFramePolicyCb)(void* peer, WebFrameRef childFrame, WebSandboxFlagsEnum flags);
typedef void (*WebFrameClientDidSetFramePolicyHeadersCb)(void* peer);
typedef void (*WebFrameClientDidAddContentSecurityPoliciesCb)(void* peer);
typedef void (*WebFrameClientDidChangeFrameOwnerPropertiesCb)(void* peer, 
  WebFrameRef childFrame, 
  WebScrollingModeEnum scrollingMode, 
  int marginWidth, 
  int marginHeight);
typedef void (*WebFrameClientDidMatchCSSCb)(void* peer, const char** newlyMatchingSelectors, int newlyMatchingSelectorsLen, const char** stoppedMatchingSelectors, int stoppedMatchingSelectorsLen);
typedef void (*WebFrameClientSetHasReceivedUserGestureCb)(void* peer);
typedef void (*WebFrameClientSetHasReceivedUserGestureBeforeNavigationCb)(void* peer, int value);
typedef int (*WebFrameClientShouldReportDetailedMessageForSourceCb)(void* peer, const char* source);
typedef void (*WebFrameClientDidAddMessageToConsoleCb)(void* peer, WebConsoleMessageLevelEnum messageLevel, const char* messageText, const char* sourceName, unsigned sourceLine, const char* stackTrace);
typedef void (*WebFrameClientDownloadURLCb)(void* peer, WebURLRequestRef url_request);
typedef void (*WebFrameClientLoadErrorPageCb)(void* peer, int reason);
//typedef void (*WebFrameClientLoadURLExternallyCb)(void* peer, WebURLRequestRef req, WebNavigationPolicyEnum policy, const char* downloadName, int shouldReplaceCurrentEntry);
typedef WebNavigationPolicyEnum (*WebFrameClientDecidePolicyForNavigationCb)(void* peer, 
    // from NavigationPolicyInfo struct
    WebDataSourceExtraDataRef extraData,
    WebURLRequestRef urlRequest,
    WebNavigationTypeEnum navigationType,
    WebNavigationPolicyEnum defaultPolicy,
    int replacesCurrentHistoryItem);
//typedef WebHistoryItemRef (*WebFrameClientHistoryItemForNewChildFrameCb)(void* peer, WebFrameRef frame);
//typedef int (*WebFrameClientHasPendingNavigationCb)(void* peer, WebFrameRef frame);
typedef int (*WebFrameClientAllowContentInitiatedDataUrlNavigationsCb)(void* peer, const char* url);
typedef void (*WebFrameClientDidStartLoadingCb)(void* peer, int toDifferentDocument);
typedef void (*WebFrameClientDidStopLoadingCb)(void* peer);
typedef void (*WebFrameClientDidChangeLoadProgressCb)(void* peer, double loadProgress);
typedef void (*WebFrameClientWillSendSubmitEventCb)(void* peer, WebNodeRef formElement);
typedef void (*WebFrameClientWillSubmitFormCb)(void* peer, WebNodeRef formElement);
typedef void (*WebFrameClientDidCreateDocumentLoaderCb)(void* peer, WebDocumentLoaderRef loader);
//typedef void (*WebFrameClientDidCreateDataSourceCb)(void* peer, WebFrameRef frame, WebDataSourceRef ds);
typedef void (*WebFrameClientDidStartProvisionalLoadCb)(void* peer, WebDocumentLoaderRef loader, WebURLRequestRef url_request);
typedef void (*WebFrameClientDidReceiveServerRedirectForProvisionalLoadCb)(void* peer);
typedef void (*WebFrameClientDidFailProvisionalLoadCb)(void* peer, 
    // from blink::WebURLError
    const char* url,
    int reason,
    int hasCopyInCache,
    int is_web_security_violation,
    WebHistoryCommitEnum type);
typedef void (*WebFrameClientDidCommitProvisionalLoadCb)(void* peer, WebHistoryItemRef item, WebHistoryCommitEnum type);
typedef void (*WebFrameClientDidCreateNewDocumentCb)(void* peer);
typedef void (*WebFrameClientDidClearWindowObjectCb)(void* peer);
typedef void (*WebFrameClientDidCreateDocumentElementCb)(void* peer);
typedef void (*WebFrameClientRunScriptsAtDocumentElementAvailableCb)(void* peer);
typedef void (*WebFrameClientDidReceiveTitleCb)(void* peer, const uint16_t* title, int title_count, WebTextDirectionEnum direction);
typedef void (*WebFrameClientDidChangeIconCb)(void* peer, WebIconURLEnum type);
typedef void (*WebFrameClientDidFinishDocumentLoadCb)(void* peer);
typedef void (*WebFrameClientRunScriptsAtDocumentReadyCb)(void* peer, int document_is_empty);
typedef void (*WebFrameClientRunScriptsAtDocumentIdleCb)(void* peer);
typedef void (*WebFrameClientDidHandleOnloadEventsCb)(void* peer);
typedef void (*WebFrameClientDidFailLoadCb)(void* peer,
    // from blink::WebURLError
    const char* url,
    int reason,
    int hasCopyInCache,
    int is_web_security_violation,
    //int wasIgnoredByHandler,
    //const char* unreachableURL,
    //const char* localizedDescription,
    WebHistoryCommitEnum type);
typedef void (*WebFrameClientDidFinishLoadCb)(void* peer);
typedef void (*WebFrameClientDidNavigateWithinPageCb)(void* peer, WebHistoryItemRef item, WebHistoryCommitEnum type, int content_initiated);
typedef void (*WebFrameClientDidUpdateCurrentHistoryItemCb)(void* peer);
typedef void (*WebFrameClientDidChangeManifestCb)(void* peer);
typedef void (*WebFrameClientDidChangeThemeColorCb)(void* peer);
typedef void (*WebFrameClientForwardResourceTimingToParentCb)(void* peer);
typedef void (*WebFrameClientDispatchLoadCb)(void* peer);
typedef WebEffectiveConnectionTypeEnum (*WebFrameClientGetEffectiveConnectionTypeCb)(void* peer);
typedef int (*WebFrameClientGetPreviewsStateForFrameCb)(void* peer);
//typedef void (*WebFrameClientRequestNotificationPermissionCb)(void* peer, WebSecurityOriginRef origin, WebNotificationPermissionCallbackRef callback);
typedef void (*WebFrameClientDidBlockFramebust)(void* peer, const char* url);
typedef void (*WebFrameClientAbortClientNavigation)(void* peer);
typedef WebPushClientRef (*WebFrameClientPushClientCb)(void* peer);
//typedef WebPresentationClientRef (*WebFrameClientPresentationClientCb)(void* peer);
typedef void (*WebFrameClientDidChangeSelectionCb)(void* peer, int isSelectionEmpty);
typedef void (*WebFrameClientDidChangeContentsCb)(void* peer);
// typedef WebColorChooserRef (*WebFrameClientCreateColorChooserCb)(void* peer,
//       WebColorChooserClientRef client,
//       unsigned color);//,
      //const blink::WebVector<blink::WebColorSuggestion>&);
typedef int (*WebFrameClientHandleCurrentKeyboardEvent)(void* peer);
typedef int (*WebFrameClientRunFileChooserCb)(void* peer, 
    int multiSelect,
    int directory,
    int saveAs,
    const char* title,
   // const char* initialValue,
    const char** acceptTypes,
    const char** selectedFiles,
    const char* capture,
    int useMediaCapture,
    int needLocalPath,
    const char* requestor, 
    WebFileChooserCompletionRef completion);
typedef void (*WebFrameClientRunModalAlertDialogCb)(void* peer, const char* message);
typedef int (*WebFrameClientRunModalConfirmDialogCb)(void* peer, const char* message);
typedef int (*WebFrameClientRunModalPromptDialogCb)(void* peer, 
      const char* message, 
      const char* defaultValue,
      const char** actualValue);
typedef int (*WebFrameClientRunModalBeforeUnloadDialogCb)(void* peer, 
      int isReload);
typedef void (*WebFrameClientShowContextMenuCb)(void* peer, WebContextMenuDataRef menuData);
typedef void (*WebFrameClientSaveImageFromDataURLCb)(void* peer, const char* url);
//typedef void (*WebFrameClientClearContextMenuCb)(void* peer);
typedef void (*WebFrameClientFrameRectsChangedCb)(void* peer, int rx, int ry, int rw, int rh);
typedef void (*WebFrameClientWillSendRequestCb)(void* peer, 
      WebURLRequestRef req);
typedef void (*WebFrameClientDidReceiveResponseCb)(void* peer,
      WebURLResponseRef resp);
// typedef void (*WebFrameClientDidChangeResourcePriorityCb)(void* peer,
//       WebFrameRef webFrame, unsigned identifier, WebURLRequestPriorityEnum priority, int);
//typedef void (*WebFrameClientDidFinishResourceLoadCb)(void* peer,
//      WebFrameRef frame, unsigned identifier);
typedef void (*WebFrameClientDidLoadResourceFromMemoryCacheCb)(void* peer, WebURLRequestRef req, WebURLResponseRef resp);
typedef void (*WebFrameClientDidDisplayInsecureContentCb)(void* peer);
typedef void (*WebFrameClientDidContainInsecureFormActionCb)(void* peer);
typedef void (*WebFrameClientDidRunInsecureContentCb)(void* peer, WebSecurityOriginRef origin, const char* insecureURL);
typedef void (*WebFrameClientDidDetectXSSCb)(void* peer, const char* url, int didBlockEntirePage);
typedef void (*WebFrameClientDidDispatchPingLoaderCb)(void* peer, const char* url);
typedef void (*WebFrameClientDidDisplayContentWithCertificateErrorsCb)(void* peer);
typedef void (*WebFrameClientDidRunContentWithCertificateErrorsCb)(void* peer);
typedef void (*WebFrameClientDidChangePerformanceTimingCb)(void* peer);
//typedef void (*WebFrameClientDidAbortLoadingCb)(void* peer, WebFrameRef frame);
typedef void (*WebFrameClientDidCreateScriptContextCb)(void* peer, JavascriptContextRef context, int worldId);
typedef void (*WebFrameClientWillReleaseScriptContextCb)(void* peer, JavascriptContextRef context, int worldId);
typedef void (*WebFrameClientDidChangeScrollOffsetCb)(void* peer);
typedef void (*WebFrameClientWillInsertBodyCb)(void* peer);
typedef void (*WebFrameClientDraggableRegionsChangedCb)(void* peer);
typedef void (*WebFrameClientScrollRectToVisibleInParentFrameCb)(void* peer, int rx, int ry, int rw, int rh);
typedef void (*WebFrameClientReportFindInPageMatchCountCb)(void* peer, int identifier, int count, int finalUpdate); 
//typedef void (*WebFrameClientReportFindInFrameMatchCountCb)(void* peer, int identifier, int count, int finalUpdate);
typedef void (*WebFrameClientReportFindInPageSelectionCb)(void* peer, int identifier, int activeMatchOrdinal, int sx, int sy, int sw, int sh);
//typedef int (*WebFrameClientShouldSearchSingleFrameCb)(void* peer);
//typedef void (*WebFrameClientRequestStorageQuotaCb)(void* peer, 
//        WebFrameRef frame, 
//        WebStorageQuotaTypeEnum type,
//        unsigned long long newQuotaInBytes,
//        WebStorageQuotaCallbacksRef cbs);
//typedef void (*WebFrameClientWillOpenWebSocketCb)(void* peer, WebSocketHandleRef socket);
// WebWakeLockClientRef (*WebFrameClientWakeLockClientCb)(void* peer);
//typedef WebGeolocationClientRef (*WebFrameClientGeolocationClientCb)(void* peer);
typedef void (*WebFrameClientWillStartUsingPeerConnectionHandlerCb)(void* peer, WebRTCPeerConnectionHandlerRef handler);
typedef WebUserMediaClientRef (*WebFrameClientUserMediaClientCb)(void* peer);
typedef WebEncryptedMediaClientRef (*WebFrameClientEncryptedMediaClientCb)(void* peer);
//typedef WebMIDIClientRef (*WebFrameClientWebMIDIClientCb)(void* peer);
//typedef int (*WebFrameClientWillCheckAndDispatchMessageEventCb)(void* peer, 
//      WebFrameRef sourceFrame,
//      WebFrameRef targetFrame,
//      WebSecurityOriginRef target,
//      WebDOMMessageEventRef domMessageEvent);
typedef const char* (*WebFrameClientUserAgentOverrideCb)(void* peer);
typedef const char* (*WebFrameClientDoNotTrackValueCb)(void* peer);
typedef int (*WebFrameClientShouldBlockWebGLCb)(void* peer);
//typedef void (*WebFrameClientDidLoseWebGLContextCb)(void* peer, WebFrameRef frame, int);
//typedef WebScreenOrientationClientRef (*WebFrameClientWebScreenOrientationClientCb)(void* peer);
typedef void (*WebFrameClientPostAccessibilityEventCb)(void* peer, WebAXObjectRef obj, WebAXEventEnum event);
typedef void (*WebFrameClientHandleAccessibilityFindInPageResultCb)(void* peer, 
      int identifier,
      int matchIndex,
      WebAXObjectRef startObject,
      int startOffset,
      WebAXObjectRef endObject,
      int endOffset);
//typedef int (*WebFrameClientIsControlledByServiceWorkerCb)(void* peer, WebDataSourceRef ds);
//typedef int64_t (*WebFrameClientServiceWorkerIDCb)(void* peer, WebDataSourceRef ds);
typedef void (*WebFrameClientEnterFullscreenCb)(void* peer);
typedef void (*WebFrameClientExitFullscreenCb)(void* peer);
typedef void (*WebFrameClientSuddenTerminationDisablerChangedCb)(void* peer, int present, WebSuddenTerminationDisablerTypeEnum type);
//typedef WebPermissionClientRef (*WebFrameClientPermissionClientCb)(void* peer);
//typedef WebVRClientRef (*WebFrameClientWebVRClientCb)(void* peer);
//typedef WebAppBannerClientRef (*WebFrameClientAppBannerClientCb)(void* peer);
typedef void (*WebFrameClientRegisterProtocolHandlerCb)(void* peer, const char* scheme, const char* url, const char* title);
typedef void (*WebFrameClientUnregisterProtocolHandlerCb)(void* peer, const char* scheme, const char* url);
//typedef WebCustomHandlersStateEnum (*WebFrameClientIsProtocolHandlerRegisteredCb)(void* peer, const char* scheme, const char* url);
//typedef WebBluetoothRef (*WebFrameClientBluetoothCb)(void* peer);
//typedef WebUSBClientRef (*WebFrameClientUsbClientCb)(void* peer);
typedef WebPageVisibilityStateEnum (*WebFrameClientVisibilityStateCb)(void* peer);

// WebRemoteFrameClient callbacks
typedef void (*WebFrameClientFrameRectsChangedRemoteCb)(
    void* peer, 
    int local_frame_rect_x, int local_frame_rect_y, 
    int local_frame_rect_width, int local_frame_rect_height,
    int screen_space_rect_x, int screen_space_rect_y, 
    int screen_space_rect_width, int screen_space_rect_height);
typedef void (*WebFrameClientCheckCompletedCb)(void* peer);
typedef void (*WebFrameClientForwardPostMessageCb)(
              void* peer,
              WebFrameRef sourceFrame,
              WebFrameRef targetFrame,
              WebSecurityOriginRef targetOrigin,
              WebDOMMessageEventRef event,
              int hasUserGesture);
typedef void (*WebFrameClientNavigateCb)(void* peer, WebURLRequestRef request, int shouldReplaceCurrentEntry);
typedef void (*WebFrameClientReloadCb)(void* peer, WebFrameLoadTypeEnum loadType, WebClientRedirectPolicyEnum redirect);
typedef void (*WebFrameClientUpdateRemoteViewportIntersectionCb)(
    void* peer,
    int viewport_x, int viewport_y, 
    int viewport_width, int viewport_height);
typedef void (*WebFrameClientVisibilityChangedCb)(void* peer, int visible);
typedef void (*WebFrameClientSetIsInertCb)(void* peer, int is_inert);
typedef void (*WebFrameClientUpdateRenderThrottlingStatusCb)(void* peer, int isThrottled, int subtreeThrottled);
typedef void (*WebFrameClientAdvanceFocusCb)(void* peer, WebFocusTypeEnum type, WebFrameRef source);
typedef WebFrameRef (*WebFrameClientGetCurrentLocalFrameCb)(void* peer);
typedef int (*WebFrameClientGetRoutingId)(void* peer);

typedef struct { 
  WebFrameClientBindToFrameCb bindToFrame;
  WebFrameClientCreatePluginCb createPlugin;
  WebFrameClientCreateMediaPlayerCb createMediaPlayer; 
  WebFrameClientCreateMediaPlayerStreamCb createMediaPlayerStream; 
  WebFrameClientCreateMediaSessionCb createMediaSession;
  WebFrameClientCreateApplicationCacheHostCb createApplicationCacheHost;
  WebFrameClientCreateServiceWorkerProviderCb createServiceWorkerProvider;
  WebFrameClientCreateExternalPopupMenuCb createExternalPopupMenu;
  WebFrameClientCookieJarCb cookieJar;
  WebFrameClientFrameBlameContextCb frameBlameContext;
  WebFrameClientInterfaceProviderCb interfaceProvider;
  WebFrameClientRemoteNavigationAssociatedInterfacesCb remoteNavigationAssociatedInterfaces;
  WebFrameClientCanCreatePluginWithoutRendererCb canCreatePluginWithoutRenderer;
  WebFrameClientDidAccessInitialDocumentCb didAccessInitialDocument;
  WebFrameClientCreateChildFrameCb createChildFrame;
  WebFrameClientFindFrameCb findFrame;
  WebFrameClientDidChangeOpenerCb didChangeOpener;
  WebFrameClientFrameDetachedCb frameDetached;
  WebFrameClientFrameFocusedCb frameFocused;
  WebFrameClientWillCommitProvisionalLoadCb willCommitProvisionalLoad;
  WebFrameClientFrameRectsChangedCb frameRectsChanged;
  WebFrameClientDidChangeNameCb didChangeName;
  WebFrameClientDidEnforceInsecureRequestPolicyCb didEnforceInsecureRequestPolicy;
  WebFrameClientDidEnforceInsecureNavigationsSetCb didEnforceInsecureNavigationsSet;
  WebFrameClientDidChangeFramePolicyCb didChangeFramePolicy;
  WebFrameClientDidSetFramePolicyHeadersCb didSetFramePolicyHeaders;
  WebFrameClientDidAddContentSecurityPoliciesCb didAddContentSecurityPolicies;
  WebFrameClientDidChangeFrameOwnerPropertiesCb didChangeFrameOwnerProperties;
  WebFrameClientDidMatchCSSCb didMatchCSS;
  WebFrameClientSetHasReceivedUserGestureCb setHasReceivedUserGesture;
  WebFrameClientSetHasReceivedUserGestureBeforeNavigationCb setHasReceivedUserGestureBeforeNavigation;
  WebFrameClientShouldReportDetailedMessageForSourceCb shouldReportDetailedMessageForSource;
  WebFrameClientDidAddMessageToConsoleCb didAddMessageToConsole;
  WebFrameClientDownloadURLCb downloadURL;
  WebFrameClientLoadErrorPageCb loadErrorPage;
  WebFrameClientDecidePolicyForNavigationCb decidePolicyForNavigation;
  WebFrameClientAllowContentInitiatedDataUrlNavigationsCb allowContentInitiatedDataUrlNavigations;
  WebFrameClientDidStartLoadingCb didStartLoading;
  WebFrameClientDidStopLoadingCb didStopLoading;
  WebFrameClientDidChangeLoadProgressCb didChangeLoadProgress;
  WebFrameClientWillSendSubmitEventCb willSendSubmitEvent;
  WebFrameClientWillSubmitFormCb willSubmitForm;
  WebFrameClientDidCreateDocumentLoaderCb didCreateDocumentLoader;
  WebFrameClientDidStartProvisionalLoadCb didStartProvisionalLoad;
  WebFrameClientDidReceiveServerRedirectForProvisionalLoadCb didReceiveServerRedirectForProvisionalLoad;
  WebFrameClientDidFailProvisionalLoadCb didFailProvisionalLoad;
  WebFrameClientDidCommitProvisionalLoadCb didCommitProvisionalLoad;
  WebFrameClientDidCreateNewDocumentCb didCreateNewDocument;
  WebFrameClientDidClearWindowObjectCb didClearWindowObject;
  WebFrameClientDidCreateDocumentElementCb didCreateDocumentElement;
  WebFrameClientRunScriptsAtDocumentElementAvailableCb runScriptsAtDocumentElementAvailable;
  WebFrameClientDidReceiveTitleCb didReceiveTitle;
  WebFrameClientDidChangeIconCb didChangeIcon;
  WebFrameClientDidFinishDocumentLoadCb didFinishDocumentLoad;
  WebFrameClientRunScriptsAtDocumentReadyCb runScriptsAtDocumentReady;
  WebFrameClientRunScriptsAtDocumentIdleCb runScriptsAtDocumentIdle;
  WebFrameClientDidHandleOnloadEventsCb didHandleOnloadEvents;
  WebFrameClientDidFailLoadCb didFailLoad;
  WebFrameClientDidFinishLoadCb didFinishLoad;
  WebFrameClientGetEffectiveConnectionTypeCb getEffectiveConnectionType;
  WebFrameClientGetPreviewsStateForFrameCb getPreviewsStateForFrame;
  WebFrameClientDidBlockFramebust didBlockFramebust;
  WebFrameClientAbortClientNavigation abortClientNavigation;
  WebFrameClientDidNavigateWithinPageCb didNavigateWithinPage;
  WebFrameClientDidUpdateCurrentHistoryItemCb didUpdateCurrentHistoryItem;
  WebFrameClientDidChangeManifestCb didChangeManifest;
  WebFrameClientDidChangeThemeColorCb didChangeThemeColor;
  WebFrameClientForwardResourceTimingToParentCb forwardResourceTimingToParent;
  WebFrameClientDispatchLoadCb dispatchLoad;
  WebFrameClientPushClientCb pushClient;
  WebFrameClientDidChangeSelectionCb didChangeSelection;
  WebFrameClientDidChangeContentsCb didChangeContents;
  WebFrameClientHandleCurrentKeyboardEvent handleCurrentKeyboardEvent;
  WebFrameClientRunModalAlertDialogCb runModalAlertDialog;
  WebFrameClientRunModalConfirmDialogCb runModalConfirmDialog;
  WebFrameClientRunModalPromptDialogCb runModalPromptDialog;
  WebFrameClientRunModalBeforeUnloadDialogCb runModalBeforeUnloadDialog;
  WebFrameClientRunFileChooserCb runFileChooser;
  WebFrameClientShowContextMenuCb showContextMenu;
  WebFrameClientSaveImageFromDataURLCb saveImageFromDataURL;
  WebFrameClientWillSendRequestCb willSendRequest;
  WebFrameClientDidReceiveResponseCb didReceiveResponse;
  //WebFrameClientDidChangeResourcePriorityCb didChangeResourcePriority;
  //WebFrameClientDidFinishResourceLoadCb didFinishResourceLoad;
  WebFrameClientDidLoadResourceFromMemoryCacheCb didLoadResourceFromMemoryCache;
  WebFrameClientDidDisplayInsecureContentCb didDisplayInsecureContent;
  WebFrameClientDidContainInsecureFormActionCb didContainInsecureFormAction;
  WebFrameClientDidRunInsecureContentCb didRunInsecureContent;
  WebFrameClientDidDetectXSSCb didDetectXSS;
  WebFrameClientDidDispatchPingLoaderCb didDispatchPingLoader;
  WebFrameClientDidDisplayContentWithCertificateErrorsCb didDisplayContentWithCertificateErrors;  
  WebFrameClientDidRunContentWithCertificateErrorsCb didRunContentWithCertificateErrors;
  WebFrameClientDidChangePerformanceTimingCb didChangePerformanceTiming;
  WebFrameClientDidCreateScriptContextCb didCreateScriptContext;
  WebFrameClientWillReleaseScriptContextCb willReleaseScriptContext;
  WebFrameClientDidChangeScrollOffsetCb didChangeScrollOffset;
  WebFrameClientWillInsertBodyCb willInsertBody;
  WebFrameClientDraggableRegionsChangedCb draggableRegionsChanged;
  WebFrameClientScrollRectToVisibleInParentFrameCb scrollRectToVisibleInParentFrame;
  WebFrameClientReportFindInPageMatchCountCb reportFindInPageMatchCount;
  WebFrameClientReportFindInPageSelectionCb reportFindInPageSelection;
  WebFrameClientWillStartUsingPeerConnectionHandlerCb willStartUsingPeerConnectionHandler;
  WebFrameClientUserMediaClientCb userMediaClient;
  WebFrameClientEncryptedMediaClientCb encryptedMediaClient;
  WebFrameClientUserAgentOverrideCb userAgentOverride;
  WebFrameClientDoNotTrackValueCb doNotTrackValue;
  WebFrameClientShouldBlockWebGLCb shouldBlockWebGL;
  WebFrameClientPostAccessibilityEventCb postAccessibilityEvent;
  WebFrameClientHandleAccessibilityFindInPageResultCb handleAccessibilityFindInPageResult;
  WebFrameClientEnterFullscreenCb enterFullscreen;
  WebFrameClientExitFullscreenCb exitFullscreen;
  WebFrameClientSuddenTerminationDisablerChangedCb suddenTerminationDisablerChanged;
  WebFrameClientRegisterProtocolHandlerCb registerProtocolHandler;
  WebFrameClientUnregisterProtocolHandlerCb unregisterProtocolHandler;
  WebFrameClientVisibilityStateCb visibilityState;
  WebFrameClientFrameRectsChangedRemoteCb frameRectsChangedRemote;
  WebFrameClientCheckCompletedCb checkCompleted;
  WebFrameClientForwardPostMessageCb forwardPostMessage;
  WebFrameClientNavigateCb navigate;
  WebFrameClientReloadCb reload;
  WebFrameClientUpdateRemoteViewportIntersectionCb updateRemoteViewportIntersection;
  WebFrameClientVisibilityChangedCb visibilityChanged;
  WebFrameClientSetIsInertCb setIsInert;
  WebFrameClientUpdateRenderThrottlingStatusCb updateRenderThrottlingStatus;
  WebFrameClientAdvanceFocusCb advanceFocus;
  WebFrameClientGetCurrentLocalFrameCb getCurrentLocalFrame;
  WebFrameClientGetRoutingId getRoutingId;
} WebFrameClientCbs;


typedef struct {
  void(*on_connect)(void*, const char*, const char*);
  void(*on_receive_text_message)(void*, const char*);
  void(*on_receive_binary_message)(void*, void*, int);
  void(*on_error)(void*);
  void(*on_consume_buffered_amount)(void*, uint64_t);
  void(*on_start_closing_handshake)(void*);
  void(*on_close)(void*, unsigned short, const char*);
} WebSocketCallbacks;

// WebNode

EXPORT void _WebNodeRetain(WebNodeRef handle);
EXPORT void _WebNodeRelease(WebNodeRef handle);
EXPORT int _WebNodeGetType(WebNodeRef handle);
EXPORT WebNodeRef _WebNodeGetParentNode(WebNodeRef handle);
EXPORT const char* _WebNodeGetNodeName(WebNodeRef handle);
EXPORT const char* _WebNodeGetNodeValue(WebNodeRef handle);
EXPORT WebNodeRef _WebNodeGetDocument(WebNodeRef handle);
EXPORT WebNodeRef _WebNodeFirstChild(WebNodeRef handle);
EXPORT WebNodeRef _WebNodeLastChild(WebNodeRef handle);
EXPORT WebNodeRef _WebNodePreviousSibling(WebNodeRef handle);
EXPORT WebNodeRef _WebNodeNextSibling(WebNodeRef handle);
EXPORT WebAXObjectRef _WebNodeGetAccessibilityObject(WebNodeRef handle);
EXPORT int _WebNodeHasChildNodes(WebNodeRef handle);
EXPORT int _WebNodeIsLink(WebNodeRef handle);
EXPORT int _WebNodeIsDocumentNode(WebNodeRef handle);
EXPORT int _WebNodeIsCommentNode(WebNodeRef handle);
EXPORT int _WebNodeIsTextNode(WebNodeRef handle);
EXPORT int _WebNodeIsFocusable(WebNodeRef handle);
//EXPORT int _WebNodeIsContentEditable(WebNodeRef handle);
EXPORT int _WebNodeIsElementNode(WebNodeRef handle);
EXPORT int _WebNodeIsInsideFocusableElement(WebNodeRef handle);
EXPORT int _WebNodeIsEqual(WebNodeRef handle, WebNodeRef other);
EXPORT int _WebNodeLessThan(WebNodeRef handle, WebNodeRef other);
EXPORT void _WebNodeDispatchEvent(WebNodeRef handle, WebEventRef event);
EXPORT HTMLCollectionRef _WebNodeGetElementsByTagName(WebNodeRef handle, const char* tag);
EXPORT WebNodeRef _WebNodeQuerySelector(WebNodeRef handle, const char* selector);
EXPORT WebNodeRef _WebNodeQuerySelectorException(WebNodeRef handle, const char* selector, int* code);
EXPORT WebElementArrayRef _WebNodeQuerySelectorAll(WebNodeRef handle, const char* selector);
EXPORT WebElementArrayRef _WebNodeQuerySelectorAllException(WebNodeRef handle, const char* selector, int* code);

EXPORT int _WebNodeIsEditingText(WebNodeRef handle);
EXPORT int _WebNodeIsContainerNode(WebNodeRef handle);
EXPORT int _WebNodeIsHTMLElement(WebNodeRef handle);
EXPORT int _WebNodeIsSVGElement(WebNodeRef handle);
EXPORT int _WebNodeIsCustomElement(WebNodeRef handle);
EXPORT int _WebNodeIsStyledElement(WebNodeRef handle);
EXPORT int _WebNodeIsDocumentFragment(WebNodeRef handle);
EXPORT int _WebNodeIsShadowRoot(WebNodeRef handle);
EXPORT int _WebNodeIsFocused(WebNodeRef handle);
EXPORT void _WebNodeSetFocused(WebNodeRef handle, int focused);
EXPORT int _WebNodeHasFocusWithin(WebNodeRef handle);
EXPORT void _WebNodeSetHasFocusWithin(WebNodeRef handle, int focused);
EXPORT int _WebNodeWasFocusedByMouse(WebNodeRef handle);
EXPORT void _WebNodeSetWasFocusedByMouse(WebNodeRef handle, int focused);
EXPORT int _WebNodeIsActive(WebNodeRef handle);
EXPORT void _WebNodeSetActive(WebNodeRef handle, int active);
EXPORT int _WebNodeInActiveChain(WebNodeRef handle);
EXPORT int _WebNodeIsDragged(WebNodeRef handle);
EXPORT void _WebNodeSetDragged(WebNodeRef handle, int dragged);
EXPORT int _WebNodeIsHovered(WebNodeRef handle);
EXPORT void _WebNodeSetHovered(WebNodeRef handle, int hovered);
EXPORT int _WebNodeIsInert(WebNodeRef handle);
EXPORT WebNodeRef _WebNodeOwnerShadowHost(WebNodeRef handle);
EXPORT WebNodeRef _WebNodeContainingShadowRoot(WebNodeRef handle);
EXPORT WebNodeRef _WebNodeShadowRoot(WebNodeRef handle);
EXPORT void _WebNodeGetTextContent(WebNodeRef handle, void* peer, void(*cb)(void*, const char*, size_t));
EXPORT void _WebNodeSetTextContent(WebNodeRef handle, const char* text);
EXPORT void _WebNodeGetBoundingBox(WebNodeRef handle, int* x, int* y, int* width, int* height);
EXPORT LayerRef _WebNodeGetContentsLayer(WebNodeRef handle);
EXPORT WebNodeRef _WebNodeInsertBefore(WebNodeRef handle, WebNodeRef node, WebNodeRef anchor);
EXPORT WebNodeRef _WebNodeReplaceChild(WebNodeRef handle, WebNodeRef newChild, WebNodeRef old);
EXPORT WebNodeRef _WebNodeRemoveChild(WebNodeRef handle, WebNodeRef child);
EXPORT WebNodeRef _WebNodeAppendChild(WebNodeRef handle, WebNodeRef child);
EXPORT WebNodeRef _WebNodeClone(WebNodeRef handle, int deep);
EXPORT int _WebNodeIsDescendantOf(WebNodeRef handle, WebNodeRef other);
EXPORT int _WebNodeContains(WebNodeRef handle, WebNodeRef other);
EXPORT int _WebNodeHasEditableStyle(WebNodeRef handle);
EXPORT int _WebNodeAddEventListener(WebNodeRef handle, const char* event_type, void* state, void(*on_event)(void*,void*));
EXPORT int _WebNodeRemoveEventListener(WebNodeRef handle, const char* event_type, void* state);
EXPORT void _WebNodeRemoveAllEventListeners(WebNodeRef handle);

// WebDocumentType
EXPORT const char* _WebDocumentTypeGetName(WebNodeRef handle);

// WebDocument
EXPORT const char* _WebDocumentGetURL(WebNodeRef handle);
EXPORT const char* _WebDocumentGetEncoding(WebNodeRef handle);
EXPORT const char* _WebDocumentGetContentLanguage(WebNodeRef handle);
EXPORT const char* _WebDocumentGetReferrer(WebNodeRef handle);
EXPORT WebLocalDomWindowRef _WebDocumentGetDomWindow(WebNodeRef handle);
EXPORT void _WebDocumentGetThemeColor(WebNodeRef handle, uint8_t* a, uint8_t* r, uint8_t* g, uint8_t* b);
EXPORT const char* _WebDocumentOpenSearchDescriptionURL(WebNodeRef handle);
EXPORT WebFrameRef _WebDocumentGetFrame(WebNodeRef handle);
EXPORT int _WebDocumentIsHTMLDocument(WebNodeRef handle);
EXPORT int _WebDocumentIsXHTMLDocument(WebNodeRef handle);
EXPORT int _WebDocumentIsPluginDocument(WebNodeRef handle);
EXPORT int _WebDocumentIsXMLDocument(WebNodeRef handle);
EXPORT int _WebDocumentIsImageDocument(WebNodeRef handle);
EXPORT int _WebDocumentIsSVGDocument(WebNodeRef handle);
EXPORT int _WebDocumentIsMediaDocument(WebNodeRef handle);
EXPORT int _WebDocumentIsSrcdocDocument(WebNodeRef handle);
EXPORT int _WebDocumentIsMobileDocument(WebNodeRef handle);
EXPORT const char* _WebDocumentGetBaseURL(WebNodeRef handle);
EXPORT WebNodeRef _WebDocumentGetDocumentElement(WebNodeRef handle);
EXPORT WebNodeRef _WebDocumentGetBody(WebNodeRef handle);
EXPORT WebNodeRef _WebDocumentGetHead(WebNodeRef handle);
EXPORT const char* _WebDocumentGetTitle(WebNodeRef handle);
EXPORT HTMLCollectionRef _WebDocumentGetAll(WebNodeRef handle);
EXPORT HTMLCollectionRef _WebDocumentGetImages(WebNodeRef handle);
EXPORT HTMLCollectionRef _WebDocumentGetEmbeds(WebNodeRef handle);
EXPORT HTMLCollectionRef _WebDocumentGetApplets(WebNodeRef handle);
EXPORT HTMLCollectionRef _WebDocumentGetLinks(WebNodeRef handle);
EXPORT HTMLCollectionRef _WebDocumentGetForms(WebNodeRef handle);
EXPORT HTMLCollectionRef _WebDocumentGetAnchors(WebNodeRef handle);
EXPORT HTMLCollectionRef _WebDocumentGetScripts(WebNodeRef handle);
EXPORT HTMLCollectionRef _WebDocumentGetElementsByTagName(WebNodeRef handle, const char* tag);
EXPORT WebNodeRef _WebDocumentCreateElement(WebNodeRef handle, const char* tag_name);
EXPORT const char* _WebDocumentGetManifestURL(WebNodeRef handle);
EXPORT int _WebDocumentManifestUseCredentials(WebNodeRef handle);
//EXPORT const char*  _WebDocumentGetFirstPartyForCookies(WebNodeRef handle);
EXPORT WebNodeRef _WebDocumentGetFocusedElement(WebNodeRef handle);
EXPORT WebNodeRef _WebDocumentGetDoctype(WebNodeRef handle);
EXPORT WebNodeRef _WebDocumentGetFullscreenElement(WebNodeRef handle);
EXPORT const char* _WebDocumentOutgoingReferrer(WebNodeRef handle);
EXPORT WebNodeRef _WebDocumentGetAccessibilityObject(WebNodeRef handle);
EXPORT int _WebDocumentIsSecureContext(WebNodeRef handle, const char* cstr);
EXPORT WebNodeRef _WebDocumentForms(WebNodeRef handle);
EXPORT const char* _WebDocumentCompleteURL(WebNodeRef handle, const char* cstr);
EXPORT WebNodeRef _WebDocumentGetElementById(WebNodeRef handle, const char* id);
EXPORT void _WebDocumentCancelFullScreen(WebNodeRef handle);
EXPORT WebAXObjectRef _WebDocumentAccessibilityObjectFromID(WebNodeRef handle, int id);
// warning: the string should be owned
EXPORT void _WebDocumentInsertStyleSheet(WebNodeRef handle,  const char* keycstr, const char* cstr);
EXPORT void _WebDocumentWatchCSSSelectors(WebNodeRef handle, const char* selectors[], int len);
EXPORT JavascriptDataRef _WebDocumentRegisterEmbedderCustomElement(WebNodeRef handle, const char* cstr, JavascriptDataRef options, int* exception);
EXPORT void _WebDocumentUpdateStyleAndLayoutTree(WebNodeRef handle);
EXPORT void _WebDocumentUpdateStyleAndLayoutTreeIgnorePendingStylesheets(WebNodeRef handle);
EXPORT void _WebDocumentUpdateStyleAndLayoutTreeForNode(WebNodeRef handle, WebNodeRef node);
EXPORT void _WebDocumentUpdateStyleAndLayout(WebNodeRef handle);
EXPORT WebSelectorQueryRef _WebDocumentQuerySelector(WebNodeRef handle, const char* query);
EXPORT WebNodeRef _WebDocumentCreateTextNode(WebNodeRef handle, const char* text);
EXPORT WebRangeRef _WebDocumentGetCaretRangeFromPoint(WebNodeRef handle, int x, int y);
EXPORT WebNodeRef _WebDocumentGetScrollingElement(WebNodeRef handle);
EXPORT LocationRef _WebDocumentGetLocation(WebNodeRef handle);

// SelectorQuery
EXPORT void _WebSelectorQueryDestroy(WebSelectorQueryRef handle);
EXPORT WebNodeRef _WebSelectorQueryFirst(WebSelectorQueryRef handle, WebNodeRef container);

// DocumentFragment
EXPORT WebNodeRef _WebDocumentFragmentCreate(WebNodeRef document);
EXPORT int _WebDocumentFragmentIsTemplateContent(WebNodeRef handle);
EXPORT void _WebDocumentFragmentParseHTML(WebNodeRef handle, const char* html, WebNodeRef context);
EXPORT int _WebDocumentFragmentParseXML(WebNodeRef handle, const char* xml, WebNodeRef context);

// DocumentLoader
EXPORT WebURLRequestRef _WebDocumentLoaderGetRequest(WebDocumentLoaderRef handle);
EXPORT WebURLResponseRef _WebDocumentLoaderGetResponse(WebDocumentLoaderRef handle);
EXPORT int _WebDocumentLoaderHasUnreachableUrl(WebDocumentLoaderRef handle);
// NOTE: on the caller responsability to free the heap allocated resource
EXPORT char* _WebDocumentLoaderGetUrl(WebDocumentLoaderRef handle, int* len);
EXPORT void _WebDocumentLoaderResetSourceLocation(WebDocumentLoaderRef handle);
EXPORT void _WebDocumentLoaderSetUserActivated(WebDocumentLoaderRef handle);
EXPORT void _WebDocumentLoaderSetServiceWorkerNetworkProvider(WebDocumentLoaderRef handle, WebServiceWorkerNetworkProviderRef provider);
EXPORT void _WebDocumentLoaderSetNavigationStartTime(WebDocumentLoaderRef handle, int64_t microseconds);

// WebElement
EXPORT int _WebElementIsFormControlElement(WebNodeRef handle);
EXPORT int _WebElementIsTextControlElement(WebNodeRef handle);
EXPORT int _WebElementIsEditable(WebNodeRef handle);
EXPORT int _WebElementIsHTMLElement(WebNodeRef handle);
EXPORT const char* _WebElementGetTagName(WebNodeRef handle);
EXPORT const char* _WebElementGetTextContext(WebNodeRef handle);
EXPORT ImageRef _WebElementGetImageContents(WebNodeRef handle);
EXPORT void _WebElementGetBoundsInViewportSpace(WebNodeRef handle, int* x, int* y, int* w, int* h);
EXPORT int _WebElementGetAttributeCount(WebNodeRef handle);
EXPORT int _WebElementHasNonEmptyLayoutSize(WebNodeRef handle);
EXPORT int _WebElementHasTagName(WebNodeRef handle, const char* tagname);
EXPORT int _WebElementHasAttribute(WebNodeRef handle, const char* attrname);
EXPORT void _WebElementRemoveAttribute(WebNodeRef handle, const char* cstr);
EXPORT const char* _WebElementGetAttribute(WebNodeRef handle, const char* cstr);
EXPORT int _WebElementSetAttribute(WebNodeRef handle, const char* nameCstr, const char* valueCstr);
EXPORT void _WebElementRequestFullscreen(WebNodeRef handle);
EXPORT const char* _WebElementAttributeLocalName(WebNodeRef handle, int index);
EXPORT const char* _WebElementAttributeValue(WebNodeRef handle, int index);
EXPORT const char* _WebElementGetOuterHtml(WebNodeRef handle);
EXPORT void _WebElementSetOuterHtml(WebNodeRef handle, const char* html, int html_size);
EXPORT char* _WebElementGetInnerHtml(WebNodeRef handle, const char* cmp, int* len);
EXPORT void _WebElementSetInnerHtml(WebNodeRef handle, const char* html, int html_size);
EXPORT WebNodeRef _WebElementGetShadowRoot(WebNodeRef handle);
EXPORT void _WebElementSetInlineStylePropertyDouble(WebNodeRef handle, const char* property, double value, int type);
EXPORT void _WebElementSetInlineStylePropertyString(WebNodeRef handle, const char* property, const char* value);
EXPORT int _WebElementRemoveInlineStyleProperty(WebNodeRef handle, const char* property);
EXPORT void _WebElementRemoveAllInlineStyleProperties(WebNodeRef handle);
EXPORT int _WebElementGetIntegralAttribute(WebNodeRef handle, const char* name);
EXPORT void _WebElementSetIntegralAttribute(WebNodeRef handle, const char* name, int value);
EXPORT void _WebElementSetUnsignedIntegralAttribute(WebNodeRef handle, const char* name, unsigned value);

// WebContainerNode
EXPORT WebNodeRef _WebContainerNodeAppendChild(WebNodeRef handle, WebNodeRef child);
EXPORT WebNodeRef _WebContainerNodeRemoveChild(WebNodeRef handle, WebNodeRef child);

/*
 *
 */

EXPORT WebNodeRef _HTMLAnchorElementCreate(WebNodeRef document);
EXPORT WebNodeRef _HTMLAreaElementCreate(WebNodeRef document);
EXPORT WebNodeRef _HTMLAudioElementCreate(WebNodeRef document);
//EXPORT WebNodeRef _HTMLBaseElementCreate(WebNodeRef document);
EXPORT WebNodeRef _HTMLBodyElementCreate(WebNodeRef document);
EXPORT WebNodeRef _HTMLBrElementCreate(WebNodeRef document);
EXPORT WebNodeRef _HTMLContentElementCreate(WebNodeRef document);
EXPORT WebNodeRef _HTMLDataElementCreate(WebNodeRef document);
//EXPORT WebNodeRef _HTMLDetailsElementCreate(WebNodeRef document);
//EXPORT WebNodeRef _HTMLDialogElementCreate(WebNodeRef document);
//EXPORT WebNodeRef _HTMLDirectoryElementCreate(WebNodeRef document);
//EXPORT WebNodeRef _HTMLDlistElementCreate(WebNodeRef document);
//EXPORT WebNodeRef _HTMLDocumentCreate(WebNodeRef document);
EXPORT WebNodeRef _HTMLEmbedElementCreate(WebNodeRef document);
//EXPORT WebNodeRef _HTMLFontElementCreate(WebNodeRef document);
EXPORT WebNodeRef _HTMLFrameOwnerElementCreate(const char* name, WebNodeRef document);
//EXPORT WebNodeRef _HTMLFrameSetElementCreate(WebNodeRef document);
EXPORT WebNodeRef _HTMLHeadElementCreate(WebNodeRef document);
//EXPORT WebNodeRef _HTMLHeadingElementCreate(const char* name, WebNodeRef document);
//EXPORT WebNodeRef _HTMLHrElementCreate(WebNodeRef document);
EXPORT WebNodeRef _HTMLHtmlElementCreate(WebNodeRef document);
EXPORT WebNodeRef _HTMLIFrameElementCreate(WebNodeRef document);
//EXPORT WebNodeRef _HTMLLiElementCreate(WebNodeRef document);
EXPORT WebNodeRef _HTMLLinkElementCreate(WebNodeRef document);
EXPORT WebNodeRef _HTMLMapElementCreate(WebNodeRef document);
//EXPORT WebNodeRef _HTMLMarqueeElementCreate(WebNodeRef document);
EXPORT WebNodeRef _HTMLMediaElementCreate(const char*, WebNodeRef document);
//EXPORT WebNodeRef _HTMLMenuElementCreate(WebNodeRef document);
EXPORT WebNodeRef _HTMLMetaElementCreate(WebNodeRef document);
EXPORT WebNodeRef _HTMLMeterElementCreate(WebNodeRef document);
//EXPORT WebNodeRef _HTMLModElementCreate(const char*, WebNodeRef document);
//EXPORT WebNodeRef _HTMLNoEmbedElementCreate(WebNodeRef document);
//EXPORT WebNodeRef _HTMLNoScriptElementCreate(WebNodeRef document);
EXPORT WebNodeRef _HTMLObjectElementCreate(WebNodeRef document);
//EXPORT WebNodeRef _HTMLOlistElementCreate(WebNodeRef document);
EXPORT WebNodeRef _HTMLParagraphElementCreate(WebNodeRef document);
//EXPORT WebNodeRef _HTMLParamElementCreate(WebNodeRef document);
//EXPORT WebNodeRef _HTMLPictureElementCreate(WebNodeRef document);
EXPORT WebNodeRef _HTMLPluginElementCreate(const char*, WebNodeRef document);
//EXPORT WebNodeRef _HTMLPreElementCreate(const char*, WebNodeRef document);
EXPORT WebNodeRef _HTMLProgressElementCreate(WebNodeRef document);
//EXPORT WebNodeRef _HTMLQuoteElementCreate(const char* name, WebNodeRef document);
//EXPORT WebNodeRef _HTMLRtElementCreate(WebNodeRef document);
//EXPORT WebNodeRef _HTMLRubyElementCreate(WebNodeRef document);
EXPORT WebNodeRef _HTMLScriptElementCreate(WebNodeRef document);
//EXPORT WebNodeRef _HTMLShadowElementCreate(WebNodeRef document);
EXPORT WebNodeRef _HTMLSlotElementCreate(WebNodeRef document);
//EXPORT WebNodeRef _HTMLSourceElementCreate(WebNodeRef document);
EXPORT WebNodeRef _HTMLSpanElementCreate(WebNodeRef document);
EXPORT WebNodeRef _HTMLStyleElementCreate(WebNodeRef document);
//EXPORT WebNodeRef _HTMLSummaryElementCreate(WebNodeRef document);
//EXPORT WebNodeRef _HTMLTableCaptionElementCreate(WebNodeRef document);
EXPORT WebNodeRef _HTMLTableCellElementCreate(const char* name, WebNodeRef document);
//EXPORT WebNodeRef _HTMLTableColElementCreate(const char*, WebNodeRef document);
EXPORT WebNodeRef _HTMLTableElementCreate(WebNodeRef document);
EXPORT WebNodeRef _HTMLTablePartElementCreate(const char* name, WebNodeRef document);
EXPORT WebNodeRef _HTMLTableRowElementCreate(WebNodeRef document);
//EXPORT WebNodeRef _HTMLTableRowsCollectionCreate(WebNodeRef document);
//EXPORT WebNodeRef _HTMLTableSectionElementCreate(const char* name, WebNodeRef document);
//EXPORT WebNodeRef _HTMLTagCollectionCreate(WebNodeRef document);
EXPORT WebNodeRef _HTMLTimeElementCreate(WebNodeRef document);
//EXPORT WebNodeRef _HTMLTitleElementCreate(WebNodeRef document);
//EXPORT WebNodeRef _HTMLUlistElementCreate(WebNodeRef document);
//EXPORT WebNodeRef _HTMLUnknownElementCreate(const char* name, WebNodeRef document);

EXPORT WebNodeRef _HTMLVideoElementCreate(WebNodeRef document);
EXPORT int _HTMLVideoElementGetVideoWidth(WebNodeRef reference);
EXPORT int _HTMLVideoElementGetVideoHeight(WebNodeRef reference);
EXPORT void _HTMLVideoElementGetVisibleSize(WebNodeRef reference, int* w, int* h);
EXPORT char* _HTMLVideoElementGetPoster(WebNodeRef reference, int* len);
EXPORT void _HTMLVideoElementGetPlaybackQuality(WebNodeRef reference, double* creation, int* total, int* dropped, int* corrupted);
EXPORT int _HTMLVideoElementSupportsFullscreen(WebNodeRef reference);
EXPORT int _HTMLVideoElementDisplayingFullscreen(WebNodeRef reference);
EXPORT uint64_t _HTMLVideoElementGetDecodedFrameCount(WebNodeRef reference);
EXPORT uint64_t _HTMLVideoElementGetDroppedFrameCount(WebNodeRef reference);
EXPORT void _HTMLVideoElementEnterFullscreen(WebNodeRef reference);
EXPORT void _HTMLVideoElementExitFullscreen(WebNodeRef reference);
EXPORT void _HTMLVideoElementPaintCurrentFrame(
  WebNodeRef reference, 
  CanvasRenderingContext2dRef canvas,
  int rx,
  int ry,
  int rw,
  int rh,
  PaintFlagsRef paint);

//EXPORT WebNodeRef _HTMLWbrElementCreate(WebNodeRef document);
/*
 *
 */

EXPORT WebNodeRef _HTMLDivElementCreate(WebNodeRef document);
EXPORT WebNodeRef _HTMLTemplateElementCreate(WebNodeRef document);
EXPORT WebNodeRef _HTMLCanvasElementCreate(WebNodeRef document);
EXPORT WebNodeRef _HTMLFrameElementCreate(WebNodeRef document);
EXPORT WebNodeRef _HTMLFormElementCreate(WebNodeRef document);
EXPORT WebNodeRef _HTMLImageElementCreate(WebNodeRef document);

// HTMLTemplateElement 
EXPORT WebNodeRef _HTMLTemplateElementGetContent(WebNodeRef handle);

// HTMLCanvasElement
EXPORT void _HTMLCanvasElementGetSize(WebNodeRef handle, int* width, int* height);
EXPORT void _HTMLCanvasElementSetSize(WebNodeRef handle, int width, int height);
EXPORT LayerRef _HTMLCanvasElementGetLayer(WebNodeRef handle);
EXPORT CanvasRenderingContext2dRef _HTMLCanvasElementCreateContext(WebNodeRef handle, const char* type);
EXPORT OffscreenCanvasRef _HTMLCanvasElementTransferControlToOffscreen(WebNodeRef handle);

// HTMLFrameElement
EXPORT int _HTMLFrameElementGetHasFrameBorder(WebNodeRef handle);
EXPORT int _HTMLFrameElementGetNoResize(WebNodeRef handle);


// HTMLImageElement
EXPORT int _HTMLImageElementGetX(WebNodeRef handle);
EXPORT int _HTMLImageElementGetY(WebNodeRef handle);
EXPORT int _HTMLImageElementGetWidth(WebNodeRef handle);
EXPORT void _HTMLImageElementSetWidth(WebNodeRef handle, int width);
EXPORT int _HTMLImageElementGetHeight(WebNodeRef handle);
EXPORT void _HTMLImageElementSetHeight(WebNodeRef handle, int height);
EXPORT int _HTMLImageElementGetNaturalWidth(WebNodeRef handle);
EXPORT int _HTMLImageElementGetNaturalHeight(WebNodeRef handle);
EXPORT int _HTMLImageElementGetLayoutBoxWidth(WebNodeRef handle);
EXPORT int _HTMLImageElementGetLayoutBoxHeight(WebNodeRef handle);
EXPORT char* _HTMLImageElementGetCurrentSrc(WebNodeRef handle, int* len);
EXPORT int _HTMLImageElementIsServerMap(WebNodeRef handle);
EXPORT char* _HTMLImageElementGetAltText(WebNodeRef handle, int* len);
EXPORT ImageRef _HTMLImageElementGetImage(WebNodeRef handle);
EXPORT void _HTMLImageElementSetImage(WebNodeRef handle, ImageRef image);
EXPORT int _HTMLImageElementIsLoaded(WebNodeRef handle);
EXPORT int _HTMLImageElementIsLoading(WebNodeRef handle);
EXPORT int _HTMLImageElementErrorOccurred(WebNodeRef handle);
EXPORT int _HTMLImageElementLoadFailedOrCancelled(WebNodeRef handle);
EXPORT char* _HTMLImageElementGetSrc(WebNodeRef handle, int* len);
EXPORT void _HTMLImageElementSetSrc(WebNodeRef handle, const char* src);
EXPORT int _HTMLImageIsComplete(WebNodeRef handle);
EXPORT int _HTMLImageHasPendingActivity(WebNodeRef handle);
EXPORT int _HTMLImageCanContainRangeEndPoint(WebNodeRef handle);
EXPORT int _HTMLImageIsCollapsed(WebNodeRef handle);
EXPORT WebNodeRef _HTMLImageElementGetFormOwner(WebNodeRef handle);
EXPORT void _HTMLImageSetIsFallbackImage(WebNodeRef handle);
EXPORT void _HTMLImageForceReload(WebNodeRef handle);

// HMTLMediaElement
EXPORT double _HTMLMediaElementGetEffectiveMediaVolume(WebNodeRef handle);
EXPORT int _HTMLMediaElementIsHtmlAudioElement(WebNodeRef handle);
EXPORT int _HTMLMediaElementIsHtmlVideoElement(WebNodeRef handle);
EXPORT int _HTMLMediaElementGetLoadType(WebNodeRef handle);
EXPORT int _HTMLMediaElementHasMediaSource(WebNodeRef handle);
EXPORT int _HTMLMediaElementHasVideo(WebNodeRef handle);
EXPORT int _HTMLMediaElementHasAudio(WebNodeRef handle);
EXPORT LayerRef _HTMLMediaElementGetWebLayer(WebNodeRef handle);
EXPORT int _HTMLMediaElementHasRemoteRoutes(WebNodeRef handle);
EXPORT int _HTMLMediaElementIsPlayingRemotely(WebNodeRef handle);
EXPORT int _HTMLMediaElementGetReadyState(WebNodeRef handle);
EXPORT int _HTMLMediaElementIsSeeking(WebNodeRef handle);
EXPORT void _HTMLMediaElementGetPlayed(WebNodeRef handle, int* len, double** start, double** end);
EXPORT void _HTMLMediaElementGetSeekable(WebNodeRef handle, int* len, double** start, double** end);
EXPORT int _HTMLMediaElementEnded(WebNodeRef handle);
EXPORT double _HTMLMediaElementGetCurrentTime(WebNodeRef handle);
EXPORT void _HTMLMediaElementSetCurrentTime(WebNodeRef handle, double value);
EXPORT double _HTMLMediaElementGetDuration(WebNodeRef handle);
EXPORT int _HTMLMediaElementIsPaused(WebNodeRef handle);
EXPORT double _HTMLMediaElementGetDefaultPlaybackRate(WebNodeRef handle);
EXPORT void _HTMLMediaElementSetDefaultPlaybackRate(WebNodeRef handle, double value);
EXPORT double _HTMLMediaElementGetPlaybackRate(WebNodeRef handle);
EXPORT void _HTMLMediaElementSetPlaybackRate(WebNodeRef handle, double value);
EXPORT void* _HTMLMediaElementGetError(WebNodeRef handle);
EXPORT char* _HTMLMediaElementGetSrc(WebNodeRef handle, int* len);
EXPORT void _HTMLMediaElementSetSrc(WebNodeRef handle, const char* src);
EXPORT void* _HTMLMediaElementGetSrcObject(WebNodeRef handle);
EXPORT void _HTMLMediaElementSetSrcObject(WebNodeRef handle, WebMediaStreamDescriptorRef src);
EXPORT int _HTMLMediaElementGetNetworkState(WebNodeRef handle);
EXPORT char* _HTMLMediaElementGetPreload(WebNodeRef handle, int* len);
EXPORT void _HTMLMediaElementSetPreload(WebNodeRef handle, const char* value);
EXPORT int _HTMLMediaElementGetPreloadType(WebNodeRef handle);
EXPORT char* _HTMLMediaElementGetEffectivePreload(WebNodeRef handle, int* len);
EXPORT int _HTMLMediaElementGetEffectivePreloadType(WebNodeRef handle);
EXPORT void _HTMLMediaElementGetBuffered(WebNodeRef handle, int* len, double** start, double** end);
EXPORT int _HTMLMediaElementAutoplay(WebNodeRef handle);
//EXPORT int _HTMLMediaElementShouldAutoplay(WebNodeRef handle);
EXPORT int _HTMLMediaElementGetLoop(WebNodeRef handle);
EXPORT void _HTMLMediaElementSetLoop(WebNodeRef handle, int value);
EXPORT int _HTMLMediaElementGetAudioDecodedByteCount(WebNodeRef handle);
EXPORT int _HTMLMediaElementGetVideoDecodedByteCount(WebNodeRef handle);
EXPORT int _HTMLMediaElementIsInCrossOriginFrame(WebNodeRef handle);
EXPORT double _HTMLMediaElementGetVolume(WebNodeRef handle);
EXPORT void _HTMLMediaElementSetVolume(WebNodeRef handle, double value);
EXPORT int _HTMLMediaElementGetMuted(WebNodeRef handle);
EXPORT void _HTMLMediaElementSetMuted(WebNodeRef handle, int value);
EXPORT int _HTMLMediaElementIsFullscreen(WebNodeRef handle);
EXPORT int _HTMLMediaElementUsesOverlayFullscreenVideo(WebNodeRef handle);
EXPORT int _HTMLMediaElementHasClosedCaptions(WebNodeRef handle);
EXPORT int _HTMLMediaElementTextTracksVisible(WebNodeRef handle);
EXPORT MediaControlsRef _HTMLMediaElementGetMediaControls(WebNodeRef handle);
EXPORT MediaAudioSourceNodeRef _HTMLMediaElementGetAudioSourceNode(WebNodeRef handle);
EXPORT void _HTMLMediaElementSetAudioSourceNode(WebNodeRef handle, MediaAudioSourceNodeRef node);
EXPORT void* _HTMLMediaElementGetControlsList(WebNodeRef handle);
EXPORT int _HTMLMediaElementSupportsPictureInPicture(WebNodeRef handle);
EXPORT double _HTMLMediaElementLastSeekTime(WebNodeRef handle);
EXPORT AudioTrackRef* _HTMLMediaElementGetAudioTracks(WebNodeRef handle, int* len);
EXPORT VideoTrackRef* _HTMLMediaElementGetVideoTracks(WebNodeRef handle, int* len);
EXPORT TextTrackRef* _HTMLMediaElementGetTextTracks(WebNodeRef handle, int* len);
EXPORT CueTimelineRef _HTMLMediaElementGetCueTimeline(WebNodeRef handle);
EXPORT int _HTMLMediaElementTextTracksAreReady(WebNodeRef handle);
EXPORT int _HTMLMediaElementShouldShowControls(WebNodeRef handle);
EXPORT void _HTMLMediaElementScheduleTextTrackResourceLoad(WebNodeRef handle);
EXPORT void _HTMLMediaElementLoad(WebNodeRef handle);
EXPORT char* _HTMLMediaElementCanPlayType(WebNodeRef handle, const char* mime, int* len);
EXPORT void _HTMLMediaElementUpdatePlaybackRate(WebNodeRef handle);
EXPORT void _HTMLMediaElementPlay(WebNodeRef handle);
EXPORT void _HTMLMediaElementPause(WebNodeRef handle);
EXPORT void _HTMLMediaElementRequestRemotePlayback(WebNodeRef handle);
EXPORT void _HTMLMediaElementRequestRemotePlaybackControl(WebNodeRef handle);
EXPORT void _HTMLMediaElementRequestRemotePlaybackStop(WebNodeRef handle);
EXPORT void _HTMLMediaElementCloseMediaSource(WebNodeRef handle);
EXPORT void _HTMLMediaElementDurationChanged(WebNodeRef handle, double duration, double request_seek);
EXPORT void _HTMLMediaElementEnterPictureInPicture(WebNodeRef handle);
EXPORT void _HTMLMediaElementExitPictureInPicture(WebNodeRef handle);
EXPORT void _HTMLMediaElementTogglePlayState(WebNodeRef handle);
EXPORT void _HTMLMediaElementAudioTrackChanged(WebNodeRef handle, void* audio_track);
EXPORT void _HTMLMediaElementSelectedVideoTrackChanged(WebNodeRef handle, void* video_track);
EXPORT TextTrackRef _HTMLMediaElementAddTextTrackWithStrings(WebNodeRef handle, const char* kind, const char* label, const char* lang);
//EXPORT void _HTMLMediaElementAddTextTrack(WebNodeRef handle, void* text_track);
//EXPORT void _HTMLMediaElementRemoveTextTrack(WebNodeRef handle, void* text_track);
//EXPORT void _HTMLMediaElementTextTracksChanged(WebNodeRef handle);
//EXPORT void _HTMLMediaElementNotifyMediaPlayerOfTextTrackChanges(WebNodeRef handle);
EXPORT void _HTMLMediaElementConfigureTextTrackDisplay(WebNodeRef handle);
EXPORT void _HTMLMediaElementUpdateTextTrackDisplay(WebNodeRef handle);
EXPORT void _HTMLMediaElementTextTrackReadyStateChanged(WebNodeRef handle, void* text_track);
EXPORT void _HTMLMediaElementTextTrackModeChanged(WebNodeRef handle, void* text_track);
EXPORT void _HTMLMediaElementDisableAutomaticTextTrackSelection(WebNodeRef handle);
EXPORT void _HTMLMediaElementAutomaticTrackSelectionForUpdatedUserPreference(WebNodeRef handle);
EXPORT void _HTMLMediaElementScheduleEvent(WebNodeRef handle, WebEventRef event);

EXPORT WebNodeRef _HTMLInputElementCreate(WebNodeRef document);
EXPORT char* _HTMLInputElementGetValue(WebNodeRef handle, int* len);
EXPORT void _HTMLInputElementSetValue(WebNodeRef handle, const char* value);

// HTMLCollection
EXPORT void _HTMLCollectionDestroy(HTMLCollectionRef handle);
EXPORT int _HTMLCollectionLenght(HTMLCollectionRef handle);
EXPORT int _HTMLCollectionIsEmpty(HTMLCollectionRef handle);
EXPORT void _HTMLCollectionReset(HTMLCollectionRef handle);
EXPORT void _HTMLCollectionAssign(HTMLCollectionRef handle, HTMLCollectionRef other);
EXPORT WebNodeRef _HTMLCollectionGetNextItem(HTMLCollectionRef handle);
EXPORT WebNodeRef _HTMLCollectionGetFirstItem(HTMLCollectionRef handle);
EXPORT WebNodeRef _HTMLCollectionGetLastItem(HTMLCollectionRef handle);

EXPORT void _WebElementArrayDestroy(WebElementArrayRef handle);
EXPORT int _WebElementArrayLenght(WebElementArrayRef handle);
EXPORT WebNodeRef _WebElementArrayGetElementAt(WebElementArrayRef handle, int index);

EXPORT const char* _WebFormElementGetAction(WebNodeRef handle);
EXPORT const char* _WebFormElementGetName(WebNodeRef handle);
EXPORT const char* _WebFormElementGetMethod(WebNodeRef handle);
//EXPORT int _WebFormElementWasUserSubmitted(WebNodeRef handle);
EXPORT int _WebFormElementShouldAutoComplete(WebNodeRef handle);
EXPORT void _WebFormElementGetNamedElements(WebNodeRef handle, const char* name, WebNodeRef* elementsOut, int* elemLen);
//EXPORT void _WebFormElementGetFormControlElements(WebNodeRef handle, WebNodeRef* elementsOut, int* elemLen);
EXPORT int _WebFormElementCheckValidity(WebNodeRef handle);
//EXPORT void _WebFormElementFinishRequestAutocomplete(WebNodeRef handle, int autocomplete);

EXPORT int _WebFormControlElementIsEnabled(WebNodeRef handle);
EXPORT int _WebFormControlElementIsReadonly(WebNodeRef handle);
EXPORT const char* _WebFormControlElementGetFormControlName(WebNodeRef handle);
EXPORT const char* _WebFormControlElementGetFormControlType(WebNodeRef handle);
EXPORT int _WebFormControlElementIsAutofilled(WebNodeRef handle);
EXPORT void _WebFormControlElementSetIsAutofilled(WebNodeRef handle, int autofilled);
EXPORT int _WebFormControlElementShouldAutocomplete(WebNodeRef handle);
EXPORT const char* _WebFormControlElementGetValue(WebNodeRef handle);
EXPORT void _WebFormControlElementSetValue(WebNodeRef handle, const char* value); 
EXPORT const char* _WebFormControlElementGetSuggestedValue(WebNodeRef handle);
EXPORT void _WebFormControlElementSetSuggestedValue(WebNodeRef handle, const char* value);
EXPORT const char* _WebFormControlElementGetEditingValue(WebNodeRef handle);
EXPORT int _WebFormControlElementGetSelectionStart(WebNodeRef handle);
EXPORT int _WebFormControlElementGetSelectionEnd(WebNodeRef handle);
EXPORT const char* _WebFormControlElementGetDirectionForFormData(WebNodeRef handle);
EXPORT const char* _WebFormControlElementGetNameForAutofill(WebNodeRef handle);
EXPORT WebNodeRef _WebFormControlElementGetForm(WebNodeRef handle);
EXPORT void _WebFormControlElementSetSelectionRange(WebNodeRef handle, int start, int end);

EXPORT void _WebAXObjectDestroy(WebAXObjectRef handle);

EXPORT const char* _WebShadowRootGetInnerHtml(WebNodeRef handle);
EXPORT void _WebShadowRootSetInnerHtml(WebNodeRef handle, const char* value, int size);
EXPORT CSSStyleSheetListRef _WebShadowRootGetStyleSheetList(WebNodeRef handle);
EXPORT void _WebShadowRootSetStyleSheetList(WebNodeRef handle, CSSStyleSheetListRef list);

EXPORT WebNodeRef _WebElementCreateShadowRoot(WebNodeRef handle);
EXPORT WebNodeRef _WebElementCreateUserAgentShadowRoot(WebNodeRef handle);
EXPORT void _WebElementAttachShadowRoot(WebNodeRef handle, int type);

// // WebWidget
EXPORT void _WebWidgetClose(WebWidgetRef handle);
EXPORT void _WebWidgetSize(WebWidgetRef handle, int* width, int* height);
//EXPORT void _WebWidgetWillStartLiveResize(WebWidgetRef handle);
EXPORT void _WebWidgetResize(WebWidgetRef handle, int width, int height);
EXPORT void _WebWidgetResizeVisualViewport(WebWidgetRef handle, int width, int height);
//EXPORT void _WebWidgetWillEndLiveResize(WebWidgetRef handle);
EXPORT void _WebWidgetDidEnterFullScreen(WebWidgetRef handle); 
EXPORT void _WebWidgetDidExitFullScreen(WebWidgetRef handle);
EXPORT void _WebWidgetBeginFrame(WebWidgetRef handle, double lastFrameTimeMonotonic);
EXPORT void _WebWidgetUpdateAllLifecyclePhases(WebWidgetRef handle);
EXPORT void _WebWidgetUpdateLifecycle(WebWidgetRef handle, WebLifecycleUpdateEnum requested_update);
EXPORT void _WebWidgetPaint(WebWidgetRef handle, CanvasRef canvas, int vx, int vy, int vw, int vh);
EXPORT void _WebWidgetPaintIgnoringCompositing(WebWidgetRef handle, CanvasRef canvas, int x, int y, int w, int h);
EXPORT void _WebWidgetLayoutAndPaintAsync(WebWidgetRef handle, WebLayoutAndPaintAsyncCallback cb);
EXPORT void _WebWidgetCompositeAndReadbackAsync(WebWidgetRef handle, WebCompositeAndReadbackAsyncCallback cb);
EXPORT void _WebWidgetThemeChanged(WebWidgetRef handle);
// TODO: We are completely losing information giving we are dealing this in a generic way
// we will need to have a method for each type of input event, so we can pass the relevant information
// according to each type of event
EXPORT int _WebWidgetHandleInputEvent(WebWidgetRef handle, WebInputEventRef event);
EXPORT void _WebWidgetSetCursorVisibilityState(WebWidgetRef handle, int isVisible);
//EXPORT int _WebWidgetHasTouchEventHandlersAt(WebWidgetRef handle, int x, int y);
EXPORT void _WebWidgetApplyViewportDeltas(WebWidgetRef handle, 
  float visualViewportDeltaWidth,
  float visualViewportDeltaHeight, 
  float layoutViewportDeltaWidth,
  float layoutViewportDeltaHeight,
  float elasticOverscrollDeltaWidth,
  float elasticOverscrollDeltaHeight,
  float scaleFactor, 
  float topControlsShownRatioDelta);

// EXPORT void _WebWidgetRecordFrameTimingEvent(WebWidgetRef handle, WebViewFrameTimingEventEnum eventType, int64_t RectId, unsigned* sourceFrame, 
//     double* startTime,
//     double* finishTime,
//     int lenght);

EXPORT void _WebWidgetMouseCaptureLost(WebWidgetRef handle);

EXPORT void _WebWidgetSetFocus(WebWidgetRef handle, int focus);

// EXPORT int _WebWidgetSetComposition(WebWidgetRef handle, 
//   const char* text,
//   unsigned* startOffset,
//   unsigned* endOffset,
//   unsigned* color,
//   int* thick,
//   unsigned* backgroundColor,
//   int lenght, 
//   int selectionStart,
//   int selectionEnd);

//EXPORT int _WebWidgetConfirmComposition(WebWidgetRef handle);
//EXPORT int _WebWidgetConfirmCompositionConfirm(WebWidgetRef handle, WebViewConfirmCompositionBehaviorEnum selectionBehavior);
//EXPORT int _WebWidgetConfirmCompositionText(WebWidgetRef handle, const char* text);
//EXPORT int _WebWidgetCompositionRange(WebWidgetRef handle, size_t* location, size_t* length);
//EXPORT void _WebWidgetTextInputInfo(WebWidgetRef handle, WebTextInputTypeEnum* type, int* flags, const char** outValue, int* selectionStart, int* selectionEnd, int* compositionStart, int* compositionEnd, const char** outInputMode);
//EXPORT WebTextInputTypeEnum _WebWidgetTextInputType(WebWidgetRef handle);
EXPORT int _WebWidgetSelectionBounds(WebWidgetRef handle, int* ax, int* ay, int* aw, int* ah, int* fx, int* fy, int* fw, int* fh);
//EXPORT int _WebWidgetSelectionTextDirection(WebWidgetRef handle, WebTextDirectionEnum* start, WebTextDirectionEnum* end);
//EXPORT int _WebWidgetIsSelectionAnchorFirst(WebWidgetRef handle);
//EXPORT int _WebWidgetCaretOrSelectionRange(WebWidgetRef handle, size_t* location, size_t* length);
//EXPORT void _WebWidgetSetTextDirection(WebWidgetRef handle, WebTextDirectionEnum dir);
EXPORT int _WebWidgetIsAcceleratedCompositingActive(WebWidgetRef handle);
EXPORT int _WebWidgetIsWebView(WebWidgetRef handle);
EXPORT int _WebWidgetIsWebFrameWidget(WebWidgetRef handle);
EXPORT int _WebWidgetIsPagePopup(WebWidgetRef handle);
EXPORT void _WebWidgetWillCloseLayerTreeView(WebWidgetRef handle);
EXPORT void _WebWidgetDidAcquirePointerLock(WebWidgetRef handle);
EXPORT void _WebWidgetDidNotAcquirePointerLock(WebWidgetRef handle);
EXPORT void _WebWidgetDidLosePointerLock(WebWidgetRef handle);
//EXPORT void _WebWidgetDidChangeWindowResizerRect(WebWidgetRef handle);
EXPORT int _WebWidgetBackgroundColor(WebWidgetRef handle);
EXPORT WebPagePopupRef _WebWidgetPagePopup(WebWidgetRef handle);
//EXPORT void _WebWidgetSetTopControlsHeight(WebWidgetRef handle, float height, int topControlsShrinkLayoutSize);
EXPORT void _WebWidgetUpdateBrowserControlsState(WebWidgetRef handle, WebTopControlsStateEnum constraints, WebTopControlsStateEnum current, int animate);

EXPORT WebWidgetRef _WebViewCreate(void* peer, 
  WebViewClientCbs callbacks,
  WebPageVisibilityStateEnum visibility,
  WebWidgetRef opener,
  void** client_out);
EXPORT void _WebViewDestroy(WebWidgetRef handle);
//EXPORT void _WebViewSetMainFrame(WebWidgetRef handle, WebFrameRef frame);
//EXPORT void _WebViewSetCredentialManagerClient(WebWidgetRef handle, void* client);
EXPORT void _WebViewSetPrerendererClient(WebWidgetRef handle, void* client);
//EXPORT void _WebViewSetSpellCheckClient(WebWidgetRef handle, void* client);
EXPORT WebSettingsRef _WebViewSettings(WebWidgetRef handle);
EXPORT char* _WebViewPageEncoding(WebWidgetRef handle, int* len);
//EXPORT void _WebViewSetPageEncoding(WebWidgetRef handle, const char* encoding);
// EXPORT int _WebViewIsTransparent(WebWidgetRef handle);
// EXPORT void _WebViewSetIsTransparent(WebWidgetRef handle, int transparent);
//EXPORT void _WebViewSetBaseBackgroundColor(WebWidgetRef handle, unsigned color);
EXPORT int _WebViewTabsToLinks(WebWidgetRef handle);
EXPORT void _WebViewSetTabsToLinks(WebWidgetRef handle, int tabs);
EXPORT int _WebViewTabKeyCyclesThroughElements(WebWidgetRef handle);
EXPORT void _WebViewSetTabKeyCyclesThroughElements(WebWidgetRef handle, int tabkeycycle);
EXPORT int _WebViewIsActive(WebWidgetRef handle);
EXPORT void _WebViewSetIsActive(WebWidgetRef handle, int active);
EXPORT void _WebViewSetDomainRelaxationForbidden(WebWidgetRef handle, int forbidden, const char* scheme);
EXPORT void _WebViewSetWindowFeatures(WebWidgetRef handle, 
  float x, 
  int xSet, 
  float y, 
  int ySet, 
  float width, 
  int widthSet, 
  float height, 
  int heightSet, 
  int menuBarVisible, 
  int statusBarVisible, 
  int toolBarVisible, 
  int scrollbarsVisible, 
  int resizable, 
  int noopener, 
  int background, 
  int persistent);

EXPORT void _WebViewSetOpenedByDOM(WebWidgetRef handle);
EXPORT WebFrameRef _WebViewMainFrame(WebWidgetRef handle);
//EXPORT WebFrameRef _WebViewFindFrameByName(WebWidgetRef handle, const char* name, WebFrameRef relativeToFrame);
EXPORT WebFrameRef _WebViewFocusedFrame(WebWidgetRef handle);
EXPORT void _WebViewSetFocusedFrame(WebWidgetRef handle, WebFrameRef frame);
EXPORT void _WebViewFocusDocumentView(WebWidgetRef handle, WebFrameRef frame);
EXPORT void _WebViewSetInitialFocus(WebWidgetRef handle, int reverse);
EXPORT void _WebViewClearFocusedElement(WebWidgetRef handle);
EXPORT int _WebViewZoomToMultipleTargetsRect(WebWidgetRef handle, int rx, int ry, int rw, int rh);
EXPORT double _WebViewZoomLevel(WebWidgetRef handle);
EXPORT double _WebViewSetZoomLevel(WebWidgetRef handle, double level);
EXPORT void _WebViewZoomLimitsChanged(WebWidgetRef handle, double minimumZoomLevel, double maximumZoomLevel);
EXPORT float _WebViewTextZoomFactor(WebWidgetRef handle);
EXPORT float _WebViewSetTextZoomFactor(WebWidgetRef handle, float factor);
EXPORT float _WebViewPageScaleFactor(WebWidgetRef handle);
EXPORT void _WebViewSetPageScaleFactor(WebWidgetRef handle, float scale);
EXPORT void _WebViewSetVisualViewportOffset(WebWidgetRef handle, float px, float py);
EXPORT void _WebViewVisualViewportOffset(WebWidgetRef handle, float* px, float* py);
EXPORT void _WebViewVisualViewportSize(WebWidgetRef handle, float* width, float* height);
EXPORT void _WebViewSetDefaultPageScaleLimits(WebWidgetRef handle, float minScale, float maxScale);
EXPORT void _WebViewSetInitialPageScaleOverride(WebWidgetRef handle, float scale);
EXPORT void _WebViewSetMaximumLegibleScale(WebWidgetRef handle, float scale);
EXPORT void _WebViewResetScrollAndScaleState(WebWidgetRef handle);
EXPORT void _WebViewSetIgnoreViewportTagScaleLimits(WebWidgetRef handle, int limits);
EXPORT void _WebViewContentsPreferredMinimumSize(WebWidgetRef handle, int* width, int* height);
EXPORT void _WebViewSetDisplayMode(WebWidgetRef handle, WebDisplayModeEnum mode);
EXPORT void _WebViewSetDeviceScaleFactor(WebWidgetRef handle, float scale);
EXPORT float _WebViewZoomFactorForDeviceScaleFactor(WebWidgetRef handle);
EXPORT void _WebViewSetZoomFactorForDeviceScaleFactor(WebWidgetRef handle, float scale);
//EXPORT void _WebViewSetDeviceColorProfile(WebWidgetRef handle, char* profile, size_t len);
//EXPORT void _WebViewResetDeviceColorProfile(WebWidgetRef handle);
EXPORT void _WebViewEnableAutoResizeMode(WebWidgetRef handle, int minSizeWidth, int minSizeHeight, int maxSizeWidth, int maxSizeHeight);
EXPORT void _WebViewDisableAutoResizeMode(WebWidgetRef handle);
EXPORT void _WebViewPerformMediaPlayerAction(WebWidgetRef handle, WebMediaPlayerActionEnum action_type, int action_enable, int locationX, int locationY);
EXPORT void _WebViewPerformPluginAction(WebWidgetRef handle, WebPluginActionEnum action_type, int action_enable, int px, int py);
EXPORT WebHitTestResultRef _WebViewHitTestResultAt(WebWidgetRef handle, int px, int py);
EXPORT WebHitTestResultRef _WebViewHitTestResultForTap(WebWidgetRef handle, int tapPointX, int tapPointY, int tapAreaWidth, int tapAreaHeight);
//EXPORT void _WebViewCopyImageAt(WebWidgetRef handle, int px, int py);
//EXPORT void _WebViewSaveImageAt(WebWidgetRef handle, int px, int py);
//EXPORT void _WebViewDragSourceEndedAt(WebWidgetRef handle, int clientX, int clientY, int screenX, int screenY, WebDragOperationEnum operation);
//EXPORT void _WebViewDragSourceSystemDragEnded(WebWidgetRef handle);
// TODO: how to represent WebDragData ?
//EXPORT WebDragOperationEnum _WebViewDragTargetDragEnter(WebWidgetRef handle, WebDragDataRef drag, int clientx, int clienty, int screenx, int screeny, WebDragOperationsMask operationsAllowed, int modifiers);
//EXPORT WebDragOperationEnum _WebViewDragTargetDragOver(WebWidgetRef handle, int clientx, int clienty, int screenx, int screeny, WebDragOperationsMask operationsAllowed, int modifiers);
//EXPORT void _WebViewDragTargetDragLeave(WebWidgetRef handle);
//EXPORT void _WebViewDragTargetDrop(WebWidgetRef handle, int px, int py, int screenx, int screeny, int modifiers);
//EXPORT size_t _WebViewSpellingMarkersLenght(WebWidgetRef handle);
//EXPORT void _WebViewSpellingMarkers(WebWidgetRef handle, uint32_t* markers, size_t* len, size_t maxlen);
//EXPORT void _WebViewRemoveSpellingMarkersUnderWords(WebWidgetRef handle, const char** words, size_t len);
EXPORT unsigned long _WebViewCreateUniqueIdentifierForRequest(WebWidgetRef handle);

typedef enum {
  Desktop = 0,
  Mobile = 1,
} WebScreenPosition;

EXPORT void _WebViewEnableDeviceEmulation(WebWidgetRef handle,
    WebScreenPosition screenPosition,
    int screenSizeWidth,
    int screenSizeHeight,
    int viewPositionX,
    int viewPositionY,
    float deviceScaleFactor,
    int viewSizeWidth,
    int viewSizeHeight,
    //int fitToView,
    float offsetX,
    float offsetY,
    float scale);

EXPORT void _WebViewDisableDeviceEmulation(WebWidgetRef handle);
//EXPORT WebAXObjectRef _WebViewAccessibilityObject(WebWidgetRef handle);
EXPORT void _WebViewPerformCustomContextMenuAction(WebWidgetRef handle, unsigned action);
//EXPORT void _WebViewShowContextMenu(WebWidgetRef handle);
//EXPORT void _WebViewExtractSmartClipData(WebWidgetRef handle, int x, int y, int w, int h, const char* text, const char* html, int* rx, int* ry, int* rw, int* rh);
EXPORT void _WebViewHidePopups(WebWidgetRef handle);
EXPORT void _WebViewSetSelectionColors(WebWidgetRef handle, int activeBackgroundColor, int activeForegroundColor, int inactiveBackgroundColor, int inactiveForegroundColor);
// EXPORT void _WebViewTransferActiveWheelFlingAnimation(WebWidgetRef handle, 
//   int dx, int dy,
//   int px, int py,
//   int gx, int gy,
//   int modifiers,
//   WebGestureDeviceEnum sourceDevice,
//   int cumulativeScrollWidth, int cumulativeScrollHeight,
//   double startTime);

// EXPORT int _WebViewEndActiveFlingAnimation(WebWidgetRef handle);
EXPORT void _WebViewSetShowPaintRects(WebWidgetRef handle, int show);
EXPORT void _WebViewSetShowFPSCounter(WebWidgetRef handle, int show);
EXPORT void _WebViewSetShowScrollBottleneckRects(WebWidgetRef handle, int show);
EXPORT void _WebViewSetVisibilityState(WebWidgetRef handle, WebPageVisibilityStateEnum visibilityState, int isInitialState);
EXPORT void _WebViewSetPageOverlayColor(WebWidgetRef handle, uint8_t a, uint8_t r, uint8_t g, uint8_t b);
//EXPORT WebCompositedDisplayListRef _WebViewGetCompositedDisplayList(WebWidgetRef handle);
EXPORT WebPageImportanceSignalsRef _WebViewGetPageImportanceSignals(WebWidgetRef handle);
EXPORT void _WebViewAcceptLanguagesChanged(WebWidgetRef handle);
EXPORT double _WebViewZoomLevelToZoomFactor(double zoomLevel);
EXPORT double _WebViewZoomFactorToZoomLevel(double zoomLevel);
EXPORT void _WebViewWillEnterModalLoop();
EXPORT void _WebViewDidExitModalLoop();
EXPORT void _WebViewSetUseExternalPopupMenus(int use);
EXPORT void _WebViewUpdateVisitedLinkState(uint64_t hash);
EXPORT void _WebViewResetVisitedLinkState(int invalidate_visited_link_hashes);
//EXPORT int _WebViewScrollFocusedNodeIntoRect(WebWidgetRef handle, int x, int y, int width, int height);
EXPORT void _WebViewSmoothScroll(WebWidgetRef handle, int targetX, int targetY, int64_t duration);
EXPORT void _WebViewAdvanceFocus(WebWidgetRef handle, int reverse);
EXPORT void _WebViewDidCloseContextMenu(WebWidgetRef handle);
EXPORT int _WebViewHasFocusedFrame(WebWidgetRef reference);

// WebFrame
EXPORT WebFrameRef _WebLocalFrameCreateMainFrame(void* peer, WebWidgetRef view, 
  WebFrameClientCbs callbacks, WebInterfaceRegistryRef registry);
EXPORT void _WebLocalFrameDestroy(WebFrameRef handle);
EXPORT int _WebFrameInShadowTree(WebFrameRef handle);
EXPORT WebFrameRef _WebFrameGetParent(WebFrameRef handle);
EXPORT WebFrameRef _WebFrameGetTop(WebFrameRef handle);
EXPORT WebFrameRef _WebFrameGetFirstChild(WebFrameRef handle);
EXPORT WebFrameRef _WebFrameGetNextSibling(WebFrameRef handle);
EXPORT WebFrameRef _WebFrameTraverseNext(WebFrameRef handle);
EXPORT JavascriptDataRef _WebFrameGetGlobalProxy(WebFrameRef handle);
EXPORT int _WebFrameScriptCanAccess(WebFrameRef handle);
EXPORT WebFrameRef _WebFrameFromFrameOwnerElement(WebNodeRef element);
EXPORT int _WebFrameSwap(WebFrameRef handle, WebFrameRef frame);
EXPORT void _WebFrameDetach(WebFrameRef handle);
EXPORT int _WebFrameIsEqual(WebFrameRef left, WebFrameRef right);
EXPORT int _WebFrameIsWebLocalFrame(WebFrameRef handle);
EXPORT int _WebFrameIsWebRemoteFrame(WebFrameRef handle);
EXPORT void _WebFrameClose(WebFrameRef handle);
EXPORT WebWidgetRef _WebFrameView(WebFrameRef handle);
EXPORT WebFrameRef _WebFrameGetOpener(WebFrameRef handle);
EXPORT void _WebFrameSetOpener(WebFrameRef handle, WebFrameRef opener);

// WebRemoteFrame
EXPORT WebFrameRef _WebRemoteFrameCreate(void* peer, WebFrameClientCbs callbacks, int web_tree_scope_type);
EXPORT void _WebRemoteFrameDestroy(WebFrameRef handle);
EXPORT void _WebRemoteFrameDidStartLoading(WebFrameRef handle);

// in limbo
EXPORT void _WebLocalFrameSetRemoteWebLayer(WebFrameRef handle, LayerRef layer);

// WebLocalFrame
EXPORT int _WebLocalFrameIsLoading(WebFrameRef handle);
EXPORT char* _WebLocalFrameAssignedName(WebFrameRef handle, int* len);
EXPORT WebFrameSelectionRef _WebLocalFrameGetSelection(WebFrameRef handle);
EXPORT WebSecurityOriginRef _WebLocalFrameGetSecurityOrigin(WebFrameRef handle);
EXPORT void _WebLocalFrameSetName(WebFrameRef handle, const char* name);
EXPORT void _WebLocalFrameIconURLS(WebFrameRef handle, int iconTypesMask, const char** urls, int* urlslen);
EXPORT void _WebLocalFrameSetSharedWorkerRepositoryClient(WebFrameRef handle, WebSharedWorkerRepositoryClientRef client);
EXPORT void _WebLocalFrameSetCanHaveScrollbars(WebFrameRef handle, int can);
EXPORT void _WebLocalFrameScrollOffset(WebFrameRef handle, int* width, int* height);
EXPORT void _WebLocalFrameSetScrollOffset(WebFrameRef handle, int width, int height);
EXPORT void _WebLocalFrameDocumentSize(WebFrameRef handle, int* width, int* height);
EXPORT int _WebLocalFrameIsSelectionAnchorFirst(WebFrameRef handle);
EXPORT int _WebLocalFrameSelectionTextDirection(WebFrameRef handle, int* text_dir_start, int* text_dir_end);
EXPORT WebWidgetRef _WebLocalFrameGetFrameWidget(WebFrameRef handle);
EXPORT int _WebLocalFrameHasVisibleContent(WebFrameRef handle);
EXPORT void _WebLocalFrameVisibleContentRect(WebFrameRef handle, int* x, int* y, int* width, int* height);
EXPORT WebNodeRef _WebLocalFrameDocument(WebFrameRef handle);
EXPORT int _WebLocalFrameDispatchBeforeUnloadEvent(WebFrameRef handle, int is_reload);
EXPORT void _WebLocalFrameDispatchUnloadEvent(WebFrameRef handle);
EXPORT void _WebLocalFrameExecuteScript(WebFrameRef handle, const char* source);
EXPORT void _WebLocalFrameExecuteScriptInIsolatedWorld(WebFrameRef handle, int worldID, const char** sources, unsigned numSources);
EXPORT void _WebLocalFrameSetIsolatedWorldSecurityOrigin(WebFrameRef handle, int worldID, WebSecurityOriginRef origin);
EXPORT void _WebLocalFrameSetIsolatedWorldContentSecurityPolicy(WebFrameRef handle, int worldID, const char* str);
EXPORT void _WebLocalFrameAddMessageToConsole(WebFrameRef handle, WebConsoleMessageLevelEnum level, const char* message);
EXPORT void _WebLocalFrameCollectGarbage(WebFrameRef handle);
EXPORT JavascriptDataRef _WebLocalFrameExecuteScriptAndReturnValue(WebFrameRef handle, const char* source);
EXPORT void _WebLocalFrameExecuteScriptInIsolatedWorldValues(WebFrameRef handle, int worldID, const char** sources, unsigned numSources, JavascriptDataRef* results, int* resultCount);
EXPORT JavascriptDataRef _WebLocalFrameCallFunctionEvenIfScriptDisabled(WebFrameRef handle, JavascriptDataRef func, JavascriptDataRef value, int argc, JavascriptDataRef* argv);
EXPORT JavascriptContextRef _WebLocalFrameMainWorldScriptContext(WebFrameRef handle);
EXPORT void _WebLocalFrameReload(WebFrameRef handle, WebFrameLoadEnum load_type);
EXPORT void _WebLocalFrameReloadWithOverrideURL(WebFrameRef handle, const char* overrideUrl, int ignoreCache);
EXPORT void _WebLocalFrameLoadRequest(WebFrameRef handle, WebURLRequestRef req);
EXPORT void _WebLocalFrameLoadData(WebFrameRef handle, const char* data, size_t size, const char* mimeType, const char* textEncoding, const char* baseURL, const char* unreachableURL, int replace);
EXPORT void _WebLocalFrameLoadHTMLString(WebFrameRef handle, const char* html, size_t html_size, const char* baseURL, const char* unreachableURL, int replace);
EXPORT void _WebLocalFrameStopLoading(WebFrameRef handle);
EXPORT void _WebLocalFrameEnableViewSourceMode(WebFrameRef handle, int enable);
EXPORT int _WebLocalFrameIsViewSourceModeEnabled(WebFrameRef handle);
EXPORT void _WebLocalFrameSetReferrerForRequest(WebFrameRef handle, WebURLRequestRef req, const char* url);

EXPORT WebAssociatedURLLoaderRef _WebLocalFrameCreateAssociatedURLLoader(WebFrameRef handle,  
    int untrustedHTTP, // Whether to validate the method and headers as if this was an XMLHttpRequest.
    int exposeAllResponseHeaders, // If policy is to use access control, whether to expose non-whitelisted response headers to the client.
    WebPreflightPolicyEnum preflightPolicy);
EXPORT void _WebLocalFrameReplaceSelection(WebFrameRef handle, const char* text);
EXPORT void _WebLocalFrameSetMarkedText(WebFrameRef handle, const char* text, unsigned location, unsigned length);
EXPORT void _WebLocalFrameUnmarkText(WebFrameRef handle);
EXPORT int _WebLocalFrameHasMarkedText(WebFrameRef handle);
EXPORT void _WebLocalFrameMarkedRange(WebFrameRef handle, int* start, int* end);
EXPORT int _WebLocalFrameFirstRectForCharacterRange(WebFrameRef handle, unsigned location, unsigned length, int* x, int* y, int* width, int* height);
EXPORT size_t _WebLocalFrameCharacterIndexForPoint(WebFrameRef handle, int px, int py);
EXPORT int _WebLocalFrameExecuteCommand(WebFrameRef handle, const char* str);
EXPORT int _WebLocalFrameExecuteCommandValue(WebFrameRef handle, const char* string, const char* value);
EXPORT int _WebLocalFrameIsCommandEnabled(WebFrameRef handle, const char* string);
EXPORT void _WebLocalFrameReplaceMisspelledRange(WebFrameRef handle, const char* text);
EXPORT void _WebLocalFrameRemoveSpellingMarkers(WebFrameRef handle);
EXPORT int _WebLocalFrameHasSelection(WebFrameRef handle);
EXPORT void _WebLocalFrameSelectionRange(WebFrameRef handle, int* start, int* end);
EXPORT char* _WebLocalFrameSelectionAsText(WebFrameRef handle, int* len);
EXPORT char* _WebLocalFrameSelectionAsMarkup(WebFrameRef handle, int* len);
EXPORT int _WebLocalFrameSelectWordAroundCaret(WebFrameRef handle);
EXPORT void _WebLocalFrameSelectRangeInt(WebFrameRef handle, int base_x, int base_y, int extent_x, int extent_y);
EXPORT void _WebLocalFrameSelectRange(WebFrameRef handle, int start, int end, int hide);
EXPORT void _WebLocalFrameMoveRangeSelection(WebFrameRef handle, 
  int base_x, 
  int base_y, 
  int extent_x, 
  int extent_y, 
  WebTextGranularityEnum granularity);
EXPORT void _WebLocalFrameMoveCaretSelection(WebFrameRef handle, int x, int y);
EXPORT int _WebLocalFrameSetEditableSelectionOffsets(WebFrameRef handle, int start, int end);
EXPORT int _WebLocalFrameSetCompositionFromExistingText(WebFrameRef handle, 
  int compositionStart, 
  int compositionEnd,
  // spans
  int* spanType,
  int* spanStart,
  int* spanEnd,
  int* spanUcolor,
  int* spanThick,
  int* spanBgcolor,
  int spanLen);
EXPORT void _WebLocalFrameExtendSelectionAndDelete(WebFrameRef handle, int before, int after);
EXPORT void _WebLocalFrameSetCaretVisible(WebFrameRef handle, int visible);
EXPORT int _WebLocalFramePrintBegin(WebFrameRef handle, 
  int contentAreaX, 
  int contentAreaY, 
  int contentAreaWidth, 
  int contentAreaHeight,
  int printableAreaX,
  int printableAreaY,
  int printableAreaWidth,
  int printableAreaHeight,
  int paperSizeWidth,
  int paperSizeHeight,
  int printerDPI,
  int rasterize_pdf,
  WebPrintScalingOptionEnum printScalingOption,
  int use_printing_layout,
  WebNodeRef constrainToNode);
EXPORT float _WebLocalFrameGetPrintPageShrink(WebFrameRef handle, int page);
EXPORT float _WebLocalFramePrintPage(WebFrameRef handle, int pageToPrint, CanvasRef canvas);
EXPORT void _WebLocalFramePrintEnd(WebFrameRef handle);
EXPORT int _WebLocalFrameIsPrintScalingDisabledForPlugin(WebFrameRef handle, WebNodeRef node);
EXPORT int _WebLocalFrameIsPageBoxVisible(WebFrameRef handle, int pageIndex);
EXPORT int _WebLocalFrameHasCustomPageSizeStyle(WebFrameRef handle, int pageIndex);
EXPORT void _WebLocalFramePageSizeAndMarginsInPixels(WebFrameRef handle, 
  int pageIndex, 
  int width, 
  int height, 
  int* marginTop, 
  int* marginRight, 
  int* marginBottom, 
  int* marginLeft);
EXPORT char* _WebLocalFramePageProperty(WebFrameRef handle, const char* propertyName, int pageIndex, int* len);
EXPORT int _WebLocalFrameFind(WebFrameRef handle, 
    int identifier, 
    const char* searchText, 
    int forward,
    int matchCase,
    int findNext,
    int wordStart,
    int medialCapitalAsWordStart, 
    int wrapWithinFrame,
    float* x, 
    float* y, 
    float* width, 
    float* height);
EXPORT void _WebLocalFrameStopFinding(WebFrameRef handle, int action);
EXPORT void _WebLocalFrameClearActiveFindMatch(WebFrameRef handle);
EXPORT void _WebLocalFrameRequestFind(WebFrameRef handle, 
    int32_t request_id, 
    const uint16_t* search_text, 
    int forward,
    int match_case,
    int find_next,
    int word_start,
    int medial_capital_as_word_start,
    int force);
//EXPORT void _WebLocalFrameIncreaseMatchCount(WebFrameRef handle, int count, int identifier);
EXPORT int _WebLocalFrameFindMatchMarkersVersion(WebFrameRef handle);
EXPORT void _WebLocalFrameActiveFindMatchRect(WebFrameRef handle, float* x, float* y, float* width, float* height);
EXPORT void _WebLocalFrameFindMatchRects(WebFrameRef handle, float** x, float** y, float** w, float** h, int* lenght);
EXPORT int _WebLocalFrameSelectNearestFindMatch(WebFrameRef handle, int px, int py, int* x, int* y, int* w, int* h);
EXPORT void _WebLocalFrameSetTickmarks(WebFrameRef handle, int* x, int* y, int* w, int* h, int lenght);
EXPORT void _WebLocalFrameDispatchMessageEventWithOriginCheck(WebFrameRef handle, 
  WebSecurityOriginRef intendedTargetOrigin, 
  WebDOMEventRef event,
  int has_user_gesture);
EXPORT void _WebLocalFrameNotifyUserActivation(WebFrameRef handle);
EXPORT WebFrameRef _WebLocalFrameForCurrentContext();
EXPORT WebFrameRef _WebLocalFrameForContext(JavascriptContextRef context);
EXPORT void _WebLocalFrameSetAutofillClient(WebFrameRef handle, WebAutofillClientRef client);
EXPORT WebAutofillClientRef _WebLocalFrameAutofillClient(WebFrameRef handle);
EXPORT void _WebLocalFrameSetFrameOwnerProperties(WebFrameRef handle, 
    WebScrollingModeEnum scrollingMode, 
    int marginWidth,
    int marginHeight);
EXPORT void _WebLocalFrameSendPings(WebFrameRef handle, const char* destinationURL);
EXPORT WebURLRequestRef _WebLocalFrameRequestFromHistoryItem(WebFrameRef handle, WebHistoryItemRef item, WebURLRequestCachePolicyEnum);
EXPORT WebURLRequestRef _WebLocalFrameRequestForReload(WebFrameRef handle, WebFrameLoadEnum type, const char* overrideURL);
EXPORT void _WebLocalFrameLoad(WebFrameRef handle, WebURLRequestRef req, WebFrameLoadEnum floadType, WebHistoryItemRef item, WebHistoryLoadTypeEnum hloadType, int is_client_redirect);
EXPORT int _WebLocalFrameIsLoading(WebFrameRef handle);
EXPORT void _WebLocalFrameSetCommittedFirstRealLoad(WebFrameRef handle);
EXPORT void _WebLocalFrameSendOrientationChangeEvent(WebFrameRef handle);
EXPORT int _WebLocalFrameGetPrintPresetOptionsForPlugin(WebFrameRef handle, WebNodeRef node, 
    int* isScalingDisabled,
    int* copies,
    WebDuplexModeEnum* duplexMode,
    int** pageRangeFrom,
    int** pageRangeTo,
    int* pageRangeLenght,
    int* isPageSizeUniform,
    int* uniformPageSizeWidth,
    int* uniformPageSizeHeight);
EXPORT void _WebLocalFrameRequestExecuteScriptAndReturnValue(WebFrameRef handle, const char* source, int userGesture, WebScriptExecutionCallbackRef cb);
EXPORT void _WebLocalFrameRequestExecuteScriptInIsolatedWorld(WebFrameRef handle, int worldID, const char** sourceIn, unsigned numSources, int userGesture, WebScriptExecutionTypeEnum execution_type, WebScriptExecutionCallbackRef cb);
EXPORT void _WebLocalFrameSetIsolatedWorldHumanReadableName(WebFrameRef handle, int worldID, const char* name);
EXPORT void _WebLocalFrameMoveRangeSelectionExtent(WebFrameRef handle, int px, int py);
EXPORT void _WebLocalFrameSetContentSettingsClient(WebFrameRef handle, WebContentSettingsClientRef client);
EXPORT void _WebLocalFrameReloadImage(WebFrameRef handle, WebNodeRef node);
EXPORT void _WebLocalFrameDidCallAddSearchProvider(WebFrameRef handle);
EXPORT void _WebLocalFrameDidCallIsSearchProviderInstalled(WebFrameRef handle);
EXPORT WebSandboxFlagsEnum _WebLocalFrameEffectiveSandboxFlags(WebFrameRef handle);
EXPORT void _WebLocalFrameAdvanceFocusInForm(WebFrameRef handle, int type);
EXPORT void _WebLocalFrameCopyImageAt(WebFrameRef handle, int x, int y);
EXPORT void _WebLocalFrameSaveImageAt(WebFrameRef handle, int x, int y);
EXPORT void _WebLocalFrameClientDroppedNavigation(WebFrameRef handle);
EXPORT void _WebLocalFrameCollapse(WebFrameRef handle, int collapsed);
EXPORT void _WebLocalFrameCheckCompleted(WebFrameRef handle);
EXPORT void _WebLocalFrameGetWebSurroundingText(
  WebFrameRef handle, 
  int maxlen, 
  void* ptr,
  void (*cb)(void*, const uint16_t*, int, int, int));

EXPORT WebDocumentLoaderRef _WebLocalFrameGetProvisionalDocumentLoader(WebFrameRef handle);
EXPORT WebDocumentLoaderRef _WebLocalFrameGetDocumentLoader(WebFrameRef handle);
EXPORT int _WebLocalFrameCommitSameDocumentNavigation(
  WebFrameRef handle,
  const char* url,
  int web_frame_load_type,
  WebHistoryItemRef item,
  int is_client_redirect);

EXPORT int _WebLocalFrameCommitNavigation(
  WebFrameRef handle,
  WebURLRequestRef request,
  int web_frame_load_type,
  WebHistoryItemRef item,
  int is_client_redirect);

EXPORT void _WebLocalFrameSetTextDirection(WebFrameRef handle, int direction);
EXPORT WebInputMethodControllerRef _WebLocalFrameGetInputMethodController(WebFrameRef handle);
EXPORT WebEditorRef _WebLocalFrameGetEditor(WebFrameRef handle);
EXPORT int _WebLocalFrameIsLocalRoot(WebFrameRef handle);
EXPORT WebFrameRef _WebLocalFrameGetLocalRoot(WebFrameRef handle);
EXPORT WebLocalDomWindowRef _WebLocalFrameGetDomWindow(WebFrameRef handle);

// WebFrameWidget

EXPORT WebWidgetRef _WebFrameWidgetCreate(
  void* peer, 
  WebViewClientCbs callbacks, 
  WebFrameRef frame);

EXPORT void _WebFrameWidgetSetVisibilityState(WebWidgetRef handle, WebPageVisibilityStateEnum visibility_state);

EXPORT WebFrameRef _WebFrameWidgetGetLocalRoot(WebWidgetRef handle);

EXPORT WebInputMethodControllerRef _WebFrameWidgetGetActiveWebInputMethodController(WebWidgetRef handle);

EXPORT WebFrameRef _WebFrameWidgetGetFocusedWebLocalFrameInWidget(WebWidgetRef handle);

EXPORT int _WebFrameWidgetScrollFocusedEditableElementIntoView(WebWidgetRef handle);

//EXPORT int _WebFrameWidgetHandleInputEvent(WebWidgetRef handle, WebInputEventRef event);

// WebHitTestResult
EXPORT void _WebHitTestResultDestroy(WebHitTestResultRef handle);

// WebSecurityOrigin
EXPORT void _WebSecurityOriginDestroy(WebSecurityOriginRef handle);

EXPORT void _WebPluginContainerDestroy(WebPluginContainerRef handle);

// WebRange
EXPORT WebRangeRef _WebRangeCreateWithDocument(WebNodeRef document);
EXPORT WebRangeRef _WebRangeCreate(WebNodeRef document, 
  WebNodeRef startContainer,
  uint16_t startOffset,
  WebNodeRef endContainer,
  uint16_t endOffset);
EXPORT void _WebRangeDestroy(WebRangeRef handle);
EXPORT WebNodeRef _WebRangeGetStartContainer(WebRangeRef handle);
EXPORT WebNodeRef _WebRangeGetEndContainer(WebRangeRef handle);
EXPORT uint64_t _WebRangeGetStartOffset(WebRangeRef handle);
EXPORT uint64_t _WebRangeGetEndOffset(WebRangeRef handle);
EXPORT int _WebRangeIsCollapsed(WebRangeRef handle);
EXPORT WebNodeRef _WebRangeGetCommonAncestorContainer(WebRangeRef handle);
EXPORT void _WebRangeGetClientRects(WebRangeRef handle, int** x, int** y, int** w, int** h, int* count);
EXPORT void _WebRangeGetBoundingClientRect(WebRangeRef handle, int* x, int* y, int* w, int* h);
EXPORT void _WebRangeSetStart(WebRangeRef handle, WebNodeRef node, uint64_t offset);
EXPORT void _WebRangeSetEnd(WebRangeRef handle, WebNodeRef node, uint64_t offset);
EXPORT void _WebRangeSetStartBefore(WebRangeRef handle, WebNodeRef node);
EXPORT void _WebRangeSetStartAfter(WebRangeRef handle, WebNodeRef node);
EXPORT void _WebRangeSetEndBefore(WebRangeRef handle, WebNodeRef node);
EXPORT void _WebRangeSetEndAfter(WebRangeRef handle, WebNodeRef node);
EXPORT void _WebRangeCollapse(WebRangeRef handle, int toStart);
EXPORT void _WebRangeSelectNode(WebRangeRef handle, WebNodeRef node);
EXPORT void _WebRangeSelectNodeContents(WebRangeRef handle, WebNodeRef node);
EXPORT int16_t _WebRangeCompareBoundaryPoints(WebRangeRef handle, uint16_t how, WebRangeRef sourceRange);
EXPORT void _WebRangeDeleteContents(WebRangeRef handle);
EXPORT WebNodeRef _WebRangeExtractContents(WebRangeRef handle);
EXPORT WebNodeRef _WebRangeCloneContents(WebRangeRef handle);
EXPORT void _WebRangeInsertNode(WebRangeRef handle, WebNodeRef node);
EXPORT void _WebRangeSurroundContents(WebRangeRef handle, WebNodeRef newParent);
EXPORT WebRangeRef _WebRangeCloneRange(WebRangeRef handle);
EXPORT void _WebRangeDetach(WebRangeRef handle);
EXPORT int _WebRangeIsPointInRange(WebRangeRef handle, WebNodeRef node, uint64_t offset);
EXPORT int16_t _WebRangeComparePoint(WebRangeRef handle, WebNodeRef node, uint64_t offset);
EXPORT int _WebRangeIntersectsNode(WebRangeRef handle, WebNodeRef node);
EXPORT WebNodeRef _WebRangeCreateContextualFragment(WebRangeRef handle, const char* fragment);
EXPORT void _WebRangeExpand(WebRangeRef handle, const char* unit);


// WebHTTPLoadInfo
EXPORT WebHTTPLoadInfoRef _WebHTTPLoadInfoCreate();
EXPORT void _WebHTTPLoadInfoDestroy(WebHTTPLoadInfoRef handle);
EXPORT int _WebHTTPLoadInfoGetHttpStatusCode(WebHTTPLoadInfoRef handle);
EXPORT void _WebHTTPLoadInfoSetHttpStatusCode(WebHTTPLoadInfoRef handle, int code);
EXPORT const char* _WebHTTPLoadInfoGetHttpStatusText(WebHTTPLoadInfoRef handle);
EXPORT void _WebHTTPLoadInfoSetHttpStatusText(WebHTTPLoadInfoRef handle, const char* status);
//EXPORT int64_t _WebHTTPLoadInfoGetEncodedDataLength(WebHTTPLoadInfoRef handle);
//EXPORT void _WebHTTPLoadInfoSetEncodedDataLength(WebHTTPLoadInfoRef handle, int64_t len);
EXPORT const char* _WebHTTPLoadInfoGetRequestHeadersText(WebHTTPLoadInfoRef handle);
EXPORT void _WebHTTPLoadInfoSetRequestHeadersText(WebHTTPLoadInfoRef handle, const char* headers);
EXPORT const char* _WebHTTPLoadInfoGetResponseHeadersText(WebHTTPLoadInfoRef handle);
EXPORT void _WebHTTPLoadInfoSetResponseHeadersText(WebHTTPLoadInfoRef handle, const char* headers);
EXPORT const char* _WebHTTPLoadInfoGetNpnNegotiatedProtocol(WebHTTPLoadInfoRef handle);
EXPORT void _WebHTTPLoadInfoSetNpnNegotiatedProtocol(WebHTTPLoadInfoRef handle, const char* proto);
EXPORT void _WebHTTPLoadInfoAddRequestHeader(WebHTTPLoadInfoRef handle, const char* name, const char* value);
EXPORT void _WebHTTPLoadInfoAddResponseHeader(WebHTTPLoadInfoRef handle, const char* name, const char* value);

// WebHTTPBody
EXPORT WebHTTPBodyRef _WebHTTPBodyCreate();
EXPORT void _WebHTTPBodyDestroy(WebHTTPBodyRef handle);
EXPORT int _WebHTTPBodyGetElementCount(WebHTTPBodyRef handle);
EXPORT int64_t _WebHTTPBodyGetIdentifier(WebHTTPBodyRef handle);
EXPORT void _WebHTTPBodySetIdentifier(WebHTTPBodyRef handle, int64_t identifier);
EXPORT int _WebHTTPBodyGetContainsPasswordData(WebHTTPBodyRef handle);
EXPORT void _WebHTTPBodySetContainsPasswordData(WebHTTPBodyRef handle, int contains);
EXPORT int _WebHTTPBodyGetElementDataSizeAt(WebHTTPBodyRef handle, int index);
// NOTE: data_bytes must be pre-allocated as we will copy into it
EXPORT int _WebHTTPBodyGetElementAt(WebHTTPBodyRef handle, int index,
        int* kind,
        uint8_t* data_bytes, 
        int* data_size,
        const char** file,
        int64_t* start,
        int64_t* len,
        double* mod,
        const char** uuid);

EXPORT void _WebHTTPBodyAppendData(WebHTTPBodyRef handle, const uint8_t* data_bytes, int data_size);
EXPORT void _WebHTTPBodyAppendFile(WebHTTPBodyRef handle, const char* file);
EXPORT void _WebHTTPBodyAppendFileRange(WebHTTPBodyRef handle, const char* file, int64_t start, int64_t length, double modificationTime);
EXPORT void _WebHTTPBodyAppendBlob(WebHTTPBodyRef handle, const char* blob);
//EXPORT void _WebHTTPBodyAppendFileSystemURLRange(WebHTTPBodyRef handle, const char* url, int64_t start, int64_t lenght, double modificationTime);

// WebURLRequest
EXPORT WebURLRequestRef _WebURLRequestCreate(const char* url);
EXPORT void _WebURLRequestDestroy(WebURLRequestRef handle);
EXPORT void _WebURLRequestGetURL(WebURLRequestRef handle, void* state, void(*cb)(void*, const char *, size_t));
EXPORT void _WebURLRequestSetURL(WebURLRequestRef handle, const char* url);
//EXPORT const char* _WebURLRequestGetFirstPartyForCookies(WebURLRequestRef handle);
//EXPORT void _WebURLRequestSetFirstPartyForCookies(WebURLRequestRef handle, const char* url);
EXPORT WebSecurityOriginRef _WebURLRequestGetRequestorOrigin(WebURLRequestRef handle);
EXPORT void _WebURLRequestSetRequestorOrigin(WebURLRequestRef handle, WebSecurityOriginRef origin);
EXPORT int _WebURLRequestGetAllowStoredCredentials(WebURLRequestRef handle);
EXPORT void _WebURLRequestSetAllowStoredCredentials(WebURLRequestRef handle, int allow);
//EXPORT int _WebURLRequestCachePolicy(WebURLRequestRef handle);
//EXPORT void _WebURLRequestSetCachePolicy(WebURLRequestRef handle, int policy);
EXPORT void _WebURLRequestGetHttpMethod(WebURLRequestRef handle, void* state, void(*cb)(void*, const char *, size_t));
EXPORT void _WebURLRequestSetHTTPMethod(WebURLRequestRef handle, const char* method);
EXPORT WebHTTPBodyRef _WebURLRequestGetHttpBody(WebURLRequestRef handle);
EXPORT void _WebURLRequestSetHttpBody(WebURLRequestRef handle, WebHTTPBodyRef body);
EXPORT int _WebURLRequestGetReportUploadProgress(WebURLRequestRef handle);
EXPORT void _WebURLRequestSetReportUploadProgress(WebURLRequestRef handle, int report);
EXPORT int _WebURLRequestGetReportRawHeaders(WebURLRequestRef handle);
EXPORT void _WebURLRequestSetReportRawHeaders(WebURLRequestRef handle, int report);
EXPORT int _WebURLRequestGetRequestContext(WebURLRequestRef handle);
EXPORT void _WebURLRequestSetRequestContext(WebURLRequestRef handle, int contex);
EXPORT int _WebURLRequestGetFrameType(WebURLRequestRef handle);
EXPORT void _WebURLRequestSetFrameType(WebURLRequestRef handle, int type);
EXPORT int _WebURLRequestGetWebReferrerPolicy(WebURLRequestRef handle);
EXPORT int _WebURLRequestGetHasUserGesture(WebURLRequestRef handle);
EXPORT void _WebURLRequestSetHasUserGesture(WebURLRequestRef handle, int hasGesture);
EXPORT int _WebURLRequestGetRequestorId(WebURLRequestRef handle);
EXPORT void _WebURLRequestSetRequestorId(WebURLRequestRef handle, int id);
//EXPORT int _WebURLRequestGetRequestorProcessId(WebURLRequestRef handle);
//EXPORT void _WebURLRequestSetRequestorProcessId(WebURLRequestRef handle, int id);
EXPORT int _WebURLRequestGetAppCacheHostId(WebURLRequestRef handle);
EXPORT void _WebURLRequestSetAppCacheHostId(WebURLRequestRef handle, int id);
EXPORT int _WebURLRequestGetDownloadToFile(WebURLRequestRef handle);
EXPORT void _WebURLRequestSetDownloadToFile(WebURLRequestRef handle, int downloadToFile);
EXPORT int _WebURLRequestGetUseStreamOnResponse(WebURLRequestRef handle);
EXPORT void _WebURLRequestSetUseStreamOnResponse(WebURLRequestRef handle, int useStream);
EXPORT int _WebURLRequestGetSkipServiceWorker(WebURLRequestRef handle);
EXPORT void _WebURLRequestSetSkipServiceWorker(WebURLRequestRef handle, int skip);
EXPORT int _WebURLRequestGetShouldResetAppCache(WebURLRequestRef handle);
EXPORT void _WebURLRequestSetShouldResetAppCache(WebURLRequestRef handle, int shouldReset);
EXPORT int _WebURLRequestGetFetchRequestMode(WebURLRequestRef handle);
EXPORT void _WebURLRequestSetFetchRequestMode(WebURLRequestRef handle, int mode);
EXPORT int _WebURLRequestGetFetchCredentialsMode(WebURLRequestRef handle);
EXPORT void _WebURLRequestSetFetchCredentialsMode(WebURLRequestRef handle, int mode);
EXPORT int _WebURLRequestGetFetchRedirectMode(WebURLRequestRef handle);
EXPORT void _WebURLRequestSetFetchRedirectMode(WebURLRequestRef handle, int mode);
//EXPORT int _WebURLRequestGetLoFiState(WebURLRequestRef handle);
//EXPORT void _WebURLRequestSetLoFiState(WebURLRequestRef handle, int state);
EXPORT int _WebURLRequestGetPriority(WebURLRequestRef handle);
EXPORT void _WebURLRequestSetPriority(WebURLRequestRef handle, int priority);
EXPORT int _WebURLRequestGetCheckForBrowserSideNavigation(WebURLRequestRef handle);
EXPORT void _WebURLRequestSetCheckForBrowserSideNavigation(WebURLRequestRef handle, int check);
EXPORT double _WebURLRequestGetUiStartTime(WebURLRequestRef handle);
EXPORT void _WebURLRequestSetUiStartTime(WebURLRequestRef handle, double startTime);
EXPORT int _WebURLRequestGetInputPerfMetricReportPolicy(WebURLRequestRef handle);
EXPORT void _WebURLRequestSetInputPerfMetricReportPolicy(WebURLRequestRef handle, int policy);
//EXPORT int _WebURLRequestGetOriginatesFromReservedIPRange(WebURLRequestRef handle);
//EXPORT void _WebURLRequestSetOriginatesFromReservedIPRange(WebURLRequestRef handle, int originates);
//EXPORT void _WebURLRequestAddHTTPOriginIfNeeded(WebURLRequestRef handle, const char* origin);
EXPORT void _WebURLRequestGetHttpHeaderField(WebURLRequestRef handle, const char* field, void* state, void(*cb)(void*, const char *, size_t));
EXPORT void _WebURLRequestSetHTTPHeaderField(WebURLRequestRef handle, const char* name, const char* value); 
EXPORT void _WebURLRequestSetHTTPReferrer(WebURLRequestRef handle, const char* referrer, int policy);
EXPORT void _WebURLRequestAddHTTPHeaderField(WebURLRequestRef handle, const char* name, const char* value);
EXPORT void _WebURLRequestClearHTTPHeaderField(WebURLRequestRef handle, const char* name);
EXPORT void _WebURLRequestSetIsSameDocumentNavigation(WebURLRequestRef handle, int same_document);
EXPORT int _WebURLRequestGetWasDiscarded(WebURLRequestRef handle);
EXPORT void _WebURLRequestSetWasDiscarded(WebURLRequestRef handle, int was_discarded);
EXPORT void _WebURLRequestSetNavigationStartTime(WebURLRequestRef reference, int64_t microseconds);
EXPORT int _WebURLRequestGetKeepAlive(WebURLRequestRef reference);
EXPORT void _WebURLRequestSetKeepAlive(WebURLRequestRef reference, int keepalive);

// WebURLResponse
EXPORT void _WebURLResponseDestroy(WebURLResponseRef handle);
EXPORT void _WebURLResponseGetURL(WebURLResponseRef handle, void* state, void(*cb)(void*, const char *, size_t));
EXPORT void _WebURLResponseSetURL(WebURLResponseRef handle, const char* url);
//EXPORT int _WebURLResponseGetConnectionId(WebURLResponseRef handle);
EXPORT void _WebURLResponseSetConnectionId(WebURLResponseRef handle, int id);
//EXPORT int _WebURLResponseConnectionReused(WebURLResponseRef handle);
EXPORT void _WebURLResponseSetConnectionReused(WebURLResponseRef handle, int reused);
//EXPORT WebHTTPLoadInfoRef _WebURLResponseGetHttpLoadInfo(WebURLResponseRef handle);
EXPORT void _WebURLResponseSetHttpLoadInfo(WebURLResponseRef handle, WebHTTPLoadInfoRef info);
EXPORT void _WebURLResponseGetMimeType(WebURLResponseRef handle, void* state, void(*cb)(void*, const char *, size_t));
EXPORT void _WebURLResponseSetMimeType(WebURLResponseRef handle, const char* mime);
EXPORT int64_t _WebURLResponseGetExpectedContentLength(WebURLResponseRef handle);
EXPORT void _WebURLResponseSetExpectedContentLength(WebURLResponseRef handle, int64_t len);
//EXPORT const char* _WebURLResponseGetTextEncoding(WebURLResponseRef handle);
EXPORT void _WebURLResponseSetTextEncodingName(WebURLResponseRef handle, const char* encoding);
//EXPORT const char* _WebURLResponseGetSuggestedFileName(WebURLResponseRef handle);
//EXPORT void _WebURLResponseSetSuggestedFileName(WebURLResponseRef handle, const char* filename); 
EXPORT int _WebURLResponseGetHttpVersion(WebURLResponseRef handle);
EXPORT void _WebURLResponseSetHttpVersion(WebURLResponseRef handle, int version);
EXPORT int _WebURLResponseGetHttpStatusCode(WebURLResponseRef handle);
EXPORT void _WebURLResponseSetHttpStatusCode(WebURLResponseRef handle, int status_code);
EXPORT void _WebURLResponseGetHttpStatusText(WebURLResponseRef handle, void* state, void(*cb)(void*, const char *, size_t));
EXPORT void _WebURLResponseSetHttpStatusText(WebURLResponseRef handle, const char* status);
//EXPORT double _WebURLResponseGetLastModifiedDate(WebURLResponseRef handle);
//EXPORT void _WebURLResponseSetLastModifiedDate(WebURLResponseRef handle, double date);
EXPORT int64_t _WebURLResponseGetAppCacheId(WebURLResponseRef handle);
EXPORT void _WebURLResponseSetAppCacheId(WebURLResponseRef handle, int64_t id);
EXPORT void _WebURLResponseGetAppCacheManifestURL(WebURLResponseRef handle, void* state, void(*cb)(void*, const char *, size_t));
EXPORT void _WebURLResponseSetAppCacheManifestURL(WebURLResponseRef handle, const char* url);
//EXPORT const char* _WebURLResponseGetSecurityInfo(WebURLResponseRef handle);
//EXPORT void _WebURLResponseSetSecurityInfo(WebURLResponseRef handle, const char* info);
//EXPORT int _WebURLResponseGetSecurityStyle(WebURLResponseRef handle);
EXPORT void _WebURLResponseSetSecurityStyle(WebURLResponseRef handle, int style);
//EXPORT int _WebURLResponseWasCached(WebURLResponseRef handle);
EXPORT void _WebURLResponseSetWasCached(WebURLResponseRef handle, int cached);
//EXPORT int _WebURLResponseWasFetchedViaSPDY(WebURLResponseRef handle);
EXPORT void _WebURLResponseSetWasFetchedViaSPDY(WebURLResponseRef handle, int fetched);
//EXPORT int _WebURLResponseWasNpnNegotiated(WebURLResponseRef handle);
//EXPORT void _WebURLResponseSetWasNpnNegotiated(WebURLResponseRef handle, int negotiated);
// EXPORT int _WebURLResponseWasAlternateProtocolAvailable(WebURLResponseRef handle);
// EXPORT void _WebURLResponseSetWasAlternateProtocolAvailable(WebURLResponseRef handle, int available);
// EXPORT int _WebURLResponseWasFetchedViaProxy(WebURLResponseRef handle);
//EXPORT void _WebURLResponseSetWasFetchedViaProxy(WebURLResponseRef handle, int fetched);
EXPORT int _WebURLResponseWasFetchedViaServiceWorker(WebURLResponseRef handle);
EXPORT void _WebURLResponseSetWasFetchedViaServiceWorker(WebURLResponseRef handle, int fetched);
//EXPORT int _WebURLResponseWasFallbackRequiredByServiceWorker(WebURLResponseRef handle);
EXPORT void _WebURLResponseSetWasFallbackRequiredByServiceWorker(WebURLResponseRef handle, int required);
//EXPORT int _WebURLResponseGetServiceWorkerResponseType(WebURLResponseRef handle);
//EXPORT void _WebURLResponseSetServiceWorkerResponseType(WebURLResponseRef handle, int type);
//EXPORT const char* _WebURLResponseGetOriginalURLViaServiceWorker(WebURLResponseRef handle);
//EXPORT void _WebURLResponseSetOriginalURLViaServiceWorker(WebURLResponseRef handle, const char* url);
//EXPORT int _WebURLResponseIsMultipartPayload(WebURLResponseRef handle);
//EXPORT void _WebURLResponseSetIsMultipartPayload(WebURLResponseRef handle, int payload);
EXPORT void _WebURLResponseGetDownloadFilePath(WebURLResponseRef handle, void* state, void(*cb)(void*, const char *, size_t));
EXPORT void _WebURLResponseSetDownloadFilePath(WebURLResponseRef handle, const char* path);
EXPORT void _WebURLResponseGetRemoteIPAddress(WebURLResponseRef handle, void* state, void(*cb)(void*, const char *, size_t));
EXPORT void _WebURLResponseSetRemoteIPAddress(WebURLResponseRef handle, const char* address);
EXPORT int16_t _WebURLResponseGetRemotePort(WebURLResponseRef handle);
EXPORT void _WebURLResponseSetRemotePort(WebURLResponseRef handle, int16_t port);
EXPORT void _WebURLResponseSetResponseTime(WebURLResponseRef handle, int64_t time);
EXPORT void _WebURLResponseGetHttpHeaderField(WebURLResponseRef handle, const char* field, void* state, void(*cb)(void*, const char *, size_t));
EXPORT void _WebURLResponseSetHTTPHeaderField(WebURLResponseRef handle, const char* name, const char* value);
EXPORT void _WebURLResponseAddHTTPHeaderField(WebURLResponseRef handle, const char* name, const char* value);
EXPORT void _WebURLResponseClearHTTPHeaderField(WebURLResponseRef handle, const char* name);
EXPORT void _WebURLResponseSetSecurityDetails(
  WebURLResponseRef handle, 
  const char* protocol, 
  const char* key, 
  const char* key_group, 
  const char* cypher, 
  const char* mac,
  const char* subject_name,
  const char* issuer,
  double valid_from,
  double valid_to);

EXPORT WebServiceWorkerNetworkProviderRef _WebServiceWorkerNetworkProviderCreate(int provider_id, int route_id, void* state, WebServiceWorkerNetworkProviderCbs callbacks);
EXPORT void _WebServiceWorkerNetworkProviderSetServiceWorkerProviderId(WebServiceWorkerNetworkProviderRef handle, int provider_id);
EXPORT void _WebServiceWorkerNetworkProviderDestroy(WebServiceWorkerNetworkProviderRef handle);

/*
 * CSSStyleSheet
 */
EXPORT CSSStyleSheetRef _CSSStyleSheetCreate(WebNodeRef document, const char* title, const char* contents);
EXPORT CSSStyleSheetRef _CSSStyleSheetCreateFromNode(WebNodeRef node, const char* title, const char* contents);
EXPORT void _CSSStyleSheetDestroy(CSSStyleSheetRef handle);
EXPORT const char* _CSSStyleSheetGetBaseURL(CSSStyleSheetRef handle);
EXPORT int _CSSStyleSheetIsLoading(CSSStyleSheetRef handle);
EXPORT const char* _CSSStyleSheetGetHref(CSSStyleSheetRef handle);
EXPORT const char* _CSSStyleSheetGetTitle(CSSStyleSheetRef handle);
EXPORT void _CSSStyleSheetSetTitle(CSSStyleSheetRef handle, const char* title);
EXPORT int _CSSStyleSheetIsDisabled(CSSStyleSheetRef handle);
EXPORT void _CSSStyleSheetSetIsDisabled(CSSStyleSheetRef handle, int disabled);
EXPORT WebNodeRef _CSSStyleSheetOwnerNode(CSSStyleSheetRef handle);
EXPORT CSSStyleSheetRef _CSSStyleSheetGetParentStyleSheet(CSSStyleSheetRef handle);
EXPORT CSSRuleListRef _CSSStyleSheetGetCSSRuleList(CSSStyleSheetRef handle);
EXPORT WebNodeRef _CSSStyleSheetGetOwnerDocument(CSSStyleSheetRef handle);
EXPORT int _CSSStyleSheetGetLenght(CSSStyleSheetRef handle);
EXPORT StyleSheetContentsRef _CSSStyleSheetGetContents(CSSStyleSheetRef handle);
EXPORT int _CSSStyleSheetIsInline(CSSStyleSheetRef handle);
EXPORT void _CSSStyleSheetGetStartPositionInSource(CSSStyleSheetRef handle, int* start, int* end); 
EXPORT int _CSSStyleSheetIsSheetLoaded(CSSStyleSheetRef handle); 
EXPORT int _CSSStyleSheetIsLoadCompleted(CSSStyleSheetRef handle);
EXPORT int _CSSStyleSheetIsAlternate(CSSStyleSheetRef handle);
EXPORT void _CSSStyleSheetClearOwnerNode(CSSStyleSheetRef handle);
EXPORT void _CSSStyleSheetClearOwnerRule(CSSStyleSheetRef handle); 
EXPORT int _CSSStyleSheetInsertRule(CSSStyleSheetRef handle, const char* rule, int index);
EXPORT int _CSSStyleSheetAddRuleIndex(CSSStyleSheetRef handle, const char* selection, const char* style, int index);
EXPORT int _CSSStyleSheetAddRule(CSSStyleSheetRef handle, const char* selection, const char* style);
EXPORT void _CSSStyleSheetDeleteRule(CSSStyleSheetRef handle, int index);
EXPORT CSSRuleRef _CSSStyleSheetGetItem(CSSStyleSheetRef handle, int index);
EXPORT void _CSSStyleSheetWillMutateRules(CSSStyleSheetRef handle);
EXPORT void _CSSStyleSheetDidMutateRules(CSSStyleSheetRef handle);
EXPORT void _CSSStyleSheetDidMutate(CSSStyleSheetRef handle);
EXPORT void _CSSStyleSheetStartLoadingDynamicSheet(CSSStyleSheetRef handle);
EXPORT void _CSSStyleSheetSetText(CSSStyleSheetRef handle, const char* text);
EXPORT void _CSSStyleSheetSetAlternateFromConstructor(CSSStyleSheetRef handle, int alternate);
EXPORT int _CSSStyleSheetCanBeActivated(CSSStyleSheetRef handle, const char* current_preferrable_name);

EXPORT void _CSSRuleDestroy(CSSRuleRef handle);
EXPORT void _CSSRuleListDestroy(CSSRuleListRef handle);

EXPORT CSSStyleSheetListRef _CSSStyleSheetListCreate(CSSStyleSheetRef styles, int style_count);

EXPORT WebPluginRef _WebPluginCreate();
EXPORT WebPluginRef _WebPluginCreateLayer(LayerRef layer);
EXPORT void _WebPluginDestroy(WebPluginRef handle);
EXPORT LayerRef _WebPluginGetLayer(WebPluginRef handle);

// WebCanvas
EXPORT void CanvasRenderingContext2dDestroy(CanvasRenderingContext2dRef handle);
EXPORT DisplayItemListRef CanvasRenderingContext2dGetDisplayItemList(CanvasRenderingContext2dRef handle);
EXPORT int CanvasRenderingContext2dGetSaveCount(CanvasRenderingContext2dRef handle);
EXPORT int CanvasRenderingContext2dGetLocalClipBounds(CanvasRenderingContext2dRef handle, float* x, float* y, float* width, float* height);
EXPORT int CanvasRenderingContext2dGetDeviceClipBounds(CanvasRenderingContext2dRef handle, int* x, int* y, int* width, int* height);
EXPORT int CanvasRenderingContext2dIsClipEmpty(CanvasRenderingContext2dRef handle);
EXPORT int CanvasRenderingContext2dIsClipRect(CanvasRenderingContext2dRef handle);
EXPORT MatrixRef CanvasRenderingContext2dTotalMatrix(CanvasRenderingContext2dRef handle);
EXPORT void CanvasRenderingContext2dFlush(CanvasRenderingContext2dRef handle);
EXPORT int CanvasRenderingContext2dSave(CanvasRenderingContext2dRef handle);
EXPORT int CanvasRenderingContext2dSaveLayerRect(CanvasRenderingContext2dRef handle, float rx, float ry, float rw, float rh, PaintFlagsRef paint);
EXPORT int CanvasRenderingContext2dSaveLayer(CanvasRenderingContext2dRef handle, PaintFlagsRef paint);
EXPORT int CanvasRenderingContext2dSaveLayerAlpha(CanvasRenderingContext2dRef handle, int alpha);
EXPORT int CanvasRenderingContext2dSaveLayerAlphaRect(CanvasRenderingContext2dRef handle, int alpha, float rx, float ry, float rw, float rh);
EXPORT int CanvasRenderingContext2dSaveLayerPreserveLCDTextRequestsRect(CanvasRenderingContext2dRef handle, float rx, float ry, float rw, float rh, PaintFlagsRef paint);
EXPORT int CanvasRenderingContext2dSaveLayerPreserveLCDTextRequests(CanvasRenderingContext2dRef handle, PaintFlagsRef paint);
EXPORT void CanvasRenderingContext2dRestore(CanvasRenderingContext2dRef handle);
EXPORT void CanvasRenderingContext2dRestoreToCount(CanvasRenderingContext2dRef handle, int save_count);
EXPORT void CanvasRenderingContext2dTranslate(CanvasRenderingContext2dRef handle, float x, float y);
EXPORT void CanvasRenderingContext2dScale(CanvasRenderingContext2dRef handle, float x, float y);
EXPORT void CanvasRenderingContext2dRotate(CanvasRenderingContext2dRef handle, float radians);
EXPORT void CanvasRenderingContext2dConcatHandle(CanvasRenderingContext2dRef handle, MatrixRef matrix);
EXPORT void CanvasRenderingContext2dSetMatrixHandle(CanvasRenderingContext2dRef handle, MatrixRef matrix);
EXPORT void CanvasRenderingContext2dClearRect(CanvasRenderingContext2dRef handle, int rx, int ry, int rw, int rh);
EXPORT void CanvasRenderingContext2dClipRect(CanvasRenderingContext2dRef handle, float rx, float ry, float rw, float rh, int clip, int anti_alias);
EXPORT void CanvasRenderingContext2dClipRRect(CanvasRenderingContext2dRef handle, float rx, float ry, float rw, float rh, int clip, int anti_alias);
EXPORT void CanvasRenderingContext2dClipPath(CanvasRenderingContext2dRef handle, PathRef path, int clip, int anti_alias);
EXPORT void CanvasRenderingContext2dDrawColor(CanvasRenderingContext2dRef handle, int a, int r, int g, int b, int mode);
EXPORT void CanvasRenderingContext2dDrawLine(CanvasRenderingContext2dRef handle, float sx, float sy, float ex, float ey, PaintFlagsRef paint);
EXPORT void CanvasRenderingContext2dDrawRect(CanvasRenderingContext2dRef handle, float rx, float ry, float rw, float rh, PaintFlagsRef paint);    
EXPORT void CanvasRenderingContext2dDrawIRect(CanvasRenderingContext2dRef handle, int rx, int ry, int rw, int rh, PaintFlagsRef paint);
EXPORT void CanvasRenderingContext2dDrawOval(CanvasRenderingContext2dRef handle, float rx, float ry, float rw, float rh, PaintFlagsRef paint);
EXPORT void CanvasRenderingContext2dDrawRRect(CanvasRenderingContext2dRef handle, float rx, float ry, float rw, float rh, PaintFlagsRef paint);    
EXPORT void CanvasRenderingContext2dDrawDRRect(CanvasRenderingContext2dRef handle, float ox, float oy, float ow, float oh, float ix, float iy, float iw, float ih, PaintFlagsRef paint);
EXPORT void CanvasRenderingContext2dDrawRoundRect(CanvasRenderingContext2dRef handle, float rx, float ry, float rw, float rh, float x, float y, PaintFlagsRef paint);
EXPORT void CanvasRenderingContext2dDrawPath(CanvasRenderingContext2dRef handle, PathRef path, PaintFlagsRef paint);
EXPORT void CanvasRenderingContext2dDrawImage(CanvasRenderingContext2dRef handle, ImageRef image, float x, float y, PaintFlagsRef paint);
EXPORT void CanvasRenderingContext2dDrawImageRect(CanvasRenderingContext2dRef handle, ImageRef image, float sx, float sy, float sw, float sh, float dx, float dy, float dw, float dh, int src_rect_constraint, PaintFlagsRef paint);
EXPORT void CanvasRenderingContext2dDrawBitmap(CanvasRenderingContext2dRef handle, BitmapRef bitmap, float left, float top, PaintFlagsRef paint);
EXPORT void CanvasRenderingContext2dDrawTextBlob(CanvasRenderingContext2dRef handle, PaintTextBlobRef text, float x, float y, PaintFlagsRef paint); 
EXPORT void CanvasRenderingContext2dDrawPicture(CanvasRenderingContext2dRef handle, PaintRecordRef record);
EXPORT char* CanvasRenderingContext2dGetFillStyle(CanvasRenderingContext2dRef handle, int* len);
EXPORT void CanvasRenderingContext2dSetFillStyle(CanvasRenderingContext2dRef handle, const char* style);
EXPORT void CanvasRenderingContext2dFillRect(CanvasRenderingContext2dRef handle, int x, int y, int w, int h);
EXPORT double CanvasRenderingContext2dGetLineWidth(CanvasRenderingContext2dRef handle);
EXPORT int CanvasRenderingContext2dGetLineCap(CanvasRenderingContext2dRef handle);
EXPORT int CanvasRenderingContext2dGetLineJoin(CanvasRenderingContext2dRef handle);
EXPORT double CanvasRenderingContext2dGetMiterLimit(CanvasRenderingContext2dRef handle);
EXPORT void CanvasRenderingContext2dGetLineDash(CanvasRenderingContext2dRef handle, double** values, int* value_count);
EXPORT void CanvasRenderingContext2dSetLineDash(CanvasRenderingContext2dRef handle, double* values, int value_count);
EXPORT double CanvasRenderingContext2dGetLineDashOffset(CanvasRenderingContext2dRef handle);
EXPORT int CanvasRenderingContext2dGetTextAlign(CanvasRenderingContext2dRef handle);
EXPORT int CanvasRenderingContext2dGetTextBaseline(CanvasRenderingContext2dRef handle);
EXPORT double CanvasRenderingContext2dGetGlobalAlpha(CanvasRenderingContext2dRef handle);
EXPORT void CanvasRenderingContext2dSetGlobalAlpha(CanvasRenderingContext2dRef handle, double alpha);
EXPORT int CanvasRenderingContext2dGetGlobalCompositeOperation(CanvasRenderingContext2dRef handle);
EXPORT char* CanvasRenderingContext2dGetFilter(CanvasRenderingContext2dRef handle, int* len);
EXPORT int CanvasRenderingContext2dImageSmoothingEnabled(CanvasRenderingContext2dRef handle);
EXPORT void CanvasRenderingContext2dSetImageSmoothingEnabled(CanvasRenderingContext2dRef handle, int value);
EXPORT int CanvasRenderingContext2dGetImageSmoothingQuality(CanvasRenderingContext2dRef handle);
EXPORT void CanvasRenderingContext2dSetImageSmoothingQuality(CanvasRenderingContext2dRef handle, int value);
EXPORT char* CanvasRenderingContext2dGetStrokeStyle(CanvasRenderingContext2dRef handle, int* len);
EXPORT void CanvasRenderingContext2dSetStrokeStyle(CanvasRenderingContext2dRef handle, const char* style);
EXPORT double CanvasRenderingContext2dGetShadowOffsetX(CanvasRenderingContext2dRef handle);
EXPORT void CanvasRenderingContext2dSetShadowOffsetX(CanvasRenderingContext2dRef handle, double value);
EXPORT double CanvasRenderingContext2dGetShadowOffsetY(CanvasRenderingContext2dRef handle);
EXPORT void CanvasRenderingContext2dSetShadowOffsetY(CanvasRenderingContext2dRef handle, double value);
EXPORT double CanvasRenderingContext2dGetShadowBlur(CanvasRenderingContext2dRef handle);
EXPORT void CanvasRenderingContext2dSetShadowBlur(CanvasRenderingContext2dRef handle, double value);
EXPORT char* CanvasRenderingContext2dGetShadowColor(CanvasRenderingContext2dRef handle, int* len);
EXPORT void CanvasRenderingContext2dSetShadowColor(CanvasRenderingContext2dRef handle, const char* color);
EXPORT void CanvasRenderingContext2dTransform(CanvasRenderingContext2dRef handle, double a, double b, double c, double d, double e, double f);
EXPORT void CanvasRenderingContext2dSetTransform(CanvasRenderingContext2dRef handle, double a, double b, double c, double d, double e, double f);
EXPORT void CanvasRenderingContext2dResetTransform(CanvasRenderingContext2dRef handle);
EXPORT CanvasGradientRef CanvasRenderingContext2dCreateLinearGradient(CanvasRenderingContext2dRef handle, double x0, double y0, double x1, double y1);
EXPORT CanvasGradientRef CanvasRenderingContext2dCreateRadialGradient(CanvasRenderingContext2dRef handle, double x0, double y0, double r0, double x1, double y1, double r1);
EXPORT CanvasPatternRef CanvasRenderingContext2dCreatePatternImageBitmap(CanvasRenderingContext2dRef handle, WebLocalDomWindowRef window,  WebImageBitmapRef image, const char* repetition_type);
EXPORT CanvasPatternRef CanvasRenderingContext2dCreatePatternImageBitmapForWorker(CanvasRenderingContext2dRef handle, WebWorkerRef worker, WebImageBitmapRef image, const char* repetition_type);
EXPORT CanvasPatternRef CanvasRenderingContext2dCreatePatternImageBitmapForServiceWorker(CanvasRenderingContext2dRef handle, ServiceWorkerGlobalScopeRef scope, WebImageBitmapRef image, const char* repetition_type);
EXPORT CanvasPatternRef CanvasRenderingContext2dCreatePatternCSSImageValue(CanvasRenderingContext2dRef handle, WebLocalDomWindowRef window, CSSImageValueRef image, const char* repetition_type);
EXPORT CanvasPatternRef CanvasRenderingContext2dCreatePatternCSSImageValueForWorker(CanvasRenderingContext2dRef handle, WebWorkerRef worker, CSSImageValueRef image, const char* repetition_type);
EXPORT CanvasPatternRef CanvasRenderingContext2dCreatePatternCSSImageValueForServiceWorker(CanvasRenderingContext2dRef handle, ServiceWorkerGlobalScopeRef scope, CSSImageValueRef image, const char* repetition_type);
EXPORT CanvasPatternRef CanvasRenderingContext2dCreatePatternHtmlImageElement(CanvasRenderingContext2dRef handle, WebLocalDomWindowRef window, WebNodeRef image, const char* repetition_type);
EXPORT CanvasPatternRef CanvasRenderingContext2dCreatePatternHtmlImageElementForWorker(CanvasRenderingContext2dRef handle, WebWorkerRef worker, WebNodeRef image, const char* repetition_type);
EXPORT CanvasPatternRef CanvasRenderingContext2dCreatePatternHtmlImageElementForServiceWorker(CanvasRenderingContext2dRef handle, ServiceWorkerGlobalScopeRef scope, WebNodeRef image, const char* repetition_type);
EXPORT CanvasPatternRef CanvasRenderingContext2dCreatePatternSVGImageElement(CanvasRenderingContext2dRef handle, WebLocalDomWindowRef window, WebNodeRef image, const char* repetition_type);
EXPORT CanvasPatternRef CanvasRenderingContext2dCreatePatternSVGImageElementForWorker(CanvasRenderingContext2dRef handle, WebWorkerRef worker, WebNodeRef image, const char* repetition_type);
EXPORT CanvasPatternRef CanvasRenderingContext2dCreatePatternSVGImageElementForServiceWorker(CanvasRenderingContext2dRef handle, ServiceWorkerGlobalScopeRef scope, WebNodeRef image, const char* repetition_type);
EXPORT CanvasPatternRef CanvasRenderingContext2dCreatePatternHtmlCanvasElement(CanvasRenderingContext2dRef handle, WebLocalDomWindowRef window, WebNodeRef image, const char* repetition_type);
EXPORT CanvasPatternRef CanvasRenderingContext2dCreatePatternHtmlCanvasElementForWorker(CanvasRenderingContext2dRef handle, WebWorkerRef worker, WebNodeRef image, const char* repetition_type);
EXPORT CanvasPatternRef CanvasRenderingContext2dCreatePatternHtmlCanvasElementForServiceWorker(CanvasRenderingContext2dRef handle, ServiceWorkerGlobalScopeRef scope, WebNodeRef image, const char* repetition_type);
EXPORT CanvasPatternRef CanvasRenderingContext2dCreatePatternOffscreenCanvas(CanvasRenderingContext2dRef handle, WebLocalDomWindowRef window, OffscreenCanvasRef image, const char* repetition_type);
EXPORT CanvasPatternRef CanvasRenderingContext2dCreatePatternOffscreenCanvasForWorker(CanvasRenderingContext2dRef handle, WebWorkerRef worker, OffscreenCanvasRef image, const char* repetition_type);
EXPORT CanvasPatternRef CanvasRenderingContext2dCreatePatternOffscreenCanvasForServiceWorker(CanvasRenderingContext2dRef handle, ServiceWorkerGlobalScopeRef scope, OffscreenCanvasRef image, const char* repetition_type);
EXPORT CanvasPatternRef CanvasRenderingContext2dCreatePatternHtmlVideoElement(CanvasRenderingContext2dRef handle, WebLocalDomWindowRef window, WebNodeRef image, const char* repetition_type);
EXPORT CanvasPatternRef CanvasRenderingContext2dCreatePatternHtmlVideoElementForWorker(CanvasRenderingContext2dRef handle, WebWorkerRef worker, WebNodeRef image, const char* repetition_type);
EXPORT CanvasPatternRef CanvasRenderingContext2dCreatePatternHtmlVideoElementForServiceWorker(CanvasRenderingContext2dRef handle, ServiceWorkerGlobalScopeRef scope, WebNodeRef image, const char* repetition_type);
EXPORT void CanvasRenderingContext2dStrokeRect(CanvasRenderingContext2dRef handle, int x, int y, int width, int height);
EXPORT void CanvasRenderingContext2dBeginPath(CanvasRenderingContext2dRef handle);
EXPORT void CanvasRenderingContext2dFillWithWinding(CanvasRenderingContext2dRef handle, int w);
EXPORT void CanvasRenderingContext2dFill(CanvasRenderingContext2dRef handle);
EXPORT void CanvasRenderingContext2dFillWithPathAndWinding(CanvasRenderingContext2dRef handle, Path2dRef path, int w);
EXPORT void CanvasRenderingContext2dFillWithPath(CanvasRenderingContext2dRef handle, Path2dRef path);
EXPORT void CanvasRenderingContext2dStroke(CanvasRenderingContext2dRef handle);
EXPORT void CanvasRenderingContext2dStrokeWithPath(CanvasRenderingContext2dRef handle, Path2dRef path);
EXPORT void CanvasRenderingContext2dClip(CanvasRenderingContext2dRef handle);
EXPORT void CanvasRenderingContext2dClipWithPath(CanvasRenderingContext2dRef handle, Path2dRef path);
EXPORT int CanvasRenderingContext2dIsPointInPathWithWinding(CanvasRenderingContext2dRef handle, double x, double y, int w);
EXPORT int CanvasRenderingContext2dIsPointInPath(CanvasRenderingContext2dRef handle, double x, double y);
EXPORT int CanvasRenderingContext2dIsPointInPathWithPathAndWinding(CanvasRenderingContext2dRef handle, Path2dRef path, double x, double y, int w);
EXPORT int CanvasRenderingContext2dIsPointInPathWithPath(CanvasRenderingContext2dRef handle, Path2dRef path, double x, double y);
EXPORT int CanvasRenderingContext2dIsPointInStroke(CanvasRenderingContext2dRef handle, double x, double y);
EXPORT int CanvasRenderingContext2dIsPointInStroke(CanvasRenderingContext2dRef handle, double x, double y);
EXPORT void CanvasRenderingContext2dDrawImageBitmap(CanvasRenderingContext2dRef handle, WebLocalDomWindowRef window, WebImageBitmapRef image, double x, double y);
EXPORT void CanvasRenderingContext2dDrawImageBitmapWH(CanvasRenderingContext2dRef handle, WebLocalDomWindowRef window, WebImageBitmapRef image, double x, double y, double width, double height);
EXPORT void CanvasRenderingContext2dDrawImageBitmapSrcDst(CanvasRenderingContext2dRef handle, WebLocalDomWindowRef window, WebImageBitmapRef image, double sx, double sy, double sw, double sh, double dx, double dy, double dw, double dh);
EXPORT void CanvasRenderingContext2dDrawImageBitmapForWorker(CanvasRenderingContext2dRef handle, WebWorkerRef worker, WebImageBitmapRef image, double x, double y);
EXPORT void CanvasRenderingContext2dDrawImageBitmapWHForWorker(CanvasRenderingContext2dRef handle, WebWorkerRef worker, WebImageBitmapRef image, double x, double y, double width, double height);
EXPORT void CanvasRenderingContext2dDrawImageBitmapSrcDstForWorker(CanvasRenderingContext2dRef handle, WebWorkerRef worker, WebImageBitmapRef image, double sx, double sy, double sw, double sh, double dx, double dy, double dw, double dh);
EXPORT void CanvasRenderingContext2dDrawImageBitmapForServiceWorker(CanvasRenderingContext2dRef handle, ServiceWorkerGlobalScopeRef scope, WebImageBitmapRef image, double x, double y);
EXPORT void CanvasRenderingContext2dDrawImageBitmapWHForServiceWorker(CanvasRenderingContext2dRef handle, ServiceWorkerGlobalScopeRef scope, WebImageBitmapRef image, double x, double y, double width, double height);
EXPORT void CanvasRenderingContext2dDrawImageBitmapSrcDstForServiceWorker(CanvasRenderingContext2dRef handle, ServiceWorkerGlobalScopeRef scope, WebImageBitmapRef image, double sx, double sy, double sw, double sh, double dx, double dy, double dw, double dh);
EXPORT void CanvasRenderingContext2dDrawImageCSSImage(CanvasRenderingContext2dRef handle, WebLocalDomWindowRef window, CSSImageValueRef image, double x, double y);
EXPORT void CanvasRenderingContext2dDrawImageCSSImageWH(CanvasRenderingContext2dRef handle, WebLocalDomWindowRef window, CSSImageValueRef image, double x, double y, double width, double height);
EXPORT void CanvasRenderingContext2dDrawImageCSSImageSrcDst(CanvasRenderingContext2dRef handle, WebLocalDomWindowRef window, CSSImageValueRef image, double sx, double sy, double sw, double sh, double dx, double dy, double dw, double dh);
EXPORT void CanvasRenderingContext2dDrawImageCSSImageForWorker(CanvasRenderingContext2dRef handle, WebWorkerRef worker, CSSImageValueRef image, double x, double y);
EXPORT void CanvasRenderingContext2dDrawImageCSSImageWHForWorker(CanvasRenderingContext2dRef handle, WebWorkerRef worker, CSSImageValueRef image, double x, double y, double width, double height);
EXPORT void CanvasRenderingContext2dDrawImageCSSImageSrcDstForWorker(CanvasRenderingContext2dRef handle, WebWorkerRef worker, CSSImageValueRef image, double sx, double sy, double sw, double sh, double dx, double dy, double dw, double dh);
EXPORT void CanvasRenderingContext2dDrawImageCSSImageForServiceWorker(CanvasRenderingContext2dRef handle, ServiceWorkerGlobalScopeRef scope, CSSImageValueRef image, double x, double y);
EXPORT void CanvasRenderingContext2dDrawImageCSSImageWHForServiceWorker(CanvasRenderingContext2dRef handle, ServiceWorkerGlobalScopeRef scope, CSSImageValueRef image, double x, double y, double width, double height);
EXPORT void CanvasRenderingContext2dDrawImageCSSImageSrcDstForServiceWorker(CanvasRenderingContext2dRef handle, ServiceWorkerGlobalScopeRef scope, CSSImageValueRef image, double sx, double sy, double sw, double sh, double dx, double dy, double dw, double dh);
EXPORT void CanvasRenderingContext2dDrawImageHTMLImage(CanvasRenderingContext2dRef handle, WebLocalDomWindowRef window, WebNodeRef image, double x, double y);
EXPORT void CanvasRenderingContext2dDrawImageHTMLImageWH(CanvasRenderingContext2dRef handle, WebLocalDomWindowRef window, WebNodeRef image, double x, double y, double width, double height);
EXPORT void CanvasRenderingContext2dDrawImageHTMLImageSrcDst(CanvasRenderingContext2dRef handle, WebLocalDomWindowRef window, WebNodeRef image, double sx, double sy, double sw, double sh, double dx, double dy, double dw, double dh);
EXPORT void CanvasRenderingContext2dDrawImageHTMLImageForWorker(CanvasRenderingContext2dRef handle, WebWorkerRef worker, WebNodeRef image, double x, double y);
EXPORT void CanvasRenderingContext2dDrawImageHTMLImageWHForWorker(CanvasRenderingContext2dRef handle, WebWorkerRef worker, WebNodeRef image, double x, double y, double width, double height);
EXPORT void CanvasRenderingContext2dDrawImageHTMLImageSrcDstForWorker(CanvasRenderingContext2dRef handle, WebWorkerRef worker, WebNodeRef image, double sx, double sy, double sw, double sh, double dx, double dy, double dw, double dh);
EXPORT void CanvasRenderingContext2dDrawImageHTMLImageForServiceWorker(CanvasRenderingContext2dRef handle, ServiceWorkerGlobalScopeRef scope, WebNodeRef image, double x, double y);
EXPORT void CanvasRenderingContext2dDrawImageHTMLImageWHForServiceWorker(CanvasRenderingContext2dRef handle, ServiceWorkerGlobalScopeRef scope, WebNodeRef image, double x, double y, double width, double height);
EXPORT void CanvasRenderingContext2dDrawImageHTMLImageSrcDstForServiceWorker(CanvasRenderingContext2dRef handle, ServiceWorkerGlobalScopeRef scope, WebNodeRef image, double sx, double sy, double sw, double sh, double dx, double dy, double dw, double dh);
EXPORT void CanvasRenderingContext2dDrawImageSVGImage(CanvasRenderingContext2dRef handle, WebLocalDomWindowRef window, WebNodeRef image, double x, double y);
EXPORT void CanvasRenderingContext2dDrawImageSVGImageWH(CanvasRenderingContext2dRef handle, WebLocalDomWindowRef window, WebNodeRef image, double x, double y, double width, double height);
EXPORT void CanvasRenderingContext2dDrawImageSVGImageSrcDst(CanvasRenderingContext2dRef handle, WebLocalDomWindowRef window, WebNodeRef image, double sx, double sy, double sw, double sh, double dx, double dy, double dw, double dh);
EXPORT void CanvasRenderingContext2dDrawImageSVGImageForWorker(CanvasRenderingContext2dRef handle, WebWorkerRef worker, WebNodeRef image, double x, double y);
EXPORT void CanvasRenderingContext2dDrawImageSVGImageWHForWorker(CanvasRenderingContext2dRef handle, WebWorkerRef worker, WebNodeRef image, double x, double y, double width, double height);
EXPORT void CanvasRenderingContext2dDrawImageSVGImageSrcDstForWorker(CanvasRenderingContext2dRef handle, WebWorkerRef worker, WebNodeRef image, double sx, double sy, double sw, double sh, double dx, double dy, double dw, double dh);
EXPORT void CanvasRenderingContext2dDrawImageSVGImageForServiceWorker(CanvasRenderingContext2dRef handle, ServiceWorkerGlobalScopeRef scope, WebNodeRef image, double x, double y);
EXPORT void CanvasRenderingContext2dDrawImageSVGImageWHForServiceWorker(CanvasRenderingContext2dRef handle, ServiceWorkerGlobalScopeRef scope, WebNodeRef image, double x, double y, double width, double height);
EXPORT void CanvasRenderingContext2dDrawImageSVGImageSrcDstForServiceWorker(CanvasRenderingContext2dRef handle, ServiceWorkerGlobalScopeRef scope, WebNodeRef image, double sx, double sy, double sw, double sh, double dx, double dy, double dw, double dh);
EXPORT void CanvasRenderingContext2dDrawImageHTMLCanvas(CanvasRenderingContext2dRef handle, WebLocalDomWindowRef window, WebNodeRef image, double x, double y);
EXPORT void CanvasRenderingContext2dDrawImageHTMLCanvasWH(CanvasRenderingContext2dRef handle, WebLocalDomWindowRef window, WebNodeRef image, double x, double y, double width, double height);
EXPORT void CanvasRenderingContext2dDrawImageHTMLCanvasSrcDst(CanvasRenderingContext2dRef handle, WebLocalDomWindowRef window, WebNodeRef image, double sx, double sy, double sw, double sh, double dx, double dy, double dw, double dh);
EXPORT void CanvasRenderingContext2dDrawImageHTMLCanvasForWorker(CanvasRenderingContext2dRef handle, WebWorkerRef worker, WebNodeRef image, double x, double y);
EXPORT void CanvasRenderingContext2dDrawImageHTMLCanvasWHForWorker(CanvasRenderingContext2dRef handle, WebWorkerRef worker, WebNodeRef image, double x, double y, double width, double height);
EXPORT void CanvasRenderingContext2dDrawImageHTMLCanvasSrcDstForWorker(CanvasRenderingContext2dRef handle, WebWorkerRef worker, WebNodeRef image, double sx, double sy, double sw, double sh, double dx, double dy, double dw, double dh);
EXPORT void CanvasRenderingContext2dDrawImageHTMLCanvasForServiceWorker(CanvasRenderingContext2dRef handle, ServiceWorkerGlobalScopeRef scope, WebNodeRef image, double x, double y);
EXPORT void CanvasRenderingContext2dDrawImageHTMLCanvasWHForServiceWorker(CanvasRenderingContext2dRef handle, ServiceWorkerGlobalScopeRef scope, WebNodeRef image, double x, double y, double width, double height);
EXPORT void CanvasRenderingContext2dDrawImageHTMLCanvasSrcDstForServiceWorker(CanvasRenderingContext2dRef handle, ServiceWorkerGlobalScopeRef scope, WebNodeRef image, double sx, double sy, double sw, double sh, double dx, double dy, double dw, double dh);
EXPORT void CanvasRenderingContext2dDrawImageOffscreenCanvas(CanvasRenderingContext2dRef handle, WebLocalDomWindowRef window, OffscreenCanvasRef image, double x, double y);
EXPORT void CanvasRenderingContext2dDrawImageOffscreenCanvasWH(CanvasRenderingContext2dRef handle, WebLocalDomWindowRef window, OffscreenCanvasRef image, double x, double y, double width, double height);
EXPORT void CanvasRenderingContext2dDrawImageOffscreenCanvasSrcDst(CanvasRenderingContext2dRef handle, WebLocalDomWindowRef window, OffscreenCanvasRef image, double sx, double sy, double sw, double sh, double dx, double dy, double dw, double dh);
EXPORT void CanvasRenderingContext2dDrawImageOffscreenCanvasForWorker(CanvasRenderingContext2dRef handle, WebWorkerRef worker, OffscreenCanvasRef image, double x, double y);
EXPORT void CanvasRenderingContext2dDrawImageOffscreenCanvasWHForWorker(CanvasRenderingContext2dRef handle, WebWorkerRef worker, OffscreenCanvasRef image, double x, double y, double width, double height);
EXPORT void CanvasRenderingContext2dDrawImageOffscreenCanvasSrcDstForWorker(CanvasRenderingContext2dRef handle, WebWorkerRef worker, OffscreenCanvasRef image, double sx, double sy, double sw, double sh, double dx, double dy, double dw, double dh);
EXPORT void CanvasRenderingContext2dDrawImageOffscreenCanvasForServiceWorker(CanvasRenderingContext2dRef handle, ServiceWorkerGlobalScopeRef scope, OffscreenCanvasRef image, double x, double y);
EXPORT void CanvasRenderingContext2dDrawImageOffscreenCanvasWHForServiceWorker(CanvasRenderingContext2dRef handle, ServiceWorkerGlobalScopeRef scope, OffscreenCanvasRef image, double x, double y, double width, double height);
EXPORT void CanvasRenderingContext2dDrawImageOffscreenCanvasSrcDstForServiceWorker(CanvasRenderingContext2dRef handle, ServiceWorkerGlobalScopeRef scope, OffscreenCanvasRef image, double sx, double sy, double sw, double sh, double dx, double dy, double dw, double dh);
EXPORT void CanvasRenderingContext2dDrawImageHTMLVideo(CanvasRenderingContext2dRef handle, WebLocalDomWindowRef window, WebNodeRef image, double x, double y);
EXPORT void CanvasRenderingContext2dDrawImageHTMLVideoWH(CanvasRenderingContext2dRef handle, WebLocalDomWindowRef window, WebNodeRef image, double x, double y, double width, double height);
EXPORT void CanvasRenderingContext2dDrawImageHTMLVideoSrcDst(CanvasRenderingContext2dRef handle, WebLocalDomWindowRef window, WebNodeRef image, double sx, double sy, double sw, double sh, double dx, double dy, double dw, double dh);
EXPORT void CanvasRenderingContext2dDrawImageHTMLVideoForWorker(CanvasRenderingContext2dRef handle, WebWorkerRef worker, WebNodeRef image, double x, double y);
EXPORT void CanvasRenderingContext2dDrawImageHTMLVideoWHForWorker(CanvasRenderingContext2dRef handle, WebWorkerRef worker, WebNodeRef image, double x, double y, double width, double height);
EXPORT void CanvasRenderingContext2dDrawImageHTMLVideoSrcDstForWorker(CanvasRenderingContext2dRef handle, WebWorkerRef worker, WebNodeRef image, double sx, double sy, double sw, double sh, double dx, double dy, double dw, double dh);
EXPORT void CanvasRenderingContext2dDrawImageHTMLVideoForServiceWorker(CanvasRenderingContext2dRef handle, ServiceWorkerGlobalScopeRef scope, WebNodeRef image, double x, double y);
EXPORT void CanvasRenderingContext2dDrawImageHTMLVideoWHForServiceWorker(CanvasRenderingContext2dRef handle, ServiceWorkerGlobalScopeRef scope, WebNodeRef image, double x, double y, double width, double height);
EXPORT void CanvasRenderingContext2dDrawImageHTMLVideoSrcDstForServiceWorker(CanvasRenderingContext2dRef handle, ServiceWorkerGlobalScopeRef scope, WebNodeRef image, double sx, double sy, double sw, double sh, double dx, double dy, double dw, double dh);
EXPORT WebImageDataRef CanvasRenderingContext2dCreateImageData(CanvasRenderingContext2dRef handle, int width, int height, int color_format, int storage_format);
EXPORT WebImageDataRef CanvasRenderingContext2dCreateImageDataWithImageData(CanvasRenderingContext2dRef handle, WebImageDataRef data);
EXPORT WebImageDataRef CanvasRenderingContext2dCreateImageDataWithBytes(CanvasRenderingContext2dRef handle, int width, int height, const uint8_t* data, int count, int color_format, int storage_format);
EXPORT WebImageDataRef CanvasRenderingContext2dCreateImageDataWithUint8Array(CanvasRenderingContext2dRef handle, int width, int height, DOMArrayBufferRef data, int color_format, int storage_format);
EXPORT WebImageDataRef CanvasRenderingContext2dGetImageData(CanvasRenderingContext2dRef handle, int x, int y, int width, int height);
EXPORT void CanvasRenderingContext2dPutImageData(CanvasRenderingContext2dRef handle, WebImageDataRef data, int x, int y);
EXPORT void CanvasRenderingContext2dPutImageDataWithDamage(CanvasRenderingContext2dRef handle, WebImageDataRef data, int x, int y, int dirty_x, int dirty_y, int dirty_width, int dirty_height);
EXPORT void CanvasRenderingContext2dClosePath(CanvasRenderingContext2dRef handle);
EXPORT void CanvasRenderingContext2dMoveTo(CanvasRenderingContext2dRef handle, float x, float y);
EXPORT void CanvasRenderingContext2dLineTo(CanvasRenderingContext2dRef handle, float x, float y);
EXPORT void CanvasRenderingContext2dQuadraticCurveTo(CanvasRenderingContext2dRef handle, float cpx, float cpy, float x, float y);
EXPORT void CanvasRenderingContext2dBezierCurveTo(CanvasRenderingContext2dRef handle, float cp1x, float cp1y, float cp2x, float cp2y, float x, float y);
EXPORT void CanvasRenderingContext2dArcTo(CanvasRenderingContext2dRef handle, float x1, float y1, float x2, float y2, float radius);
EXPORT void CanvasRenderingContext2dRect(CanvasRenderingContext2dRef handle, float x, float y, float width, float height);
EXPORT void CanvasRenderingContext2dArc(CanvasRenderingContext2dRef handle, float x, float y, float radius, float startAngle, float endAngle, int anticlockwise);
EXPORT void CanvasRenderingContext2dEllipse(CanvasRenderingContext2dRef handle, float x, float y, float radiusX, float radiusY, float rotation, float startAngle, float endAngle, int anticlockwise);
EXPORT char* CanvasRenderingContext2dGetFont(CanvasRenderingContext2dRef handle, int* len);
EXPORT void CanvasRenderingContext2dFillTextWithWidth(CanvasRenderingContext2dRef handle, const char*, double x, double y, double width);
EXPORT void CanvasRenderingContext2dFillText(CanvasRenderingContext2dRef handle, const char*, double x, double y);
EXPORT void CanvasRenderingContext2dStrokeTextWithWidth(CanvasRenderingContext2dRef handle, const char*, double x, double y, double width);
EXPORT void CanvasRenderingContext2dStrokeText(CanvasRenderingContext2dRef handle, const char*, double x, double y);
EXPORT int CanvasRenderingContext2dGetTextDirection(CanvasRenderingContext2dRef handle);

// PaintCanvas
EXPORT void PaintCanvasRenderingContext2dDestroy(PaintCanvasRenderingContext2dRef handle);
EXPORT DisplayItemListRef PaintCanvasRenderingContext2dGetDisplayItemList(PaintCanvasRenderingContext2dRef handle);
EXPORT int PaintCanvasRenderingContext2dGetSaveCount(PaintCanvasRenderingContext2dRef handle);
EXPORT int PaintCanvasRenderingContext2dGetLocalClipBounds(PaintCanvasRenderingContext2dRef handle, float* x, float* y, float* width, float* height);
EXPORT int PaintCanvasRenderingContext2dGetDeviceClipBounds(PaintCanvasRenderingContext2dRef handle, int* x, int* y, int* width, int* height);
EXPORT int PaintCanvasRenderingContext2dIsClipEmpty(PaintCanvasRenderingContext2dRef handle);
EXPORT int PaintCanvasRenderingContext2dIsClipRect(PaintCanvasRenderingContext2dRef handle);
EXPORT MatrixRef PaintCanvasRenderingContext2dTotalMatrix(PaintCanvasRenderingContext2dRef handle);
EXPORT void PaintCanvasRenderingContext2dFlush(PaintCanvasRenderingContext2dRef handle);
EXPORT int PaintCanvasRenderingContext2dSave(PaintCanvasRenderingContext2dRef handle);
EXPORT int PaintCanvasRenderingContext2dSaveLayerRect(PaintCanvasRenderingContext2dRef handle, float rx, float ry, float rw, float rh, PaintFlagsRef paint);
EXPORT int PaintCanvasRenderingContext2dSaveLayer(PaintCanvasRenderingContext2dRef handle, PaintFlagsRef paint);
EXPORT int PaintCanvasRenderingContext2dSaveLayerAlpha(PaintCanvasRenderingContext2dRef handle, int alpha);
EXPORT int PaintCanvasRenderingContext2dSaveLayerAlphaRect(PaintCanvasRenderingContext2dRef handle, int alpha, float rx, float ry, float rw, float rh);
EXPORT int PaintCanvasRenderingContext2dSaveLayerPreserveLCDTextRequestsRect(PaintCanvasRenderingContext2dRef handle, float rx, float ry, float rw, float rh, PaintFlagsRef paint);
EXPORT int PaintCanvasRenderingContext2dSaveLayerPreserveLCDTextRequests(PaintCanvasRenderingContext2dRef handle, PaintFlagsRef paint);
EXPORT void PaintCanvasRenderingContext2dRestore(PaintCanvasRenderingContext2dRef handle);
EXPORT void PaintCanvasRenderingContext2dRestoreToCount(PaintCanvasRenderingContext2dRef handle, int save_count);
EXPORT void PaintCanvasRenderingContext2dTranslate(PaintCanvasRenderingContext2dRef handle, float x, float y);
EXPORT void PaintCanvasRenderingContext2dScale(PaintCanvasRenderingContext2dRef handle, float x, float y);
EXPORT void PaintCanvasRenderingContext2dRotate(PaintCanvasRenderingContext2dRef handle, float radians);
EXPORT void PaintCanvasRenderingContext2dConcatHandle(PaintCanvasRenderingContext2dRef handle, MatrixRef matrix);
EXPORT void PaintCanvasRenderingContext2dSetMatrixHandle(PaintCanvasRenderingContext2dRef handle, MatrixRef matrix);
EXPORT void PaintCanvasRenderingContext2dClipRect(PaintCanvasRenderingContext2dRef handle, float rx, float ry, float rw, float rh, int clip, int anti_alias);
EXPORT void PaintCanvasRenderingContext2dClipRRect(PaintCanvasRenderingContext2dRef handle, float rx, float ry, float rw, float rh, int clip, int anti_alias);
EXPORT void PaintCanvasRenderingContext2dClipPath(PaintCanvasRenderingContext2dRef handle, PathRef path, int clip, int anti_alias);
EXPORT void PaintCanvasRenderingContext2dClearRect(PaintCanvasRenderingContext2dRef handle, int rx, int ry, int rw, int rh);
EXPORT void PaintCanvasRenderingContext2dDrawColor(PaintCanvasRenderingContext2dRef handle, int a, int r, int g, int b, int mode);
EXPORT void PaintCanvasRenderingContext2dDrawLine(PaintCanvasRenderingContext2dRef handle, float sx, float sy, float ex, float ey, PaintFlagsRef paint);
EXPORT void PaintCanvasRenderingContext2dDrawRect(PaintCanvasRenderingContext2dRef handle, float rx, float ry, float rw, float rh, PaintFlagsRef paint);    
EXPORT void PaintCanvasRenderingContext2dDrawIRect(PaintCanvasRenderingContext2dRef handle, int rx, int ry, int rw, int rh, PaintFlagsRef paint);
EXPORT void PaintCanvasRenderingContext2dDrawOval(PaintCanvasRenderingContext2dRef handle, float rx, float ry, float rw, float rh, PaintFlagsRef paint);
EXPORT void PaintCanvasRenderingContext2dDrawRRect(PaintCanvasRenderingContext2dRef handle, float rx, float ry, float rw, float rh, PaintFlagsRef paint);    
EXPORT void PaintCanvasRenderingContext2dDrawDRRect(PaintCanvasRenderingContext2dRef handle, float ox, float oy, float ow, float oh, float ix, float iy, float iw, float ih, PaintFlagsRef paint);
EXPORT void PaintCanvasRenderingContext2dDrawRoundRect(PaintCanvasRenderingContext2dRef handle, float rx, float ry, float rw, float rh, float x, float y, PaintFlagsRef paint);
EXPORT void PaintCanvasRenderingContext2dDrawPath(PaintCanvasRenderingContext2dRef handle, PathRef path, PaintFlagsRef paint);
EXPORT void PaintCanvasRenderingContext2dDrawImage(PaintCanvasRenderingContext2dRef handle, ImageRef image, float x, float y, PaintFlagsRef paint);
EXPORT void PaintCanvasRenderingContext2dDrawImageRect(PaintCanvasRenderingContext2dRef handle, ImageRef image, float sx, float sy, float sw, float sh, float dx, float dy, float dw, float dh, int src_rect_constraint, PaintFlagsRef paint);
EXPORT void PaintCanvasRenderingContext2dDrawBitmap(PaintCanvasRenderingContext2dRef handle, BitmapRef bitmap, float left, float top, PaintFlagsRef paint);
EXPORT void PaintCanvasRenderingContext2dDrawTextBlob(PaintCanvasRenderingContext2dRef handle, PaintTextBlobRef text, float x, float y, PaintFlagsRef paint); 
EXPORT void PaintCanvasRenderingContext2dDrawPicture(PaintCanvasRenderingContext2dRef handle, PaintRecordRef record);

EXPORT char* PaintCanvasRenderingContext2dGetFillStyle(PaintCanvasRenderingContext2dRef handle, int* len);
EXPORT void PaintCanvasRenderingContext2dSetFillStyle(PaintCanvasRenderingContext2dRef handle, const char* style);
EXPORT void PaintCanvasRenderingContext2dFillRect(PaintCanvasRenderingContext2dRef handle, int x, int y, int w, int h);
EXPORT double PaintCanvasRenderingContext2dGetLineWidth(PaintCanvasRenderingContext2dRef handle);
EXPORT int PaintCanvasRenderingContext2dGetLineCap(PaintCanvasRenderingContext2dRef handle);
EXPORT int PaintCanvasRenderingContext2dGetLineJoin(PaintCanvasRenderingContext2dRef handle);
EXPORT double PaintCanvasRenderingContext2dGetMiterLimit(PaintCanvasRenderingContext2dRef handle);
EXPORT void PaintCanvasRenderingContext2dGetLineDash(PaintCanvasRenderingContext2dRef handle, double** values, int* value_count);
EXPORT void PaintCanvasRenderingContext2dSetLineDash(PaintCanvasRenderingContext2dRef handle, double* values, int value_count);
EXPORT double PaintCanvasRenderingContext2dGetLineDashOffset(PaintCanvasRenderingContext2dRef handle);
EXPORT int PaintCanvasRenderingContext2dGetTextAlign(PaintCanvasRenderingContext2dRef handle);
EXPORT int PaintCanvasRenderingContext2dGetTextBaseline(PaintCanvasRenderingContext2dRef handle);
EXPORT double PaintCanvasRenderingContext2dGetGlobalAlpha(PaintCanvasRenderingContext2dRef handle);
EXPORT void PaintCanvasRenderingContext2dSetGlobalAlpha(PaintCanvasRenderingContext2dRef handle, double alpha);
EXPORT int PaintCanvasRenderingContext2dGetGlobalCompositeOperation(PaintCanvasRenderingContext2dRef handle);
EXPORT char* PaintCanvasRenderingContext2dGetFilter(PaintCanvasRenderingContext2dRef handle, int* len);
EXPORT int PaintCanvasRenderingContext2dImageSmoothingEnabled(PaintCanvasRenderingContext2dRef handle);
EXPORT void PaintCanvasRenderingContext2dSetImageSmoothingEnabled(PaintCanvasRenderingContext2dRef handle, int value);
EXPORT int PaintCanvasRenderingContext2dGetImageSmoothingQuality(PaintCanvasRenderingContext2dRef handle);
EXPORT void PaintCanvasRenderingContext2dSetImageSmoothingQuality(PaintCanvasRenderingContext2dRef handle, int value);
EXPORT char* PaintCanvasRenderingContext2dGetStrokeStyle(PaintCanvasRenderingContext2dRef handle, int* len);
EXPORT void PaintCanvasRenderingContext2dSetStrokeStyle(PaintCanvasRenderingContext2dRef handle, const char* style);
EXPORT double PaintCanvasRenderingContext2dGetShadowOffsetX(PaintCanvasRenderingContext2dRef handle);
EXPORT void PaintCanvasRenderingContext2dSetShadowOffsetX(PaintCanvasRenderingContext2dRef handle, double value);
EXPORT double PaintCanvasRenderingContext2dGetShadowOffsetY(PaintCanvasRenderingContext2dRef handle);
EXPORT void PaintCanvasRenderingContext2dSetShadowOffsetY(PaintCanvasRenderingContext2dRef handle, double value);
EXPORT double PaintCanvasRenderingContext2dGetShadowBlur(PaintCanvasRenderingContext2dRef handle);
EXPORT void PaintCanvasRenderingContext2dSetShadowBlur(PaintCanvasRenderingContext2dRef handle, double value);
EXPORT char* PaintCanvasRenderingContext2dGetShadowColor(PaintCanvasRenderingContext2dRef handle, int* len);
EXPORT void PaintCanvasRenderingContext2dSetShadowColor(PaintCanvasRenderingContext2dRef handle, const char* color);
EXPORT void PaintCanvasRenderingContext2dTransform(PaintCanvasRenderingContext2dRef handle, double a, double b, double c, double d, double e, double f);
EXPORT void PaintCanvasRenderingContext2dSetTransform(PaintCanvasRenderingContext2dRef handle, double a, double b, double c, double d, double e, double f);
EXPORT void PaintCanvasRenderingContext2dResetTransform(PaintCanvasRenderingContext2dRef handle);
EXPORT CanvasGradientRef PaintCanvasRenderingContext2dCreateLinearGradient(PaintCanvasRenderingContext2dRef handle, double x0, double y0, double x1, double y1);
EXPORT CanvasGradientRef PaintCanvasRenderingContext2dCreateRadialGradient(PaintCanvasRenderingContext2dRef handle, double x0, double y0, double r0, double x1, double y1, double r1);

EXPORT CanvasPatternRef PaintCanvasRenderingContext2dCreatePatternImageBitmap(PaintCanvasRenderingContext2dRef handle, WebLocalDomWindowRef window,  WebImageBitmapRef image, const char* repetition_type);
EXPORT CanvasPatternRef PaintCanvasRenderingContext2dCreatePatternImageBitmapForWorker(PaintCanvasRenderingContext2dRef handle, WebWorkerRef worker, WebImageBitmapRef image, const char* repetition_type);
EXPORT CanvasPatternRef PaintCanvasRenderingContext2dCreatePatternImageBitmapForServiceWorker(PaintCanvasRenderingContext2dRef handle, ServiceWorkerGlobalScopeRef scope, WebImageBitmapRef image, const char* repetition_type);
EXPORT CanvasPatternRef PaintCanvasRenderingContext2dCreatePatternCSSImageValue(PaintCanvasRenderingContext2dRef handle, WebLocalDomWindowRef window, CSSImageValueRef image, const char* repetition_type);
EXPORT CanvasPatternRef PaintCanvasRenderingContext2dCreatePatternCSSImageValueForWorker(PaintCanvasRenderingContext2dRef handle, WebWorkerRef worker, CSSImageValueRef image, const char* repetition_type);
EXPORT CanvasPatternRef PaintCanvasRenderingContext2dCreatePatternCSSImageValueForServiceWorker(PaintCanvasRenderingContext2dRef handle, ServiceWorkerGlobalScopeRef scope, CSSImageValueRef image, const char* repetition_type);
EXPORT CanvasPatternRef PaintCanvasRenderingContext2dCreatePatternHtmlImageElement(PaintCanvasRenderingContext2dRef handle, WebLocalDomWindowRef window, WebNodeRef image, const char* repetition_type);
EXPORT CanvasPatternRef PaintCanvasRenderingContext2dCreatePatternHtmlImageElementForWorker(PaintCanvasRenderingContext2dRef handle, WebWorkerRef worker, WebNodeRef image, const char* repetition_type);
EXPORT CanvasPatternRef PaintCanvasRenderingContext2dCreatePatternHtmlImageElementForServiceWorker(PaintCanvasRenderingContext2dRef handle, ServiceWorkerGlobalScopeRef scope, WebNodeRef image, const char* repetition_type);
EXPORT CanvasPatternRef PaintCanvasRenderingContext2dCreatePatternSVGImageElement(PaintCanvasRenderingContext2dRef handle, WebLocalDomWindowRef window, WebNodeRef image, const char* repetition_type);
EXPORT CanvasPatternRef PaintCanvasRenderingContext2dCreatePatternSVGImageElementForWorker(PaintCanvasRenderingContext2dRef handle, WebWorkerRef worker, WebNodeRef image, const char* repetition_type);
EXPORT CanvasPatternRef PaintCanvasRenderingContext2dCreatePatternSVGImageElementForServiceWorker(PaintCanvasRenderingContext2dRef handle, ServiceWorkerGlobalScopeRef scope, WebNodeRef image, const char* repetition_type);
EXPORT CanvasPatternRef PaintCanvasRenderingContext2dCreatePatternHtmlCanvasElement(PaintCanvasRenderingContext2dRef handle, WebLocalDomWindowRef window, WebNodeRef image, const char* repetition_type);
EXPORT CanvasPatternRef PaintCanvasRenderingContext2dCreatePatternHtmlCanvasElementForWorker(PaintCanvasRenderingContext2dRef handle, WebWorkerRef worker, WebNodeRef image, const char* repetition_type);
EXPORT CanvasPatternRef PaintCanvasRenderingContext2dCreatePatternHtmlCanvasElementForServiceWorker(PaintCanvasRenderingContext2dRef handle, ServiceWorkerGlobalScopeRef scope, WebNodeRef image, const char* repetition_type);
EXPORT CanvasPatternRef PaintCanvasRenderingContext2dCreatePatternOffscreenCanvas(PaintCanvasRenderingContext2dRef handle, WebLocalDomWindowRef window, OffscreenCanvasRef image, const char* repetition_type);
EXPORT CanvasPatternRef PaintCanvasRenderingContext2dCreatePatternOffscreenCanvasForWorker(PaintCanvasRenderingContext2dRef handle, WebWorkerRef worker, OffscreenCanvasRef image, const char* repetition_type);
EXPORT CanvasPatternRef PaintCanvasRenderingContext2dCreatePatternOffscreenCanvasForServiceWorker(PaintCanvasRenderingContext2dRef handle, ServiceWorkerGlobalScopeRef scope, OffscreenCanvasRef image, const char* repetition_type);
EXPORT CanvasPatternRef PaintCanvasRenderingContext2dCreatePatternHtmlVideoElement(PaintCanvasRenderingContext2dRef handle, WebLocalDomWindowRef window, WebNodeRef image, const char* repetition_type);
EXPORT CanvasPatternRef PaintCanvasRenderingContext2dCreatePatternHtmlVideoElementForWorker(PaintCanvasRenderingContext2dRef handle, WebWorkerRef worker, WebNodeRef image, const char* repetition_type);
EXPORT CanvasPatternRef PaintCanvasRenderingContext2dCreatePatternHtmlVideoElementForServiceWorker(PaintCanvasRenderingContext2dRef handle, ServiceWorkerGlobalScopeRef scope, WebNodeRef image, const char* repetition_type);


EXPORT void PaintCanvasRenderingContext2dStrokeRect(PaintCanvasRenderingContext2dRef handle, int x, int y, int width, int height);
EXPORT void PaintCanvasRenderingContext2dBeginPath(PaintCanvasRenderingContext2dRef handle);
EXPORT void PaintCanvasRenderingContext2dFillWithWinding(PaintCanvasRenderingContext2dRef handle, int w);
EXPORT void PaintCanvasRenderingContext2dFill(PaintCanvasRenderingContext2dRef handle);
EXPORT void PaintCanvasRenderingContext2dFillWithPathAndWinding(PaintCanvasRenderingContext2dRef handle, Path2dRef path, int w);
EXPORT void PaintCanvasRenderingContext2dFillWithPath(PaintCanvasRenderingContext2dRef handle, Path2dRef path);
EXPORT void PaintCanvasRenderingContext2dStroke(PaintCanvasRenderingContext2dRef handle);
EXPORT void PaintCanvasRenderingContext2dStrokeWithPath(PaintCanvasRenderingContext2dRef handle, Path2dRef path);
EXPORT void PaintCanvasRenderingContext2dClip(PaintCanvasRenderingContext2dRef handle);
EXPORT void PaintCanvasRenderingContext2dClipWithPath(PaintCanvasRenderingContext2dRef handle, Path2dRef path);
EXPORT int PaintCanvasRenderingContext2dIsPointInPathWithWinding(PaintCanvasRenderingContext2dRef handle, double x, double y, int w);
EXPORT int PaintCanvasRenderingContext2dIsPointInPath(PaintCanvasRenderingContext2dRef handle, double x, double y);
EXPORT int PaintCanvasRenderingContext2dIsPointInPathWithPathAndWinding(PaintCanvasRenderingContext2dRef handle, Path2dRef path, double x, double y, int w);
EXPORT int PaintCanvasRenderingContext2dIsPointInPathWithPath(PaintCanvasRenderingContext2dRef handle, Path2dRef path, double x, double y);
EXPORT int PaintCanvasRenderingContext2dIsPointInStroke(PaintCanvasRenderingContext2dRef handle, double x, double y);
EXPORT int PaintCanvasRenderingContext2dIsPointInStroke(PaintCanvasRenderingContext2dRef handle, double x, double y);
EXPORT void PaintCanvasRenderingContext2dDrawImageBitmap(PaintCanvasRenderingContext2dRef handle, WebLocalDomWindowRef window, WebImageBitmapRef image, double x, double y);
EXPORT void PaintCanvasRenderingContext2dDrawImageBitmapWH(PaintCanvasRenderingContext2dRef handle, WebLocalDomWindowRef window, WebImageBitmapRef image, double x, double y, double width, double height);
EXPORT void PaintCanvasRenderingContext2dDrawImageBitmapSrcDst(PaintCanvasRenderingContext2dRef handle, WebLocalDomWindowRef window, WebImageBitmapRef image, double sx, double sy, double sw, double sh, double dx, double dy, double dw, double dh);
EXPORT void PaintCanvasRenderingContext2dDrawImageBitmapForWorker(PaintCanvasRenderingContext2dRef handle, WebWorkerRef worker, WebImageBitmapRef image, double x, double y);
EXPORT void PaintCanvasRenderingContext2dDrawImageBitmapWHForWorker(PaintCanvasRenderingContext2dRef handle, WebWorkerRef worker, WebImageBitmapRef image, double x, double y, double width, double height);
EXPORT void PaintCanvasRenderingContext2dDrawImageBitmapSrcDstForWorker(PaintCanvasRenderingContext2dRef handle, WebWorkerRef worker, WebImageBitmapRef image, double sx, double sy, double sw, double sh, double dx, double dy, double dw, double dh);
EXPORT void PaintCanvasRenderingContext2dDrawImageBitmapForServiceWorker(PaintCanvasRenderingContext2dRef handle, ServiceWorkerGlobalScopeRef scope, WebImageBitmapRef image, double x, double y);
EXPORT void PaintCanvasRenderingContext2dDrawImageBitmapWHForServiceWorker(PaintCanvasRenderingContext2dRef handle, ServiceWorkerGlobalScopeRef scope, WebImageBitmapRef image, double x, double y, double width, double height);
EXPORT void PaintCanvasRenderingContext2dDrawImageBitmapSrcDstForServiceWorker(PaintCanvasRenderingContext2dRef handle, ServiceWorkerGlobalScopeRef scope, WebImageBitmapRef image, double sx, double sy, double sw, double sh, double dx, double dy, double dw, double dh);
EXPORT void PaintCanvasRenderingContext2dDrawImageCSSImage(PaintCanvasRenderingContext2dRef handle, WebLocalDomWindowRef window, CSSImageValueRef image, double x, double y);
EXPORT void PaintCanvasRenderingContext2dDrawImageCSSImageWH(PaintCanvasRenderingContext2dRef handle, WebLocalDomWindowRef window, CSSImageValueRef image, double x, double y, double width, double height);
EXPORT void PaintCanvasRenderingContext2dDrawImageCSSImageSrcDst(PaintCanvasRenderingContext2dRef handle, WebLocalDomWindowRef window, CSSImageValueRef image, double sx, double sy, double sw, double sh, double dx, double dy, double dw, double dh);
EXPORT void PaintCanvasRenderingContext2dDrawImageCSSImageForWorker(PaintCanvasRenderingContext2dRef handle, WebWorkerRef worker, CSSImageValueRef image, double x, double y);
EXPORT void PaintCanvasRenderingContext2dDrawImageCSSImageWHForWorker(PaintCanvasRenderingContext2dRef handle, WebWorkerRef worker, CSSImageValueRef image, double x, double y, double width, double height);
EXPORT void PaintCanvasRenderingContext2dDrawImageCSSImageSrcDstForWorker(PaintCanvasRenderingContext2dRef handle, WebWorkerRef worker, CSSImageValueRef image, double sx, double sy, double sw, double sh, double dx, double dy, double dw, double dh);
EXPORT void PaintCanvasRenderingContext2dDrawImageCSSImageForServiceWorker(PaintCanvasRenderingContext2dRef handle, ServiceWorkerGlobalScopeRef scope, CSSImageValueRef image, double x, double y);
EXPORT void PaintCanvasRenderingContext2dDrawImageCSSImageWHForServiceWorker(PaintCanvasRenderingContext2dRef handle, ServiceWorkerGlobalScopeRef scope, CSSImageValueRef image, double x, double y, double width, double height);
EXPORT void PaintCanvasRenderingContext2dDrawImageCSSImageSrcDstForServiceWorker(PaintCanvasRenderingContext2dRef handle, ServiceWorkerGlobalScopeRef scope, CSSImageValueRef image, double sx, double sy, double sw, double sh, double dx, double dy, double dw, double dh);
EXPORT void PaintCanvasRenderingContext2dDrawImageHTMLImage(PaintCanvasRenderingContext2dRef handle, WebLocalDomWindowRef window, WebNodeRef image, double x, double y);
EXPORT void PaintCanvasRenderingContext2dDrawImageHTMLImageWH(PaintCanvasRenderingContext2dRef handle, WebLocalDomWindowRef window, WebNodeRef image, double x, double y, double width, double height);
EXPORT void PaintCanvasRenderingContext2dDrawImageHTMLImageSrcDst(PaintCanvasRenderingContext2dRef handle, WebLocalDomWindowRef window, WebNodeRef image, double sx, double sy, double sw, double sh, double dx, double dy, double dw, double dh);
EXPORT void PaintCanvasRenderingContext2dDrawImageHTMLImageForWorker(PaintCanvasRenderingContext2dRef handle, WebWorkerRef worker, WebNodeRef image, double x, double y);
EXPORT void PaintCanvasRenderingContext2dDrawImageHTMLImageWHForWorker(PaintCanvasRenderingContext2dRef handle, WebWorkerRef worker, WebNodeRef image, double x, double y, double width, double height);
EXPORT void PaintCanvasRenderingContext2dDrawImageHTMLImageSrcDstForWorker(PaintCanvasRenderingContext2dRef handle, WebWorkerRef worker, WebNodeRef image, double sx, double sy, double sw, double sh, double dx, double dy, double dw, double dh);
EXPORT void PaintCanvasRenderingContext2dDrawImageHTMLImageForServiceWorker(PaintCanvasRenderingContext2dRef handle, ServiceWorkerGlobalScopeRef scope, WebNodeRef image, double x, double y);
EXPORT void PaintCanvasRenderingContext2dDrawImageHTMLImageWHForServiceWorker(PaintCanvasRenderingContext2dRef handle, ServiceWorkerGlobalScopeRef scope, WebNodeRef image, double x, double y, double width, double height);
EXPORT void PaintCanvasRenderingContext2dDrawImageHTMLImageSrcDstForServiceWorker(PaintCanvasRenderingContext2dRef handle, ServiceWorkerGlobalScopeRef scope, WebNodeRef image, double sx, double sy, double sw, double sh, double dx, double dy, double dw, double dh);
EXPORT void PaintCanvasRenderingContext2dDrawImageSVGImage(PaintCanvasRenderingContext2dRef handle, WebLocalDomWindowRef window, WebNodeRef image, double x, double y);
EXPORT void PaintCanvasRenderingContext2dDrawImageSVGImageWH(PaintCanvasRenderingContext2dRef handle, WebLocalDomWindowRef window, WebNodeRef image, double x, double y, double width, double height);
EXPORT void PaintCanvasRenderingContext2dDrawImageSVGImageSrcDst(PaintCanvasRenderingContext2dRef handle, WebLocalDomWindowRef window, WebNodeRef image, double sx, double sy, double sw, double sh, double dx, double dy, double dw, double dh);
EXPORT void PaintCanvasRenderingContext2dDrawImageSVGImageForWorker(PaintCanvasRenderingContext2dRef handle, WebWorkerRef worker, WebNodeRef image, double x, double y);
EXPORT void PaintCanvasRenderingContext2dDrawImageSVGImageWHForWorker(PaintCanvasRenderingContext2dRef handle, WebWorkerRef worker, WebNodeRef image, double x, double y, double width, double height);
EXPORT void PaintCanvasRenderingContext2dDrawImageSVGImageSrcDstForWorker(PaintCanvasRenderingContext2dRef handle, WebWorkerRef worker, WebNodeRef image, double sx, double sy, double sw, double sh, double dx, double dy, double dw, double dh);
EXPORT void PaintCanvasRenderingContext2dDrawImageSVGImageForServiceWorker(PaintCanvasRenderingContext2dRef handle, ServiceWorkerGlobalScopeRef scope, WebNodeRef image, double x, double y);
EXPORT void PaintCanvasRenderingContext2dDrawImageSVGImageWHForServiceWorker(PaintCanvasRenderingContext2dRef handle, ServiceWorkerGlobalScopeRef scope, WebNodeRef image, double x, double y, double width, double height);
EXPORT void PaintCanvasRenderingContext2dDrawImageSVGImageSrcDstForServiceWorker(PaintCanvasRenderingContext2dRef handle, ServiceWorkerGlobalScopeRef scope, WebNodeRef image, double sx, double sy, double sw, double sh, double dx, double dy, double dw, double dh);
EXPORT void PaintCanvasRenderingContext2dDrawImageHTMLCanvas(PaintCanvasRenderingContext2dRef handle, WebLocalDomWindowRef window, WebNodeRef image, double x, double y);
EXPORT void PaintCanvasRenderingContext2dDrawImageHTMLCanvasWH(PaintCanvasRenderingContext2dRef handle, WebLocalDomWindowRef window, WebNodeRef image, double x, double y, double width, double height);
EXPORT void PaintCanvasRenderingContext2dDrawImageHTMLCanvasSrcDst(PaintCanvasRenderingContext2dRef handle, WebLocalDomWindowRef window, WebNodeRef image, double sx, double sy, double sw, double sh, double dx, double dy, double dw, double dh);
EXPORT void PaintCanvasRenderingContext2dDrawImageHTMLCanvasForWorker(PaintCanvasRenderingContext2dRef handle, WebWorkerRef worker, WebNodeRef image, double x, double y);
EXPORT void PaintCanvasRenderingContext2dDrawImageHTMLCanvasWHForWorker(PaintCanvasRenderingContext2dRef handle, WebWorkerRef worker, WebNodeRef image, double x, double y, double width, double height);
EXPORT void PaintCanvasRenderingContext2dDrawImageHTMLCanvasSrcDstForWorker(PaintCanvasRenderingContext2dRef handle, WebWorkerRef worker, WebNodeRef image, double sx, double sy, double sw, double sh, double dx, double dy, double dw, double dh);
EXPORT void PaintCanvasRenderingContext2dDrawImageHTMLCanvasForServiceWorker(PaintCanvasRenderingContext2dRef handle, ServiceWorkerGlobalScopeRef scope, WebNodeRef image, double x, double y);
EXPORT void PaintCanvasRenderingContext2dDrawImageHTMLCanvasWHForServiceWorker(PaintCanvasRenderingContext2dRef handle, ServiceWorkerGlobalScopeRef scope, WebNodeRef image, double x, double y, double width, double height);
EXPORT void PaintCanvasRenderingContext2dDrawImageHTMLCanvasSrcDstForServiceWorker(PaintCanvasRenderingContext2dRef handle, ServiceWorkerGlobalScopeRef scope, WebNodeRef image, double sx, double sy, double sw, double sh, double dx, double dy, double dw, double dh);
EXPORT void PaintCanvasRenderingContext2dDrawImageOffscreenCanvas(PaintCanvasRenderingContext2dRef handle, WebLocalDomWindowRef window, OffscreenCanvasRef image, double x, double y);
EXPORT void PaintCanvasRenderingContext2dDrawImageOffscreenCanvasWH(PaintCanvasRenderingContext2dRef handle, WebLocalDomWindowRef window, OffscreenCanvasRef image, double x, double y, double width, double height);
EXPORT void PaintCanvasRenderingContext2dDrawImageOffscreenCanvasSrcDst(PaintCanvasRenderingContext2dRef handle, WebLocalDomWindowRef window, OffscreenCanvasRef image, double sx, double sy, double sw, double sh, double dx, double dy, double dw, double dh);
EXPORT void PaintCanvasRenderingContext2dDrawImageOffscreenCanvasForWorker(PaintCanvasRenderingContext2dRef handle, WebWorkerRef worker, OffscreenCanvasRef image, double x, double y);
EXPORT void PaintCanvasRenderingContext2dDrawImageOffscreenCanvasWHForWorker(PaintCanvasRenderingContext2dRef handle, WebWorkerRef worker, OffscreenCanvasRef image, double x, double y, double width, double height);
EXPORT void PaintCanvasRenderingContext2dDrawImageOffscreenCanvasSrcDstForWorker(PaintCanvasRenderingContext2dRef handle, WebWorkerRef worker, OffscreenCanvasRef image, double sx, double sy, double sw, double sh, double dx, double dy, double dw, double dh);
EXPORT void PaintCanvasRenderingContext2dDrawImageOffscreenCanvasForServiceWorker(PaintCanvasRenderingContext2dRef handle, ServiceWorkerGlobalScopeRef scope, OffscreenCanvasRef image, double x, double y);
EXPORT void PaintCanvasRenderingContext2dDrawImageOffscreenCanvasWHForServiceWorker(PaintCanvasRenderingContext2dRef handle, ServiceWorkerGlobalScopeRef scope, OffscreenCanvasRef image, double x, double y, double width, double height);
EXPORT void PaintCanvasRenderingContext2dDrawImageOffscreenCanvasSrcDstForServiceWorker(PaintCanvasRenderingContext2dRef handle, ServiceWorkerGlobalScopeRef scope, OffscreenCanvasRef image, double sx, double sy, double sw, double sh, double dx, double dy, double dw, double dh);
EXPORT void PaintCanvasRenderingContext2dDrawImageHTMLVideo(PaintCanvasRenderingContext2dRef handle, WebLocalDomWindowRef window, WebNodeRef image, double x, double y);
EXPORT void PaintCanvasRenderingContext2dDrawImageHTMLVideoWH(PaintCanvasRenderingContext2dRef handle, WebLocalDomWindowRef window, WebNodeRef image, double x, double y, double width, double height);
EXPORT void PaintCanvasRenderingContext2dDrawImageHTMLVideoSrcDst(PaintCanvasRenderingContext2dRef handle, WebLocalDomWindowRef window, WebNodeRef image, double sx, double sy, double sw, double sh, double dx, double dy, double dw, double dh);
EXPORT void PaintCanvasRenderingContext2dDrawImageHTMLVideoForWorker(PaintCanvasRenderingContext2dRef handle, WebWorkerRef worker, WebNodeRef image, double x, double y);
EXPORT void PaintCanvasRenderingContext2dDrawImageHTMLVideoWHForWorker(PaintCanvasRenderingContext2dRef handle, WebWorkerRef worker, WebNodeRef image, double x, double y, double width, double height);
EXPORT void PaintCanvasRenderingContext2dDrawImageHTMLVideoSrcDstForWorker(PaintCanvasRenderingContext2dRef handle, WebWorkerRef worker, WebNodeRef image, double sx, double sy, double sw, double sh, double dx, double dy, double dw, double dh);
EXPORT void PaintCanvasRenderingContext2dDrawImageHTMLVideoForServiceWorker(PaintCanvasRenderingContext2dRef handle, ServiceWorkerGlobalScopeRef scope, WebNodeRef image, double x, double y);
EXPORT void PaintCanvasRenderingContext2dDrawImageHTMLVideoWHForServiceWorker(PaintCanvasRenderingContext2dRef handle, ServiceWorkerGlobalScopeRef scope, WebNodeRef image, double x, double y, double width, double height);
EXPORT void PaintCanvasRenderingContext2dDrawImageHTMLVideoSrcDstForServiceWorker(PaintCanvasRenderingContext2dRef handle, ServiceWorkerGlobalScopeRef scope, WebNodeRef image, double sx, double sy, double sw, double sh, double dx, double dy, double dw, double dh);
EXPORT WebImageDataRef PaintCanvasRenderingContext2dCreateImageData(PaintCanvasRenderingContext2dRef handle, int width, int height, int color_format, int storage_format);
EXPORT WebImageDataRef PaintCanvasRenderingContext2dCreateImageDataWithImageData(PaintCanvasRenderingContext2dRef handle, WebImageDataRef data);
EXPORT WebImageDataRef PaintCanvasRenderingContext2dCreateImageDataWithBytes(PaintCanvasRenderingContext2dRef handle, int width, int height, const uint8_t* data, int count, int color_format, int storage_format);
EXPORT WebImageDataRef PaintCanvasRenderingContext2dCreateImageDataWithUint8Array(PaintCanvasRenderingContext2dRef handle, int width, int height, DOMArrayBufferRef data, int color_format, int storage_format);
EXPORT WebImageDataRef PaintCanvasRenderingContext2dGetImageData(PaintCanvasRenderingContext2dRef handle, int x, int y, int width, int height);
EXPORT void PaintCanvasRenderingContext2dPutImageData(PaintCanvasRenderingContext2dRef handle, WebImageDataRef data, int x, int y);
EXPORT void PaintCanvasRenderingContext2dPutImageDataWithDamage(PaintCanvasRenderingContext2dRef handle, WebImageDataRef data, int x, int y, int dirty_x, int dirty_y, int dirty_width, int dirty_height);
EXPORT void PaintCanvasRenderingContext2dClosePath(PaintCanvasRenderingContext2dRef handle);
EXPORT void PaintCanvasRenderingContext2dMoveTo(PaintCanvasRenderingContext2dRef handle, float x, float y);
EXPORT void PaintCanvasRenderingContext2dLineTo(PaintCanvasRenderingContext2dRef handle, float x, float y);
EXPORT void PaintCanvasRenderingContext2dQuadraticCurveTo(PaintCanvasRenderingContext2dRef handle, float cpx, float cpy, float x, float y);
EXPORT void PaintCanvasRenderingContext2dBezierCurveTo(PaintCanvasRenderingContext2dRef handle, float cp1x, float cp1y, float cp2x, float cp2y, float x, float y);
EXPORT void PaintCanvasRenderingContext2dArcTo(PaintCanvasRenderingContext2dRef handle, float x1, float y1, float x2, float y2, float radius);
EXPORT void PaintCanvasRenderingContext2dRect(PaintCanvasRenderingContext2dRef handle, float x, float y, float width, float height);
EXPORT void PaintCanvasRenderingContext2dArc(PaintCanvasRenderingContext2dRef handle, float x, float y, float radius, float startAngle, float endAngle, int anticlockwise);
EXPORT void PaintCanvasRenderingContext2dEllipse(PaintCanvasRenderingContext2dRef handle, float x, float y, float radiusX, float radiusY, float rotation, float startAngle, float endAngle, int anticlockwise);


// WebInputEvent
EXPORT float _WebInputEventGetFrameScale(WebInputEventRef handle);
EXPORT void _WebInputEventSetFrameScale(WebInputEventRef handle, float scale);
EXPORT void _WebInputEventGetFrameTranslate(WebInputEventRef handle, float* x, float* y);
EXPORT void _WebInputEventSetFrameTranslate(WebInputEventRef handle, float x, float y);
EXPORT int _WebInputEventGetType(WebInputEventRef handle);
EXPORT void _WebInputEventSetType(WebInputEventRef handle, int type);
EXPORT int _WebInputEventGetModifiers(WebInputEventRef handle);
EXPORT void _WebInputEventSetModifiers(WebInputEventRef handle, int type);
EXPORT int64_t _WebInputEventGetTimestamp(WebInputEventRef handle);
EXPORT void _WebInputEventSetTimestamp(WebInputEventRef handle, int64_t ts);
EXPORT int _WebInputEventGetSize(WebInputEventRef handle);
EXPORT int _WebInputEventIsMouseEvent(WebInputEventRef handle);
EXPORT int _WebInputEventIsKeyboardEvent(WebInputEventRef handle);
EXPORT int _WebInputEventIsTouchEvent(WebInputEventRef handle);
EXPORT int _WebInputEventIsGestureEvent(WebInputEventRef handle);
EXPORT int _WebInputEventIsPointerEvent(WebInputEventRef handle);  

// MouseEvent
EXPORT void _WebMouseEventGetPositionInWidget(WebInputEventRef handle, float* x, float* y);
EXPORT void _WebMouseEventSetPositionInWidget(WebInputEventRef handle, float x, float y);
EXPORT void _WebMouseEventGetPositionInScreen(WebInputEventRef handle, float* x, float* y);
EXPORT void _WebMouseEventSetPositionInScreen(WebInputEventRef handle, float x, float y);
EXPORT int32_t _WebMouseEventGetId(WebInputEventRef handle);
EXPORT float _WebMouseEventGetForce(WebInputEventRef handle);
EXPORT int32_t _WebMouseEventGetButton(WebInputEventRef handle);
EXPORT int _WebMouseEventGetMovementX(WebInputEventRef handle);
EXPORT int _WebMouseEventGetMovementY(WebInputEventRef handle);
EXPORT int _WebMouseEventGetClickCount(WebInputEventRef handle);

EXPORT void _WebGestureEventGetPositionInWidget(WebInputEventRef handle, float* x, float* y);
EXPORT void _WebGestureEventSetPositionInWidget(WebInputEventRef handle, float x, float y);
EXPORT void _WebGestureEventGetPositionInScreen(WebInputEventRef handle, float* x, float* y);
EXPORT void _WebGestureEventSetPositionInScreen(WebInputEventRef handle, float x, float y);

EXPORT int _WebKeyboardEventGetWindowsKeyCode(WebInputEventRef handle);
EXPORT void _WebKeyboardEventSetWindowsKeyCode(WebInputEventRef handle, int code);
EXPORT int _WebKeyboardEventGetNativeKeyCode(WebInputEventRef handle);
EXPORT void _WebKeyboardEventSetNativeKeyCode(WebInputEventRef handle, int code);
EXPORT int _WebKeyboardEventGetDomCode(WebInputEventRef handle);
EXPORT void _WebKeyboardEventSetDomCode(WebInputEventRef handle, int code);
EXPORT int _WebKeyboardEventGetDomKey(WebInputEventRef handle);
EXPORT void _WebKeyboardEventSetDomKey(WebInputEventRef handle, int code);
EXPORT int _WebKeyboardEventIsSystemKey(WebInputEventRef handle);
EXPORT void _WebKeyboardEventSetIsSystemKey(WebInputEventRef handle, int system_key);
EXPORT int _WebKeyboardEventIsBrowserShortcut(WebInputEventRef handle);
EXPORT void _WebKeyboardEventSetIsBrowserShortcut(WebInputEventRef handle, int is_browser_shortcut);
EXPORT void _WebKeyboardEventGetText(WebInputEventRef handle, void* ptr, void(*cb)(void*, const uint16_t*));
EXPORT void _WebKeyboardEventSetText(WebInputEventRef handle, const char* text, int size);
EXPORT void _WebKeyboardEventGetUnmodifiedText(WebInputEventRef handle, void* ptr, void(*cb)(void*, const uint16_t*));
EXPORT void _WebKeyboardEventSetUnmodifiedText(WebInputEventRef handle, const char* text, int size);

EXPORT XMLHttpRequestRef _XMLHttpRequestCreate(WebNodeRef document);
EXPORT int _XMLHttpRequestGetReadyState(XMLHttpRequestRef reference);
EXPORT int _XMLHttpRequestGetStatus(XMLHttpRequestRef reference);
EXPORT char* _XMLHttpRequestGetStatusTextString(XMLHttpRequestRef reference, int* len);
EXPORT int64_t _XMLHttpRequestGetTimeout(XMLHttpRequestRef reference);
EXPORT void _XMLHttpRequestSetTimeout(XMLHttpRequestRef reference, int64_t value);
EXPORT int _XMLHttpRequestHasPendingActivity(XMLHttpRequestRef reference);
EXPORT char* _XMLHttpRequestGetUrl(XMLHttpRequestRef reference, int* len);
EXPORT int _XMLHttpRequestWithCredentials(XMLHttpRequestRef reference);
EXPORT void _XMLHttpRequestSetWithCredentials(XMLHttpRequestRef reference, int value);
EXPORT char* _XMLHttpRequestGetResponseUrl(XMLHttpRequestRef reference, int* len);
EXPORT char* _XMLHttpRequestGetResponseText(XMLHttpRequestRef reference, int* len);
EXPORT WebNodeRef _XMLHttpRequestGetResponseXML(XMLHttpRequestRef reference);
EXPORT BlobRef _XMLHttpRequestGetResponseBlob(XMLHttpRequestRef reference);
EXPORT DOMArrayBufferRef _XMLHttpRequestGetResponseArrayBuffer(XMLHttpRequestRef reference);
EXPORT int _XMLHttpRequestGetResponseType(XMLHttpRequestRef reference);
EXPORT void _XMLHttpRequestSetResponseType(XMLHttpRequestRef reference, int type);
EXPORT int _XMLHttpRequestIsAsync(XMLHttpRequestRef reference);
EXPORT void _XMLHttpRequestOpen(XMLHttpRequestRef reference, int method, const char* url);
EXPORT void _XMLHttpRequestOpenWithAsync(XMLHttpRequestRef reference, int method, const char* url, int async);
EXPORT void _XMLHttpRequestOpenWithUsername(XMLHttpRequestRef reference, int method, const char* url, int async, const char* username, const char* password);
EXPORT void _XMLHttpRequestSend(XMLHttpRequestRef reference);
EXPORT void _XMLHttpRequestAbort(XMLHttpRequestRef reference);
EXPORT void _XMLHttpRequestSetRequestHeader(XMLHttpRequestRef reference, const char* name, const char* value);
EXPORT void _XMLHttpRequestOverrideMimeType(XMLHttpRequestRef reference, const char* type);
EXPORT char* _XMLHttpRequestGetAllResponseHeaders(XMLHttpRequestRef reference, int* len);
EXPORT char* _XMLHttpRequestGetResponseHeader(XMLHttpRequestRef reference, const char* name, int* len);
EXPORT void _XMLHttpRequestSetOnReadyStateChangeCallback(XMLHttpRequestRef reference, void* state, void(*cb)(void*, void*, void*));
EXPORT void _XMLHttpRequestSetOnTimeoutCallback(XMLHttpRequestRef reference, void* state, void(*cb)(void*, void*, void*));
EXPORT void _XMLHttpRequestSetOnProgressCallback(XMLHttpRequestRef reference, void* state, void(*cb)(void*, int, uint64_t, uint64_t));
EXPORT void _XMLHttpRequestSetOnAbortCallback(XMLHttpRequestRef reference, void* state, void(*cb)(void*, void*, void*));
EXPORT void _XMLHttpRequestSetOnErrorCallback(XMLHttpRequestRef reference, void* state, void(*cb)(void*, void*, void*));
EXPORT void _XMLHttpRequestSetOnLoadCallback(XMLHttpRequestRef reference, void* state, void(*cb)(void*, void*, void*));
EXPORT void _XMLHttpRequestSetOnLoadStartCallback(XMLHttpRequestRef reference, void* state, void(*cb)(void*, void*, void*));
EXPORT void _XMLHttpRequestSetOnLoadEndCallback(XMLHttpRequestRef reference, void* state, void(*cb)(void*, void*, void*));

EXPORT DOMArrayBufferRef _DOMArrayBufferCreate(unsigned numElements, unsigned elementByteSize);
EXPORT DOMArrayBufferRef _DOMArrayBufferCreateWithBuffer(const void* source, unsigned byteLength);
EXPORT void* _DOMArrayBufferGetData(DOMArrayBufferRef reference);
EXPORT unsigned _DOMArrayBufferGetByteLength(DOMArrayBufferRef reference);
EXPORT int _DOMArrayBufferIsNeutered(DOMArrayBufferRef reference);
EXPORT int _DOMArrayBufferIsShared(DOMArrayBufferRef reference);
EXPORT DOMArrayBufferRef _DOMArrayBufferSlice(DOMArrayBufferRef reference, int begin, int end);
EXPORT DOMArrayBufferRef _DOMArrayBufferSliceBegin(DOMArrayBufferRef reference, int begin);

EXPORT int _DOMArrayBufferViewGetType(DOMArrayBufferViewRef reference);
EXPORT DOMArrayBufferRef _DOMArrayBufferViewGetBuffer(DOMArrayBufferViewRef reference);
EXPORT unsigned _DOMArrayBufferViewGetByteLenght(DOMArrayBufferViewRef reference);
EXPORT unsigned _DOMArrayBufferViewGetByteOffset(DOMArrayBufferViewRef reference);

EXPORT DOMArrayBufferViewRef _Float32ArrayCreateWithSize(unsigned size);
EXPORT DOMArrayBufferViewRef _Float32ArrayCreateWithData(const float* data, unsigned size);
EXPORT DOMArrayBufferViewRef _Float32ArrayCreateWithBuffer(DOMArrayBufferRef reference, unsigned byte_offset, unsigned length);
EXPORT DOMArrayBufferViewRef _Float64ArrayCreateWithSize(unsigned size);
EXPORT DOMArrayBufferViewRef _Float64ArrayCreateWithData(const double* data, unsigned size);
EXPORT DOMArrayBufferViewRef _Float64ArrayCreateWithBuffer(DOMArrayBufferRef reference, unsigned byte_offset, unsigned length);
EXPORT DOMArrayBufferViewRef _Int8ArrayCreateWithSize(unsigned size);
EXPORT DOMArrayBufferViewRef _Int8ArrayCreateWithData(const int8_t* data, unsigned size);
EXPORT DOMArrayBufferViewRef _Int8ArrayCreateWithBuffer(DOMArrayBufferRef reference, unsigned byte_offset, unsigned length);
EXPORT DOMArrayBufferViewRef _Int16ArrayCreateWithSize(unsigned size);
EXPORT DOMArrayBufferViewRef _Int16ArrayCreateWithData(const int16_t* data, unsigned size);
EXPORT DOMArrayBufferViewRef _Int16ArrayCreateWithBuffer(DOMArrayBufferRef reference, unsigned byte_offset, unsigned length);
EXPORT DOMArrayBufferViewRef _Int32ArrayCreateWithSize(unsigned size);
EXPORT DOMArrayBufferViewRef _Int32ArrayCreateWithData(const int32_t* data, unsigned size);
EXPORT DOMArrayBufferViewRef _Int32ArrayCreateWithBuffer(DOMArrayBufferRef reference, unsigned byte_offset, unsigned length);
EXPORT DOMArrayBufferViewRef _Uint8ArrayCreateWithSize(unsigned size);
EXPORT DOMArrayBufferViewRef _Uint8ArrayCreateWithData(const uint8_t* data, unsigned size);
EXPORT DOMArrayBufferViewRef _Uint8ArrayCreateWithBuffer(DOMArrayBufferRef reference, unsigned byte_offset, unsigned length);
EXPORT DOMArrayBufferViewRef _Uint8ClampedArrayCreateWithSize(unsigned size);
EXPORT DOMArrayBufferViewRef _Uint8ClampedArrayCreateWithData(const uint8_t* data, unsigned size);
EXPORT DOMArrayBufferViewRef _Uint8ClampedArrayCreateWithBuffer(DOMArrayBufferRef reference, unsigned byte_offset, unsigned length);
EXPORT DOMArrayBufferViewRef _Uint16ArrayCreateWithSize(unsigned size);
EXPORT DOMArrayBufferViewRef _Uint16ArrayCreateWithData(const uint16_t* data, unsigned size);
EXPORT DOMArrayBufferViewRef _Uint16ArrayCreateWithBuffer(DOMArrayBufferRef reference, unsigned byte_offset, unsigned length);
EXPORT DOMArrayBufferViewRef _Uint32ArrayCreateWithSize(unsigned size);
EXPORT DOMArrayBufferViewRef _Uint32ArrayCreateWithData(const uint32_t* data, unsigned size);
EXPORT DOMArrayBufferViewRef _Uint32ArrayCreateWithBuffer(DOMArrayBufferRef reference, unsigned byte_offset, unsigned length);

EXPORT BlobDataRef _BlobDataCreateEmpty();
EXPORT BlobDataRef _BlobDataCreateForFile(const char* path);
EXPORT void _BlobDataDestroy(BlobDataRef handle);
EXPORT char* _BlobDataGetContentType(BlobDataRef handle, int* len);
EXPORT void _BlobDataSetContentType(BlobDataRef handle, const char* content_type);
EXPORT void _BlobDataAppendBytes(BlobDataRef handle, const void* data, size_t length);
EXPORT void _BlobDataAppendFile(
  BlobDataRef handle,
  const char* path,
  long long offset,
  long long length,
  double expected_modification_time);
EXPORT void _BlobDataAppendBlobData(
  BlobDataRef handle,
  BlobDataRef blob_data,
  long long offset,
  long long length);
EXPORT void _BlobDataAppendBlobDataHandle(
  BlobDataRef handle,
  BlobDataHandleRef blob_data,
  long long offset,
  long long length);
EXPORT void _BlobDataAppendFileSystemURL(
  BlobDataRef handle,
  const char* url,
  long long offset,
  long long length,
  double expected_modification_time);
EXPORT void _BlobDataAppendText(
  BlobDataRef handle,
  const char* text, 
  int normalize_line_endings_to_native);
EXPORT uint64_t _BlobDataGetLength(BlobDataRef handle);

EXPORT BlobDataHandleRef _BlobDataHandleCreateEmpty();
EXPORT BlobDataHandleRef _BlobDataHandleCreateData(BlobDataRef buffer, long long size);
EXPORT BlobDataHandleRef _BlobDataHandleCreateUUID(const char* uuid, const char* type, long long size);
EXPORT void _BlobDataHandleDestroy(BlobDataHandleRef handle);

EXPORT BlobRef _BlobCreateEmpty();
EXPORT BlobRef _BlobCreateBytes(const unsigned char* data, unsigned bytes, const char* content_type);
EXPORT BlobRef _BlobCreateDataHandle(BlobDataHandleRef data);
EXPORT BlobRef _BlobCreateData(BlobDataRef buf, long long size);

EXPORT char* _DOMUrlCreateObjectURLForBlob(BlobRef blob, int* len);
EXPORT char* _DOMUrlCreateObjectURLForBlobWithContext(WebNodeRef document_handle, BlobRef blob, int* len);
EXPORT char* _DOMUrlCreateObjectURLForSourceWithContext(WebNodeRef document_handle, MediaSourceRef source, int* len);

// WebFrameSelection
EXPORT int _WebFrameSelectionGetLayoutSelectionStart(WebFrameSelectionRef reference, unsigned* result);
EXPORT int _WebFrameSelectionGetLayoutSelectionEnd(WebFrameSelectionRef reference, unsigned* result);
EXPORT int _WebFrameSelectionGetIsAvailable(WebFrameSelectionRef reference);
EXPORT WebNodeRef _WebFrameSelectionGetDocument(WebFrameSelectionRef reference);
EXPORT WebFrameRef _WebFrameSelectionGetLocalFrame(WebFrameSelectionRef reference);
EXPORT WebNodeRef _WebFrameSelectionGetRootEditableElementOrDocumentElement(WebFrameSelectionRef reference);
EXPORT int _WebFrameSelectionNeedsLayoutSelectionUpdate(WebFrameSelectionRef reference);
EXPORT void _WebFrameSelectionGetAbsoluteCaretBounds(WebFrameSelectionRef reference, int* x, int* y, int* w, int* h);
EXPORT int _WebFrameSelectionGetGranularity(WebFrameSelectionRef reference);
EXPORT WebSelectionRef _WebFrameSelectionGetSelection(WebFrameSelectionRef reference);
EXPORT int _WebFrameSelectionGetIsDirectional(WebFrameSelectionRef reference);
EXPORT int _WebFrameSelectionGetSelectionHasFocus(WebFrameSelectionRef reference);
EXPORT int _WebFrameSelectionGetFrameIsFocused(WebFrameSelectionRef reference);
EXPORT void _WebFrameSelectionSetFrameIsFocused(WebFrameSelectionRef reference, int focused);
EXPORT int _WebFrameSelectionGetFrameIsFocusedAndActive(WebFrameSelectionRef reference);
EXPORT WebRangeRef _WebFrameSelectionGetDocumentCachedRange(WebFrameSelectionRef reference);
EXPORT int _WebFrameSelectionGetIsHidden(WebFrameSelectionRef reference);
EXPORT int _WebFrameSelectionGetIsHandleVisible(WebFrameSelectionRef reference);
EXPORT int _WebFrameSelectionGetShouldShrinkNextTap(WebFrameSelectionRef reference);
EXPORT int _WebFrameSelectionGetShouldShowBlockCursor(WebFrameSelectionRef reference);
EXPORT void _WebFrameSelectionSetShouldShowBlockCursor(WebFrameSelectionRef reference, int show);
EXPORT int _WebFrameSelectionGetIsCaretBlinkingSuspended(WebFrameSelectionRef reference);
EXPORT void _WebFrameSelectionSetIsCaretBlinkingSuspended(WebFrameSelectionRef reference, int suspended);
EXPORT char* _WebFrameSelectionGetSelectedHTMLForClipboard(WebFrameSelectionRef reference, int* len);
EXPORT char* _WebFrameSelectionGetSelectedText(WebFrameSelectionRef reference, int* len);
EXPORT char* _WebFrameSelectionGetSelectedTextForClipboard(WebFrameSelectionRef reference, int* len);
EXPORT void _WebFrameSelectionGetAbsoluteUnclippedBounds(WebFrameSelectionRef reference, int* x, int* y, int* w, int* h);
EXPORT int _WebFrameSelectionGetCharacterIndexForPoint(WebFrameSelectionRef reference, int x, int y);
EXPORT void _WebFrameSelectionMoveCaretSelection(WebFrameSelectionRef reference, int x, int y);
EXPORT void _WebFrameSelectionSetSelection(WebFrameSelectionRef reference, 
    WebSelectionRef selection,
    int cursorAlignOnScroll,
    int doNotClearStrategy,
    int doNotSetFocus,
    int granularity,
    int setSelectionBy,
    int shouldClearTypingStyle,
    int shouldCloseTyping,
    int shouldShowHandle,
    int shouldShrinkNextTap,
    int isDirectional);
EXPORT void _WebFrameSelectionSetSelectionAndEndTyping(WebFrameSelectionRef reference, WebSelectionRef selection);
EXPORT void _WebFrameSelectionSelectAllBy(WebFrameSelectionRef reference, int by);
EXPORT void _WebFrameSelectionSelectAll(WebFrameSelectionRef reference);
EXPORT void _WebFrameSelectionSelectSubString(WebFrameSelectionRef reference, WebNodeRef element, int offset, int count);
EXPORT void _WebFrameSelectionClear(WebFrameSelectionRef reference);
EXPORT void _WebFrameSelectionSelectFrameElementInParentIfFullySelected(WebFrameSelectionRef reference);
EXPORT int _WebFrameSelectionContains(WebFrameSelectionRef reference, int px, int py);
EXPORT int _WebFrameSelectionModify(WebFrameSelectionRef reference,
    int alteration,
    int direction,
    int granularity,
    int by);
EXPORT void _WebFrameSelectionMoveRangeSelectionExtent(WebFrameSelectionRef reference, int px, int py);
EXPORT void _WebFrameSelectionMoveRangeSelection(WebFrameSelectionRef reference,
    int base_x, 
    int base_y,
    int extent_x, 
    int extent_y,
    int granularity);
EXPORT void _WebFrameSelectionCommitAppearanceIfNeeded(WebFrameSelectionRef reference);
EXPORT void _WebFrameSelectionSetCaretVisible(WebFrameSelectionRef reference, int visible);
EXPORT void _WebFrameSelectionPageActivationChanged(WebFrameSelectionRef reference);
EXPORT int _WebFrameSelectionSelectWordAroundCaret(WebFrameSelectionRef reference);
EXPORT void _WebFrameSelectionSetFocusedNodeIfNeeded(WebFrameSelectionRef reference);
EXPORT void _WebFrameSelectionNotifyTextControlOfSelectionChange(WebFrameSelectionRef reference, int by);
EXPORT char* _WebFrameSelectionGetSelectedTextWithOptions(WebFrameSelectionRef reference, 
    int collapseTrailingSpace,
    int doesNotBreakAtReplacedElement,
    int emitsCharactersBetweenAllVisiblePositions,
    int emitsImageAltText,
    int emitsSpaceForNbsp,
    int emitsObjectReplacementcharacter,
    int emitsOriginalText,
    int emitsSmallXForTextSecurity,
    int entersOpenShadowRoots,
    int entersTextControls,
    int excludeAutofilledValue,
    int forInnerText,
    int forSelectionToString,
    int forWindowFind,
    int ignoresStyleVisibility,
    int stopsOnFormControls,
    int doesNotEmitSpaceBeyondRangeEnd,
    int skipsUnselectableContent,
    int suppressesNewlineEmission,
    int* len);
EXPORT void _WebFrameSelectionRevealSelection(WebFrameSelectionRef reference, int alignment, int revealExtent);
EXPORT void _WebFrameSelectionSetSelectionFromNone(WebFrameSelectionRef reference);
EXPORT void _WebFrameSelectionUpdateAppearance(WebFrameSelectionRef reference);
EXPORT void _WebFrameSelectionCacheRangeOfDocument(WebFrameSelectionRef reference, WebRangeRef range);
EXPORT void _WebFrameSelectionClearDocumentCachedRange(WebFrameSelectionRef reference);
EXPORT void _WebFrameSelectionClearLayoutSelection(WebFrameSelectionRef reference);
EXPORT WebFrameCaretRef _WebFrameSelectionGetFrameCaret(WebFrameSelectionRef reference);

// WebSelection
EXPORT WebNodeRef _WebSelectionGetAnchorNode(WebSelectionRef reference);
EXPORT uint64_t _WebSelectionGetAnchorOffset(WebSelectionRef reference);
EXPORT WebNodeRef _WebSelectionGetFocusNode(WebSelectionRef reference);
EXPORT uint64_t _WebSelectionGetFocusOffset(WebSelectionRef reference);
EXPORT WebNodeRef _WebSelectionGetBaseNode(WebSelectionRef reference);
EXPORT uint64_t _WebSelectionGetBaseOffset(WebSelectionRef reference);
EXPORT WebNodeRef _WebSelectionGetExtentNode(WebSelectionRef reference);
EXPORT uint64_t _WebSelectionGetExtentOffset(WebSelectionRef reference);
EXPORT int _WebSelectionGetRangeCount(WebSelectionRef reference);
EXPORT int _WebSelectionGetIsCollapsed(WebSelectionRef reference);
EXPORT char* _WebSelectionGetType(WebSelectionRef reference, int* len);
EXPORT WebRangeRef _WebSelectionGetRangeAt(WebSelectionRef reference, int index);
EXPORT void _WebSelectionAddRange(WebSelectionRef reference, WebRangeRef range);
EXPORT void _WebSelectionRemoveRange(WebSelectionRef reference, WebRangeRef range);
EXPORT void _WebSelectionRemoveAllRanges(WebSelectionRef reference);
EXPORT void _WebSelectionEmpty(WebSelectionRef reference);
EXPORT void _WebSelectionCollapse(WebSelectionRef reference, WebNodeRef node, uint64_t offset);
//EXPORT void _WebSelectionSetPosition(WebSelectionRef reference, WebNodeRef node, uint64_t offset);
EXPORT void _WebSelectionCollapseToStart(WebSelectionRef reference);
EXPORT void _WebSelectionCollapseToEnd(WebSelectionRef reference);
EXPORT void _WebSelectionExtend(WebSelectionRef reference, WebNodeRef node, uint64_t offset);
EXPORT void _WebSelectionSetBaseAndExtent(WebSelectionRef reference, 
    WebNodeRef baseNode, uint64_t baseOffset,
    WebNodeRef extentNode, uint64_t extentOffset);
EXPORT void _WebSelectionSelectAllChildren(WebSelectionRef reference, WebNodeRef node);
EXPORT void _WebSelectionDeleteFromDocument(WebSelectionRef reference);
EXPORT int _WebSelectionContainsNode(WebSelectionRef reference, WebNodeRef node, int allowPartialContainment);

// WebFrameCaret

EXPORT int _WebFrameCaretGetIsActive(WebFrameCaretRef reference);
EXPORT int _WebFrameCaretGetIsCaretBlinkingSuspended(WebFrameCaretRef reference); 
EXPORT void _WebFrameCaretSetIsCaretBlinkingSuspended(WebFrameCaretRef reference, int suspended);
EXPORT void _WebFrameCaretGetAbsoluteCaretBounds(WebFrameCaretRef reference, int* x, int* y, int* w, int* h);
EXPORT int _WebFrameCaretGetShouldShowBlockCursor(WebFrameCaretRef reference);
EXPORT void _WebFrameCaretSetShouldShowBlockCursor(WebFrameCaretRef reference, int show);
EXPORT void _WebFrameCaretStopCaretBlinkTimer(WebFrameCaretRef reference);
EXPORT void _WebFrameCaretStartBlinkCaret(WebFrameCaretRef reference);
EXPORT void _WebFrameCaretSetCaretVisibility(WebFrameCaretRef reference, int visibility);

// WebInputMethodController

EXPORT void _WebInputMethodControllerGetTextInputInfo(
  WebInputMethodControllerRef handle,
  int* type,
  int* flags,
  char** value,
  int* value_len,
  int* sstart,
  int* send,
  int* cstart,
  int* cend,
  int* input_mode);
EXPORT int _WebInputMethodControllerComputeWebTextInputNextPreviousFlags(WebInputMethodControllerRef handle);
EXPORT int _WebInputMethodControllerGetTextInputType(WebInputMethodControllerRef handle);
EXPORT void _WebInputMethodControllerGetSelectionOffsets(WebInputMethodControllerRef handle, int* start, int* end);
//EXPORT void _WebInputMethodControllerGetCompositionRange(WebInputMethodControllerRef handle, int* start, int* end);
//EXPORT int _WebInputMethodControllerGetCompositionCharacterBounds(WebInputMethodControllerRef handle, int* count, int** x, int** y, int** w, int** h);
EXPORT void _WebInputMethodControllerSetComposition(
  WebInputMethodControllerRef handle, 
  const char* text,
  int* span_type,
  int* span_start,
  int* span_end,
  int* span_ucolor,
  int* span_thick,
  int* span_bg,
  int span_count,
  int selection_start,
  int selection_end);
EXPORT int _WebInputMethodControllerCommitText(
  WebInputMethodControllerRef handle, 
  const char* text,
  int* span_type,
  int* span_start,
  int* span_end,
  int* span_ucolor,
  int* span_thick,
  int* span_bg,
  int span_count,
  int caret_position);
EXPORT int _WebInputMethodControllerFinishComposingText(WebInputMethodControllerRef handle, int selection_behavior);
EXPORT void _WebInputMethodControllerDeleteSurroundingText(WebInputMethodControllerRef handle, int before, int after);
EXPORT void _WebInputMethodControllerDeleteSurroundingTextInCodePoints(WebInputMethodControllerRef handle, int before, int after);
EXPORT int _WebInputMethodControllerHasComposition(WebInputMethodControllerRef handle);
EXPORT void _WebInputMethodControllerSetCompositionFromExistingText(
  WebInputMethodControllerRef handle, 
  int* span_type,
  int* span_start,
  int* span_end,
  int* span_ucolor,
  int* span_thick,
  int* span_bg,
  int span_count,
  int composition_start,
  int composition_end);
EXPORT void _WebInputMethodControllerCancelComposition(WebInputMethodControllerRef handle);
EXPORT WebRangeRef _WebInputMethodControllerGetCompositionEphemeralRange(WebInputMethodControllerRef handle, WebFrameRef frame);  
EXPORT int _WebInputMethodControllerSetEditableSelectionOffsets(WebInputMethodControllerRef reference, int start, int end);
EXPORT void _WebInputMethodControllerExtendSelectionAndDelete(WebInputMethodControllerRef handle, int before, int after);
EXPORT void _WebInputMethodControllerCreateRangeForSelection(WebInputMethodControllerRef handle, int start, int end, int length, int* start_out, int* end_out);
EXPORT int _WebInputMethodControllerReplaceText(WebInputMethodControllerRef handle, const char* text, int start, int end);

// TextRange helper
EXPORT void _WebTextRangeCreateFromNodeAndRange(WebNodeRef node, int rstart, int rend, int* start, int* end);

// WebAutofillClient
EXPORT void WebAutofillClientDidCompleteFocusChangeInFrame(WebAutofillClientRef handle);

// WebEditor
EXPORT int _WebEditorCanEdit(WebEditorRef handle);
EXPORT void _WebEditorHandleKeyboardEvent(WebEditorRef handle, WebFrameRef frame, WebInputEventRef event);

EXPORT WebEventRef _WebEventCreateEmpty();
EXPORT WebEventRef _WebEventCreate(const char* type, int bubbles, int cancelable);
EXPORT char* _WebEventGetType(WebEventRef reference, int* len);
EXPORT WebNodeRef _WebEventGetTarget(WebEventRef reference);
EXPORT WebNodeRef _WebEventGetCurrentTarget(WebEventRef reference);
EXPORT WebNodeRef _WebEventGetSrcElement(WebEventRef reference);
EXPORT int _WebEventGetEventPhase(WebEventRef reference);
EXPORT int _WebEventBubbles(WebEventRef reference);
EXPORT int _WebEventIsCancelable(WebEventRef reference);
EXPORT int _WebEventDefaultPrevented(WebEventRef reference);
EXPORT int _WebEventIsComposed(WebEventRef reference);
EXPORT int _WebEventIsTrusted(WebEventRef reference);
EXPORT int64_t _WebEventGetTimestamp(WebEventRef reference);
EXPORT void _WebEventStopPropagation(WebEventRef reference);
EXPORT void _WebEventStopImmediatePropagation(WebEventRef reference);
EXPORT void _WebEventPreventDefault(WebEventRef reference);
EXPORT void _WebEventInitEvent(WebEventRef reference, const char* type, int bubbles, int cancelable);
EXPORT int _WebEventIsUIEvent(WebEventRef reference);
EXPORT int _WebEventIsMouseEvent(WebEventRef reference);
EXPORT int _WebEventIsFocusEvent(WebEventRef reference);
EXPORT int _WebEventIsKeyboardEvent(WebEventRef reference);
EXPORT int _WebEventIsTouchEvent(WebEventRef reference);
EXPORT int _WebEventIsGestureEvent(WebEventRef reference);
EXPORT int _WebEventIsWheelEvent(WebEventRef reference);
EXPORT int _WebEventIsRelatedEvent(WebEventRef reference);
EXPORT int _WebEventIsPointerEvent(WebEventRef reference);
EXPORT int _WebEventIsInputEvent(WebEventRef reference);
EXPORT int _WebEventIsDragEvent(WebEventRef reference);
EXPORT int _WebEventIsClipboardEvent(WebEventRef reference);
EXPORT int _WebEventIsBeforeTextInsertedEvent(WebEventRef reference);
EXPORT int _WebEventIsBeforeUnloadEvent(WebEventRef reference);

// MediaControls
EXPORT void _MediaControlsMaybeShow(MediaControlsRef handle);
EXPORT void _MediaControlsHide(MediaControlsRef handle);
EXPORT void _MediaControlsReset(MediaControlsRef handle);

// WebMediaPlayer
EXPORT WebMediaPlayerRef _WebMediaPlayerCreateURL(
  void* state,
  struct WebMediaPlayerDelegateCallbacks callbacks,
  WebFrameRef frame, 
  const char* url,
  void* client,
  void* enc_client,
  void* module,
  const char* sink_id,
  void* web_view_client);
EXPORT WebMediaPlayerRef _WebMediaPlayerCreateMediaStreamDescriptor(
  void* state,
  struct WebMediaPlayerDelegateCallbacks callbacks,
  WebFrameRef frame, 
  WebMediaStreamDescriptorRef descriptor,
  void* client,
  void* enc_client,
  void* module,
  const char* sink_id,
  void* web_view_client);
EXPORT WebMediaPlayerRef _WebMediaPlayerCreateMediaStreamVideo(
  void* state,
  struct WebMediaPlayerDelegateCallbacks callbacks,
  WebFrameRef frame,
  const char* id,
  const char* name,
  int is_remote,
  void* client,
  void* enc_client,
  void* module,
  const char* sink_id,
  void* web_view_client);
EXPORT WebMediaPlayerRef _WebMediaPlayerCreateMediaStreamAudio(
  void* state,
  struct WebMediaPlayerDelegateCallbacks callbacks,
  WebFrameRef frame,
  const char* id,
  const char* name,
  int is_remote,
  void* client,
  void* enc_client,
  void* module,
  const char* sink_id,
  void* web_view_client);
EXPORT void _WebMediaPlayerDestroy(WebMediaPlayerRef reference);
EXPORT int _WebMediaPlayerHasVideo(WebMediaPlayerRef reference);
EXPORT int _WebMediaPlayerHasAudio(WebMediaPlayerRef reference);
EXPORT void _WebMediaPlayerGetNaturalSize(WebMediaPlayerRef reference, int* w, int* h);
EXPORT void _WebMediaPlayerGetVisibleRect(WebMediaPlayerRef reference, int* w, int* h);
EXPORT int _WebMediaPlayerIsPaused(WebMediaPlayerRef reference);
EXPORT int _WebMediaPlayerIsSeeking(WebMediaPlayerRef reference);
EXPORT double _WebMediaPlayerGetDuration(WebMediaPlayerRef reference);
EXPORT double _WebMediaPlayerGetTimelineOffset(WebMediaPlayerRef reference);
EXPORT double _WebMediaPlayerGetCurrentTime(WebMediaPlayerRef reference);
EXPORT int _WebMediaPlayerGetNetworkState(WebMediaPlayerRef reference);
EXPORT int _WebMediaPlayerGetRadyState(WebMediaPlayerRef reference);
EXPORT char* _WebMediaPlayerGetErrorMessage(WebMediaPlayerRef reference, int* len);
EXPORT uint32_t _WebMediaPlayerGetDecodedFrameCount(WebMediaPlayerRef reference);
EXPORT uint32_t _WebMediaPlayerGetDroppedFrameCount(WebMediaPlayerRef reference);
EXPORT uint32_t _WebMediaPlayerGetAudioDecodedByteCount(WebMediaPlayerRef reference);
EXPORT uint32_t _WebMediaPlayerGetVideoDecodedByteCount(WebMediaPlayerRef reference);
EXPORT void _WebMediaPlayerGetBuffered(WebMediaPlayerRef reference, int* len, double** start, double** end);
EXPORT void _WebMediaPlayerGetSeekable(WebMediaPlayerRef reference, int* len, double** start, double** end);
EXPORT void _WebMediaPlayerLoadWithURL(WebMediaPlayerRef reference, int load_type, const char* url, int cors_mode);
EXPORT void _WebMediaPlayerPlay(WebMediaPlayerRef reference);
EXPORT void _WebMediaPlayerPause(WebMediaPlayerRef reference);
EXPORT void _WebMediaPlayerSeek(WebMediaPlayerRef reference, double seconds);
EXPORT void _WebMediaPlayerSetRate(WebMediaPlayerRef reference, double rate);
EXPORT void _WebMediaPlayerSetVolume(WebMediaPlayerRef reference, double volume);
EXPORT double _WebMediaPlayerGetMediaTimeForTimeValue(WebMediaPlayerRef reference, double time_value);
EXPORT void _WebMediaPlayerOnFrameHidden(WebMediaPlayerRef reference);
EXPORT void _WebMediaPlayerOnFrameClosed(WebMediaPlayerRef reference);
EXPORT void _WebMediaPlayerOnFrameShown(WebMediaPlayerRef reference);
EXPORT void _WebMediaPlayerOnIdleTimeout(WebMediaPlayerRef reference);
EXPORT void _WebMediaPlayerOnPlay(WebMediaPlayerRef reference);
EXPORT void _WebMediaPlayerOnPause(WebMediaPlayerRef reference);
EXPORT void _WebMediaPlayerOnSeekForward(WebMediaPlayerRef reference, double seconds);
EXPORT void _WebMediaPlayerOnSeekBackward(WebMediaPlayerRef reference, double seconds);
EXPORT void _WebMediaPlayerOnVolumeMultiplierUpdate(WebMediaPlayerRef reference, double multiplier);
EXPORT void _WebMediaPlayerOnBecamePersistentVideo(WebMediaPlayerRef reference, int value);
EXPORT void _WebMediaPlayerOnPictureInPictureModeEnded(WebMediaPlayerRef reference);

EXPORT WebMediaStreamDescriptorRef _WebMediaStreamDescriptorCreate();
EXPORT char* _WebMediaStreamDescriptorGetId(WebMediaStreamDescriptorRef reference, int* len);
EXPORT int _WebMediaStreamDescriptorGetUniqueId(WebMediaStreamDescriptorRef reference);
EXPORT void _WebMediaStreamDescriptorGetAudioTracks(WebMediaStreamDescriptorRef reference, WebMediaStreamComponentRef** tracks, int* len);
EXPORT void _WebMediaStreamDescriptorGetVideoTracks(WebMediaStreamDescriptorRef reference, WebMediaStreamComponentRef** tracks, int* len);
EXPORT int _WebMediaStreamDescriptorGetAudioTrackCount(WebMediaStreamDescriptorRef reference);
EXPORT int _WebMediaStreamDescriptorGetVideoTrackCount(WebMediaStreamDescriptorRef reference);
EXPORT WebMediaStreamComponentRef _WebMediaStreamDescriptorGetAudioTrack(WebMediaStreamDescriptorRef reference, int index);
EXPORT WebMediaStreamComponentRef _WebMediaStreamDescriptorGetVideoTrack(WebMediaStreamDescriptorRef reference, int index);
EXPORT WebMediaStreamComponentRef _WebMediaStreamDescriptorGetAudioTrackById(WebMediaStreamDescriptorRef reference, const char* id);
EXPORT WebMediaStreamComponentRef _WebMediaStreamDescriptorGetVideoTrackById(WebMediaStreamDescriptorRef reference, const char* id);
EXPORT void _WebMediaStreamDescriptorAddTrack(WebMediaStreamDescriptorRef reference, WebMediaStreamComponentRef track);
EXPORT void _WebMediaStreamDescriptorRemoveTrack(WebMediaStreamDescriptorRef reference, WebMediaStreamComponentRef track);

EXPORT void _WebMediaStreamComponentGetSource(WebMediaStreamComponentRef reference,
    char** id,
    int* id_len,
    int* type,
    char** name,
    int* name_len,
    int* remote,
    int* ready_state);
EXPORT int _WebMediaStreamComponentIsEnabled(WebMediaStreamComponentRef reference);
EXPORT int _WebMediaStreamComponentIsMuted(WebMediaStreamComponentRef reference);

EXPORT void _WebNetworkStateNotifierSetOnline(int online);
EXPORT void _WebNetworkStateNotifierSetWebConnection(int connection_type, double max_bandwidth_mbps);
EXPORT void _WebNetworkStateNotifierSetNetworkQuality(int connection_type, int64_t http_rtt, int64_t transport_rtt, int downlink_throughput_kbps);
EXPORT void _WebNetworkStateNotifierSetSaveDataEnabled(int enabled);

// MediaSource
EXPORT int _MediaSourceIsTypeSupported(const char* type);
EXPORT MediaSourceRef _MediaSourceCreate(WebNodeRef document);
EXPORT double _MediaSourceGetDuration(MediaSourceRef handle);
EXPORT SourceBufferRef _MediaSourceAddSourceBuffer(MediaSourceRef handle, const char* type);
EXPORT void _MediaSourceRemoveSourceBuffer(MediaSourceRef handle, SourceBufferRef buffer);
EXPORT char* _MediaSourceGetReadyState(MediaSourceRef handle, int* len);
EXPORT void _MediaSourceEndOfStream(MediaSourceRef handle, const char* error);
EXPORT void _MediaSourceSetLiveSeekableRange(MediaSourceRef handle, double start, double end);
EXPORT void _MediaSourceClearLiveSeekableRange(MediaSourceRef handle);
EXPORT void _MediaSourceOnSourceOpen(MediaSourceRef handle, void* state, void(*cb)(void*, void*));
EXPORT void _MediaSourceOnSourceEnded(MediaSourceRef handle, void* state, void(*cb)(void*, void*));
EXPORT void _MediaSourceOnSourceClose(MediaSourceRef handle, void* state, void(*cb)(void*, void*));

// SourceBuffer
EXPORT char* _SourceBufferGetMode(SourceBufferRef handle, int* len);
EXPORT int _SourceBufferIsUpdating(SourceBufferRef handle);
EXPORT void _SourceBufferGetBuffered(SourceBufferRef handle, int* len, double** start, double** end);
EXPORT double _SourceBufferGetTimestampOffset(SourceBufferRef handle);
EXPORT double _SourceBufferAppendWindowStart(SourceBufferRef handle);
EXPORT double _SourceBufferAppendWindowEnd(SourceBufferRef handle);
EXPORT void _SourceBufferAppendBuffer(SourceBufferRef handle, DOMArrayBufferRef data);
//EXPORT void _SourceBufferAppendBuffer(SourceBufferRef handle, ArrayBufferView data);
EXPORT void _SourceBufferAbort(SourceBufferRef handle);
EXPORT void _SourceBufferRemove(SourceBufferRef handle, double start, double end);
EXPORT void _SourceBufferOnUpdateStart(SourceBufferRef handle, void* state, void(*cb)(void*, void*));
EXPORT void _SourceBufferOnUpdate(SourceBufferRef handle, void* state, void(*cb)(void*, void*));
EXPORT void _SourceBufferOnUpdateEnd(SourceBufferRef handle, void* state, void(*cb)(void*, void*));
EXPORT void _SourceBufferOnError(SourceBufferRef handle, void* state, void(*cb)(void*, void*));
EXPORT void _SourceBufferOnAbort(SourceBufferRef handle, void* state, void(*cb)(void*, void*));

// WebGL
EXPORT void WebGLRenderingContextGetContextAttributes(WebGLRenderingContextRef handle, int* a, int* b);
EXPORT GLenum WebGLRenderingContextGetError(WebGLRenderingContextRef handle);
EXPORT int WebGLRenderingContextIsContextLost(WebGLRenderingContextRef handle);
EXPORT void WebGLRenderingContextActiveTexture(WebGLRenderingContextRef handle, GLenum texture);
EXPORT void WebGLRenderingContextAttachShader(WebGLRenderingContextRef handle, WebGLProgramRef program, WebGLShaderRef shader);
EXPORT void WebGLRenderingContextBindAttribLocation(WebGLRenderingContextRef handle, WebGLProgramRef program, GLuint index, const char* name);
EXPORT void WebGLRenderingContextBindBuffer(WebGLRenderingContextRef handle, GLenum target, WebGLBufferRef buffer);
EXPORT void WebGLRenderingContextBindFramebuffer(WebGLRenderingContextRef handle, GLenum target, WebGLFramebufferRef framebuffer);
EXPORT void WebGLRenderingContextBindRenderbuffer(WebGLRenderingContextRef handle, GLenum target, WebGLRenderbufferRef renderbuffer);
EXPORT void WebGLRenderingContextBindTexture(WebGLRenderingContextRef handle, GLenum target, WebGLTextureRef texture);
EXPORT void WebGLRenderingContextBlendColor(WebGLRenderingContextRef handle, GLclampf red, GLclampf green, GLclampf blue, GLclampf alpha);
EXPORT void WebGLRenderingContextBlendEquation(WebGLRenderingContextRef handle, GLenum mode);
EXPORT void WebGLRenderingContextBlendEquationSeparate(WebGLRenderingContextRef handle, GLenum modeRGB, GLenum modeAlpha);
EXPORT void WebGLRenderingContextBlendFunc(WebGLRenderingContextRef handle, GLenum sfactor, GLenum dfactor);
EXPORT void WebGLRenderingContextBlendFuncSeparate(WebGLRenderingContextRef handle, GLenum srcRGB, GLenum dstRGB, GLenum srcAlpha, GLenum dstAlpha);
EXPORT void WebGLRenderingContextBufferData0(WebGLRenderingContextRef handle, GLenum target, GLsizeiptr size, GLenum usage);
EXPORT void WebGLRenderingContextBufferData1(WebGLRenderingContextRef handle, GLenum target, DOMArrayBufferViewRef data, GLenum usage);
EXPORT void WebGLRenderingContextBufferData2(WebGLRenderingContextRef handle, GLenum target, DOMArrayBufferRef data, GLenum usage);
EXPORT void WebGLRenderingContextBufferSubData0(WebGLRenderingContextRef handle, GLenum target, GLintptr offset, DOMArrayBufferViewRef data);
EXPORT void WebGLRenderingContextBufferSubData1(WebGLRenderingContextRef handle, GLenum target, GLintptr offset, DOMArrayBufferRef data);
EXPORT GLenum WebGLRenderingContextCheckFramebufferStatus(WebGLRenderingContextRef handle, GLenum target);
EXPORT void WebGLRenderingContextClear(WebGLRenderingContextRef handle, GLbitfield mask);
EXPORT void WebGLRenderingContextClearColor(WebGLRenderingContextRef handle, GLclampf r, GLclampf g, GLclampf b, GLclampf a);
EXPORT void WebGLRenderingContextClearDepth(WebGLRenderingContextRef handle, GLclampf depth);
EXPORT void WebGLRenderingContextClearStencil(WebGLRenderingContextRef handle, GLint s);
EXPORT void WebGLRenderingContextColorMask(WebGLRenderingContextRef handle, GLboolean r, GLboolean g, GLboolean b, GLboolean a);
EXPORT void WebGLRenderingContextCompileShader(WebGLRenderingContextRef handle, WebGLShaderRef shader);
EXPORT void WebGLRenderingContextCompressedTexImage2D0(WebGLRenderingContextRef handle, GLenum target, GLint level, GLenum internalformat, GLsizei width, GLsizei height, GLint border, DOMArrayBufferViewRef data);
EXPORT void WebGLRenderingContextCompressedTexSubImage2D0(WebGLRenderingContextRef handle, GLenum target, GLint level, GLint xoffset, GLint yoffset, GLsizei width, GLsizei height, GLenum format, DOMArrayBufferViewRef data);
EXPORT void WebGLRenderingContextCopyTexImage2D(WebGLRenderingContextRef handle, GLenum target, GLint level, GLenum internalformat, GLint x, GLint y, GLsizei width, GLsizei height, GLint border);
EXPORT void WebGLRenderingContextCopyTexSubImage2D(WebGLRenderingContextRef handle, GLenum target, GLint level, GLint xoffset, GLint yoffset, GLint x, GLint y, GLsizei width, GLsizei height);
EXPORT WebGLBufferRef WebGLRenderingContextCreateBuffer(WebGLRenderingContextRef handle);
EXPORT WebGLFramebufferRef WebGLRenderingContextCreateFramebuffer(WebGLRenderingContextRef handle);
EXPORT WebGLProgramRef WebGLRenderingContextCreateProgram(WebGLRenderingContextRef handle);
EXPORT WebGLRenderbufferRef WebGLRenderingContextCreateRenderbuffer(WebGLRenderingContextRef handle);
EXPORT WebGLShaderRef WebGLRenderingContextCreateShader(WebGLRenderingContextRef handle, GLenum type);
EXPORT WebGLTextureRef WebGLRenderingContextCreateTexture(WebGLRenderingContextRef handle);
EXPORT void WebGLRenderingContextCullFace(WebGLRenderingContextRef handle, GLenum mode);
EXPORT void WebGLRenderingContextDeleteBuffer(WebGLRenderingContextRef handle, WebGLBufferRef buffer);
EXPORT void WebGLRenderingContextDeleteFramebuffer(WebGLRenderingContextRef handle, WebGLFramebufferRef framebuffer);
EXPORT void WebGLRenderingContextDeleteProgram(WebGLRenderingContextRef handle, WebGLProgramRef program);
EXPORT void WebGLRenderingContextDeleteRenderbuffer(WebGLRenderingContextRef handle, WebGLRenderbufferRef renderbuffer);
EXPORT void WebGLRenderingContextDeleteShader(WebGLRenderingContextRef handle, WebGLShaderRef shader);
EXPORT void WebGLRenderingContextDeleteTexture(WebGLRenderingContextRef handle, WebGLTextureRef texture);
EXPORT void WebGLRenderingContextDepthFunc(WebGLRenderingContextRef handle, GLenum func);
EXPORT void WebGLRenderingContextDepthMask(WebGLRenderingContextRef handle, GLboolean flag);
EXPORT void WebGLRenderingContextDepthRange(WebGLRenderingContextRef handle, GLclampf zNear, GLclampf zFar);
EXPORT void WebGLRenderingContextDetachShader(WebGLRenderingContextRef handle, WebGLProgramRef program, WebGLShaderRef shader);
EXPORT void WebGLRenderingContextDisable(WebGLRenderingContextRef handle, GLenum cap);
EXPORT void WebGLRenderingContextDisableVertexAttribArray(WebGLRenderingContextRef handle, GLuint index);
EXPORT void WebGLRenderingContextDrawArrays(WebGLRenderingContextRef handle, GLenum mode, GLint first, GLsizei count);
EXPORT void WebGLRenderingContextDrawElements(WebGLRenderingContextRef handle, GLenum mode, GLsizei count, GLenum type, GLintptr offset);
EXPORT void WebGLRenderingContextEnable(WebGLRenderingContextRef handle, GLenum cap);
EXPORT void WebGLRenderingContextEnableVertexAttribArray(WebGLRenderingContextRef handle, GLuint index);
EXPORT void WebGLRenderingContextFinish(WebGLRenderingContextRef handle);
EXPORT void WebGLRenderingContextFlush(WebGLRenderingContextRef handle);
EXPORT void WebGLRenderingContextFramebufferRenderbuffer(WebGLRenderingContextRef handle, GLenum target, GLenum attachment, GLenum renderbuffertarget, WebGLRenderbufferRef renderbuffer);
EXPORT void WebGLRenderingContextFramebufferTexture2D(WebGLRenderingContextRef handle, GLenum target, GLenum attachment, GLenum textarget, WebGLTextureRef texture, GLint level);
EXPORT void WebGLRenderingContextFrontFace(WebGLRenderingContextRef handle, GLenum mode);
EXPORT void WebGLRenderingContextGenerateMipmap(WebGLRenderingContextRef handle, GLenum target);
EXPORT WebGLActiveInfoRef WebGLRenderingContextGetActiveAttrib(WebGLRenderingContextRef handle, WebGLProgramRef program, GLuint index);
EXPORT WebGLActiveInfoRef WebGLRenderingContextGetActiveUniform(WebGLRenderingContextRef handle, WebGLProgramRef program, GLuint index);
EXPORT void WebGLRenderingContextGetAttachedShaders(WebGLRenderingContextRef handle, WebGLProgramRef program, WebGLShaderRef* out, int* count);
EXPORT GLint WebGLRenderingContextGetAttribLocation(WebGLRenderingContextRef handle, WebGLProgramRef program, const char* name);
EXPORT void* WebGLRenderingContextGetBufferParameter(WebGLRenderingContextRef handle, GLenum target, GLenum name);
EXPORT void* WebGLRenderingContextGetExtension(WebGLRenderingContextRef handle, const char* name);
EXPORT void* WebGLRenderingContextGetFramebufferAttachmentParameter(WebGLRenderingContextRef handle, GLenum target, GLenum attachment, GLenum name);
EXPORT void* WebGLRenderingContextGetParameter(WebGLRenderingContextRef handle, GLenum name);
EXPORT void* WebGLRenderingContextGetProgramParameter(WebGLRenderingContextRef handle, WebGLProgramRef program, GLenum name);
EXPORT char* WebGLRenderingContextGetProgramInfoLog(WebGLRenderingContextRef handle, WebGLProgramRef program, int* len);
EXPORT void* WebGLRenderingContextGetRenderbufferParameter(WebGLRenderingContextRef handle, GLenum target, GLenum name);
EXPORT void* WebGLRenderingContextGetShaderParameter(WebGLRenderingContextRef handle, WebGLShaderRef shader, GLenum name);
EXPORT char* WebGLRenderingContextGetShaderInfoLog(WebGLRenderingContextRef handle, WebGLShaderRef shader, int* len);
EXPORT WebGLShaderPrecisionFormatRef WebGLRenderingContextGetShaderPrecisionFormat(WebGLRenderingContextRef handle, GLenum shadertype, GLenum precisiontype);
EXPORT char* WebGLRenderingContextGetShaderSource(WebGLRenderingContextRef handle, WebGLShaderRef shader, int* len);
EXPORT void WebGLRenderingContextGetSupportedExtensions(WebGLRenderingContextRef handle, const char** ext_out, int* count) ;
EXPORT void* WebGLRenderingContextGetTexParameter(WebGLRenderingContextRef handle, GLenum target, GLenum name);
EXPORT void* WebGLRenderingContextGetUniform(WebGLRenderingContextRef handle, WebGLProgramRef program, WebGLUniformLocationRef location);
EXPORT WebGLUniformLocationRef WebGLRenderingContextGetUniformLocation(WebGLRenderingContextRef handle, WebGLProgramRef program, const char* name);
EXPORT void* WebGLRenderingContextGetVertexAttrib(WebGLRenderingContextRef handle, GLuint index, GLenum name);
EXPORT GLintptr WebGLRenderingContextGetVertexAttribOffset(WebGLRenderingContextRef handle, GLuint index, GLenum name);
EXPORT void WebGLRenderingContextHint(WebGLRenderingContextRef handle, GLenum target, GLenum mode);
EXPORT GLboolean WebGLRenderingContextIsBuffer(WebGLRenderingContextRef handle, WebGLBufferRef buffer);
EXPORT GLboolean WebGLRenderingContextIsEnabled(WebGLRenderingContextRef handle, GLenum cap);
EXPORT GLboolean WebGLRenderingContextIsFramebuffer(WebGLRenderingContextRef handle, WebGLFramebufferRef framebuffer);
EXPORT GLboolean WebGLRenderingContextIsProgram(WebGLRenderingContextRef handle, WebGLProgramRef program);
EXPORT GLboolean WebGLRenderingContextIsRenderbuffer(WebGLRenderingContextRef handle, WebGLRenderbufferRef renderbuffer);
EXPORT GLboolean WebGLRenderingContextIsShader(WebGLRenderingContextRef handle, WebGLShaderRef shader);
EXPORT GLboolean WebGLRenderingContextIsTexture(WebGLRenderingContextRef handle, WebGLTextureRef texture);
EXPORT void WebGLRenderingContextLineWidth(WebGLRenderingContextRef handle, GLfloat width);
EXPORT void WebGLRenderingContextLinkProgram(WebGLRenderingContextRef handle, WebGLProgramRef program);
EXPORT void WebGLRenderingContextPixelStorei(WebGLRenderingContextRef handle, GLenum name, GLint param);
EXPORT void WebGLRenderingContextPolygonOffset(WebGLRenderingContextRef handle, GLfloat factor, GLfloat units);
EXPORT void WebGLRenderingContextReadPixels(WebGLRenderingContextRef handle, GLint x, GLint y, GLsizei width, GLsizei height, GLenum format, GLenum type, DOMArrayBufferViewRef pixels);
EXPORT void WebGLRenderingContexRenderbufferStorage(WebGLRenderingContextRef handle, GLenum target, GLenum internalformat, GLsizei width, GLsizei height);
EXPORT void WebGLRenderingContextSampleCoverage(WebGLRenderingContextRef handle, GLclampf value, GLboolean invert);
EXPORT void WebGLRenderingContextScissor(WebGLRenderingContextRef handle, GLint x, GLint y, GLsizei width, GLsizei height);
EXPORT void WebGLRenderingContextShaderSource(WebGLRenderingContextRef handle, WebGLShaderRef shader, const char* string);
EXPORT void WebGLRenderingContextStencilFunc(WebGLRenderingContextRef handle, GLenum func, GLint ref, GLuint mask);
EXPORT void WebGLRenderingContextStencilFuncSeparate(WebGLRenderingContextRef handle, GLenum face, GLenum func, GLint ref, GLuint mask);
EXPORT void WebGLRenderingContextStencilMask(WebGLRenderingContextRef handle, GLuint mask);
EXPORT void WebGLRenderingContextStencilMaskSeparate(WebGLRenderingContextRef handle, GLenum face, GLuint mask);
EXPORT void WebGLRenderingContextStencilOp(WebGLRenderingContextRef handle, GLenum fail, GLenum zfail, GLenum zpass);
EXPORT void WebGLRenderingContextStencilOpSeparate(WebGLRenderingContextRef handle, GLenum face, GLenum fail, GLenum zfail, GLenum zpass);
EXPORT void WebGLRenderingContextTexParameterf(WebGLRenderingContextRef handle, GLenum target, GLenum name, GLfloat param);
EXPORT void WebGLRenderingContextTexParameteri(WebGLRenderingContextRef handle, GLenum target, GLenum name, GLint param);
EXPORT void WebGLRenderingContextTexImage2D0(WebGLRenderingContextRef handle, GLenum target, GLint level, GLint internalformat, GLsizei width, GLsizei height, GLint border, GLenum format, GLenum type, DOMArrayBufferViewRef pixels);
EXPORT void WebGLRenderingContextTexImage2D1(WebGLRenderingContextRef handle, GLenum target, GLint level, GLint internalformat, GLenum format, GLenum type, WebImageDataRef pixels);
EXPORT void WebGLRenderingContextTexImage2D2(WebGLRenderingContextRef handle, GLenum target, GLint level, GLint internalformat, GLenum format, GLenum type, WebNodeRef image);
EXPORT void WebGLRenderingContextTexImage2D3(WebGLRenderingContextRef handle, GLenum target, GLint level, GLint internalformat, GLenum format, GLenum type, WebNodeRef canvas);
EXPORT void WebGLRenderingContextTexImage2D4(WebGLRenderingContextRef handle, GLenum target, GLint level, GLint internalformat, GLenum format, GLenum type, WebNodeRef video);
EXPORT void WebGLRenderingContextTexImage2D5(WebGLRenderingContextRef handle, GLenum target, GLint level, GLint internalformat, GLenum format, GLenum type, WebImageBitmapRef bitmap);
EXPORT void WebGLRenderingContextTexSubImage2D0(WebGLRenderingContextRef handle, GLenum target, GLint level, GLint xoffset, GLint yoffset, GLsizei width, GLsizei height, GLenum format, GLenum type, DOMArrayBufferViewRef pixels);
EXPORT void WebGLRenderingContextTexSubImage2D1(WebGLRenderingContextRef handle, GLenum target, GLint level, GLint xoffset, GLint yoffset, GLenum format, GLenum type, WebImageDataRef pixels);
EXPORT void WebGLRenderingContextTexSubImage2D2(WebGLRenderingContextRef handle, GLenum target, GLint level, GLint xoffset, GLint yoffset, GLenum format, GLenum type, WebNodeRef image);
EXPORT void WebGLRenderingContextTexSubImage2D3(WebGLRenderingContextRef handle, GLenum target, GLint level, GLint xoffset, GLint yoffset, GLenum format, GLenum type, WebNodeRef canvas);
EXPORT void WebGLRenderingContextTexSubImage2D4(WebGLRenderingContextRef handle, GLenum target, GLint level, GLint xoffset, GLint yoffset, GLenum format, GLenum type, WebNodeRef video);
EXPORT void WebGLRenderingContextTexSubImage2D5(WebGLRenderingContextRef handle, GLenum target, GLint level, GLint xoffset, GLint yoffset, GLenum format, GLenum type, WebImageBitmapRef bitmap);
EXPORT void WebGLRenderingContextUniform1f(WebGLRenderingContextRef handle, WebGLUniformLocationRef location, GLfloat x);
EXPORT void WebGLRenderingContextUniform1fv0(WebGLRenderingContextRef handle, WebGLUniformLocationRef location, DOMArrayBufferViewRef /*Float32Array*/ v);
EXPORT void WebGLRenderingContextUniform1fv1(WebGLRenderingContextRef handle, WebGLUniformLocationRef location, int v_count, const GLfloat* v);
EXPORT void WebGLRenderingContextUniform1i(WebGLRenderingContextRef handle, WebGLUniformLocationRef location, GLint x);
EXPORT void WebGLRenderingContextUniform1iv0(WebGLRenderingContextRef handle, WebGLUniformLocationRef location, DOMArrayBufferViewRef /*Int32Array*/ v);
EXPORT void WebGLRenderingContextUniform1iv1(WebGLRenderingContextRef handle, WebGLUniformLocationRef location, int v_count, const GLint* v);
EXPORT void WebGLRenderingContextUniform2f(WebGLRenderingContextRef handle, WebGLUniformLocationRef location, GLfloat x, GLfloat y);
EXPORT void WebGLRenderingContextUniform2fv0(WebGLRenderingContextRef handle, WebGLUniformLocationRef location, DOMArrayBufferViewRef /*Float32Array*/ v);
EXPORT void WebGLRenderingContextUniform2fv1(WebGLRenderingContextRef handle, WebGLUniformLocationRef location, int v_count, const GLfloat* v);
EXPORT void WebGLRenderingContextUniform2i(WebGLRenderingContextRef handle, WebGLUniformLocationRef location, GLint x, GLint y);
EXPORT void WebGLRenderingContextUniform2iv0(WebGLRenderingContextRef handle, WebGLUniformLocationRef location, DOMArrayBufferViewRef /*Int32Array*/ v);
EXPORT void WebGLRenderingContextUniform2iv1(WebGLRenderingContextRef handle, WebGLUniformLocationRef location, int v_count, const GLint* v);
EXPORT void WebGLRenderingContextUniform3f(WebGLRenderingContextRef handle, WebGLUniformLocationRef location, GLfloat x, GLfloat y, GLfloat z);
EXPORT void WebGLRenderingContextUniform3fv0(WebGLRenderingContextRef handle, WebGLUniformLocationRef location, DOMArrayBufferViewRef /*Float32Array*/ v);
EXPORT void WebGLRenderingContextUniform3fv1(WebGLRenderingContextRef handle, WebGLUniformLocationRef location, int v_count, const GLfloat* v);
EXPORT void WebGLRenderingContextUniform3i(WebGLRenderingContextRef handle, WebGLUniformLocationRef location, GLint x, GLint y, GLint z);
EXPORT void WebGLRenderingContextUniform3iv0(WebGLRenderingContextRef handle, WebGLUniformLocationRef location, DOMArrayBufferViewRef /*Int32Array*/ v);
EXPORT void WebGLRenderingContextUniform3iv1(WebGLRenderingContextRef handle, WebGLUniformLocationRef location, int v_count, const GLint* v);
EXPORT void WebGLRenderingContextUniform4f(WebGLRenderingContextRef handle, WebGLUniformLocationRef location, GLfloat x, GLfloat y, GLfloat z, GLfloat w);
EXPORT void WebGLRenderingContextUniform4fv0(WebGLRenderingContextRef handle, WebGLUniformLocationRef location, DOMArrayBufferViewRef /*Float32Array*/ v);
EXPORT void WebGLRenderingContextUniform4fv1(WebGLRenderingContextRef handle, WebGLUniformLocationRef location, int v_count, const GLfloat* v);
EXPORT void WebGLRenderingContextUniform4i(WebGLRenderingContextRef handle, WebGLUniformLocationRef location, GLint x, GLint y, GLint z, GLint w);
EXPORT void WebGLRenderingContextUniform4iv0(WebGLRenderingContextRef handle, WebGLUniformLocationRef location, DOMArrayBufferViewRef /*Int32Array*/ v);
EXPORT void WebGLRenderingContextUniform4iv1(WebGLRenderingContextRef handle, WebGLUniformLocationRef location, int v_count, const GLint* v);
EXPORT void WebGLRenderingContextUniformMatrix2fv0(WebGLRenderingContextRef handle, WebGLUniformLocationRef location, GLboolean transpose, DOMArrayBufferRef /*Float32Array*/ array);
EXPORT void WebGLRenderingContextUniformMatrix2fv1(WebGLRenderingContextRef handle, WebGLUniformLocationRef location, GLboolean transpose, int arr_count, const GLfloat* array);
EXPORT void WebGLRenderingContextUniformMatrix3fv0(WebGLRenderingContextRef handle, WebGLUniformLocationRef location, GLboolean transpose, DOMArrayBufferRef /*Float32Array*/ array);
EXPORT void WebGLRenderingContextUniformMatrix3fv1(WebGLRenderingContextRef handle, WebGLUniformLocationRef location, GLboolean transpose, int arr_count, const GLfloat* array);
EXPORT void WebGLRenderingContextUniformMatrix4fv0(WebGLRenderingContextRef handle, WebGLUniformLocationRef location, GLboolean transpose, DOMArrayBufferRef /*Float32Array*/ array);
EXPORT void WebGLRenderingContextUniformMatrix4fv1(WebGLRenderingContextRef handle, WebGLUniformLocationRef location, GLboolean transpose, int arr_count, const GLfloat* array);
EXPORT void WebGLRenderingContextUseProgram(WebGLRenderingContextRef handle, WebGLProgramRef program);
EXPORT void WebGLRenderingContextValidateProgram(WebGLRenderingContextRef handle, WebGLProgramRef program);
EXPORT void WebGLRenderingContextVertexAttrib1f(WebGLRenderingContextRef handle, GLuint index, GLfloat x);
EXPORT void WebGLRenderingContextVertexAttrib1fv0(WebGLRenderingContextRef handle, GLuint index, DOMArrayBufferRef /*Float32Array*/ values);
EXPORT void WebGLRenderingContextVertexAttrib1fv1(WebGLRenderingContextRef handle, GLuint index, int values_size, const GLfloat* values);
EXPORT void WebGLRenderingContextVertexAttrib2f(WebGLRenderingContextRef handle, GLuint index, GLfloat x, GLfloat y);
EXPORT void WebGLRenderingContextVertexAttrib2fv0(WebGLRenderingContextRef handle, GLuint index, DOMArrayBufferRef /*Float32Array*/ values);
EXPORT void WebGLRenderingContextVertexAttrib2fv1(WebGLRenderingContextRef handle, GLuint index, int values_size, const GLfloat* values);
EXPORT void WebGLRenderingContextVertexAttrib3f(WebGLRenderingContextRef handle, GLuint index, GLfloat x, GLfloat y, GLfloat z);
EXPORT void WebGLRenderingContextVertexAttrib3fv0(WebGLRenderingContextRef handle, GLuint index, DOMArrayBufferRef /*Float32Array*/ values);
EXPORT void WebGLRenderingContextVertexAttrib3fv1(WebGLRenderingContextRef handle, GLuint index, int values_size, const GLfloat* values);
EXPORT void WebGLRenderingContextVertexAttrib4f(WebGLRenderingContextRef handle, GLuint index, GLfloat x, GLfloat y, GLfloat z, GLfloat w);
EXPORT void WebGLRenderingContextVertexAttrib4fv0(WebGLRenderingContextRef handle, GLuint index, DOMArrayBufferRef /*Float32Array*/ values);
EXPORT void WebGLRenderingContextVertexAttrib4fv1(WebGLRenderingContextRef handle, GLuint index, int values_size, const GLfloat* values);
EXPORT void WebGLRenderingContextVertexAttribPointer(WebGLRenderingContextRef handle, GLuint index, GLint size, GLenum type, GLboolean normalized, GLsizei stride, GLintptr offset);
EXPORT void WebGLRenderingContextViewport(WebGLRenderingContextRef handle, GLint x, GLint y, GLsizei width, GLsizei height);
EXPORT void WebGLRenderingContextCommit(WebGLRenderingContextRef handle, WebLocalDomWindowRef window, void* state, void(*cb)(void*, void*));
EXPORT void WebGLRenderingContextCommitFromWorker(WebGLRenderingContextRef handle, WebWorkerRef worker, void* state, void(*cb)(void*, void*));
EXPORT void WebGLRenderingContextCommitFromServiceWorker(WebGLRenderingContextRef handle, ServiceWorkerGlobalScopeRef scope, void* state, void(*cb)(void*, void*));


// webgl2
EXPORT void WebGL2RenderingContextBufferData3(WebGLRenderingContextRef handle, GLenum target, DOMArrayBufferViewRef srcData, GLenum usage, GLuint srcOffset, GLuint length);
EXPORT void WebGL2RenderingContextBufferSubData(WebGLRenderingContextRef handle, GLenum target, GLintptr dstByteOffset, DOMArrayBufferViewRef srcData, GLuint srcOffset, GLuint length);
EXPORT void WebGL2RenderingContextCopyBufferSubData(WebGLRenderingContextRef handle, GLenum readTarget, GLenum writeTarget, GLintptr readOffset, GLintptr writeOffset, GLsizeiptr size);
EXPORT void WebGL2RenderingContextGetBufferSubData(WebGLRenderingContextRef handle, GLenum target, GLintptr srcByteOffset, DOMArrayBufferViewRef dstData, GLuint dstOffset, GLuint length);
EXPORT GLint WebGL2RenderingContextGetFragDataLocation(WebGLRenderingContextRef handle, WebGLProgramRef program, const char* name);
EXPORT void WebGL2RenderingContextTexImage2D6(WebGLRenderingContextRef handle, GLenum target, GLint level, GLint internalformat, GLsizei width, GLsizei height, GLint border, GLenum format, GLenum type, GLintptr offset);
EXPORT void WebGL2RenderingContextTexImage2D7(WebGLRenderingContextRef handle, GLenum target, GLint level, GLint internalformat, GLsizei width, GLsizei height, GLint border, GLenum format, GLenum type, WebImageDataRef data);
EXPORT void WebGL2RenderingContextTexImage2D8(WebGLRenderingContextRef handle, GLenum target, GLint level, GLint internalformat, GLsizei width, GLsizei height, GLint border, GLenum format, GLenum type, WebNodeRef image);
EXPORT void WebGL2RenderingContextTexImage2D9(WebGLRenderingContextRef handle, GLenum target, GLint level, GLint internalformat, GLsizei width, GLsizei height, GLint border, GLenum format, GLenum type, WebNodeRef canvas);
EXPORT void WebGL2RenderingContextTexImage2D10(WebGLRenderingContextRef handle, GLenum target, GLint level, GLint internalformat, GLsizei width, GLsizei height, GLint border, GLenum format, GLenum type, WebNodeRef video);
EXPORT void WebGL2RenderingContextTexImage2D11(WebGLRenderingContextRef handle, GLenum target, GLint level, GLint internalformat, GLsizei width, GLsizei height, GLint border, GLenum format, GLenum type, WebImageBitmapRef bitmap);
EXPORT void WebGL2RenderingContextTexImage2D12(WebGLRenderingContextRef handle, GLenum target, GLint level, GLint internalformat, GLsizei width, GLsizei height, GLint border, GLenum format, GLenum type, DOMArrayBufferViewRef srcData, GLuint srcOffset);
EXPORT void WebGL2RenderingContextTexSubImage2D6(WebGLRenderingContextRef handle, GLenum target, GLint level, GLint xoffset, GLint yoffset, GLsizei width, GLsizei height, GLenum format, GLenum type, GLintptr offset);
EXPORT void WebGL2RenderingContextTexSubImage2D7(WebGLRenderingContextRef handle, GLenum target, GLint level, GLint xoffset, GLint yoffset, GLsizei width, GLsizei height, GLenum format, GLenum type, WebImageDataRef data);
EXPORT void WebGL2RenderingContextTexSubImage2D8(WebGLRenderingContextRef handle, GLenum target, GLint level, GLint xoffset, GLint yoffset, GLsizei width, GLsizei height, GLenum format, GLenum type, WebNodeRef image);
EXPORT void WebGL2RenderingContextTexSubImage2D9(WebGLRenderingContextRef handle, GLenum target, GLint level, GLint xoffset, GLint yoffset, GLsizei width, GLsizei height, GLenum format, GLenum type, WebNodeRef canvas);
EXPORT void WebGL2RenderingContextTexSubImage2D10(WebGLRenderingContextRef handle, GLenum target, GLint level, GLint xoffset, GLint yoffset, GLsizei width, GLsizei height, GLenum format, GLenum type, WebNodeRef video);
EXPORT void WebGL2RenderingContextTexSubImage2D11(WebGLRenderingContextRef handle, GLenum target, GLint level, GLint xoffset, GLint yoffset, GLsizei width, GLsizei height, GLenum format, GLenum type, WebImageBitmapRef bitmap);
EXPORT void WebGL2RenderingContextTexSubImage2D12(WebGLRenderingContextRef handle, GLenum target, GLint level, GLint xoffset, GLint yoffset, GLsizei width, GLsizei height, GLenum format, GLenum type, DOMArrayBufferViewRef srcData, GLuint srcOffset);
EXPORT void WebGL2RenderingContextTexStorage2D0(WebGLRenderingContextRef handle, GLenum target, GLsizei levels, GLenum internalformat, GLsizei width, GLsizei height);
EXPORT void WebGL2RenderingContextTexStorage3D1(WebGLRenderingContextRef handle, GLenum target, GLsizei levels, GLenum internalformat, GLsizei width, GLsizei height, GLsizei depth);
EXPORT void WebGL2RenderingContextTexImage3D0(WebGLRenderingContextRef handle, GLenum target, GLint level, GLint internalformat, GLsizei width, GLsizei height, GLsizei depth, GLint border, GLenum format, GLenum type, GLintptr offset);
EXPORT void WebGL2RenderingContextTexImage3D1(WebGLRenderingContextRef handle, GLenum target, GLint level, GLint internalformat, GLsizei width, GLsizei height, GLsizei depth, GLint border, GLenum format, GLenum type, WebImageDataRef data);
EXPORT void WebGL2RenderingContextTexImage3D2(WebGLRenderingContextRef handle, GLenum target, GLint level, GLint internalformat, GLsizei width, GLsizei height, GLsizei depth, GLint border, GLenum format, GLenum type, WebNodeRef image);
EXPORT void WebGL2RenderingContextTexImage3D3(WebGLRenderingContextRef handle, GLenum target, GLint level, GLint internalformat, GLsizei width, GLsizei height, GLsizei depth, GLint border, GLenum format, GLenum type, WebNodeRef canvas);
EXPORT void WebGL2RenderingContextTexImage3D4(WebGLRenderingContextRef handle, GLenum target, GLint level, GLint internalformat, GLsizei width, GLsizei height, GLsizei depth, GLint border, GLenum format, GLenum type, WebNodeRef video);
EXPORT void WebGL2RenderingContextTexImage3D5(WebGLRenderingContextRef handle, GLenum target, GLint level, GLint internalformat, GLsizei width, GLsizei height, GLsizei depth, GLint border, GLenum format, GLenum type, WebImageBitmapRef bitmap);
EXPORT void WebGL2RenderingContextTexImage3D6(WebGLRenderingContextRef handle, GLenum target, GLint level, GLint internalformat, GLsizei width, GLsizei height, GLsizei depth, GLint border, GLenum format, GLenum type, DOMArrayBufferViewRef pixels);
EXPORT void WebGL2RenderingContextTexImage3D7(WebGLRenderingContextRef handle, GLenum target, GLint level, GLint internalformat, GLsizei width, GLsizei height, GLsizei depth, GLint border, GLenum format, GLenum type, DOMArrayBufferViewRef pixels, GLuint srcOffset);
EXPORT void WebGL2RenderingContextTexSubImage3D0(WebGLRenderingContextRef handle, GLenum target, GLint level, GLint xoffset, GLint yoffset, GLint zoffset, GLsizei width, GLsizei height, GLsizei depth, GLenum format, GLenum type, GLintptr offset);
EXPORT void WebGL2RenderingContextTexSubImage3D1(WebGLRenderingContextRef handle, GLenum target, GLint level, GLint xoffset, GLint yoffset, GLint zoffset, GLsizei width, GLsizei height, GLsizei depth, GLenum format, GLenum type, WebImageDataRef data);
EXPORT void WebGL2RenderingContextTexSubImage3D2(WebGLRenderingContextRef handle, GLenum target, GLint level, GLint xoffset, GLint yoffset, GLint zoffset, GLsizei width, GLsizei height, GLsizei depth, GLenum format, GLenum type, WebNodeRef  image);
EXPORT void WebGL2RenderingContextTexSubImage3D3(WebGLRenderingContextRef handle, GLenum target, GLint level, GLint xoffset, GLint yoffset, GLint zoffset, GLsizei width, GLsizei height, GLsizei depth, GLenum format, GLenum type, WebNodeRef  canvas);
EXPORT void WebGL2RenderingContextTexSubImage3D4(WebGLRenderingContextRef handle, GLenum target, GLint level, GLint xoffset, GLint yoffset, GLint zoffset, GLsizei width, GLsizei height, GLsizei depth, GLenum format, GLenum type, WebNodeRef  video);
EXPORT void WebGL2RenderingContextTexSubImage3D5(WebGLRenderingContextRef handle, GLenum target, GLint level, GLint xoffset, GLint yoffset, GLint zoffset, GLsizei width, GLsizei height, GLsizei depth, GLenum format, GLenum type, WebImageBitmapRef bitmap);
EXPORT void WebGL2RenderingContextTexSubImage3D6(WebGLRenderingContextRef handle, GLenum target, GLint level, GLint xoffset, GLint yoffset, GLint zoffset, GLsizei width, GLsizei height, GLsizei depth, GLenum format, GLenum type, DOMArrayBufferViewRef pixels, GLuint srcOffset);
EXPORT void WebGL2RenderingContextCopyTexSubImage3D(WebGLRenderingContextRef handle, GLenum target, GLint level, GLint xoffset, GLint yoffset, GLint zoffset, GLint x, GLint y, GLsizei width, GLsizei height);
EXPORT void WebGL2RenderingContextCompressedTexImage2D1(WebGLRenderingContextRef handle, GLenum target, GLint level, GLenum internalformat, GLsizei width, GLsizei height, GLint border, DOMArrayBufferViewRef data, GLuint srcOffset, GLuint srcLengthOverride);
EXPORT void WebGL2RenderingContextCompressedTexSubImage2D1(WebGLRenderingContextRef handle, GLenum target, GLint level, GLint xoffset, GLint yoffset, GLsizei width, GLsizei height, GLenum format, DOMArrayBufferViewRef data, GLuint srcOffset, GLuint srcLengthOverride);
EXPORT void WebGL2RenderingContextCompressedTexImage3D0(WebGLRenderingContextRef handle, GLenum target, GLint level, GLenum internalformat, GLsizei width, GLsizei height, GLsizei depth, GLint border, DOMArrayBufferViewRef data, GLuint srcOffset, GLuint srcLengthOverride);
EXPORT void WebGL2RenderingContextCompressedTexSubImage3D0(WebGLRenderingContextRef handle, GLenum target, GLint level, GLint xoffset, GLint yoffset, GLint zoffset, GLsizei width, GLsizei height, GLsizei depth, GLenum format, DOMArrayBufferViewRef data, GLuint srcOffset, GLuint srcLengthOverride);
EXPORT void WebGL2RenderingContextCompressedTexImage2D2(WebGLRenderingContextRef handle, GLenum target, GLint level, GLenum internalformat, GLsizei width, GLsizei height, GLint border, GLsizei imageSize, GLintptr offset);
EXPORT void WebGL2RenderingContextCompressedTexSubImage2D2(WebGLRenderingContextRef handle, GLenum target, GLint level, GLint xoffset, GLint yoffset, GLsizei width, GLsizei height, GLenum format, GLsizei imageSize, GLintptr offset);
EXPORT void WebGL2RenderingContextCompressedTexImage3D1(WebGLRenderingContextRef handle, GLenum target, GLint level, GLenum internalformat, GLsizei width, GLsizei height, GLsizei depth, GLint border, GLsizei imageSize, GLintptr offset);
EXPORT void WebGL2RenderingContextCompressedTexSubImage3D1(WebGLRenderingContextRef handle, GLenum target, GLint level, GLint xoffset, GLint yoffset, GLint zoffset, GLsizei width, GLsizei height, GLsizei depth, GLenum format, GLsizei imageSize, GLintptr offset);
EXPORT void WebGL2RenderingContextUniform1ui(WebGLRenderingContextRef handle, WebGLUniformLocationRef location, GLuint v0);
EXPORT void WebGL2RenderingContextUniform2ui(WebGLRenderingContextRef handle, WebGLUniformLocationRef location, GLuint v0, GLuint v1);
EXPORT void WebGL2RenderingContextUniform3ui(WebGLRenderingContextRef handle, WebGLUniformLocationRef location, GLuint v0, GLuint v1, GLuint v2);
EXPORT void WebGL2RenderingContextUniform4ui(WebGLRenderingContextRef handle, WebGLUniformLocationRef location, GLuint v0, GLuint v1, GLuint v2, GLuint v3);
EXPORT void WebGL2RenderingContextUniform1fv2(WebGLRenderingContextRef handle, WebGLUniformLocationRef location, DOMArrayBufferViewRef /*Float32Array*/ v, GLuint srcOffset, GLuint srcLength);
EXPORT void WebGL2RenderingContextUniform1fv3(WebGLRenderingContextRef handle, WebGLUniformLocationRef location, int v_count, const GLfloat* v, GLuint srcOffset, GLuint srcLength);
EXPORT void WebGL2RenderingContextUniform2fv2(WebGLRenderingContextRef handle, WebGLUniformLocationRef location, DOMArrayBufferViewRef /*Float32Array*/ v, GLuint srcOffset, GLuint srcLength);
EXPORT void WebGL2RenderingContextUniform2fv3(WebGLRenderingContextRef handle, WebGLUniformLocationRef location, int v_count, const GLfloat* v, GLuint srcOffset, GLuint srcLength);
EXPORT void WebGL2RenderingContextUniform3fv2(WebGLRenderingContextRef handle, WebGLUniformLocationRef location, DOMArrayBufferViewRef /*Float32Array*/ v, GLuint srcOffset, GLuint srcLength);
EXPORT void WebGL2RenderingContextUniform3fv3(WebGLRenderingContextRef handle, WebGLUniformLocationRef location, int v_count, const GLfloat* v, GLuint srcOffset, GLuint srcLength);
EXPORT void WebGL2RenderingContextUniform4fv2(WebGLRenderingContextRef handle, WebGLUniformLocationRef location, DOMArrayBufferViewRef /*Float32Array*/ v, GLuint srcOffset, GLuint srcLength);
EXPORT void WebGL2RenderingContextUniform4fv3(WebGLRenderingContextRef handle, WebGLUniformLocationRef location, int v_count, const GLfloat* v, GLuint srcOffset, GLuint srcLength);
EXPORT void WebGL2RenderingContextUniform1iv2(WebGLRenderingContextRef handle, WebGLUniformLocationRef location, DOMArrayBufferViewRef /*Int32Array*/ v, GLuint srcOffset, GLuint srcLength);
EXPORT void WebGL2RenderingContextUniform1iv3(WebGLRenderingContextRef handle, WebGLUniformLocationRef location, int v_count, const GLint* v, GLuint srcOffset, GLuint srcLength);
EXPORT void WebGL2RenderingContextUniform2iv3(WebGLRenderingContextRef handle, WebGLUniformLocationRef location, DOMArrayBufferViewRef /*Int32Array*/ v, GLuint srcOffset, GLuint srcLength);
EXPORT void WebGL2RenderingContextUniform2iv2(WebGLRenderingContextRef handle, WebGLUniformLocationRef location, int v_count, const GLint* v, GLuint srcOffset, GLuint srcLength);
EXPORT void WebGL2RenderingContextUniform3iv2(WebGLRenderingContextRef handle, WebGLUniformLocationRef location, DOMArrayBufferViewRef /*Int32Array*/ v, GLuint srcOffset, GLuint srcLength);
EXPORT void WebGL2RenderingContextUniform3iv3(WebGLRenderingContextRef handle, WebGLUniformLocationRef location, int v_count, const GLint* v, GLuint srcOffset, GLuint srcLength);
EXPORT void WebGL2RenderingContextUniform4iv2(WebGLRenderingContextRef handle, WebGLUniformLocationRef location, DOMArrayBufferViewRef /*Int32Array*/ v, GLuint srcOffset, GLuint srcLength);
EXPORT void WebGL2RenderingContextUniform4iv3(WebGLRenderingContextRef handle, WebGLUniformLocationRef location, int v_count, const GLint* v, GLuint srcOffset, GLuint srcLength);
EXPORT void WebGL2RenderingContextUniform1uiv0(WebGLRenderingContextRef handle, WebGLUniformLocationRef location, DOMArrayBufferViewRef /*Uint32Array*/ v, GLuint srcOffset , GLuint srcLength);
EXPORT void WebGL2RenderingContextUniform1uiv1(WebGLRenderingContextRef handle, WebGLUniformLocationRef location, int v_count, const GLuint* v, GLuint srcOffset , GLuint srcLength);
EXPORT void WebGL2RenderingContextUniform2uiv0(WebGLRenderingContextRef handle, WebGLUniformLocationRef location, DOMArrayBufferViewRef /*Uint32Array*/ v, GLuint srcOffset , GLuint srcLength);
EXPORT void WebGL2RenderingContextUniform2uiv1(WebGLRenderingContextRef handle, WebGLUniformLocationRef location, int v_count, const GLuint* v, GLuint srcOffset , GLuint srcLength);
EXPORT void WebGL2RenderingContextUniform3uiv0(WebGLRenderingContextRef handle, WebGLUniformLocationRef location, DOMArrayBufferViewRef /*Uint32Array*/ v, GLuint srcOffset , GLuint srcLength);
EXPORT void WebGL2RenderingContextUniform3uiv1(WebGLRenderingContextRef handle, WebGLUniformLocationRef location, int v_count, const GLuint* v, GLuint srcOffset , GLuint srcLength);
EXPORT void WebGL2RenderingContextUniform4uiv0(WebGLRenderingContextRef handle, WebGLUniformLocationRef location, DOMArrayBufferViewRef /*Uint32Array*/ v, GLuint srcOffset , GLuint srcLength);
EXPORT void WebGL2RenderingContextUniform4uiv1(WebGLRenderingContextRef handle, WebGLUniformLocationRef location, int v_count, const GLuint* v, GLuint srcOffset , GLuint srcLength);
EXPORT void WebGL2RenderingContextUniformMatrix2fv2(WebGLRenderingContextRef handle, WebGLUniformLocationRef location, GLboolean transpose, DOMArrayBufferRef /*Float32Array*/ array, GLuint srcOffset, GLuint srcLength);
EXPORT void WebGL2RenderingContextUniformMatrix2fv3(WebGLRenderingContextRef handle, WebGLUniformLocationRef location, GLboolean transpose, int array_count, const GLfloat* array, GLuint srcOffset, GLuint srcLength);
EXPORT void WebGL2RenderingContextUniformMatrix3fv2(WebGLRenderingContextRef handle, WebGLUniformLocationRef location, GLboolean transpose, DOMArrayBufferRef /*Float32Array*/ array, GLuint srcOffset, GLuint srcLength);
EXPORT void WebGL2RenderingContextUniformMatrix3fv3(WebGLRenderingContextRef handle, WebGLUniformLocationRef location, GLboolean transpose, int array_count, const GLfloat* array, GLuint srcOffset, GLuint srcLength);
EXPORT void WebGL2RenderingContextUniformMatrix4fv2(WebGLRenderingContextRef handle, WebGLUniformLocationRef location, GLboolean transpose, DOMArrayBufferRef /*Float32Array*/ array, GLuint srcOffset, GLuint srcLength);
EXPORT void WebGL2RenderingContextUniformMatrix4fv3(WebGLRenderingContextRef handle, WebGLUniformLocationRef location, GLboolean transpose, int array_count, const GLfloat* array, GLuint srcOffset, GLuint srcLength);
EXPORT void WebGL2RenderingContextUniformMatrix2x3fv0(WebGLRenderingContextRef handle, WebGLUniformLocationRef location, GLboolean transpose, DOMArrayBufferRef /*Float32Array*/ array, GLuint srcOffset, GLuint srcLength);
EXPORT void WebGL2RenderingContextUniformMatrix2x3fv1(WebGLRenderingContextRef handle, WebGLUniformLocationRef location, GLboolean transpose, int array_count, const GLfloat* array, GLuint srcOffset, GLuint srcLength);
EXPORT void WebGL2RenderingContextUniformMatrix3x2fv0(WebGLRenderingContextRef handle, WebGLUniformLocationRef location, GLboolean transpose, DOMArrayBufferRef /*Float32Array*/ array, GLuint srcOffset, GLuint srcLength);
EXPORT void WebGL2RenderingContextUniformMatrix3x2fv1(WebGLRenderingContextRef handle, WebGLUniformLocationRef location, GLboolean transpose, int array_count, const GLfloat* array, GLuint srcOffset, GLuint srcLength);
EXPORT void WebGL2RenderingContextUniformMatrix2x4fv0(WebGLRenderingContextRef handle, WebGLUniformLocationRef location, GLboolean transpose, DOMArrayBufferRef /*Float32Array*/ array, GLuint srcOffset, GLuint srcLength);
EXPORT void WebGL2RenderingContextUniformMatrix2x4fv1(WebGLRenderingContextRef handle, WebGLUniformLocationRef location, GLboolean transpose, int array_count, const GLfloat* array, GLuint srcOffset, GLuint srcLength);
EXPORT void WebGL2RenderingContextUniformMatrix4x2fv0(WebGLRenderingContextRef handle, WebGLUniformLocationRef location, GLboolean transpose, DOMArrayBufferRef /*Float32Array*/ array, GLuint srcOffset, GLuint srcLength);
EXPORT void WebGL2RenderingContextUniformMatrix4x2fv1(WebGLRenderingContextRef handle, WebGLUniformLocationRef location, GLboolean transpose, int array_count, const GLfloat* array, GLuint srcOffset, GLuint srcLength);
EXPORT void WebGL2RenderingContextUniformMatrix3x4fv0(WebGLRenderingContextRef handle, WebGLUniformLocationRef location, GLboolean transpose, DOMArrayBufferRef /*Float32Array*/ value, GLuint srcOffset, GLuint srcLength);
EXPORT void WebGL2RenderingContextUniformMatrix3x4fv1(WebGLRenderingContextRef handle, WebGLUniformLocationRef location, GLboolean transpose, int value_count, const GLfloat* value, GLuint srcOffset, GLuint srcLength);
EXPORT void WebGL2RenderingContextUniformMatrix4x3fv0(WebGLRenderingContextRef handle, WebGLUniformLocationRef location, GLboolean transpose, DOMArrayBufferRef /*Float32Array*/ array, GLuint srcOffset, GLuint srcLength);
EXPORT void WebGL2RenderingContextUniformMatrix4x3fv1(WebGLRenderingContextRef handle, WebGLUniformLocationRef location, GLboolean transpose, int value_count, const GLfloat* value, GLuint srcOffset, GLuint srcLength);
EXPORT void WebGL2RenderingContextVertexAttribI4i(WebGLRenderingContextRef handle, GLuint index, GLint x, GLint y, GLint z, GLint w);
EXPORT void WebGL2RenderingContextVertexAttribI4iv0(WebGLRenderingContextRef handle, GLuint index, DOMArrayBufferRef/*Int32Array*/ v);
EXPORT void WebGL2RenderingContextVertexAttribI4iv1(WebGLRenderingContextRef handle, GLuint index, int v_count, const GLint* v);
EXPORT void WebGL2RenderingContextVertexAttribI4ui(WebGLRenderingContextRef handle, GLuint index, GLuint x, GLuint y, GLuint z, GLuint w);
EXPORT void WebGL2RenderingContextVertexAttribI4uiv0(WebGLRenderingContextRef handle, GLuint index, DOMArrayBufferRef /*Uint32Array*/ v);
EXPORT void WebGL2RenderingContextVertexAttribI4uiv1(WebGLRenderingContextRef handle, GLuint index, int v_count, const GLuint* v);
EXPORT void WebGL2RenderingContextVertexAttribIPointer(WebGLRenderingContextRef handle, GLuint index, GLint size, GLenum type, GLsizei stride, GLintptr offset);
EXPORT void WebGL2RenderingContextBlitFramebuffer(WebGLRenderingContextRef handle, GLint srcX0, GLint srcY0, GLint srcX1, GLint srcY1, GLint dstX0, GLint dstY0, GLint dstX1, GLint dstY1, GLbitfield mask, GLenum filter);
EXPORT void WebGL2RenderingContextFramebufferTextureLayer(WebGLRenderingContextRef handle, GLenum target, GLenum attachment, WebGLTextureRef texture, GLint level, GLint layer);
EXPORT void* WebGL2RenderingContextGetInternalformatParameter(WebGLRenderingContextRef handle, GLenum target, GLenum internalformat, GLenum name);
EXPORT void WebGL2RenderingContextInvalidateFramebuffer(WebGLRenderingContextRef handle, GLenum target, int attachments_count, const GLenum* attachments);
EXPORT void WebGL2RenderingContextInvalidateSubFramebuffer(WebGLRenderingContextRef handle, GLenum target, int attachments_count, const GLenum* attachments, GLint x, GLint y, GLsizei width, GLsizei height);
EXPORT void WebGL2RenderingContextReadBuffer(WebGLRenderingContextRef handle, GLenum mode);
EXPORT void WebGL2RenderingContextRenderbufferStorageMultisample(WebGLRenderingContextRef handle, GLenum target, GLsizei samples, GLenum internalformat, GLsizei width, GLsizei height);
EXPORT void WebGL2RenderingContextVertexAttribDivisor(WebGLRenderingContextRef handle, GLuint index, GLuint divisor);
EXPORT void WebGL2RenderingContextDrawArraysInstanced(WebGLRenderingContextRef handle, GLenum mode, GLint first, GLsizei count, GLsizei instanceCount);
EXPORT void WebGL2RenderingContextDrawElementsInstanced(WebGLRenderingContextRef handle, GLenum mode, GLsizei count, GLenum type, GLintptr offset, GLsizei instanceCount);
EXPORT void WebGL2RenderingContextDrawRangeElements(WebGLRenderingContextRef handle, GLenum mode, GLuint start, GLuint end, GLsizei count, GLenum type, GLintptr offset);
EXPORT void WebGL2RenderingContextDrawBuffers(WebGLRenderingContextRef handle, int buffer_count, const GLenum* buffers);
EXPORT void WebGL2RenderingContextClearBufferiv0(WebGLRenderingContextRef handle, GLenum buffer, GLint drawbuffer, DOMArrayBufferRef /*Int32Array*/ value, GLuint srcOffset);
EXPORT void WebGL2RenderingContextClearBufferiv1(WebGLRenderingContextRef handle, GLenum buffer, GLint drawbuffer, int value_count, const GLint* value, GLuint srcOffset);
EXPORT void WebGL2RenderingContextClearBufferuiv0(WebGLRenderingContextRef handle, GLenum buffer, GLint drawbuffer, DOMArrayBufferRef /*Uint32Array*/ value, GLuint srcOffset);
EXPORT void WebGL2RenderingContextClearBufferuiv1(WebGLRenderingContextRef handle, GLenum buffer, GLint drawbuffer, int value_count, const GLuint* value, GLuint srcOffset);
EXPORT void WebGL2RenderingContextClearBufferfv0(WebGLRenderingContextRef handle, GLenum buffer, GLint drawbuffer,  DOMArrayBufferRef /*Float32Array*/ value, GLuint srcOffset);
EXPORT void WebGL2RenderingContextClearBufferfv1(WebGLRenderingContextRef handle, GLenum buffer, GLint drawbuffer, int value_count, const GLfloat* value, GLuint srcOffset);
EXPORT void WebGL2RenderingContextClearBufferfi(WebGLRenderingContextRef handle, GLenum buffer, GLint drawbuffer, GLfloat depth, GLint stencil);
EXPORT WebGLQueryRef WebGL2RenderingContextCreateQuery(WebGLRenderingContextRef handle);
EXPORT void WebGL2RenderingContextDeleteQuery(WebGLRenderingContextRef handle, WebGLQueryRef query);
EXPORT GLboolean WebGL2RenderingContextIsQuery(WebGLRenderingContextRef handle, WebGLQueryRef query);
EXPORT void WebGL2RenderingContextBeginQuery(WebGLRenderingContextRef handle, GLenum target, WebGLQueryRef query);
EXPORT void WebGL2RenderingContextEndQuery(WebGLRenderingContextRef handle, GLenum target);
EXPORT void* WebGL2RenderingContextGetQuery(WebGLRenderingContextRef handle, GLenum target, GLenum name);
EXPORT void* WebGL2RenderingContextGetQueryParameter(WebGLRenderingContextRef handle, WebGLQueryRef query, GLenum name);
EXPORT WebGLSamplerRef WebGL2RenderingContextCreateSampler(WebGLRenderingContextRef handle);
EXPORT void WebGL2RenderingContextDeleteSampler(WebGLRenderingContextRef handle, WebGLSamplerRef sampler);
EXPORT GLboolean WebGL2RenderingContextIsSampler(WebGLRenderingContextRef handle, WebGLSamplerRef sampler);
EXPORT void WebGL2RenderingContextBindSampler(WebGLRenderingContextRef handle, GLuint unit, WebGLSamplerRef sampler);
EXPORT void WebGL2RenderingContextSamplerParameteri(WebGLRenderingContextRef handle, WebGLSamplerRef sampler, GLenum name, GLint param);
EXPORT void WebGL2RenderingContextSamplerParameterf(WebGLRenderingContextRef handle, WebGLSamplerRef sampler, GLenum name, GLfloat param);
EXPORT void* WebGL2RenderingContextGetSamplerParameter(WebGLRenderingContextRef handle, WebGLSamplerRef sampler, GLenum name);
EXPORT WebGLSyncRef WebGL2RenderingContextFenceSync(WebGLRenderingContextRef handle, GLenum condition, GLbitfield flags);
EXPORT GLboolean WebGL2RenderingContextIsSync(WebGLRenderingContextRef handle, WebGLSyncRef sync);
EXPORT void WebGL2RenderingContextDeleteSync(WebGLRenderingContextRef handle, WebGLSyncRef sync);
EXPORT GLenum WebGL2RenderingContextClientWaitSync(WebGLRenderingContextRef handle, WebGLSyncRef sync, GLbitfield flags, GLuint64 timeout);
EXPORT void WebGL2RenderingContextWaitSync(WebGLRenderingContextRef handle, WebGLSyncRef sync, GLbitfield flags, GLint64 timeout);
EXPORT void* WebGL2RenderingContextGetSyncParameter(WebGLRenderingContextRef handle, WebGLSyncRef sync, GLenum name);
EXPORT WebGLTransformFeedbackRef WebGL2RenderingContextCreateTransformFeedback(WebGLRenderingContextRef handle);
EXPORT void WebGL2RenderingContextDeleteTransformFeedback(WebGLRenderingContextRef handle, WebGLTransformFeedbackRef feedback);
EXPORT GLboolean WebGL2RenderingContextIsTransformFeedback(WebGLRenderingContextRef handle, WebGLTransformFeedbackRef feedback);
EXPORT void WebGL2RenderingContextBindTransformFeedback(WebGLRenderingContextRef handle, GLenum target, WebGLTransformFeedbackRef feedback);
EXPORT void WebGL2RenderingContextBeginTransformFeedback(WebGLRenderingContextRef handle, GLenum primitiveMode);
EXPORT void WebGL2RenderingContextEndTransformFeedback(WebGLRenderingContextRef handle);
EXPORT void WebGL2RenderingContextTransformFeedbackVaryings(WebGLRenderingContextRef handle, WebGLProgramRef program, int varyingsCount, const char** varyings, GLenum bufferMode);
EXPORT WebGLActiveInfoRef WebGL2RenderingContextGetTransformFeedbackVarying(WebGLRenderingContextRef handle, WebGLProgramRef program, GLuint index);
EXPORT void WebGL2RenderingContextPauseTransformFeedback(WebGLRenderingContextRef handle); 
EXPORT void WebGL2RenderingContextResumeTransformFeedback(WebGLRenderingContextRef handle);
EXPORT void WebGL2RenderingContextBindBufferBase(WebGLRenderingContextRef handle, GLenum target, GLuint index, WebGLBufferRef buffer);
EXPORT void WebGL2RenderingContextBindBufferRange(WebGLRenderingContextRef handle, GLenum target, GLuint index, WebGLBufferRef buffer, GLintptr offset, GLsizeiptr size);
EXPORT void* WebGL2RenderingContextGetIndexedParameter(WebGLRenderingContextRef handle, GLenum target, GLuint index);
EXPORT void WebGL2RenderingContextGetUniformIndices(WebGLRenderingContextRef handle, WebGLProgramRef program, int uniformNamesCount, char** uniformNames, GLuint* indices_out);
EXPORT void* WebGL2RenderingContextGetActiveUniforms(WebGLRenderingContextRef handle, WebGLProgramRef program, GLuint* uniformIndices, GLenum name);
EXPORT GLuint WebGL2RenderingContextGetUniformBlockIndex(WebGLRenderingContextRef handle, WebGLProgramRef program, const char* uniformBlockName);
EXPORT void* WebGL2RenderingContextGetActiveUniformBlockParameter(WebGLRenderingContextRef handle, WebGLProgramRef program, GLuint uniformBlockIndex, GLenum name);
EXPORT char* WebGL2RenderingContextGetActiveUniformBlockName(WebGLRenderingContextRef handle, WebGLProgramRef program, GLuint uniformBlockIndex, int* len);
EXPORT void WebGL2RenderingContextUniformBlockBinding(WebGLRenderingContextRef handle, WebGLProgramRef program, GLuint uniformBlockIndex, GLuint uniformBlockBinding);
EXPORT WebGLVertexArrayObjectRef WebGL2RenderingContextCreateVertexArray(WebGLRenderingContextRef handle);
EXPORT void WebGL2RenderingContextDeleteVertexArray(WebGLRenderingContextRef handle, WebGLVertexArrayObjectRef vertexArray);
EXPORT GLboolean WebGL2RenderingContextIsVertexArray(WebGLRenderingContextRef handle, WebGLVertexArrayObjectRef vertexArray);
EXPORT void WebGL2RenderingContextBindVertexArray(WebGLRenderingContextRef handle, WebGLVertexArrayObjectRef vertexArray);
EXPORT void WebGL2RenderingContextReadPixels0(WebGLRenderingContextRef handle, GLint x, GLint y, GLsizei width, GLsizei height, GLenum format, GLenum type, DOMArrayBufferViewRef dstData, GLintptr offset);
EXPORT void WebGL2RenderingContextReadPixels1(WebGLRenderingContextRef handle, GLint x, GLint y, GLsizei width, GLsizei height, GLenum format, GLenum type, GLintptr offset);

// DomWindow
EXPORT WebNavigatorRef WebLocalDomWindowGetNavigator(WebLocalDomWindowRef handle);
EXPORT LocationRef WebLocalDomWindowGetLocation(WebLocalDomWindowRef handle);

// Navigator
EXPORT WebServiceWorkerContainerRef WebNavigatorGetServiceWorker(WebNavigatorRef handle, WebLocalDomWindowRef window);

// WebServiceWorkerContainer
EXPORT WebServiceWorkerRef WebServiceWorkerContainerGetController(WebServiceWorkerContainerRef handle);
EXPORT ScriptPromiseRef WebServiceWorkerContainerRegister(WebServiceWorkerContainerRef handle, WebLocalDomWindowRef window, int script_type, const char* pattern);
EXPORT ScriptPromiseRef WebServiceWorkerContainerRegisterWithScope(WebServiceWorkerContainerRef handle, WebLocalDomWindowRef window, int script_type, const char* pattern, const char* scope);
EXPORT ScriptPromiseRef WebServiceWorkerContainerGetRegistration(WebServiceWorkerContainerRef handle, WebLocalDomWindowRef window, const char* url);
EXPORT ScriptPromiseRef WebServiceWorkerContainerGetRegistrations(WebServiceWorkerContainerRef handle, WebLocalDomWindowRef window);
EXPORT int WebServiceWorkerContainerSetOnMessageEventListener(WebServiceWorkerContainerRef handle, void* state, void(*on_event)(void*,void*));
//EXPORT int WebServiceWorkerContainerRemoveEventListener(WebServiceWorkerContainerRef handle, const char* event_type, void* state);

// WebServiceWorker
EXPORT char* WebServiceWorkerGetScriptUrl(WebServiceWorkerRef handle, int* len);

EXPORT void WebServiceWorkerPostMessageString(WebServiceWorkerRef handle, WebLocalDomWindowRef window, MessagePortRef* ports, int port_count, const char* message, int message_len);
EXPORT void WebServiceWorkerPostMessageBlob(WebServiceWorkerRef handle, WebLocalDomWindowRef window, MessagePortRef* ports, int port_count, BlobRef blob);
EXPORT void WebServiceWorkerPostMessageArrayBuffer(WebServiceWorkerRef handle, WebLocalDomWindowRef window, MessagePortRef* ports, int port_count, DOMArrayBufferRef buffer);
EXPORT void WebServiceWorkerPostMessageSerializedScriptValue(WebServiceWorkerRef handle, WebLocalDomWindowRef window, OwnedSerializedScriptValueRef serialized_script);

EXPORT void WebServiceWorkerPostMessageStringFromWorker(WebServiceWorkerRef handle, ServiceWorkerGlobalScopeRef scope, MessagePortRef* ports, int port_count, const char* message, int message_len);
EXPORT void WebServiceWorkerPostMessageBlobFromWorker(WebServiceWorkerRef handle, ServiceWorkerGlobalScopeRef scope, MessagePortRef* ports, int port_count, BlobRef blob);
EXPORT void WebServiceWorkerPostMessageArrayBufferFromWorker(WebServiceWorkerRef handle, ServiceWorkerGlobalScopeRef scope, MessagePortRef* ports, int port_count, DOMArrayBufferRef buffer);
EXPORT void WebServiceWorkerPostMessageSerializedScriptValueFromWorker(WebServiceWorkerRef handle, ServiceWorkerGlobalScopeRef scope, OwnedSerializedScriptValueRef serialized_script);

// ScriptPromise
EXPORT void WebScriptPromiseDestroy(ScriptPromiseRef handle);
EXPORT ScriptPromiseRef WebScriptPromiseThen(ScriptPromiseRef handle, WebLocalDomWindowRef window, void* state, void(*resolve_cb)(void*, void*, void*), void(*reject_cb)(void*));
EXPORT ScriptPromiseRef WebScriptPromiseThenForWorker(ScriptPromiseRef handle, WebWorkerRef worker, void* state, void(*resolve_cb)(void*, void*, void*), void(*reject_cb)(void*));
//EXPORT void WebScriptPromiseCatch(ScriptPromiseRef handle, WebLocalDomWindowRef window, void* state, void(*cb)(void*));


// MessageChannel
EXPORT MessageChannelRef MessageChannelCreate(WebLocalDomWindowRef window);
EXPORT void MessageChannelDestroy(MessageChannelRef handle);
EXPORT MessagePortRef MessageChannelGetPort1(MessageChannelRef handle);
EXPORT MessagePortRef MessageChannelGetPort2(MessageChannelRef handle);

// MessagePort
EXPORT OwnedMessagePortRef MessagePortCreate();
EXPORT OwnedMessagePortRef MessagePortCreateOwning(MessagePortRef ref);
EXPORT MessagePortRef MessagePortGetReference(OwnedMessagePortRef owned);
EXPORT void MessagePortDestroy(OwnedMessagePortRef handle);
EXPORT int MessagePortSetOnMessageEventListener(MessagePortRef handle, void* state, void(*on_event)(void*,void*));
//EXPORT int MessagePortRemoveEventListener(MessagePortRef handle, const char* event_type, void* state);
EXPORT void MessagePortPostMessageString(MessagePortRef handle, WebLocalDomWindowRef window, MessagePortRef* ports, int port_count, const char* str, int len);
EXPORT void MessagePortPostMessageStringFromWorker(MessagePortRef handle, WebWorkerRef worker, MessagePortRef* ports, int port_count, const char* str, int len);
EXPORT void MessagePortPostMessageStringFromServiceWorker(MessagePortRef handle, ServiceWorkerGlobalScopeRef global_scope, MessagePortRef* ports, int port_count, const char* str, int len);
EXPORT void MessagePortPostMessageBlob(MessagePortRef reference, WebLocalDomWindowRef window,MessagePortRef* ports, int port_count, BlobRef blob);
EXPORT void MessagePortPostMessageBlobFromWorker(MessagePortRef reference, WebWorkerRef worker, MessagePortRef* ports, int port_count, BlobRef blob);
EXPORT void MessagePortPostMessageArrayBuffer(MessagePortRef handle, WebLocalDomWindowRef window, MessagePortRef* ports, int port_count, DOMArrayBufferRef buffer);
EXPORT void MessagePortPostMessageArrayBufferFromWorker(MessagePortRef handle, WebWorkerRef worker, MessagePortRef* ports, int port_count, DOMArrayBufferRef buffer);
EXPORT void MessagePortPostMessageSerializedScriptValue(MessagePortRef handle, WebLocalDomWindowRef window, OwnedSerializedScriptValueRef serialized_script);
EXPORT void MessagePortPostMessageSerializedScriptValueFromWorker(MessagePortRef handle, WebWorkerRef worker, OwnedSerializedScriptValueRef serialized_script);

EXPORT WebWorkerRef WebWorkerCreate(WebLocalDomWindowRef window, const char* url);
EXPORT WebWorkerRef WebWorkerCreateNative(WebLocalDomWindowRef window, void* state, WorkerNativeClientCallbacks callbacks);
EXPORT void WebWorkerDestroy(WebWorkerRef reference);
EXPORT int WebWorkerGetThreadId(WebWorkerRef reference);
EXPORT int WebWorkerGetType(WebWorkerRef reference);
EXPORT void WebWorkerTerminate(WebWorkerRef reference);
EXPORT int WebWorkerEvaluateScriptSource(WebWorkerRef reference, const char* script_str);
EXPORT void WebWorkerPostMessageString(WebWorkerRef reference, WebLocalDomWindowRef window, const char* message_str);
EXPORT void WebWorkerPostMessageBlob(WebWorkerRef reference, WebLocalDomWindowRef window, BlobRef blob);
EXPORT void WebWorkerPostMessageArrayBuffer(WebWorkerRef handle, WebLocalDomWindowRef window, DOMArrayBufferRef buffer);
EXPORT void WebWorkerPostMessageSerializedScriptValue(WebWorkerRef handle, WebLocalDomWindowRef window, OwnedSerializedScriptValueRef serialized_script);
EXPORT int WebWorkerSetOnMessageEventListener(WebWorkerRef reference, void* state, void(*on_event)(void*,void*));
EXPORT void WebWorkerPostTask(WebWorkerRef reference, int64_t microseconds, void* state, void(*cb)(void*));
EXPORT JavascriptContextRef WebWorkerGetV8Context(WebWorkerRef reference);
EXPORT JavascriptDataRef WebWorkerGetV8Global(WebWorkerRef reference);
EXPORT JavascriptDataRef WebWorkerGetV8GlobalWithContext(WebWorkerRef reference, JavascriptContextRef context);
EXPORT void WebWorkerRequestAnimationFrame(WebWorkerRef reference, void* state, void(*cb)(void*, double));

EXPORT WorkletRef PaintWorkletCreate(WebLocalDomWindowRef window);
EXPORT void PaintWorkletDestroy(WorkletRef reference);
EXPORT ScriptPromiseRef PaintWorkletAddModule(WorkletRef reference, const char* name);
EXPORT WorkletGlobalScopeRef PaintWorkletGetAvailablePaintWorkletGlobalScope(WorkletRef reference);
EXPORT WorkletGlobalScopeRef PaintWorkletGetPaintWorkletGlobalScopeAt(WorkletRef reference, int index);
EXPORT int PaintWorkletGetPaintWorkletGlobalScopeCount(WorkletRef reference);
EXPORT double PaintWorkletGlobalScopeGetDevicePixelRatio(WorkletGlobalScopeRef reference);
//EXPORT void PaintWorkletGlobalScopeRegisterPaint(WorkletGlobalScopeRef reference, WebLocalDomWindowRef window, const char* name, void* state, void(*paintcb)(void*, const void*));
EXPORT void PaintWorkletGlobalScopeRegisterPaintNative(WorkletGlobalScopeRef reference, WebLocalDomWindowRef window, const char* name, void* state, void(*paintcb)(void*, void*, void*, void*, const void*));


// PaintSize
EXPORT void PaintSizeGet(PaintSizeRef handle, int* w, int* h);

EXPORT void ExtendableMessageEventGetPorts(ExtendableMessageEventRef reference, MessagePortRef* port_refs, int* port_count);
EXPORT SerializedScriptValueRef ExtendableMessageEventGetSerializedData(ExtendableMessageEventRef reference);
EXPORT char* ExtendableMessageEventGetDataString(SerializedScriptValueRef reference, WebLocalDomWindowRef window, int* len);
EXPORT void ExtendableEventWaitUntil(WebDOMEventRef handle, ServiceWorkerGlobalScopeRef scope, ScriptPromiseRef promise);

EXPORT OwnedSerializedScriptValueRef SerializedScriptValueCreateString(WebLocalDomWindowRef window, const char* str, DOMArrayBufferRef const* arrays, int array_count, OffscreenCanvasRef const* canvas, int canvas_count, MessagePortRef const* ports, int port_count, WebImageBitmapRef const* images, int images_count);
EXPORT OwnedSerializedScriptValueRef SerializedScriptValueCreateStringForWorker(WebWorkerRef worker, const char* str, DOMArrayBufferRef const* arrays, int array_count, OffscreenCanvasRef const* canvas, int canvas_count, MessagePortRef const* ports, int port_count, WebImageBitmapRef const* images, int images_count);
EXPORT OwnedSerializedScriptValueRef SerializedScriptValueCreateStringForServiceWorker(ServiceWorkerGlobalScopeRef scope, const char* str, DOMArrayBufferRef const* arrays, int array_count, OffscreenCanvasRef const* canvas, int canvas_count, MessagePortRef const* ports, int port_count, WebImageBitmapRef const* images, int images_count);
EXPORT OwnedSerializedScriptValueRef SerializedScriptValueCreateBlob(WebLocalDomWindowRef window, BlobRef blob, DOMArrayBufferRef const* arrays, int array_count, OffscreenCanvasRef const* canvas, int canvas_count, MessagePortRef const* ports, int port_count, WebImageBitmapRef const* images, int image_count);
EXPORT OwnedSerializedScriptValueRef SerializedScriptValueCreateBlobForWorker(WebWorkerRef worker, BlobRef blob, DOMArrayBufferRef const* arrays, int array_count, OffscreenCanvasRef const* canvas, int canvas_count, MessagePortRef const* ports, int port_count, WebImageBitmapRef const* images, int image_count);
EXPORT OwnedSerializedScriptValueRef SerializedScriptValueCreateArrayBuffer(WebLocalDomWindowRef window, DOMArrayBufferRef buffer, DOMArrayBufferRef const* arrays, int array_count, OffscreenCanvasRef const* canvas, int canvas_count, MessagePortRef const* ports, int port_count, WebImageBitmapRef const* images, int image_count);
EXPORT OwnedSerializedScriptValueRef SerializedScriptValueCreateArrayBufferForWorker(WebWorkerRef worker, DOMArrayBufferRef buffer, DOMArrayBufferRef const* arrays, int array_count, OffscreenCanvasRef const* canvas, int canvas_count, MessagePortRef const* ports, int port_count, WebImageBitmapRef const* images, int image_count);
EXPORT OwnedSerializedScriptValueRef SerializedScriptValueCreateOffscreenCanvas(WebLocalDomWindowRef window, OffscreenCanvasRef canvas, DOMArrayBufferRef const* arrays, int array_count, OffscreenCanvasRef const* canvases, int canvas_count, MessagePortRef const* ports, int port_count, WebImageBitmapRef const* images, int image_count);
EXPORT OwnedSerializedScriptValueRef SerializedScriptValueCreateOffscreenCanvasForWorker(WebWorkerRef worker, OffscreenCanvasRef canvas, DOMArrayBufferRef const* arrays, int array_count, OffscreenCanvasRef const* canvases, int canvas_count, MessagePortRef const* ports, int port_count, WebImageBitmapRef const* images, int image_count);
EXPORT OwnedSerializedScriptValueRef SerializedScriptValueCreateOffscreenCanvasForServiceWorker(ServiceWorkerGlobalScopeRef scope, OffscreenCanvasRef canvas, DOMArrayBufferRef const* arrays, int array_count, OffscreenCanvasRef const* canvases, int canvas_count, MessagePortRef const* ports, int port_count, WebImageBitmapRef const* images, int image_count);

EXPORT SerializedScriptValueRef SerializedScriptValueFromOwned(OwnedSerializedScriptValueRef owned_ref);
EXPORT void SerializedScriptValueDestroy(OwnedSerializedScriptValueRef owned);
EXPORT const uint8_t* SerializedScriptValueGetData(SerializedScriptValueRef reference);
EXPORT int SerializedScriptValueGetDataLength(SerializedScriptValueRef reference);
EXPORT char* SerializedScriptValueGetString(SerializedScriptValueRef reference, WebLocalDomWindowRef window, int* len);
EXPORT char* SerializedScriptValueGetStringForWorker(SerializedScriptValueRef reference, WebWorkerRef worker, int* len);
EXPORT char* SerializedScriptValueGetStringForServiceWorker(SerializedScriptValueRef reference, ServiceWorkerGlobalScopeRef scope, int* len);
EXPORT OffscreenCanvasRef SerializedScriptValueGetOffscreenCanvas(SerializedScriptValueRef reference, WebLocalDomWindowRef window);
EXPORT OffscreenCanvasRef SerializedScriptValueGetOffscreenCanvasForWorker(SerializedScriptValueRef reference, WebWorkerRef worker);
EXPORT OffscreenCanvasRef SerializedScriptValueGetOffscreenCanvasForServiceWorker(SerializedScriptValueRef reference, ServiceWorkerGlobalScopeRef scope);

EXPORT char* UnpackedSerializedScriptValueReadString(UnpackedSerializedScriptValueRef reference, int* len);

EXPORT int MessageEventGetDataType(WebDOMEventRef reference);
EXPORT char* MessageEventGetDataAsString(WebDOMEventRef reference, int* len);
EXPORT SerializedScriptValueRef MessageEventGetDataAsSerializedScriptValue(WebDOMEventRef reference);
EXPORT UnpackedSerializedScriptValueRef MessageEventGetDataAsUnpackedSerializedScriptValue(WebDOMEventRef reference);
EXPORT BlobRef MessageEventGetDataAsBlob(WebDOMEventRef reference);
EXPORT DOMArrayBufferRef MessageEventGetDataAsArrayBuffer(WebDOMEventRef reference);

EXPORT WebServiceWorkerRegistrationRef WebServiceWorkerRegistrationFromJavascriptValue(JavascriptContextRef context, JavascriptDataRef value);
EXPORT WebServiceWorkerRef WebServiceWorkerRegistrationGetInstalling(WebServiceWorkerRegistrationRef handle);
EXPORT WebServiceWorkerRef WebServiceWorkerRegistrationGetWaiting(WebServiceWorkerRegistrationRef handle);
EXPORT WebServiceWorkerRef WebServiceWorkerRegistrationGetActive(WebServiceWorkerRegistrationRef handle);
EXPORT char* WebServiceWorkerRegistrationGetScope(WebServiceWorkerRegistrationRef handle, int* len);
EXPORT ScriptPromiseRef WebServiceWorkerRegistrationUpdate(WebServiceWorkerRegistrationRef handle);
EXPORT ScriptPromiseRef WebServiceWorkerRegistrationUnregister(WebServiceWorkerRegistrationRef handle);
EXPORT WebNavigationPreloadManagerRef WebServiceWorkerRegistrationGetNavigationPreload(WebServiceWorkerRegistrationRef handle);
EXPORT char* WebServiceWorkerRegistrationGetUpdateViaCache(WebServiceWorkerRegistrationRef handle, int* len);
EXPORT void WebServiceWorkerRegistrationAddOnUpdateFoundEventListener(WebServiceWorkerRegistrationRef handle, void* state, void(*on_updatefound)(void*,void*));

EXPORT WebNavigatorRef ServiceWorkerGlobalScopeGetNavigator(ServiceWorkerGlobalScopeRef handle);
EXPORT WebServiceWorkerContainerRef ServiceWorkerGlobalScopeGetServiceWorkerContainer(ServiceWorkerGlobalScopeRef handle);
EXPORT WebServiceWorkerRef ServiceWorkerGlobalScopeGetServiceWorker(ServiceWorkerGlobalScopeRef handle);
EXPORT WebServiceWorkerClientsRef ServiceWorkerGlobalScopeGetClients(ServiceWorkerGlobalScopeRef handle);
EXPORT ScriptPromiseRef ServiceWorkerGlobalScopeSkipWaiting(ServiceWorkerGlobalScopeRef handle);
EXPORT int ServiceWorkerGlobalScopeIsInstalling(ServiceWorkerGlobalScopeRef handle);
EXPORT void ServiceWorkerGlobalScopeFetch(ServiceWorkerGlobalScopeRef handle, const char* url, void* state, void(*cb)(void*, void*));
EXPORT void ServiceWorkerGlobalScopeEvaluateScriptSource(ServiceWorkerGlobalScopeRef handle, const char* script_str);
EXPORT int ServiceWorkerGlobalScopeSetOnMessageEventListener(ServiceWorkerGlobalScopeRef handle, void* state, void(*on_event)(void*,void*));
EXPORT int ServiceWorkerGlobalScopeSetOnInstallEventListener(ServiceWorkerGlobalScopeRef handle, void* state, void(*on_event)(void*,void*));
EXPORT int ServiceWorkerGlobalScopeSetOnActivateEventListener(ServiceWorkerGlobalScopeRef handle, void* state, void(*on_event)(void*,void*));
EXPORT int ServiceWorkerGlobalScopeSetOnFetchEventListener(ServiceWorkerGlobalScopeRef handle, void* state, void(*on_event)(void*,void*));
EXPORT JavascriptContextRef ServiceWorkerGlobalScopeGetJavascriptContext(ServiceWorkerGlobalScopeRef handle);
EXPORT void ServiceWorkerGlobalScopePostTask(ServiceWorkerGlobalScopeRef handle, int64_t microseconds, void* state, void(*cb)(void*));

EXPORT void WebServiceWorkerClientsGet(WebServiceWorkerClientsRef handle, ServiceWorkerGlobalScopeRef scope, const char* id, void* state, void(*cb)(void*, void*));
EXPORT void WebServiceWorkerClientsMatchAll(WebServiceWorkerClientRef handle, ServiceWorkerGlobalScopeRef scope, WebServiceWorkerClientRef*, int* count);
EXPORT void WebServiceWorkerClientsClaim(WebServiceWorkerClientRef handle, ServiceWorkerGlobalScopeRef scope, void* state, void(*cb)(void*, void*));
EXPORT ScriptPromiseRef WebServiceWorkerClientsClaimPromise(WebServiceWorkerClientRef handle, ServiceWorkerGlobalScopeRef scope);
EXPORT void WebServiceWorkerClientPostMessage(WebServiceWorkerClientRef handle, ServiceWorkerGlobalScopeRef scope, OwnedSerializedScriptValueRef serialized_script);

EXPORT int PromiseBooleanFromJavascriptValue(JavascriptContextRef contextref, JavascriptDataRef valueref);
EXPORT char* PromiseStringFromJavascriptValue(JavascriptContextRef contextref, JavascriptDataRef valueref, int* len);
EXPORT DOMArrayBufferRef PromiseArrayBufferFromJavascriptValue(JavascriptContextRef contextref, JavascriptDataRef valueref);
EXPORT FormDataRef PromiseFormDataFromJavascriptValue(JavascriptContextRef contextref, JavascriptDataRef valueref);
EXPORT BlobRef PromiseBlobFromJavascriptValue(JavascriptContextRef contextref, JavascriptDataRef valueref);

// Fetch
EXPORT void FetchFromWindow(WebLocalDomWindowRef window, const char* url, void* state, void(*cb)(void*, void*));
EXPORT void FetchFromWorker(WebWorkerRef worker, const char* url, void* state, void(*cb)(void*, void*));

// FetchEvent
EXPORT RequestRef FetchEventGetRequest(WebDOMEventRef reference);
EXPORT char* FetchEventGetClientId(WebDOMEventRef reference, int* size);
EXPORT int FetchEventIsReload(WebDOMEventRef reference);
EXPORT void FetchEventRespondWith(WebDOMEventRef reference, ServiceWorkerGlobalScopeRef scope, ScriptPromiseRef promise);
EXPORT ScriptPromiseRef FetchEventPreloadResponse(WebDOMEventRef reference, ServiceWorkerGlobalScopeRef scope);

// Headers
EXPORT char* HeadersGet(HeadersRef reference, const char* key, int* len);
EXPORT void HeadersSet(HeadersRef reference, const char* key, const char* value);
EXPORT int HeadersHas(HeadersRef reference, const char* key);
EXPORT void HeadersAppend(HeadersRef reference, const char* key, const char* value);
EXPORT void HeadersRemove(HeadersRef reference, const char* key);

// ReadableStreamReader
EXPORT ScriptPromiseRef ReadableStreamReaderClosed(ReadableStreamReaderRef reference, WebWorkerRef worker);
EXPORT ScriptPromiseRef ReadableStreamReaderCancel(ReadableStreamReaderRef reference, WebWorkerRef worker);
EXPORT ScriptPromiseRef ReadableStreamReaderRead(ReadableStreamReaderRef reference, WebWorkerRef worker);
EXPORT void ReadableStreamReaderReleaseLock(ReadableStreamReaderRef reference, WebWorkerRef worker);

// ReadableStream
EXPORT ReadableStreamReaderRef ReadableStreamGetReader(ReadableStreamRef reference, WebWorkerRef worker);
EXPORT ScriptPromiseRef ReadableStreamCancel(ReadableStreamRef reference, WebWorkerRef worker);
EXPORT ReadableStreamRef ReadableStreamPipeThrough(ReadableStreamRef reference, WebWorkerRef worker, TransformStreamRef transformStream);
EXPORT ScriptPromiseRef ReadableStreamPipeTo(ReadableStreamRef reference, WebWorkerRef worker, const char* destination);
EXPORT void ReadableStreamTee(ReadableStreamRef reference, WebWorkerRef worker, ReadableStreamRef* a, ReadableStreamRef* b);
EXPORT int ReadableStreamLocked(ReadableStreamRef reference, WebWorkerRef worker);

EXPORT ScriptPromiseRef WritableStreamWriterClosed(WritableStreamWriterRef reference, WebWorkerRef worker);
EXPORT int WritableStreamWriterGetDesiredSize(WritableStreamWriterRef reference, WebWorkerRef worker);
EXPORT ScriptPromiseRef WritableStreamWriterReady(WritableStreamWriterRef reference, WebWorkerRef worker);
EXPORT ScriptPromiseRef WritableStreamWriterAbort(WritableStreamWriterRef reference, WebWorkerRef worker);
EXPORT ScriptPromiseRef WritableStreamWriterClose(WritableStreamWriterRef reference, WebWorkerRef worker);
EXPORT void WritableStreamWriterReleaseLock(WritableStreamWriterRef reference, WebWorkerRef worker);
EXPORT ScriptPromiseRef WritableStreamWriterWrite(WritableStreamWriterRef reference, WebWorkerRef worker);
EXPORT ScriptPromiseRef WritableStreamWriterWriteChunk(WritableStreamWriterRef reference, WebWorkerRef worker, const uint8_t* bytes, int size);

EXPORT int WritableStreamIsLocked(WritableStreamRef reference, WebWorkerRef worker);
EXPORT WritableStreamWriterRef WritableStreamGetWriter(WritableStreamRef reference, WebWorkerRef worker);  
EXPORT ScriptPromiseRef WritableStreamAbort(WritableStreamRef reference, WebWorkerRef worker);
EXPORT void WritableStreamSerialize(WritableStreamRef reference, WebWorkerRef worker, MessagePortRef port);
EXPORT WritableStreamRef WritableStreamDeserialize(WebWorkerRef worker, MessagePortRef port);

EXPORT int TransformStreamControllerGetDesiredSize(TransformStreamControllerRef reference, WebWorkerRef worker, int* value);
EXPORT void TransformStreamControllerEnqueue(TransformStreamControllerRef reference, WebWorkerRef worker);
EXPORT void TransformStreamControllerEnqueueChunk(TransformStreamControllerRef reference, WebWorkerRef worker, const uint8_t* chunk, int chunk_size);
EXPORT void TransformStreamControllerError(TransformStreamControllerRef reference, WebWorkerRef worker);
EXPORT void TransformStreamControllerTerminate(TransformStreamControllerRef reference, WebWorkerRef worker);

EXPORT TransformStreamRef TransformStreamCreate(WebWorkerRef worker, void* state, void(*transform)(void*, const uint8_t*, int, void*), void(*flush)(void*, void*));
EXPORT TransformStreamRef TransformStreamCreateStreams(WebWorkerRef worker, void* state, ReadableStreamRef readable, WritableStreamRef writable, void(*transform)(void*, const uint8_t*, int, void*), void(*flush)(void*, void*));
EXPORT void TransformStreamDestroy(TransformStreamRef reference);
EXPORT ReadableStreamRef TransformStreamGetReadable(TransformStreamRef reference, WebWorkerRef worker);
EXPORT WritableStreamRef TransformStreamGetWritable(TransformStreamRef reference, WebWorkerRef worker);

EXPORT ScriptPromiseRef RequestGetArrayBuffer(RequestRef reference, WebWorkerRef worker);
EXPORT ScriptPromiseRef RequestGetBlob(RequestRef reference, WebWorkerRef worker);
EXPORT ScriptPromiseRef RequestGetFormData(RequestRef reference, WebWorkerRef worker);
EXPORT ScriptPromiseRef RequestGetJson(RequestRef reference, WebWorkerRef worker);
EXPORT ScriptPromiseRef RequestGetText(RequestRef reference, WebWorkerRef worker);

EXPORT ScriptPromiseRef RequestGetArrayBufferFromServiceWorker(RequestRef reference, ServiceWorkerGlobalScopeRef scope);
EXPORT ScriptPromiseRef RequestGetBlobFromServiceWorker(RequestRef reference, ServiceWorkerGlobalScopeRef scope);
EXPORT ScriptPromiseRef RequestGetFormDataFromServiceWorker(RequestRef reference, ServiceWorkerGlobalScopeRef scope);
EXPORT ScriptPromiseRef RequestGetJsonFromServiceWorker(RequestRef reference, ServiceWorkerGlobalScopeRef scope);
EXPORT ScriptPromiseRef RequestGetTextFromServiceWorker(RequestRef reference, ServiceWorkerGlobalScopeRef scope);

EXPORT ReadableStreamRef RequestGetReadableBodyStream(RequestRef reference);
EXPORT int RequestHasBody(RequestRef reference);
EXPORT char* RequestGetMethod(RequestRef reference, int* len);
EXPORT char* RequestGetUrl(RequestRef reference, int* len);
EXPORT HeadersRef RequestGetHeaders(RequestRef reference);
EXPORT char* RequestGetDestination(RequestRef reference, int* len);
EXPORT char* RequestGetReferrer(RequestRef reference, int* len);
EXPORT char* RequestGetReferrerPolicy(RequestRef reference, int* len);
EXPORT char* RequestGetMode(RequestRef reference, int* len);
EXPORT char* RequestGetCredentials(RequestRef reference, int* len);
EXPORT char* RequestGetCache(RequestRef reference, int* len);
EXPORT char* RequestGetRedirect(RequestRef reference, int* len);
EXPORT char* RequestGetIntegrity(RequestRef reference, int* len);
EXPORT int RequestKeepalive(RequestRef reference);
EXPORT int RequestIsHistoryNavigation(RequestRef reference);

EXPORT ScriptPromiseRef ResponseGetArrayBuffer(ResponseRef reference, WebWorkerRef worker);
EXPORT ScriptPromiseRef ResponseGetBlob(ResponseRef reference, WebWorkerRef worker);
EXPORT ScriptPromiseRef ResponseGetFormData(ResponseRef reference, WebWorkerRef worker);
EXPORT ScriptPromiseRef ResponseGetJson(ResponseRef reference, WebWorkerRef worker);
EXPORT ScriptPromiseRef ResponseGetText(ResponseRef reference, WebWorkerRef worker);
EXPORT ReadableStreamRef ResponseGetBody(ResponseRef reference);
EXPORT char* ResponseGetContentType(ResponseRef reference, int* len);
EXPORT char* ResponseGetMimeType(ResponseRef reference, int* len);
EXPORT int ResponseGetOk(ResponseRef reference);
EXPORT char* ResponseGetStatusText(ResponseRef reference, int* len);
EXPORT HeadersRef ResponseGetHeaders(ResponseRef reference);
EXPORT int ResponseHasBody(ResponseRef reference);
EXPORT char* ResponseGetType(ResponseRef reference, int* len);
EXPORT char* ResponseGetUrl(ResponseRef reference, int* len);
EXPORT int ResponseRedirected(ResponseRef reference);
EXPORT uint16_t ResponseGetStatus(ResponseRef reference);

// OffscreenCanvas

EXPORT OffscreenCanvasRef OffscreenCanvasCreate(int width, int height);
EXPORT void OffscreenCanvasDestroy(OffscreenCanvasRef handle);
EXPORT int OffscreenCanvasGetWidth(OffscreenCanvasRef handle);
EXPORT int OffscreenCanvasGetHeight(OffscreenCanvasRef handle);
EXPORT OffscreenCanvasRenderingContext2dRef OffscreenCanvasCreateContext(OffscreenCanvasRef handle, WebLocalDomWindowRef window, const char* type);
EXPORT OffscreenCanvasRenderingContext2dRef OffscreenCanvasCreateContextFromWorker(OffscreenCanvasRef handle, WebWorkerRef worker, const char* type);
EXPORT OffscreenCanvasRenderingContext2dRef OffscreenCanvasCreateContextFromServiceWorker(OffscreenCanvasRef handle, ServiceWorkerGlobalScopeRef scope, const char* type);

// OffscreenCanvasRenderingContext2d
//EXPORT void OffscreenCanvasRenderingContext2dDestroy(OffscreenCanvasRenderingContext2dRefhandle);
EXPORT DisplayItemListRef OffscreenCanvasRenderingContext2dGetDisplayItemList(OffscreenCanvasRenderingContext2dRef handle);
EXPORT int OffscreenCanvasRenderingContext2dGetSaveCount(OffscreenCanvasRenderingContext2dRef handle);
EXPORT int OffscreenCanvasRenderingContext2dGetLocalClipBounds(OffscreenCanvasRenderingContext2dRef handle, float* x, float* y, float* width, float* height);
EXPORT int OffscreenCanvasRenderingContext2dGetDeviceClipBounds(OffscreenCanvasRenderingContext2dRef handle, int* x, int* y, int* width, int* height);
EXPORT int OffscreenCanvasRenderingContext2dIsClipEmpty(OffscreenCanvasRenderingContext2dRef handle);
EXPORT int OffscreenCanvasRenderingContext2dIsClipRect(OffscreenCanvasRenderingContext2dRef handle);
EXPORT MatrixRef OffscreenCanvasRenderingContext2dTotalMatrix(OffscreenCanvasRenderingContext2dRef handle);
EXPORT void OffscreenCanvasRenderingContext2dFlush(OffscreenCanvasRenderingContext2dRef handle);
EXPORT int OffscreenCanvasRenderingContext2dSave(OffscreenCanvasRenderingContext2dRef handle);
EXPORT int OffscreenCanvasRenderingContext2dSaveLayerRect(OffscreenCanvasRenderingContext2dRef handle, float rx, float ry, float rw, float rh, PaintFlagsRef paint);
EXPORT int OffscreenCanvasRenderingContext2dSaveLayer(OffscreenCanvasRenderingContext2dRef handle, PaintFlagsRef paint);
EXPORT int OffscreenCanvasRenderingContext2dSaveLayerAlpha(OffscreenCanvasRenderingContext2dRef handle, int alpha);
EXPORT int OffscreenCanvasRenderingContext2dSaveLayerAlphaRect(OffscreenCanvasRenderingContext2dRef handle, int alpha, float rx, float ry, float rw, float rh);
EXPORT int OffscreenCanvasRenderingContext2dSaveLayerPreserveLCDTextRequestsRect(OffscreenCanvasRenderingContext2dRef handle, float rx, float ry, float rw, float rh, PaintFlagsRef paint);
EXPORT int OffscreenCanvasRenderingContext2dSaveLayerPreserveLCDTextRequests(OffscreenCanvasRenderingContext2dRef handle, PaintFlagsRef paint);
EXPORT void OffscreenCanvasRenderingContext2dRestore(OffscreenCanvasRenderingContext2dRef handle);
EXPORT void OffscreenCanvasRenderingContext2dRestoreToCount(OffscreenCanvasRenderingContext2dRef handle, int save_count);
EXPORT void OffscreenCanvasRenderingContext2dTranslate(OffscreenCanvasRenderingContext2dRef handle, float x, float y);
EXPORT void OffscreenCanvasRenderingContext2dScale(OffscreenCanvasRenderingContext2dRef handle, float x, float y);
EXPORT void OffscreenCanvasRenderingContext2dRotate(OffscreenCanvasRenderingContext2dRef handle, float radians);
EXPORT void OffscreenCanvasRenderingContext2dConcatHandle(OffscreenCanvasRenderingContext2dRef handle, MatrixRef matrix);
EXPORT void OffscreenCanvasRenderingContext2dSetMatrixHandle(OffscreenCanvasRenderingContext2dRef handle, MatrixRef matrix);
EXPORT void OffscreenCanvasRenderingContext2dClearRect(OffscreenCanvasRenderingContext2dRef handle, int rx, int ry, int rw, int rh);    
EXPORT void OffscreenCanvasRenderingContext2dClipRect(OffscreenCanvasRenderingContext2dRef handle, float rx, float ry, float rw, float rh, int clip, int anti_alias);
EXPORT void OffscreenCanvasRenderingContext2dClipRRect(OffscreenCanvasRenderingContext2dRef handle, float rx, float ry, float rw, float rh, int clip, int anti_alias);
EXPORT void OffscreenCanvasRenderingContext2dClipPath(OffscreenCanvasRenderingContext2dRef handle, PathRef path, int clip, int anti_alias);
EXPORT void OffscreenCanvasRenderingContext2dDrawColor(OffscreenCanvasRenderingContext2dRef handle, int a, int r, int g, int b, int mode);
EXPORT void OffscreenCanvasRenderingContext2dDrawLine(OffscreenCanvasRenderingContext2dRef handle, float sx, float sy, float ex, float ey, PaintFlagsRef paint);
EXPORT void OffscreenCanvasRenderingContext2dDrawRect(OffscreenCanvasRenderingContext2dRef handle, float rx, float ry, float rw, float rh, PaintFlagsRef paint);    
EXPORT void OffscreenCanvasRenderingContext2dDrawIRect(OffscreenCanvasRenderingContext2dRef handle, int rx, int ry, int rw, int rh, PaintFlagsRef paint);
EXPORT void OffscreenCanvasRenderingContext2dDrawOval(OffscreenCanvasRenderingContext2dRef handle, float rx, float ry, float rw, float rh, PaintFlagsRef paint);
EXPORT void OffscreenCanvasRenderingContext2dDrawRRect(OffscreenCanvasRenderingContext2dRef handle, float rx, float ry, float rw, float rh, PaintFlagsRef paint);    
EXPORT void OffscreenCanvasRenderingContext2dDrawDRRect(OffscreenCanvasRenderingContext2dRef handle, float ox, float oy, float ow, float oh, float ix, float iy, float iw, float ih, PaintFlagsRef paint);
EXPORT void OffscreenCanvasRenderingContext2dDrawRoundRect(OffscreenCanvasRenderingContext2dRef handle, float rx, float ry, float rw, float rh, float x, float y, PaintFlagsRef paint);
EXPORT void OffscreenCanvasRenderingContext2dDrawPath(OffscreenCanvasRenderingContext2dRef handle, PathRef path, PaintFlagsRef paint);
EXPORT void OffscreenCanvasRenderingContext2dDrawImage(OffscreenCanvasRenderingContext2dRef handle, ImageRef image, float x, float y, PaintFlagsRef paint);
EXPORT void OffscreenCanvasRenderingContext2dDrawImageRect(OffscreenCanvasRenderingContext2dRef handle, ImageRef image, float sx, float sy, float sw, float sh, float dx, float dy, float dw, float dh, int src_rect_constraint, PaintFlagsRef paint);
EXPORT void OffscreenCanvasRenderingContext2dDrawBitmap(OffscreenCanvasRenderingContext2dRef handle, BitmapRef bitmap, float left, float top, PaintFlagsRef paint);
EXPORT void OffscreenCanvasRenderingContext2dDrawTextBlob(OffscreenCanvasRenderingContext2dRef handle, PaintTextBlobRef text, float x, float y, PaintFlagsRef paint); 
EXPORT void OffscreenCanvasRenderingContext2dDrawPicture(OffscreenCanvasRenderingContext2dRef handle, PaintRecordRef record);
EXPORT void OffscreenCanvasRenderingContext2dCommit(OffscreenCanvasRenderingContext2dRef handle, WebLocalDomWindowRef window, void* state, void(*cb)(void*, void*));
EXPORT void OffscreenCanvasRenderingContext2dCommitFromWorker(OffscreenCanvasRenderingContext2dRef handle, WebWorkerRef worker, void* state, void(*cb)(void*, void*));
EXPORT void OffscreenCanvasRenderingContext2dCommitFromServiceWorker(OffscreenCanvasRenderingContext2dRef handle, ServiceWorkerGlobalScopeRef scope, void* state, void(*cb)(void*, void*));
EXPORT char* OffscreenCanvasRenderingContext2dGetFillStyle(OffscreenCanvasRenderingContext2dRef handle, int* len);
EXPORT void OffscreenCanvasRenderingContext2dSetFillStyle(OffscreenCanvasRenderingContext2dRef handle, const char* style);
EXPORT void OffscreenCanvasRenderingContext2dFillRect(OffscreenCanvasRenderingContext2dRef handle, int x, int y, int w, int h);
EXPORT double OffscreenCanvasRenderingContext2dGetLineWidth(OffscreenCanvasRenderingContext2dRef handle);
EXPORT int OffscreenCanvasRenderingContext2dGetLineCap(OffscreenCanvasRenderingContext2dRef handle);
EXPORT int OffscreenCanvasRenderingContext2dGetLineJoin(OffscreenCanvasRenderingContext2dRef handle);
EXPORT double OffscreenCanvasRenderingContext2dGetMiterLimit(OffscreenCanvasRenderingContext2dRef handle);
EXPORT void OffscreenCanvasRenderingContext2dGetLineDash(OffscreenCanvasRenderingContext2dRef handle, double** values, int* value_count);
EXPORT void OffscreenCanvasRenderingContext2dSetLineDash(OffscreenCanvasRenderingContext2dRef handle, double* values, int value_count);
EXPORT double OffscreenCanvasRenderingContext2dGetLineDashOffset(OffscreenCanvasRenderingContext2dRef handle);
EXPORT char* OffscreenCanvasRenderingContext2dGetFont(OffscreenCanvasRenderingContext2dRef handle, int* len);
EXPORT int OffscreenCanvasRenderingContext2dGetTextAlign(OffscreenCanvasRenderingContext2dRef handle);
EXPORT int OffscreenCanvasRenderingContext2dGetTextBaseline(OffscreenCanvasRenderingContext2dRef handle);
EXPORT int OffscreenCanvasRenderingContext2dGetTextDirection(OffscreenCanvasRenderingContext2dRef handle);
EXPORT double OffscreenCanvasRenderingContext2dGetGlobalAlpha(OffscreenCanvasRenderingContext2dRef handle);
EXPORT void OffscreenCanvasRenderingContext2dSetGlobalAlpha(OffscreenCanvasRenderingContext2dRef handle, double alpha);
EXPORT int OffscreenCanvasRenderingContext2dGetGlobalCompositeOperation(OffscreenCanvasRenderingContext2dRef handle);
EXPORT char* OffscreenCanvasRenderingContext2dGetFilter(OffscreenCanvasRenderingContext2dRef handle, int* len);
EXPORT int OffscreenCanvasRenderingContext2dImageSmoothingEnabled(OffscreenCanvasRenderingContext2dRef handle);
EXPORT void OffscreenCanvasRenderingContext2dSetImageSmoothingEnabled(OffscreenCanvasRenderingContext2dRef handle, int value);
EXPORT int OffscreenCanvasRenderingContext2dGetImageSmoothingQuality(OffscreenCanvasRenderingContext2dRef handle);
EXPORT void OffscreenCanvasRenderingContext2dSetImageSmoothingQuality(OffscreenCanvasRenderingContext2dRef handle, int value);
EXPORT char* OffscreenCanvasRenderingContext2dGetStrokeStyle(OffscreenCanvasRenderingContext2dRef handle, int* len);
EXPORT void OffscreenCanvasRenderingContext2dSetStrokeStyle(OffscreenCanvasRenderingContext2dRef handle, const char* style);
EXPORT double OffscreenCanvasRenderingContext2dGetShadowOffsetX(OffscreenCanvasRenderingContext2dRef handle);
EXPORT void OffscreenCanvasRenderingContext2dSetShadowOffsetX(OffscreenCanvasRenderingContext2dRef handle, double value);
EXPORT double OffscreenCanvasRenderingContext2dGetShadowOffsetY(OffscreenCanvasRenderingContext2dRef handle);
EXPORT void OffscreenCanvasRenderingContext2dSetShadowOffsetY(OffscreenCanvasRenderingContext2dRef handle, double value);
EXPORT double OffscreenCanvasRenderingContext2dGetShadowBlur(OffscreenCanvasRenderingContext2dRef handle);
EXPORT void OffscreenCanvasRenderingContext2dSetShadowBlur(OffscreenCanvasRenderingContext2dRef handle, double value);
EXPORT char* OffscreenCanvasRenderingContext2dGetShadowColor(OffscreenCanvasRenderingContext2dRef handle, int* len);
EXPORT void OffscreenCanvasRenderingContext2dSetShadowColor(OffscreenCanvasRenderingContext2dRef handle, const char* color);
EXPORT void OffscreenCanvasRenderingContext2dTransform(OffscreenCanvasRenderingContext2dRef handle, double a, double b, double c, double d, double e, double f);
EXPORT void OffscreenCanvasRenderingContext2dSetTransform(OffscreenCanvasRenderingContext2dRef handle, double a, double b, double c, double d, double e, double f);
EXPORT void OffscreenCanvasRenderingContext2dResetTransform(OffscreenCanvasRenderingContext2dRef handle);
EXPORT CanvasGradientRef OffscreenCanvasRenderingContext2dCreateLinearGradient(OffscreenCanvasRenderingContext2dRef handle, double x0, double y0, double x1, double y1);
EXPORT CanvasGradientRef OffscreenCanvasRenderingContext2dCreateRadialGradient(OffscreenCanvasRenderingContext2dRef handle, double x0, double y0, double r0, double x1, double y1, double r1);
EXPORT CanvasPatternRef OffscreenCanvasRenderingContext2dCreatePatternImageBitmap(OffscreenCanvasRenderingContext2dRef handle, WebLocalDomWindowRef window,  WebImageBitmapRef image, const char* repetition_type);
EXPORT CanvasPatternRef OffscreenCanvasRenderingContext2dCreatePatternImageBitmapForWorker(OffscreenCanvasRenderingContext2dRef handle, WebWorkerRef worker, WebImageBitmapRef image, const char* repetition_type);
EXPORT CanvasPatternRef OffscreenCanvasRenderingContext2dCreatePatternImageBitmapForServiceWorker(OffscreenCanvasRenderingContext2dRef handle, ServiceWorkerGlobalScopeRef scope, WebImageBitmapRef image, const char* repetition_type);
EXPORT CanvasPatternRef OffscreenCanvasRenderingContext2dCreatePatternCSSImageValue(OffscreenCanvasRenderingContext2dRef handle, WebLocalDomWindowRef window, CSSImageValueRef image, const char* repetition_type);
EXPORT CanvasPatternRef OffscreenCanvasRenderingContext2dCreatePatternCSSImageValueForWorker(OffscreenCanvasRenderingContext2dRef handle, WebWorkerRef worker, CSSImageValueRef image, const char* repetition_type);
EXPORT CanvasPatternRef OffscreenCanvasRenderingContext2dCreatePatternCSSImageValueForServiceWorker(OffscreenCanvasRenderingContext2dRef handle, ServiceWorkerGlobalScopeRef scope, CSSImageValueRef image, const char* repetition_type);
EXPORT CanvasPatternRef OffscreenCanvasRenderingContext2dCreatePatternHtmlImageElement(OffscreenCanvasRenderingContext2dRef handle, WebLocalDomWindowRef window, WebNodeRef image, const char* repetition_type);
EXPORT CanvasPatternRef OffscreenCanvasRenderingContext2dCreatePatternHtmlImageElementForWorker(OffscreenCanvasRenderingContext2dRef handle, WebWorkerRef worker, WebNodeRef image, const char* repetition_type);
EXPORT CanvasPatternRef OffscreenCanvasRenderingContext2dCreatePatternHtmlImageElementForServiceWorker(OffscreenCanvasRenderingContext2dRef handle, ServiceWorkerGlobalScopeRef scope, WebNodeRef image, const char* repetition_type);
EXPORT CanvasPatternRef OffscreenCanvasRenderingContext2dCreatePatternSVGImageElement(OffscreenCanvasRenderingContext2dRef handle, WebLocalDomWindowRef window, WebNodeRef image, const char* repetition_type);
EXPORT CanvasPatternRef OffscreenCanvasRenderingContext2dCreatePatternSVGImageElementForWorker(OffscreenCanvasRenderingContext2dRef handle, WebWorkerRef worker, WebNodeRef image, const char* repetition_type);
EXPORT CanvasPatternRef OffscreenCanvasRenderingContext2dCreatePatternSVGImageElementForServiceWorker(OffscreenCanvasRenderingContext2dRef handle, ServiceWorkerGlobalScopeRef scope, WebNodeRef image, const char* repetition_type);
EXPORT CanvasPatternRef OffscreenCanvasRenderingContext2dCreatePatternHtmlCanvasElement(OffscreenCanvasRenderingContext2dRef handle, WebLocalDomWindowRef window, WebNodeRef image, const char* repetition_type);
EXPORT CanvasPatternRef OffscreenCanvasRenderingContext2dCreatePatternHtmlCanvasElementForWorker(OffscreenCanvasRenderingContext2dRef handle, WebWorkerRef worker, WebNodeRef image, const char* repetition_type);
EXPORT CanvasPatternRef OffscreenCanvasRenderingContext2dCreatePatternHtmlCanvasElementForServiceWorker(OffscreenCanvasRenderingContext2dRef handle, ServiceWorkerGlobalScopeRef scope, WebNodeRef image, const char* repetition_type);
EXPORT CanvasPatternRef OffscreenCanvasRenderingContext2dCreatePatternOffscreenCanvas(OffscreenCanvasRenderingContext2dRef handle, WebLocalDomWindowRef window, OffscreenCanvasRef image, const char* repetition_type);
EXPORT CanvasPatternRef OffscreenCanvasRenderingContext2dCreatePatternOffscreenCanvasForWorker(OffscreenCanvasRenderingContext2dRef handle, WebWorkerRef worker, OffscreenCanvasRef image, const char* repetition_type);
EXPORT CanvasPatternRef OffscreenCanvasRenderingContext2dCreatePatternOffscreenCanvasForServiceWorker(OffscreenCanvasRenderingContext2dRef handle, ServiceWorkerGlobalScopeRef scope, OffscreenCanvasRef image, const char* repetition_type);
EXPORT CanvasPatternRef OffscreenCanvasRenderingContext2dCreatePatternHtmlVideoElement(OffscreenCanvasRenderingContext2dRef handle, WebLocalDomWindowRef window, WebNodeRef image, const char* repetition_type);
EXPORT CanvasPatternRef OffscreenCanvasRenderingContext2dCreatePatternHtmlVideoElementForWorker(OffscreenCanvasRenderingContext2dRef handle, WebWorkerRef worker, WebNodeRef image, const char* repetition_type);
EXPORT CanvasPatternRef OffscreenCanvasRenderingContext2dCreatePatternHtmlVideoElementForServiceWorker(OffscreenCanvasRenderingContext2dRef handle, ServiceWorkerGlobalScopeRef scope, WebNodeRef image, const char* repetition_type);
EXPORT void OffscreenCanvasRenderingContext2dStrokeRect(OffscreenCanvasRenderingContext2dRef handle, int x, int y, int width, int height);
EXPORT void OffscreenCanvasRenderingContext2dBeginPath(OffscreenCanvasRenderingContext2dRef handle);
EXPORT void OffscreenCanvasRenderingContext2dFillWithWinding(OffscreenCanvasRenderingContext2dRef handle, int w);
EXPORT void OffscreenCanvasRenderingContext2dFill(OffscreenCanvasRenderingContext2dRef handle);
EXPORT void OffscreenCanvasRenderingContext2dFillWithPathAndWinding(OffscreenCanvasRenderingContext2dRef handle, Path2dRef path, int w);
EXPORT void OffscreenCanvasRenderingContext2dFillWithPath(OffscreenCanvasRenderingContext2dRef handle, Path2dRef path);
EXPORT void OffscreenCanvasRenderingContext2dStroke(OffscreenCanvasRenderingContext2dRef handle);
EXPORT void OffscreenCanvasRenderingContext2dStrokeWithPath(OffscreenCanvasRenderingContext2dRef handle, Path2dRef path);
EXPORT void OffscreenCanvasRenderingContext2dClip(OffscreenCanvasRenderingContext2dRef handle);
EXPORT void OffscreenCanvasRenderingContext2dClipWithPath(OffscreenCanvasRenderingContext2dRef handle, Path2dRef path);
EXPORT int OffscreenCanvasRenderingContext2dIsPointInPathWithWinding(OffscreenCanvasRenderingContext2dRef handle, double x, double y, int w);
EXPORT int OffscreenCanvasRenderingContext2dIsPointInPath(OffscreenCanvasRenderingContext2dRef handle, double x, double y);
EXPORT int OffscreenCanvasRenderingContext2dIsPointInPathWithPathAndWinding(OffscreenCanvasRenderingContext2dRef handle, Path2dRef path, double x, double y, int w);
EXPORT int OffscreenCanvasRenderingContext2dIsPointInPathWithPath(OffscreenCanvasRenderingContext2dRef handle, Path2dRef path, double x, double y);
EXPORT int OffscreenCanvasRenderingContext2dIsPointInStroke(OffscreenCanvasRenderingContext2dRef handle, double x, double y);
EXPORT int OffscreenCanvasRenderingContext2dIsPointInStroke(OffscreenCanvasRenderingContext2dRef handle, double x, double y);
EXPORT void OffscreenCanvasRenderingContext2dFillTextWithWidth(OffscreenCanvasRenderingContext2dRef handle, const char*, double x, double y, double width);
EXPORT void OffscreenCanvasRenderingContext2dFillText(OffscreenCanvasRenderingContext2dRef handle, const char*, double x, double y);
EXPORT void OffscreenCanvasRenderingContext2dStrokeTextWithWidth(OffscreenCanvasRenderingContext2dRef handle, const char*, double x, double y, double width);
EXPORT void OffscreenCanvasRenderingContext2dStrokeText(OffscreenCanvasRenderingContext2dRef handle, const char*, double x, double y);
EXPORT void OffscreenCanvasRenderingContext2dDrawImageBitmap(OffscreenCanvasRenderingContext2dRef handle, WebLocalDomWindowRef window, WebImageBitmapRef image, double x, double y);
EXPORT void OffscreenCanvasRenderingContext2dDrawImageBitmapWH(OffscreenCanvasRenderingContext2dRef handle, WebLocalDomWindowRef window, WebImageBitmapRef image, double x, double y, double width, double height);
EXPORT void OffscreenCanvasRenderingContext2dDrawImageBitmapSrcDst(OffscreenCanvasRenderingContext2dRef handle, WebLocalDomWindowRef window, WebImageBitmapRef image, double sx, double sy, double sw, double sh, double dx, double dy, double dw, double dh);
EXPORT void OffscreenCanvasRenderingContext2dDrawImageBitmapForWorker(OffscreenCanvasRenderingContext2dRef handle, WebWorkerRef worker, WebImageBitmapRef image, double x, double y);
EXPORT void OffscreenCanvasRenderingContext2dDrawImageBitmapWHForWorker(OffscreenCanvasRenderingContext2dRef handle, WebWorkerRef worker, WebImageBitmapRef image, double x, double y, double width, double height);
EXPORT void OffscreenCanvasRenderingContext2dDrawImageBitmapSrcDstForWorker(OffscreenCanvasRenderingContext2dRef handle, WebWorkerRef worker, WebImageBitmapRef image, double sx, double sy, double sw, double sh, double dx, double dy, double dw, double dh);
EXPORT void OffscreenCanvasRenderingContext2dDrawImageBitmapForServiceWorker(OffscreenCanvasRenderingContext2dRef handle, ServiceWorkerGlobalScopeRef scope, WebImageBitmapRef image, double x, double y);
EXPORT void OffscreenCanvasRenderingContext2dDrawImageBitmapWHForServiceWorker(OffscreenCanvasRenderingContext2dRef handle, ServiceWorkerGlobalScopeRef scope, WebImageBitmapRef image, double x, double y, double width, double height);
EXPORT void OffscreenCanvasRenderingContext2dDrawImageBitmapSrcDstForServiceWorker(OffscreenCanvasRenderingContext2dRef handle, ServiceWorkerGlobalScopeRef scope, WebImageBitmapRef image, double sx, double sy, double sw, double sh, double dx, double dy, double dw, double dh);
EXPORT void OffscreenCanvasRenderingContext2dDrawImageCSSImage(OffscreenCanvasRenderingContext2dRef handle, WebLocalDomWindowRef window, CSSImageValueRef image, double x, double y);
EXPORT void OffscreenCanvasRenderingContext2dDrawImageCSSImageWH(OffscreenCanvasRenderingContext2dRef handle, WebLocalDomWindowRef window, CSSImageValueRef image, double x, double y, double width, double height);
EXPORT void OffscreenCanvasRenderingContext2dDrawImageCSSImageSrcDst(OffscreenCanvasRenderingContext2dRef handle, WebLocalDomWindowRef window, CSSImageValueRef image, double sx, double sy, double sw, double sh, double dx, double dy, double dw, double dh);
EXPORT void OffscreenCanvasRenderingContext2dDrawImageCSSImageForWorker(OffscreenCanvasRenderingContext2dRef handle, WebWorkerRef worker, CSSImageValueRef image, double x, double y);
EXPORT void OffscreenCanvasRenderingContext2dDrawImageCSSImageWHForWorker(OffscreenCanvasRenderingContext2dRef handle, WebWorkerRef worker, CSSImageValueRef image, double x, double y, double width, double height);
EXPORT void OffscreenCanvasRenderingContext2dDrawImageCSSImageSrcDstForWorker(OffscreenCanvasRenderingContext2dRef handle, WebWorkerRef worker, CSSImageValueRef image, double sx, double sy, double sw, double sh, double dx, double dy, double dw, double dh);
EXPORT void OffscreenCanvasRenderingContext2dDrawImageCSSImageForServiceWorker(OffscreenCanvasRenderingContext2dRef handle, ServiceWorkerGlobalScopeRef scope, CSSImageValueRef image, double x, double y);
EXPORT void OffscreenCanvasRenderingContext2dDrawImageCSSImageWHForServiceWorker(OffscreenCanvasRenderingContext2dRef handle, ServiceWorkerGlobalScopeRef scope, CSSImageValueRef image, double x, double y, double width, double height);
EXPORT void OffscreenCanvasRenderingContext2dDrawImageCSSImageSrcDstForServiceWorker(OffscreenCanvasRenderingContext2dRef handle, ServiceWorkerGlobalScopeRef scope, CSSImageValueRef image, double sx, double sy, double sw, double sh, double dx, double dy, double dw, double dh);
EXPORT void OffscreenCanvasRenderingContext2dDrawImageHTMLImage(OffscreenCanvasRenderingContext2dRef handle, WebLocalDomWindowRef window, WebNodeRef image, double x, double y);
EXPORT void OffscreenCanvasRenderingContext2dDrawImageHTMLImageWH(OffscreenCanvasRenderingContext2dRef handle, WebLocalDomWindowRef window, WebNodeRef image, double x, double y, double width, double height);
EXPORT void OffscreenCanvasRenderingContext2dDrawImageHTMLImageSrcDst(OffscreenCanvasRenderingContext2dRef handle, WebLocalDomWindowRef window, WebNodeRef image, double sx, double sy, double sw, double sh, double dx, double dy, double dw, double dh);
EXPORT void OffscreenCanvasRenderingContext2dDrawImageHTMLImageForWorker(OffscreenCanvasRenderingContext2dRef handle, WebWorkerRef worker, WebNodeRef image, double x, double y);
EXPORT void OffscreenCanvasRenderingContext2dDrawImageHTMLImageWHForWorker(OffscreenCanvasRenderingContext2dRef handle, WebWorkerRef worker, WebNodeRef image, double x, double y, double width, double height);
EXPORT void OffscreenCanvasRenderingContext2dDrawImageHTMLImageSrcDstForWorker(OffscreenCanvasRenderingContext2dRef handle, WebWorkerRef worker, WebNodeRef image, double sx, double sy, double sw, double sh, double dx, double dy, double dw, double dh);
EXPORT void OffscreenCanvasRenderingContext2dDrawImageHTMLImageForServiceWorker(OffscreenCanvasRenderingContext2dRef handle, ServiceWorkerGlobalScopeRef scope, WebNodeRef image, double x, double y);
EXPORT void OffscreenCanvasRenderingContext2dDrawImageHTMLImageWHForServiceWorker(OffscreenCanvasRenderingContext2dRef handle, ServiceWorkerGlobalScopeRef scope, WebNodeRef image, double x, double y, double width, double height);
EXPORT void OffscreenCanvasRenderingContext2dDrawImageHTMLImageSrcDstForServiceWorker(OffscreenCanvasRenderingContext2dRef handle, ServiceWorkerGlobalScopeRef scope, WebNodeRef image, double sx, double sy, double sw, double sh, double dx, double dy, double dw, double dh);
EXPORT void OffscreenCanvasRenderingContext2dDrawImageSVGImage(OffscreenCanvasRenderingContext2dRef handle, WebLocalDomWindowRef window, WebNodeRef image, double x, double y);
EXPORT void OffscreenCanvasRenderingContext2dDrawImageSVGImageWH(OffscreenCanvasRenderingContext2dRef handle, WebLocalDomWindowRef window, WebNodeRef image, double x, double y, double width, double height);
EXPORT void OffscreenCanvasRenderingContext2dDrawImageSVGImageSrcDst(OffscreenCanvasRenderingContext2dRef handle, WebLocalDomWindowRef window, WebNodeRef image, double sx, double sy, double sw, double sh, double dx, double dy, double dw, double dh);
EXPORT void OffscreenCanvasRenderingContext2dDrawImageSVGImageForWorker(OffscreenCanvasRenderingContext2dRef handle, WebWorkerRef worker, WebNodeRef image, double x, double y);
EXPORT void OffscreenCanvasRenderingContext2dDrawImageSVGImageWHForWorker(OffscreenCanvasRenderingContext2dRef handle, WebWorkerRef worker, WebNodeRef image, double x, double y, double width, double height);
EXPORT void OffscreenCanvasRenderingContext2dDrawImageSVGImageSrcDstForWorker(OffscreenCanvasRenderingContext2dRef handle, WebWorkerRef worker, WebNodeRef image, double sx, double sy, double sw, double sh, double dx, double dy, double dw, double dh);
EXPORT void OffscreenCanvasRenderingContext2dDrawImageSVGImageForServiceWorker(OffscreenCanvasRenderingContext2dRef handle, ServiceWorkerGlobalScopeRef scope, WebNodeRef image, double x, double y);
EXPORT void OffscreenCanvasRenderingContext2dDrawImageSVGImageWHForServiceWorker(OffscreenCanvasRenderingContext2dRef handle, ServiceWorkerGlobalScopeRef scope, WebNodeRef image, double x, double y, double width, double height);
EXPORT void OffscreenCanvasRenderingContext2dDrawImageSVGImageSrcDstForServiceWorker(OffscreenCanvasRenderingContext2dRef handle, ServiceWorkerGlobalScopeRef scope, WebNodeRef image, double sx, double sy, double sw, double sh, double dx, double dy, double dw, double dh);
EXPORT void OffscreenCanvasRenderingContext2dDrawImageHTMLCanvas(OffscreenCanvasRenderingContext2dRef handle, WebLocalDomWindowRef window, WebNodeRef image, double x, double y);
EXPORT void OffscreenCanvasRenderingContext2dDrawImageHTMLCanvasWH(OffscreenCanvasRenderingContext2dRef handle, WebLocalDomWindowRef window, WebNodeRef image, double x, double y, double width, double height);
EXPORT void OffscreenCanvasRenderingContext2dDrawImageHTMLCanvasSrcDst(OffscreenCanvasRenderingContext2dRef handle, WebLocalDomWindowRef window, WebNodeRef image, double sx, double sy, double sw, double sh, double dx, double dy, double dw, double dh);
EXPORT void OffscreenCanvasRenderingContext2dDrawImageHTMLCanvasForWorker(OffscreenCanvasRenderingContext2dRef handle, WebWorkerRef worker, WebNodeRef image, double x, double y);
EXPORT void OffscreenCanvasRenderingContext2dDrawImageHTMLCanvasWHForWorker(OffscreenCanvasRenderingContext2dRef handle, WebWorkerRef worker, WebNodeRef image, double x, double y, double width, double height);
EXPORT void OffscreenCanvasRenderingContext2dDrawImageHTMLCanvasSrcDstForWorker(OffscreenCanvasRenderingContext2dRef handle, WebWorkerRef worker, WebNodeRef image, double sx, double sy, double sw, double sh, double dx, double dy, double dw, double dh);
EXPORT void OffscreenCanvasRenderingContext2dDrawImageHTMLCanvasForServiceWorker(OffscreenCanvasRenderingContext2dRef handle, ServiceWorkerGlobalScopeRef scope, WebNodeRef image, double x, double y);
EXPORT void OffscreenCanvasRenderingContext2dDrawImageHTMLCanvasWHForServiceWorker(OffscreenCanvasRenderingContext2dRef handle, ServiceWorkerGlobalScopeRef scope, WebNodeRef image, double x, double y, double width, double height);
EXPORT void OffscreenCanvasRenderingContext2dDrawImageHTMLCanvasSrcDstForServiceWorker(OffscreenCanvasRenderingContext2dRef handle, ServiceWorkerGlobalScopeRef scope, WebNodeRef image, double sx, double sy, double sw, double sh, double dx, double dy, double dw, double dh);
EXPORT void OffscreenCanvasRenderingContext2dDrawImageOffscreenCanvas(OffscreenCanvasRenderingContext2dRef handle, WebLocalDomWindowRef window, OffscreenCanvasRef image, double x, double y);
EXPORT void OffscreenCanvasRenderingContext2dDrawImageOffscreenCanvasWH(OffscreenCanvasRenderingContext2dRef handle, WebLocalDomWindowRef window, OffscreenCanvasRef image, double x, double y, double width, double height);
EXPORT void OffscreenCanvasRenderingContext2dDrawImageOffscreenCanvasSrcDst(OffscreenCanvasRenderingContext2dRef handle, WebLocalDomWindowRef window, OffscreenCanvasRef image, double sx, double sy, double sw, double sh, double dx, double dy, double dw, double dh);
EXPORT void OffscreenCanvasRenderingContext2dDrawImageOffscreenCanvasForWorker(OffscreenCanvasRenderingContext2dRef handle, WebWorkerRef worker, OffscreenCanvasRef image, double x, double y);
EXPORT void OffscreenCanvasRenderingContext2dDrawImageOffscreenCanvasWHForWorker(OffscreenCanvasRenderingContext2dRef handle, WebWorkerRef worker, OffscreenCanvasRef image, double x, double y, double width, double height);
EXPORT void OffscreenCanvasRenderingContext2dDrawImageOffscreenCanvasSrcDstForWorker(OffscreenCanvasRenderingContext2dRef handle, WebWorkerRef worker, OffscreenCanvasRef image, double sx, double sy, double sw, double sh, double dx, double dy, double dw, double dh);
EXPORT void OffscreenCanvasRenderingContext2dDrawImageOffscreenCanvasForServiceWorker(OffscreenCanvasRenderingContext2dRef handle, ServiceWorkerGlobalScopeRef scope, OffscreenCanvasRef image, double x, double y);
EXPORT void OffscreenCanvasRenderingContext2dDrawImageOffscreenCanvasWHForServiceWorker(OffscreenCanvasRenderingContext2dRef handle, ServiceWorkerGlobalScopeRef scope, OffscreenCanvasRef image, double x, double y, double width, double height);
EXPORT void OffscreenCanvasRenderingContext2dDrawImageOffscreenCanvasSrcDstForServiceWorker(OffscreenCanvasRenderingContext2dRef handle, ServiceWorkerGlobalScopeRef scope, OffscreenCanvasRef image, double sx, double sy, double sw, double sh, double dx, double dy, double dw, double dh);
EXPORT void OffscreenCanvasRenderingContext2dDrawImageHTMLVideo(OffscreenCanvasRenderingContext2dRef handle, WebLocalDomWindowRef window, WebNodeRef image, double x, double y);
EXPORT void OffscreenCanvasRenderingContext2dDrawImageHTMLVideoWH(OffscreenCanvasRenderingContext2dRef handle, WebLocalDomWindowRef window, WebNodeRef image, double x, double y, double width, double height);
EXPORT void OffscreenCanvasRenderingContext2dDrawImageHTMLVideoSrcDst(OffscreenCanvasRenderingContext2dRef handle, WebLocalDomWindowRef window, WebNodeRef image, double sx, double sy, double sw, double sh, double dx, double dy, double dw, double dh);
EXPORT void OffscreenCanvasRenderingContext2dDrawImageHTMLVideoForWorker(OffscreenCanvasRenderingContext2dRef handle, WebWorkerRef worker, WebNodeRef image, double x, double y);
EXPORT void OffscreenCanvasRenderingContext2dDrawImageHTMLVideoWHForWorker(OffscreenCanvasRenderingContext2dRef handle, WebWorkerRef worker, WebNodeRef image, double x, double y, double width, double height);
EXPORT void OffscreenCanvasRenderingContext2dDrawImageHTMLVideoSrcDstForWorker(OffscreenCanvasRenderingContext2dRef handle, WebWorkerRef worker, WebNodeRef image, double sx, double sy, double sw, double sh, double dx, double dy, double dw, double dh);
EXPORT void OffscreenCanvasRenderingContext2dDrawImageHTMLVideoForServiceWorker(OffscreenCanvasRenderingContext2dRef handle, ServiceWorkerGlobalScopeRef scope, WebNodeRef image, double x, double y);
EXPORT void OffscreenCanvasRenderingContext2dDrawImageHTMLVideoWHForServiceWorker(OffscreenCanvasRenderingContext2dRef handle, ServiceWorkerGlobalScopeRef scope, WebNodeRef image, double x, double y, double width, double height);
EXPORT void OffscreenCanvasRenderingContext2dDrawImageHTMLVideoSrcDstForServiceWorker(OffscreenCanvasRenderingContext2dRef handle, ServiceWorkerGlobalScopeRef scope, WebNodeRef image, double sx, double sy, double sw, double sh, double dx, double dy, double dw, double dh);
EXPORT WebImageDataRef OffscreenCanvasRenderingContext2dCreateImageData(OffscreenCanvasRenderingContext2dRef handle, int width, int height, int color_format, int storage_format);
EXPORT WebImageDataRef OffscreenCanvasRenderingContext2dCreateImageDataWithImageData(OffscreenCanvasRenderingContext2dRef handle, WebImageDataRef data);
EXPORT WebImageDataRef OffscreenCanvasRenderingContext2dCreateImageDataWithBytes(OffscreenCanvasRenderingContext2dRef handle, int width, int height, const uint8_t* data, int count, int color_format, int storage_format);
EXPORT WebImageDataRef OffscreenCanvasRenderingContext2dCreateImageDataWithUint8Array(OffscreenCanvasRenderingContext2dRef handle, int width, int height, DOMArrayBufferRef data, int color_format, int storage_format);
EXPORT WebImageDataRef OffscreenCanvasRenderingContext2dGetImageData(OffscreenCanvasRenderingContext2dRef handle, int x, int y, int width, int height);
EXPORT void OffscreenCanvasRenderingContext2dPutImageData(OffscreenCanvasRenderingContext2dRef handle, WebImageDataRef data, int x, int y);
EXPORT void OffscreenCanvasRenderingContext2dPutImageDataWithDamage(OffscreenCanvasRenderingContext2dRef handle, WebImageDataRef data, int x, int y, int dirty_x, int dirty_y, int dirty_width, int dirty_height);
EXPORT void OffscreenCanvasRenderingContext2dClosePath(OffscreenCanvasRenderingContext2dRef handle);
EXPORT void OffscreenCanvasRenderingContext2dMoveTo(OffscreenCanvasRenderingContext2dRef handle, float x, float y);
EXPORT void OffscreenCanvasRenderingContext2dLineTo(OffscreenCanvasRenderingContext2dRef handle, float x, float y);
EXPORT void OffscreenCanvasRenderingContext2dQuadraticCurveTo(OffscreenCanvasRenderingContext2dRef handle, float cpx, float cpy, float x, float y);
EXPORT void OffscreenCanvasRenderingContext2dBezierCurveTo(OffscreenCanvasRenderingContext2dRef handle, float cp1x, float cp1y, float cp2x, float cp2y, float x, float y);
EXPORT void OffscreenCanvasRenderingContext2dArcTo(OffscreenCanvasRenderingContext2dRef handle, float x1, float y1, float x2, float y2, float radius);
EXPORT void OffscreenCanvasRenderingContext2dRect(OffscreenCanvasRenderingContext2dRef handle, float x, float y, float width, float height);
EXPORT void OffscreenCanvasRenderingContext2dArc(OffscreenCanvasRenderingContext2dRef handle, float x, float y, float radius, float startAngle, float endAngle, int anticlockwise);
EXPORT void OffscreenCanvasRenderingContext2dEllipse(OffscreenCanvasRenderingContext2dRef handle, float x, float y, float radiusX, float radiusY, float rotation, float startAngle, float endAngle, int anticlockwise);

EXPORT Path2dOwnedRef Path2dCreate();
EXPORT Path2dOwnedRef Path2dCreateWithString(const char* data);
EXPORT void Path2dDestroy(Path2dOwnedRef handle);
EXPORT Path2dRef Path2dFromOwned(Path2dOwnedRef owned);
EXPORT void Path2dAddPath(Path2dRef handle, Path2dRef path);
EXPORT void Path2dAddPathWithTransform(Path2dRef handle, Path2dRef path, SVGMatrixRef transform);
EXPORT void Path2dClosePath(Path2dRef handle);
EXPORT void Path2dMoveTo(Path2dRef handle, float x, float y);
EXPORT void Path2dLineTo(Path2dRef handle, float x, float y);
EXPORT void Path2dQuadraticCurveTo(Path2dRef handle, float cpx, float cpy, float x, float y);
EXPORT void Path2dBezierCurveTo(Path2dRef handle, float cp1x, float cp1y, float cp2x, float cp2y, float x, float y);
EXPORT void Path2dArcTo(Path2dRef handle, float x0, float y0, float x1, float y1, float radius);
EXPORT void Path2dArc(Path2dRef handle, float x, float y, float radius, float startAngle, float endAngle);
EXPORT void Path2dArcWithParams(Path2dRef handle, float x, float y, float radius, float startAngle, float endAngle, int anticlockwise);
EXPORT void Path2dEllipse(Path2dRef handle, float x, float y, float radiusX, float radiusY, float rotation, float startAngle, float endAngle);
EXPORT void Path2dEllipseWithParams(Path2dRef handle, float x, float y, float radiusX, float radiusY, float rotation, float startAngle, float endAngle, int anticlockwise);
EXPORT void Path2dRect(Path2dRef handle, float x, float y, float width, float height);

EXPORT WebImageDataOwnedRef _WebImageDataCreateSize(int width, int height, int colorspace, int storage_format);
EXPORT WebImageDataOwnedRef _WebImageDataCreateUint8Array(DOMArrayBufferRef bytes, int width, int height, int colorspace, int storage_format);
EXPORT WebImageDataOwnedRef _WebImageDataCreateBytes(const uint8_t* bytes, int bytes_size, int width, int height, int colorspace, int storage_format);
EXPORT WebImageDataRef _WebImageDataFromOwned(WebImageDataOwnedRef handle);
EXPORT void _WebImageDataDestroy(WebImageDataOwnedRef handle);
EXPORT void _WebImageDataGetSize(WebImageDataRef reference, int* w, int* h);
EXPORT int _WebImageDataGetWidth(WebImageDataRef reference);
EXPORT int _WebImageDataGetHeight(WebImageDataRef reference);
EXPORT int _WebImageDataGetImageDataStorageFormat(WebImageDataRef reference);
EXPORT DOMArrayBufferRef _WebImageDataGetData(WebImageDataRef reference);
EXPORT WebImageDataRef _WebImageDataCropRect(WebImageDataRef reference, int width, int height, int flip_y);

// WebImage
EXPORT WebImageBitmapOwnedRef _WebImageBitmapCreateFromImage(ImageRef image);
EXPORT WebImageBitmapOwnedRef _WebImageBitmapCreateFromHTMLImageElementWithRect(WebNodeRef video, WebNodeRef document, int width, int height);
EXPORT WebImageBitmapOwnedRef _WebImageBitmapCreateFromHTMLImageElement(WebNodeRef video, WebNodeRef document);
EXPORT WebImageBitmapOwnedRef _WebImageBitmapCreateFromSVGImageElementWithRect(WebNodeRef video, WebNodeRef document, int width, int height);
EXPORT WebImageBitmapOwnedRef _WebImageBitmapCreateFromSVGImageElement(WebNodeRef video, WebNodeRef document);
EXPORT WebImageBitmapOwnedRef _WebImageBitmapCreateFromHTMLVideoElementWithRect(WebNodeRef video, WebNodeRef document, int width, int height);
EXPORT WebImageBitmapOwnedRef _WebImageBitmapCreateFromHTMLVideoElement(WebNodeRef video, WebNodeRef document);
EXPORT WebImageBitmapOwnedRef _WebImageBitmapCreateFromHTMLCanvasElementWithRect(WebNodeRef canvas, int width, int height);
EXPORT WebImageBitmapOwnedRef _WebImageBitmapCreateFromHTMLCanvasElement(WebNodeRef canvas);
EXPORT WebImageBitmapOwnedRef _WebImageBitmapCreateFromOffscreenCanvasWithRect(OffscreenCanvasRef canvas, int width, int height);
EXPORT WebImageBitmapOwnedRef _WebImageBitmapCreateFromOffscreenCanvas(OffscreenCanvasRef canvas);
EXPORT WebImageBitmapOwnedRef _WebImageBitmapCreateFromImageDataWithRect(WebImageDataRef data, int width, int height);
EXPORT WebImageBitmapOwnedRef _WebImageBitmapCreateFromImageData(WebImageDataRef data);
EXPORT WebImageBitmapOwnedRef _WebImageBitmapCreateFromImageBitmapWithRect(WebImageBitmapRef bitmap, int width, int height);
EXPORT WebImageBitmapOwnedRef _WebImageBitmapCreateFromImageBitmap(WebImageBitmapRef bitmap);
EXPORT WebImageBitmapOwnedRef _WebImageBitmapCreateFromUint8Array(
      DOMArrayBufferRef bytes, 
      int width, 
      int height,
      int is_premultiplied, 
      int is_originClean,
      int pixel_format,
      int color_space);
EXPORT WebImageBitmapOwnedRef _WebImageBitmapCreateFromBytes(
      const uint8_t* bytes, 
      int byteSize,
      int width, 
      int height,
      int is_premultiplied, 
      int is_originClean,
      int pixel_format,
      int color_space);
EXPORT WebImageBitmapRef _WebImageBitmapFromOwned(WebImageBitmapOwnedRef handle);
EXPORT void _WebImageBitmapDestroy(WebImageBitmapOwnedRef handle);
EXPORT int _WebImageBitmapGetWidth(WebImageBitmapRef reference);
EXPORT int _WebImageBitmapGetHeight(WebImageBitmapRef reference);
EXPORT void _WebImageBitmapGetSize(WebImageBitmapRef reference, int* w, int* h);
EXPORT int _WebImageBitmapIsNeutered(WebImageBitmapRef reference);
EXPORT int _WebImageBitmapIsOriginClean(WebImageBitmapRef reference);
EXPORT int _WebImageBitmapIsPremultiplied(WebImageBitmapRef reference);
EXPORT Uint8ArrayBufferRef _WebImageBitmapCopyBitmapData(WebImageBitmapRef reference);
EXPORT Uint8ArrayBufferRef _WebImageBitmapCopyBitmapDataWithOptions(WebImageBitmapRef reference, int disposition, int color_type);
EXPORT void _WebImageBitmapClose(WebImageBitmapRef reference);

EXPORT void Uint8ArrayBufferDestroy(Uint8ArrayBufferRef handle);

EXPORT SVGMatrixOwnedRef SVGMatrixCreate(double a, double b, double c, double d, double e, double f);
EXPORT void SVGMatrixDestroy(SVGMatrixOwnedRef handle);
EXPORT SVGMatrixRef SVGMatrixFromOwned(SVGMatrixOwnedRef handle);

EXPORT WebSocketRef WebSocketCreate(
  WebNodeRef document,
  void* state, 
  WebSocketCallbacks callbacks);
EXPORT WebSocketRef WebSocketCreateForWorker(
  WebWorkerRef worker,
  void* state, 
  WebSocketCallbacks callbacks);
EXPORT WebSocketRef WebSocketCreateForServiceWorker(
  ServiceWorkerGlobalScopeRef scope,
  void* state, 
  WebSocketCallbacks callbacks);
EXPORT void WebSocketDestroy(WebSocketRef reference);
EXPORT char* WebSocketGetSubprotocol(WebSocketRef reference, int* len);
EXPORT void WebSocketConnect(WebSocketRef reference, const char* curl, const char* purl);
EXPORT void WebSocketSendText(WebSocketRef reference, const char* text);
EXPORT void WebSocketSendArrayBuffer(WebSocketRef reference, DOMArrayBufferRef array_buffer, size_t offset, size_t lenght);
EXPORT void WebSocketClose(WebSocketRef reference, int code, const char* reason);
EXPORT void WebSocketFail(WebSocketRef reference, const char* reason);
EXPORT void WebSocketDisconnect(WebSocketRef reference);
EXPORT void WebSocketReleaseBinaryMessage(WebSocketRef reference, void* ptr, int size);

EXPORT char* LocationGetProtocol(LocationRef reference, int* len);
EXPORT char* LocationGetHost(LocationRef reference, int* len);
EXPORT char* LocationGetHostname(LocationRef reference, int* len);
EXPORT char* LocationGetPort(LocationRef reference, int* len);
EXPORT char* LocationGetPathname(LocationRef reference, int* len);
EXPORT char* LocationGetSearch(LocationRef reference, int* len);
EXPORT char* LocationGetHash(LocationRef reference, int* len);
EXPORT char* LocationGetOrigin(LocationRef reference, int* len);

#endif