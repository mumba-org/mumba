// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics
import Gpu
import MumbaShims
import Foundation

public typealias LayerPositionConstraint = Int

public func BlendFromInt32(value: Int32) -> BlendMode {
  return .Clear
}

public func BlendToInt32(value: BlendMode) -> Int32 {
  return 0
}

///
public enum LayerType: Int {
  case None                    = -1
  case SolidColorLayer         = 0
  case NinePatchLayer          = 1
  case PictureLayer            = 2
  case TextureLayer            = 3
  case SurfaceLayer            = 4
  case VideoLayer              = 5
}

public struct LayerSettings {
  public var type: LayerType
  public var useCompositorAnimationTimelines: Bool = false
  public var isDefault: Bool = false

  public init(type: LayerType) { self.type = type }
}

public struct PaintProperties {
  var bounds: IntSize = IntSize()
  var sourceFrameNumber: Int = 0

  init() {}
}

public enum PaintingControlSetting : Int32 {
   case PaintingBehaviorNormal          = 0
   case DisplayListConstructionDisabled = 1
   case DisplayListCachingDisabled      = 2
   case DisplayListPaintingDisabled     = 3
}

public protocol LayerClient {

  var fillsBoundsCompletely: Bool { get set }
  var paintableRegion: IntRect { get }

  func paintContentsToDisplayList(
    paintingStatus: PaintingControlSetting) -> DisplayItemList

  func prepareTransferableResource(
      bitmapRegistrar: TextureLayer, 
      transferableResource: TransferableResource, 
      releaseCallback: inout SingleReleaseCallback?) -> Bool

  func getApproximateUnsharedMemoryUsage() -> Int
}

public typealias SingleReleaseCallback = (Gpu.SyncToken, Bool) -> Void

///
public class Layer {

  /// The Layer Id
  public var id: Int64 {
    return _LayerId(reference)
  }

  public var elementId: UInt64 {
    get {
      return _LayerGetElementId(reference)
    }
    set {
      _LayerSetElementId(reference, newValue)
    }
  }

  ///
  public var type: LayerType {
    guard let layerType = LayerType(rawValue: Int(_LayerType(reference))) else {
      return .None
    }
    return layerType
  }

  public var parent: Layer? {
    get {
      //if cachedParent == nil {
        let layerParent = _LayerParent(reference)
        if layerParent == nil {
          return nil
        }
        //cachedParent = Layer(reference: layerParent!, isWeak: true)
        return Layer(reference: layerParent!, isWeak: true)
      //}
      //return cachedParent
    }
    //set {
      //cachedParent = newValue
    //}
  }

  public var rootLayer: Layer? {
    //if cachedRoot == nil {
      // case the layer doesnt have any root
      let rootLayer = _LayerRootLayer(reference)
      if rootLayer == nil {
        return nil
      }
      //cachedRoot = Layer(reference: rootLayer!, isWeak: true)
      return Layer(reference: rootLayer!, isWeak: true)
    //}
    //return cachedRoot
  }

  /// Get or set the layer background color
  public var backgroundColor: Color {
    get {
      var a: UInt8 = 0, r: UInt8 = 0, g: UInt8 = 0, b: UInt8 = 0
      _LayerBackgroundColor(reference, &a, &r, &g, &b)
      return Color(a: a, r: r, g: g, b: b)
    }
    set (color) {
      _LayerSetBackgroundColor(reference, color.a, color.r, color.g, color.b)
    }
  }

  public var bounds: IntSize {
    get {
      var width: Int32 = 0, height: Int32 = 0
      _LayerBounds(reference, &width, &height)
      return IntSize(width: Int(width), height: Int(height))
    }
    set {
      _LayerSetBounds(reference, Int32(newValue.width), Int32(newValue.height))
    }
  }

  public var masksToBounds: Bool {
    get {
      return Bool(_LayerMasksToBounds(reference))
    }
    set {
      _LayerSetMasksToBounds(reference, newValue.intValue)
    }
  }

  public var maskLayer: Layer? {
    get {
      let layer = _LayerMaskLayer(reference)
      if layer == nil {
        return nil
      }
      return Layer(reference: layer!)
    }
    set {
      if let mask = newValue {
        _LayerSetMaskLayer(reference, mask.reference)
      }
    }
  }

  public var opacity: Float {
    get {
      return _LayerOpacity(reference)
    }
    set {
      _LayerSetOpacity(reference, newValue)
    }
  }

  public var effectiveOpacity: Float {
    return _LayerGetEffectiveOpacity(reference)
  }

  public var blendMode: BlendMode {
    get {
      return BlendFromInt32(value: _LayerBlendMode(reference))
    }
    set {
      _LayerSetBlendMode(reference, BlendToInt32(value: newValue))
    }
  }

  // public var drawBlendMode: BlendMode {
  //   get {
  //     return BlendFromInt32(value: _LayerDrawBlendMode(reference))
  //   }
  //   set {
  //     _LayerSetDrawBlendMode(reference, BlendToInt32(value: newValue))
  //   }
  // }

  public var filters: FilterOperations? {
    get {
      assert(false)
      //_LayerFilterOperations(reference)
      return nil
    }
    set {
      assert(false)
      //_LayerSetFilterOperations(reference)
    }
  }

  public var backgroundFilters: FilterOperations? {
    get {
      assert(false)
      //_LayerBackgroundFilters(reference)
      return nil
    }
    set {
      assert(false)
      //_LayerSetBackgroundFilters(reference)
    }
  }

  public var contentsOpaque: Bool {
    get {
      return Bool(_LayerContentsOpaque(reference))
    }
    set {
      _LayerSetContentsOpaque(reference, newValue.intValue)
    }
  }

  public var position: FloatPoint {
    get {
      var x: Float = 0, y: Float = 0
      _LayerPosition(reference, &x, &y)
      return FloatPoint(x: x, y: y)
    }
    set (point) {
      _LayerSetPosition(reference, point.x, point.y)
    }
  }

  public var positionConstraint: LayerPositionConstraint {
    get {
      _LayerPositionConstraint(reference)
      return 0
    }
    set {
      _LayerSetPositionConstraint(reference)
    }
  }

  // TODO: the Mat4 that represents the transform is already 
  // a native reference to the skia matrix, so we can perfectly
  // pass and get the native reference directly, instead of passing
  // each offset of the matrix
  // it will be particularly expensive in terms of subscript, given
  // that for each offset, there will be a native fetch into the reference
  // that is unfortunately allocated in the heap

  public var transform: Transform {
    get {
      var x1 = 0.0, x2 = 0.0, x3 = 0.0, x4 = 0.0, x5 = 0.0
      var x6 = 0.0, x7 = 0.0, x8 = 0.0, x9 = 0.0, x10 = 0.0
      var x11 = 0.0, x12 = 0.0, x13 = 0.0, x14 = 0.0, x15 = 0.0, x16 = 0.0

      _LayerTransform(reference,
        &x1,
        &x2,
        &x3,
        &x4,
        &x5,
        &x6,
        &x7,
        &x8,
        &x9,
        &x10,
        &x11,
        &x12,
        &x13,
        &x14,
        &x15,
        &x16)

      return Transform(x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15, x16)
    }
    set (x) {
      _LayerSetTransform(reference,
        x[0,0], // col1row1
        x[0,1], // col2row1
        x[0,2], // col3row1
        x[0,3], // col4row1
        x[1,0], // col1row2
        x[1,1], // col2row2
        x[1,2], // col3row2
        x[1,3], // col4row2
        x[2,0], // col1row3
        x[2,1], // col2row3
        x[2,2], // col3row3
        x[2,3], // col4row3
        x[3,0], // col1row4
        x[3,1], // col2row4
        x[3,2], // col3row4
        x[3,3])  // col4row4)
    }
  }

  public var transformOrigin: FloatPoint3 {
    get {
      var x: Float = 0.0, y: Float = 0.0, z: Float = 0.0
      _LayerTransformOrigin(reference, &x, &y, &z)
      return FloatPoint3(x: x, y: y, z: z)
    }
    set (point){
      _LayerSetTransformOrigin(reference, point.x, point.y, point.z)
    }
  }

  // public var transformIsAnimating: Bool {
  //   return Bool(_LayerTransformIsAnimating(reference))
  // }

  // public var hasPotentiallyRunningTransformAnimation: Bool {
  //   return Bool(_LayerHasPotentiallyRunningTransformAnimation(reference))
  // }

  // public var hasOnlyTranslationTransforms: Bool {
  //   return Bool(_LayerHasOnlyTranslationTransforms(reference))
  // }

  // public var animationsPreserveAxisAlignment: Bool {
  //   return Bool(_LayerAnimationsPreserveAxisAlignment(reference))
  // }

  // public var transformIsInvertible: Bool {
  //   return Bool(_LayerTransformIsInvertible(reference))
  // }

  // public var opacityIsAnimating: Bool {
  //   return Bool(_LayerOpacityIsAnimating(reference))
  // }

  // public var hasPotentiallyRunningOpacityAnimation: Bool {
  //   return Bool(_LayerHasPotentiallyRunningOpacityAnimation(reference))
  // }

  // public var filterIsAnimating: Bool {
  //   return Bool(_LayerFilterIsAnimating(reference))
  // }

  // public var hasPotentiallyRunningFilterAnimation: Bool {
  //   return Bool(_LayerHasPotentiallyRunningFilterAnimation(reference))
  // }

  public var scrollParent: Layer? {
    get {
      let layer = _LayerScrollParent(reference)
      if layer == nil {
        return nil
      }
      return Layer(reference: layer!)
    }
    set {
      if let layer = newValue {
        _LayerSetScrollParent(reference, layer.reference)
      }
    }
  }

  public var scrollOffset: ScrollOffset {
    get {
      var x: Float = 0.0, y: Float = 0.0
      _LayerScrollOffset(reference, &x, &y)
      return ScrollOffset(x: x, y: y)
    }
    set {
      _LayerSetScrollOffset(reference, newValue.x, newValue.y)
    }
  }

  public var numUnclippedDescendants: Int {
    get {
      return Int(_LayerNumUnclippedDescendants(reference))
    }
    set {
      _LayerSetNumUnclippedDescendants(reference, Int32(newValue))
    }
  }

  // public var touchEventHandlerRegion: Graphics.Region {
  //   //get {
  //     var x: Int32 = 0, y: Int32 = 0, w: Int32 = 0, h: Int32 = 0
  //     _LayerTouchEventHandlerRegion(reference, &x, &y, &w, &h)
  //     return Graphics.Region(rect: IntRect(x: Int(x), y: Int(y), width: Int(w), height: Int(h)))
  //   //}
  //   // set (region) {
  //   //   let bounds = region.bounds
  //   //   _LayerSetTouchEventHandlerRegion(reference, Int32(bounds.x), Int32(bounds.y), Int32(bounds.width), Int32(bounds.height))
  //   // }
  // }

  // public var scrollBlocksOn: ScrollBlocksOn {
  //   get {
  //     return ScrollBlocksOn(rawValue: Int(_LayerScrollBlocksOn(reference)))!
  //   }
  //   set {
  //     _LayerSetScrollBlocksOn(reference, Int32(newValue.rawValue))
  //   }
  // }

  public var scrollable: Bool {
    return Bool(_LayerScrollable(reference))
  }

  public var transformTreeIndex: Int {
    get {
      return Int(_LayerTransformTreeIndex(reference))
    }
    set {
      _LayerSetTransformTreeIndex(reference, Int32(newValue))
    }
  }

  public var clipTreeIndex: Int {
    get {
      return Int(_LayerClipTreeIndex(reference))
    }
    set {
      _LayerSetClipTreeIndex(reference, Int32(newValue))
    }
  }

  public var effectTreeIndex: Int {
    get {
      return Int(_LayerEffectTreeIndex(reference))
    }
    set {
      _LayerSetEffectTreeIndex(reference, Int32(newValue))
    }
  }

  public var offsetToTransformParent: FloatVec2 {
    get {
      var x: Float = 0.0, y: Float = 0.0
      _LayerOffsetToTransformParent(reference, &x, &y)
      return FloatVec2(x: x, y: y)
    }
    set (offset) {
      _LayerSetOffsetToTransformParent(reference, offset.x, offset.y)
    }
  }

  // public var visibleRectFromPropertyTrees: IntRect {
  //   get {
  //     var x: Int32 = 0, y: Int32 = 0, w: Int32 = 0, h: Int32 = 0
  //     _LayerVisibleRectFromPropertyTrees(reference, &x, &y, &w, &h)
  //     return IntRect(x: Int(x), y: Int(y), width: Int(w), height: Int(h))
  //   }
  //   set (rect) {
  //     _LayerSetVisibleRectFromPropertyTrees(reference, Int32(rect.x), Int32(rect.y), Int32(rect.width), Int32(rect.height))
  //   }
  // }

  // public var clipRectInTargetSpaceFromPropertyTrees: IntRect {
  //   get {
  //     var x: Int32 = 0, y: Int32 = 0, w: Int32 = 0, h: Int32 = 0
  //     _LayerClipRectInTargetSpaceFromPropertyTrees(reference, &x, &y, &w, &h)
  //     return IntRect(x: Int(x), y: Int(y), width: Int(w), height: Int(h))
  //   }
  //   set (rect) {
  //     _LayerSetClipRectInTargetSpaceFromPropertyTrees(reference, Int32(rect.x), Int32(rect.y), Int32(rect.width), Int32(rect.height))
  //   }
  // }

  public var shouldFlattenTransformFromPropertyTree: Bool {
    get {
      return Bool(_LayerShouldFlattenTransformFromPropertyTree(reference))
    }
    set {
      _LayerSetShouldFlattenTransformFromPropertyTree(reference, newValue.intValue)
    }
  }

  // public var visited: Bool {
  //   get {
  //     return Bool(_LayerVisited(reference))
  //   }
  //   set {
  //     _LayerSetVisited(reference, newValue.intValue)
  //   }
  // }

  public var clipParent: Layer? {
    get {
      let layer = _LayerClipParent(reference)
       if layer == nil {
        return nil
      }
      return Layer(reference: layer!)
    }
    set {
      if let layer = newValue {
        _LayerSetClipParent(reference, layer.reference)
      }
    }
  }

  // public var scrollDelta: FloatVec2 {
  //   var x: Float = 0.0, y: Float = 0.0
  //   _LayerScrollDelta(reference, &x, &y)
  //   return FloatVec2(x: x, y: y)
  // }

  public var doubleSided: Bool {
    get {
      return Bool(_LayerDoubleSided(reference))
    }
    set {
      _LayerSetDoubleSided(reference, newValue.intValue)
    }
  }

  public var shouldFlattenTransform: Bool {
    get {
      return Bool(_LayerShouldFlattenTransform(reference))
    }
    set {
      _LayerSetShouldFlattenTransform(reference, newValue.intValue)
    }
  }

  public var is3dSorted: Bool {
    return Bool(_LayerIs3dSorted(reference))
  }

  public var drawsContent: Bool {
    return Bool(_LayerDrawsContent(reference))
  }

  public var visibleLayerRect: IntRect {
    var x: CInt = 0, y: CInt = 0, w: CInt = 0, h: CInt = 0
    _LayerGetVisibleLayerRect(reference, &x, &y, &w, &h)
    return IntRect(x: Int(x), y: Int(y), width: Int(w), height: Int(h)) 
  }

  // public var replicaLayer: Layer? {
  //   get {
  //     let layer = _LayerReplicaLayer(reference)
  //     if layer == nil {
  //       return nil
  //     }
  //     return Layer(reference: layer!)
  //   }
  //   set {
  //     if let layer = newValue {
  //       _LayerSetReplicaLayer(reference, layer.reference)
  //     }
  //   }
  // }

  // public var hasMask: Bool {
  //   return Bool(_LayerHasMask(reference))
  // }

  // public var hasReplica: Bool {
  //   return Bool(_LayerHasReplica(reference))
  // }

  // public var replicaHasMask: Bool {
  //   return Bool(_LayerReplicaHasMask(reference))
  // }

  // public var numDescendantsThatDrawContent: Int {
  //   return Int(_LayerNumDescendantsThatDrawContent(reference))
  // }

  // public var needsPushProperties: Bool {
  //   get {
  //     return Bool(_LayerNeedsPushProperties(reference))
  //   }
  //   set {
  //     _LayerSetNeedsPushProperties(reference)
  //   }
  // }

  // public var descendantNeedsPushProperties: Bool {
  //   return Bool(_LayerDescendantNeedsPushProperties(reference))
  // }

  // public var haveWheelEventHandlers: Bool {
  //   get {
  //     return Bool(_LayerHaveWheelEventHandlers(reference))
  //   }
  //   set {
  //     _LayerSetHaveWheelEventHandlers(reference, newValue.intValue)
  //   }
  // }

  // public var haveScrollEventHandlers: Bool {
  //   get {
  //     return Bool(_LayerHaveScrollEventHandlers(reference))
  //   }
  //   set {
  //     _LayerSetHaveScrollEventHandlers(reference, newValue.intValue)
  //   }
  // }

  public var nonFastScrollableRegion: Graphics.Region {
    get {
      var x: Int32 = 0, y: Int32 = 0, w: Int32 = 0, h: Int32 = 0
      _LayerNonFastScrollableRegion(reference, &x, &y, &w, &h)
      return Graphics.Region(rect: IntRect(x: Int(x), y: Int(y), width: Int(w), height: Int(h)))
    }
    set (region){
      let bounds = region.bounds
      _LayerSetNonFastScrollableRegion(reference, Int32(bounds.x), Int32(bounds.y), Int32(bounds.width), Int32(bounds.height))
    }
  }

  // public var scrollCompensationAdjustment: FloatVec2 {
  //   get {
  //     var x: Float = 0, y: Float = 0
  //     _LayerScrollCompensationAdjustment(reference, &x, &y)
  //     return FloatVec2(x: x, y: y)
  //   }
  //   set (vec) {
  //     _LayerSetScrollCompensationAdjustment(reference, vec.x, vec.y)
  //   }
  // }

  //public func shouldScrollOnMainThread(shouldScroll: Bool) {
    //get {
    //  return Bool(_LayerShouldScrollOnMainThread(reference))
    //}
    //set {
  //  _LayerSetShouldScrollOnMainThread(reference, shouldScroll.intValue)
    //}
  //}

  public var shouldScrollOnMainThread: Bool {
    return _LayerShouldScrollOnMainThread(reference) == 0 ? false : true
  }

  public var useParentBackfaceVisibility: Bool {
    get {
      return Bool(_LayerUseParentBackfaceVisibility(reference))
    }
    set {
      _LayerSetUseParentBackfaceVisibility(reference, newValue.intValue)
    }
  }

  // public var isActive: Bool {
  //   return Bool(_LayerIsActive(reference))
  // }

  // public func sortedForRecursion(sorted: Bool) {
  //   // get {
  //   //   return Bool(_LayerSortedForRecursion(reference))
  //   // }
  //   //set {
  //     _LayerSetSortedForRecursion(reference, sorted.intValue)
  //   //}
  // }

  // public var numLayerOrDescendantsWithCopyRequest: Int {
  //   get {
  //     return Int(_LayerNumLayerOrDescendantsWithCopyRequest(reference))
  //   }
  //   set {
  //     _LayerSetNumLayerOrDescendantWithCopyRequest(reference, Int32(newValue))
  //   }
  // }

  // public var layerOrDescendantIsDrawn: Bool {
  //   get {
  //     return Bool(_LayerLayerOrDescendantIsDrawn(reference))
  //   }
  //   set {
  //     _LayerSetLayerOrDescendantIsDrawn(reference, newValue.intValue)
  //   }
  // }

  // public var layerAnimationController: LayerAnimationController? {
  //   let controller = _LayerLayerAnimationController(reference)
  //   if controller == nil {
  //     return nil
  //   }
  //   return LayerAnimationController(reference: controller!)
  // }

  // public var hasActiveAnimation: Bool {
  //   return Bool(_LayerHasActiveAnimation(reference))
  // }

  public var paintProperties: PaintProperties? {
    //_LayerPaintProperties(reference)
    return nil
  }

  // public var hasRenderSurface: Bool {
  //   return Bool(_LayerHasRenderSurface(reference))
  // }

  public var hideLayerAndSubtree: Bool {
    get {
      return Bool(_LayerHideLayerAndSubtree(reference))
    }
    set {
      _LayerSetHideLayerAndSubtree(reference, newValue.intValue)
    }
  }

  public var layerMask: Layer? {
    get {
      let layer = _LayerMaskLayer(reference)
      if layer == nil {
        return nil
      }
      return Layer(reference: layer!)
    }
    set {
      if let layer = newValue {
        _LayerSetMaskLayer(reference, layer.reference)
      }
    }
  }

  public var cacheRenderSurface: Bool {
    get {
      return _LayerGetCacheRenderSurface(reference) == 0 ? false : true
    }
    set {
      _LayerSetCacheRenderSurface(reference, newValue ? 1 : 0)
    }
  }

  public var trilinearFiltering: Bool {
    get {
      return _LayerGetTrilinearFiltering(reference) == 0 ? false : true
    }
    set {
      _LayerSetTrilinearFiltering(reference, newValue ? 1 : 0)
    }
  }

  public var client: LayerClient?

  internal var layerTreeHost: LayerTreeHost? {
    get {
      //if cachedHost == nil {
        let host = _LayerLayerTreeHost(reference)
        if host == nil { // this should never happent
          return nil
        }
        //cachedHost = LayerTreeHost(reference: host!, isWeak: true)
        return LayerTreeHost(reference: host!, isWeak: true)
      //}
      //return cachedHost
    }
    set {
      if let host = newValue {
        _LayerSetLayerTreeHost(reference, host.reference)
      }
    }
  }

  public var forceRenderSurface: Bool {
    get {
      return Bool(_LayerForceRenderSurface(reference))
    }
    set {
      _LayerSetForceRenderSurface(reference, newValue.intValue)
    }
  }

  // foreign modules need to access this
  public var reference: LayerRef!
  // cache for reference types
  // the reason we cache, is for ownership
  // so they will safely cleanup in this object destruction
  //var cachedRoot: Layer?
  //var cachedParent: Layer?
 // var cachedHost: LayerTreeHost?
  var isWeak: Bool = false

  public init(settings: LayerSettings, client: LayerClient?) throws {
    
    //print("Layer: type = \(settings.type) value = \(settings.type.rawValue)")
    let ctype = settings.type.rawValue

    var callbacks = CLayerClientCallbacks()

    callbacks.paintContentsToDisplayList = { (layer: UnsafeMutableRawPointer?, ctrlset: Int32) -> UnsafeMutableRawPointer? in
      //assert(layer != nil)
      let p = unsafeBitCast(layer, to: Layer.self)
      let ctrl = PaintingControlSetting(rawValue: ctrlset)
      let displayList = p.client!.paintContentsToDisplayList(paintingStatus: ctrl!)
      let ref = displayList.releaseUnsafeReference()
      return ref
    }

    callbacks.prepareTransferableResource = { (layer: UnsafeMutableRawPointer?, 
      bitmapRegistrar: UnsafeMutableRawPointer?, 
      transferableResource: UnsafeMutableRawPointer?, 
      releaseCallback: UnsafeMutableRawPointer?) -> Int32 in
      //print("Layer.prepareTransferableResource")
      //assert(layer ! = nil)
      let p = unsafeBitCast(layer, to: Layer.self)
      let registrar = TextureLayer(reference: bitmapRegistrar!)
      let resource = TransferableResource(reference: transferableResource!)
      var cb: SingleReleaseCallback?

      let ok = p.client!.prepareTransferableResource(
        bitmapRegistrar: registrar,
        transferableResource: resource,
        releaseCallback: &cb
      ) 
      
      // WRONG: Lifetime problem here
      //releaseCallback = nil//cb

      return ok ? 1 : 0
    }

    callbacks.paintableRegion = { (layer: UnsafeMutableRawPointer?, x: UnsafeMutablePointer<Int32>!, y: UnsafeMutablePointer<Int32>!, w: UnsafeMutablePointer<Int32>!, h: UnsafeMutablePointer<Int32>!) -> Void in
      //assert(layer != nil)
      let p = unsafeBitCast(layer, to: Layer.self)
      let rect = p.client!.paintableRegion
      x.initialize(repeating: Int32(rect.x), count: 1)
      y.initialize(repeating: Int32(rect.y), count: 1)
      w.initialize(repeating: Int32(rect.width), count: 1)
      h.initialize(repeating: Int32(rect.height), count: 1)
    }

    callbacks.fillsBoundsCompletely = { (layer: UnsafeMutableRawPointer?) -> Int32 in
      //assert(layer != nil)
      let p = unsafeBitCast(layer, to: Layer.self)
      return p.client!.fillsBoundsCompletely ? 1 : 0
    }

    callbacks.getApproximateUnsharedMemoryUsage = { (layer: UnsafeMutableRawPointer?) -> Int32 in
      //assert(layer != nil)
      let p = unsafeBitCast(layer, to: Layer.self)
      return Int32(p.client!.getApproximateUnsharedMemoryUsage())
    }

    //reference = nil
    var nativeLayer: LayerRef? = nil
    if settings.isDefault {
      nativeLayer = _LayerCreateDefault()
    } else {
      //let selfptr: UnsafeMutableRawPointer = UnsafeMutableRawPointer(Unmanaged.passUnretained(self).toOpaque())
      let selfptr = unsafeBitCast(Unmanaged.passUnretained(self).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
      nativeLayer = _LayerCreate(CInt(ctype), selfptr, callbacks)
    }

    guard nativeLayer != nil else {
      throw CompositorError.OnCreateLayer(exception: CompositorException.NativeLayer)
    }
    self.client = client
    reference = nativeLayer!
  }

  public init(reference: LayerRef, isWeak: Bool = false) {
    self.reference = reference
    self.isWeak = isWeak
  }

  deinit {
    if !isWeak {
      _LayerDestroy(reference)
    }
  }

  public class func create() -> Layer {
    let ref = _LayerCreateDefault()
    return Layer(reference: ref!)
  }

  public class func createTextureLayer(settings: inout LayerSettings, client: LayerClient) throws -> TextureLayer {
    //print("Layer: createTextureLayer")
    settings.type = LayerType.TextureLayer
    return try TextureLayer(settings: &settings, client: client)
  }

  //public class func createDelegatedRendererLayer(settings: inout LayerSettings, client: LayerClient, _ frameProvider: DelegatedFrameProvider) throws -> DelegatedRendererLayer {
  //  return try DelegatedRendererLayer(settings: &settings, client: client)
  //}

  public class func createSurfaceLayer(settings: inout LayerSettings, client: LayerClient, satisfyCallback: SurfaceLayer.SatisfyCallback, requireCallback: SurfaceLayer.RequireCallback) throws -> SurfaceLayer {
    //print("Layer: createSurfaceLayer")
    settings.type = LayerType.SurfaceLayer
    return try SurfaceLayer(settings: &settings, client: client)
  }

  public class func createSolidColorLayer(settings: inout LayerSettings, client: LayerClient) throws -> SolidColorLayer {
    //print("Layer: createSolidColorLayer")
    settings.type = LayerType.SolidColorLayer
    return try SolidColorLayer(settings: &settings, client: client)
  }

  public class func createPictureLayer(settings: inout LayerSettings, client: LayerClient) throws -> PictureLayer {
    //print("Layer: createPictureLayer")
    settings.type = LayerType.PictureLayer
    return try PictureLayer(settings: &settings, client: client)
  }

  public class func createNinePatchLayer(settings: inout LayerSettings, client: LayerClient) throws -> NinePatchLayer {
    //print("Layer: createNinePatchLayer")
    settings.type = LayerType.NinePatchLayer
    return try NinePatchLayer(settings: &settings, client: client)
  }

  public class func createVideoLayer(settings: inout LayerSettings, client: LayerClient) throws -> VideoLayer {
    //print("Layer: createVideoLayer")
    settings.type = LayerType.VideoLayer
    return try VideoLayer(settings: &settings, client: client)
  }

  /// Add a child layer
  public func addChild(child: Layer) {
    //print("Compositor.Layer: adding layer \(child.id) as child of \(self.id)")
    _LayerAddChild(reference, child.reference)
  }

  public func insertChild(child: Layer, index: Int) {
    //print("Compositor.Layer: adding layer \(child.id) as child of \(self.id)")
    _LayerInsertChild(reference, child.reference, Int32(index))
  }

  public func replaceChild(child: Layer, newLayer: Layer) {
    _LayerReplaceChild(reference, child.reference, newLayer.reference)
  }

  public func removeFromParent() {
    _LayerRemoveFromParent(reference)
  }

  public func removeAllChildren() {
     _LayerRemoveAllChildren(reference)
  }

  public func setChildren(children: [Layer]) {
    //children.withUnsafeBufferPointer({
    //  _LayerSetChildren(reference)
    //})
    assert(false)
  }

  public func hasAncestor(ancestor: Layer) -> Bool {
    return Bool(_LayerHasAncestor(reference, ancestor.reference))
  }

  public func children() -> [Layer]? {
    //_LayerChildren(reference)
    assert(false)
    return nil
  }

  public func childAt(index: Int) -> Layer? {
    let child = _LayerChildAt(reference, Int32(index))
    if child == nil {
      return nil
    }
    return Layer(reference: child!)
  }

  public func requestCopyOfOutput(request: CopyOutputRequest) {
    _LayerRequestCopyOfOutput(reference, request.reference)
  }

  public func hasCopyRequest() -> Bool {
    return Bool(_LayerHasCopyRequest(reference))
  }

  public func opaqueBackgroundColor() -> Color {
    var r: UInt8 = 0, g: UInt8 = 0, b: UInt8 = 0
    _LayerSafeOpaqueBackgroundColor(reference, &r, &g, &b)
    return Color(a: 255 ,r: r, g: g, b: b)
  }

  public func setNeedsDisplayRect(dirtyRect: IntRect) {
   _LayerSetNeedsDisplayRect(reference, Int32(dirtyRect.x), Int32(dirtyRect.y), Int32(dirtyRect.width), Int32(dirtyRect.height))
  }

  public func setNeedsDisplay() {
   _LayerSetNeedsDisplay(reference)
  }

  // public func usesDefaultBlendMode() -> Bool {
  //   return Bool(_LayerUsesDefaultBlendMode(reference))
  // }

  public func setIsRootForIsolatedGroup(root: Bool) {
    _LayerSetIsRootForIsolatedGroup(reference, root.intValue)
  }

  public func isRootForIsolatedGroup() -> Bool {
    return Bool(_LayerIsRootForIsolatedGroup(reference))
  }

  public func setIsContainerForFixedPositionLayers(container: Bool) {
    _LayerSetIsContainerForFixedPositionLayers(reference, container.intValue)
  }

  public func isContainerForFixedPositionLayers() -> Bool {
    return Bool(_LayerIsContainerForFixedPositionLayers(reference))
  }

  // public func fixedContainerSizeDelta() -> FloatVec2 {
  //   var x: Float = 0.0, y: Float = 0.0
  //   _LayerFixedContainerSizeDelta(reference,&x, &y)
  //   return FloatVec2(x: x, y: y)
  // }

  // public func maximumTargetScale(scale: inout Float) -> Bool {
  //   return Bool(_LayerMaximumTargetScale(reference, &scale))
  // }

  // public func animationStartScale(scale: inout Float) -> Bool {
  //   return Bool(_LayerAnimationStartScale(reference, &scale))
  // }

  // public func hasAnyAnimationTargetingProperty(property: AnimationTargetProperty) -> Bool {
  //   return Bool(_LayerHasAnyAnimationTargetingProperty(reference, property.rawValue))
  // }

  // public func scrollOffsetAnimationWasInterrupted() -> Bool {
  //   return Bool(_LayerScrollOffsetAnimationWasInterrupted(reference))
  // }

  // public func addScrollChild(child: Layer) {
  //   _LayerAddScrollChild(reference, child.reference)
  // }

  // public func removeScrollChild(child: Layer) {
  //   _LayerRemoveScrollChild(reference, child.reference)
  // }

  // public func scrollChildren() -> [Layer]? {
  //   //let layer = _LayerScrollChildren(reference)
  //   //if layer != nil {
  //   //  return Layer(reference: layer)
  //   //}
  //   assert(false)
  //   return nil
  // }

  // public func addClipChild(child: Layer) {
  //   _LayerAddClipChild(reference, child.reference)
  // }

  // public func removeClipChild(child: Layer) {
  //   _LayerRemoveClipChild(reference, child.reference)
  // }

  // public func clipChildren() -> [Layer]? {
  //   //let layer = _LayerClipChildren(reference)
  //   //if layer != nil {
  //   //  return Layer(reference: layer)
  //   //}
  //   assert(false)
  //   return nil
  // }

  // TODO: should be a property
  // public func drawTransform() -> Transform {
  //   var x1 = 0.0, x2 = 0.0, x3 = 0.0, x4 = 0.0, x5 = 0.0
  //   var x6 = 0.0, x7 = 0.0, x8 = 0.0, x9 = 0.0, x10 = 0.0
  //   var x11 = 0.0, x12 = 0.0, x13 = 0.0, x14 = 0.0, x15 = 0.0, x16 = 0.0

  //   _LayerDrawTransform(reference,
  //     &x1,
  //     &x2,
  //     &x3,
  //     &x4,
  //     &x5,
  //     &x6,
  //     &x7,
  //     &x8,
  //     &x9,
  //     &x10,
  //     &x11,
  //     &x12,
  //     &x13,
  //     &x14,
  //     &x15,
  //     &x16)

  //   return Transform(x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15, x16)
  // }

  // TODO: should be a property
  public func screenSpaceTransform() -> Transform {
    var x1 = 0.0, x2 = 0.0, x3 = 0.0, x4 = 0.0, x5 = 0.0
    var x6 = 0.0, x7 = 0.0, x8 = 0.0, x9 = 0.0, x10 = 0.0
    var x11 = 0.0, x12 = 0.0, x13 = 0.0, x14 = 0.0, x15 = 0.0, x16 = 0.0

    _LayerScreenSpaceTransform(reference,
      &x1,
      &x2,
      &x3,
      &x4,
      &x5,
      &x6,
      &x7,
      &x8,
      &x9,
      &x10,
      &x11,
      &x12,
      &x13,
      &x14,
      &x15,
      &x16)

    return Transform(x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15, x16)
  }

  public func setScrollOffsetFromImplSide(scrollOffset: ScrollOffset) {
    _LayerSetScrollOffsetFromImplSide(reference, scrollOffset.x, scrollOffset.y)
  }

  // public func setScrollClipLayerId(clipLayerId: Int) {
  //   _LayerSetScrollClipLayerId(reference, Int32(clipLayerId))
  // }

  public func setUserScrollable(horizontal: Bool, vertical: Bool) {
    _LayerSetUserScrollable(reference, horizontal.intValue, vertical.intValue)
  }

  public func userScrollableHorizontal() -> Bool {
    return Bool(_LayerUserScrollableHorizontal(reference))
  }

  public func userScrollableVertical() -> Bool {
    return Bool(_LayerUserScrollableVertical(reference))
  }

  public func setDidScrollCallback(callback: ScrollCallback) {
    _LayerSetDidScrollCallback(reference)
  }

  public func currentScrollOffset() -> ScrollOffset {
    var x: Float = 0.0, y: Float = 0.0
    _LayerCurrentScrollOffset(reference, &x, &y)
    return ScrollOffset(x: x, y: y)
  }

  // public func hasDelegatedContent() -> Bool {
  //   return Bool(_LayerHasDelegatedContent(reference))
  // }

  // public func hasContributingDelegatedRenderPasses() -> Bool {
  //   return Bool(_LayerHasContributingDelegatedRenderPasses(reference))
  // }

  public func setIsDrawable(isDrawable: Bool) {
    _LayerSetIsDrawable(reference, isDrawable.intValue)
  }

  // public func savePaintProperties() {
  //   _LayerSavePaintProperties(reference)
  // }

  public func update() -> Bool {
    return Bool(_LayerUpdate(reference))
  }

  // public func setIsMask(isMask: Bool) {
  //   _LayerSetIsMask(reference, isMask.intValue)
  // }

  // public func isSuitableForGpuRasterization() -> Bool {
  //   return Bool(_LayerIsSuitableForGpuRasterization(reference))
  // }

  public func pushPropertiesTo(layer: Layer) {
    _LayerPushPropertiesTo(reference, layer.reference)
  }

  // public func addAnimation(animation: Animation) -> Bool {
  //   return Bool(_LayerAddAnimation(reference, animation.reference))
  // }

  // public func pauseAnimation(animationId: Int, timeOffset: TimeInterval) {
  //   _LayerPauseAnimation(reference, Int32(animationId), timeOffset)
  // }

  // public func removeAnimation(animationId: Int) {
  //   _LayerRemoveAnimation(reference, Int32(animationId))
  // }

  // public func setLayerAnimationDelegate(delegate: AnimationDelegate) {
  //   // TODO: we need to implement this shit
  //   //_LayerSetLayerAnimationDelegate(reference)
  //   assert(false)
  // }

  // public func registerForAnimations(registrar: AnimationRegistrar) {
  //   _LayerRegisterForAnimations(reference, registrar.reference)
  // }

  // public func addLayerAnimationEventObserver(animationObserver: LayerAnimationEventObserver) {
  //   // TODO: we need to implement this shit
  //   //_LayerAddLayerAnimationEventObserver(reference, animationObserver.reference)
  //   //assert(false)
  //   ////print("warning: called not implemented addLayerAnimationEventObserver.. remember to implement")
  // }

  // public func removeLayerAnimationEventObserver(animationObserver: LayerAnimationEventObserver) {
  //   // TODO: we need to implement this shit
  //   //_LayerRemoveLayerAnimationEventObserver(reference, animationObserver.reference)
  //   //assert(false)
  //   ////print("warning: called not implemented removeLayerAnimationEventObserver.. remember to implement")
  // }

  // public func toScrollbarLayer() -> ScrollbarLayerInterface? {
  //   //_LayerToScrollbarLayer(reference)
  //   assert(false)
  //   return nil
  // }

  public func set3dSortingContextID(id: Int) {
    _LayerSet3dSortingContextId(reference, Int32(id))
  }

  public func sortingContextID() -> Int {
    return Int(_LayerSortingContextId(reference))
  }

  public func setPropertyTreeSequenceNumber(sequenceNumber: Int) {
    _LayerSetPropertyTreeSequenceNumber(reference, Int32(sequenceNumber))
  }

  // public func visibleLayerRect() -> IntRect {
  //   var x: Int32 = 0, y: Int32 = 0, w: Int32 = 0, h: Int32 = 0
  //   _LayerVisibleLayerRect(reference, &x, &y, &w, &h)
  //   return IntRect(x: Int(x), y: Int(y), width: Int(w), height: Int(h))
  // }

  // public func scrollOffsetForAnimation() -> ScrollOffset {
  //   var x = 0.0, y = 0.0
  //   _LayerScrollOffsetForAnimation(reference, &x, &y)
  //   return ScrollOffset(x: x, y: y)
  // }

  // public func onFilterAnimated(filters: FilterOperations) {
  //   //_LayerOnFilterAnimated(reference)
  //   assert(false)
  // }

  // public func onOpacityAnimated(opacity: Float) {
  //   _LayerOnOpacityAnimated(reference, opacity)
  // }

  // public func onTransformAnimated(transform: Transform) {

  //   _LayerOnTransformAnimated(reference,
  //     transform[0,0], // col1row1
  //     transform[0,1], // col2row1
  //     transform[0,2], // col3row1
  //     transform[0,3], // col4row1
  //     transform[1,0], // col1row2
  //     transform[1,1], // col2row2
  //     transform[1,2], // col3row2
  //     transform[1,3], // col4row2
  //     transform[2,0], // col1row3
  //     transform[2,1], // col2row3
  //     transform[2,2], // col3row3
  //     transform[2,3], // col4row3
  //     transform[3,0], // col1row4
  //     transform[3,1], // col2row4
  //     transform[3,2], // col3row4
  //     transform[3,3])
  // }

  // public func onScrollOffsetAnimated(scrollOffset: ScrollOffset) {
  //   _LayerOnScrollOffsetAnimated(reference, scrollOffset.x, scrollOffset.y)
  // }

  // public func onAnimationWaitingForDeletion() {
  //   _LayerOnAnimationWaitingForDeletion(reference)
  // }

  // public func onTransformIsPotentiallyAnimatingChanged(isAnimating: Bool) {
  //   _LayerOnTransformIsPotentiallyAnimatingChanged(reference, isAnimating.intValue)
  // }

}

public final class TextureLayer : Layer {

  public var flipped: Bool {
    get {
      return _TextureLayerFlipped(reference) != 0
    }
    set {
      _TextureLayerSetFlipped(reference, newValue ? 1 : 0)
    }
  }

  public var isSnapped: Bool {
    return _TextureLayerIsSnapped(reference) != 0
  }

  public init(settings: inout LayerSettings, client: LayerClient) throws {
    //print("TextureLayer: init()")
    settings.type = .TextureLayer
    try super.init(settings: settings, client: client)
  }

  public override init(reference: LayerRef, isWeak: Bool = false) {
    super.init(reference: reference, isWeak: isWeak)
  }

  public func clearClient() {
    _TextureLayerClearClient(reference)
  }

  public func clearTexture() {
    _TextureLayerClearTexture(reference)
  }

  public func setUV(topLeft: FloatPoint, bottomRight: FloatPoint) {
    _TextureLayerSetUV(reference, topLeft.x, topLeft.y, bottomRight.x, bottomRight.y)
  }

  public func setNearestNeighbor(_ nearestNeighbor: Bool) {
    _TextureLayerSetNearestNeighbor(reference, nearestNeighbor ? 1 : 0)
  }

  public func setVertexOpacity(bottomLeft: Float,
                               topLeft: Float,
                               topRight: Float,
                               bottomRight: Float) {
    _TextureLayerSetVertexOpacity(reference, bottomLeft, topLeft, topRight, bottomRight)
  }

  public func setPremultipliedAlpha(_ premultipliedAlpha: Bool) {
    _TextureLayerSetPremultipliedAlpha(reference, premultipliedAlpha ? 1 : 0)
  }

  public func setBlendBackgroundColor(_ blend: Bool) {
    _TextureLayerSetBlendBackgroundColor(reference, blend ? 1 : 0)
  }

  // Code path for plugins which supply their own mailbox.
  
  // TODO: implement and try it out with GL
  public func setTransferableResource(
    resource: TransferableResource,
    releaseCallback: SingleReleaseCallback) {
    _TextureLayerSetTransferableResource(reference,
      resource.reference)
  }

}

// public final class DelegatedRendererLayer : Layer {

//   public init(settings: inout LayerSettings, client: LayerClient) throws {
//     settings.type = .DelegatedRendererLayer
//     try super.init(settings: settings, client: client)
//   }

// }

public final class SurfaceLayer : Layer {

  public typealias SatisfyCallback = ()
  public typealias RequireCallback = ()

  public init(settings: inout LayerSettings, client: LayerClient) throws {
    settings.type = .SurfaceLayer
    try super.init(settings: settings, client: client)
  }

  public func setSurfaceId(surfaceId: SurfaceId, scale: Float, size: IntSize) {
    assert(false)
  }

}

public final class SolidColorLayer : Layer {

  public init(settings: inout LayerSettings, client: LayerClient) throws {
    settings.type = .SolidColorLayer
    try super.init(settings: settings, client: client)
  }

}

public final class NinePatchLayer : Layer {

  public var aperture: IntRect

  public var border: IntRect

  public var fillCenter: Bool

  public var bitmap: Bitmap

  public init(settings: inout LayerSettings, client: LayerClient) throws {
    settings.type = .NinePatchLayer
    aperture = IntRect()
    border = IntRect()
    fillCenter = false
    bitmap = Bitmap()
    try super.init(settings: settings, client: client)
  }

}

public final class PictureLayer : Layer {

  public init(settings: inout LayerSettings, client: LayerClient) throws {
    settings.type = .PictureLayer
    try super.init(settings: settings, client: client)
  }

}

public final class VideoLayer : Layer {

  public init(settings: inout LayerSettings, client: LayerClient) throws {
    settings.type = .VideoLayer
    try super.init(settings: settings, client: client)
  }
}