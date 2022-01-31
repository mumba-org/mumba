// Copyright (c) 2022 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Foundation
import MumbaShims

public enum RepoType : Int {
  case Torrent = 0
  case Ipfs = 1
  case Filesystem = 2
  case Git = 3
  case Http = 4
  case Rpc = 5
}

public enum RepoAddressFormat : Int {
  case Classic = 0 // ??
  case Base32 = 1
  case Base36 = 2
  case Base58 = 3
  case Base64 = 4
  case IpfsDhtCid = 5
  case TorrentMagnet = 6
  case TorrentEd25519 = 7
}

public enum PKCryptoFormat : Int {
  case Ed25519 = 0
}

public struct Repo {
  var uuid: String
  var type: RepoType
  var name: String
  var address: String
  var addressFormat: RepoAddressFormat
  var addressFormatVersion: String
  var publicKey: String
  var pkCryptoFormat: PKCryptoFormat
  var rootTree: String
  var creator: String

  public init() {
    uuid = String()
    type = RepoType.Torrent
    name = String()
    address = String()
    addressFormat = RepoAddressFormat.Classic
    addressFormatVersion = String()
    publicKey = String()
    pkCryptoFormat = PKCryptoFormat.Ed25519
    rootTree = String()
    creator = String()
  }

  public init(
    uuid: String,
    type: RepoType,
    name: String,
    address: String,
    addressFormat: RepoAddressFormat,
    addressFormatVersion: String,
    publicKey: String,
    pkCryptoFormat: PKCryptoFormat,
    rootTree: String,
    creator: String) {
    self.uuid = uuid
    self.type = type
    self.name = name
    self.address = address
    self.addressFormat = addressFormat
    self.addressFormatVersion = addressFormatVersion
    self.publicKey = publicKey
    self.pkCryptoFormat = pkCryptoFormat
    self.rootTree = rootTree
    self.creator = creator
  }
}

public protocol RepoWatcher : class {
  var unsafeReference: UnsafeMutableRawPointer { get }
  func onRepoAdded(_ : Repo)
  func onRepoRemoved(_ : Repo)
}

internal class RepoWatcherState {
  var id: Int
  var watcher: RepoWatcher
  var reference: UnsafeMutableRawPointer

  init(id: Int, watcher: RepoWatcher, reference: UnsafeMutableRawPointer) {
    self.id = id
    self.watcher = watcher
    self.reference = reference
  }

  init(watcher: RepoWatcher, reference: UnsafeMutableRawPointer) {
    self.id = -1
    self.watcher = watcher
    self.reference = reference
  }

  deinit {
    _RepoWatcherDestroy(reference)
  }
}

public class RepoRegistry {
  
  internal var reference: RepoRegistryRef
  internal var callbacks: [RepoCallbackState]
  private var watchers: [Int : RepoWatcherState]

  public init(reference: RepoRegistryRef) {
    self.reference = reference
    callbacks = []
    watchers = [:]
  }

  deinit {
    _RepoRegistryDestroy(reference)
  }

  public func addRepo(address: String, _ callback: @escaping (_: Bool) -> Void) {
    var repo = Repo()
    repo.address = address
    addRepo(repo, callback)
  }

  public func addRepo(_ repo: Repo, _ callback: @escaping (_: Bool) -> Void) {
    let callbackState = RepoCallbackState(self, have: callback)
    callbacks.append(callbackState)
    let statePtr = unsafeBitCast(Unmanaged.passUnretained(callbackState).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    repo.uuid.withCString { ustr in
      repo.name.withCString { nstr in
        repo.address.withCString { astr in
          repo.addressFormatVersion.withCString { afstr in
            repo.publicKey.withCString { pkstr in
              repo.rootTree.withCString { rtstr in
                repo.creator.withCString { cstr in
                  _RepoRegistryAddRepo(reference, ustr, CInt(repo.type.rawValue), nstr, astr, CInt(repo.addressFormat.rawValue), afstr, pkstr, CInt(repo.pkCryptoFormat.rawValue), rtstr, cstr, statePtr, { (state: UnsafeMutableRawPointer?, status: Int32) in
                    let cb = unsafeBitCast(state, to: RepoCallbackState.self)
                    cb.haveCallback!(status == 0)
                    cb.dispose()
                  })
                }
              }
            }
          }
        }
      }
    }
  }

  public func addRepos(_ repos: [Repo]) {
    for repo in repos {
      addRepo(repo, { _ in })
    }
  }

  public func removeRepo(address: String, _ callback: @escaping (_: Bool) -> Void) {
    let callbackState = RepoCallbackState(self, have: callback)
    callbacks.append(callbackState)
    let statePtr = unsafeBitCast(Unmanaged.passUnretained(callbackState).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    address.withCString {
      _RepoRegistryRemoveRepo(reference, $0, statePtr, { (state: UnsafeMutableRawPointer?, status: Int32) in 
        let cb = unsafeBitCast(state, to: RepoCallbackState.self)
        cb.haveCallback!(status == 0)
        cb.dispose()
      })
    }
  }

  public func removeRepo(uuid: String, _ callback: @escaping (_: Bool) -> Void) {
    let callbackState = RepoCallbackState(self, have: callback)
    callbacks.append(callbackState)
    let statePtr = unsafeBitCast(Unmanaged.passUnretained(callbackState).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    uuid.withCString {
      _RepoRegistryRemoveRepoByUUID(reference, $0, statePtr, { (state: UnsafeMutableRawPointer?, status: Int32) in 
        let cb = unsafeBitCast(state, to: RepoCallbackState.self)
        cb.haveCallback!(status == 0)
        cb.dispose()
      })
    }
  }

  public func haveRepo(address: String, _ callback: @escaping (_: Bool) -> Void) {
    let callbackState = RepoCallbackState(self, have: callback)
    callbacks.append(callbackState)
    let statePtr = unsafeBitCast(Unmanaged.passUnretained(callbackState).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
  
    address.withCString { pcstr in
      _RepoRegistryHaveRepo(reference, pcstr, statePtr, { (handle: UnsafeMutableRawPointer?, have: CInt) in
          let cb = unsafeBitCast(handle, to: RepoCallbackState.self)
          cb.haveCallback!(have != 0)
          cb.dispose()
      })
    }
  }

  public func haveRepo(name: String, _ callback: @escaping (_: Bool) -> Void) {
    let callbackState = RepoCallbackState(self, have: callback)
    callbacks.append(callbackState)
    name.withCString { pcstr in
      let callbackState = RepoCallbackState(self, have: callback)
      callbacks.append(callbackState)
      let statePtr = unsafeBitCast(Unmanaged.passUnretained(callbackState).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
      _RepoRegistryHaveRepoByName(reference, pcstr, statePtr, { (handle: UnsafeMutableRawPointer?, have: CInt) in
          let cb = unsafeBitCast(handle, to: RepoCallbackState.self)
          cb.haveCallback!(have != 0)
          cb.dispose()
      })
    }
  }

  public func haveRepo(uuid: String, _ callback: @escaping (_: Bool) -> Void) {
    uuid.withCString { pcstr in
      let callbackState = RepoCallbackState(self, have: callback)
      callbacks.append(callbackState)
      let statePtr = unsafeBitCast(Unmanaged.passUnretained(callbackState).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
      _RepoRegistryHaveRepoByUUID(reference, pcstr, statePtr, { (handle: UnsafeMutableRawPointer?, have: CInt) in
          let cb = unsafeBitCast(handle, to: RepoCallbackState.self)
          cb.haveCallback!(have != 0)
          cb.dispose()
      })
    }
  }

  public func lookupRepo(address: String, _ callback: @escaping (_: Repo?) -> Void) {
      address.withCString { pcstr in
        let callbackState = RepoCallbackState(self, lookup: callback)
        callbacks.append(callbackState)
        let statePtr = unsafeBitCast(Unmanaged.passUnretained(callbackState).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
        _RepoRegistryLookupRepo(reference, pcstr, statePtr, { (         
          handle: UnsafeMutableRawPointer?, 
          status: CInt, 
          uuid: UnsafePointer<CChar>?, 
          type: CInt, 
          name: UnsafePointer<CChar>?, 
          address: UnsafePointer<CChar>?,
          addressFormat: CInt, 
          addressFormatVersion: UnsafePointer<CChar>?, 
          publicKey: UnsafePointer<CChar>?, 
          pkCryptoFormat: CInt, 
          rootTree: UnsafePointer<CChar>?, 
          creator: UnsafePointer<CChar>?) in
           let cb = unsafeBitCast(handle, to: RepoCallbackState.self)
           cb.lookupCallback!(status == 0 ? Repo(
            uuid: String(cString: uuid!),
            type: RepoType(rawValue: Int(type))!,
            name: String(cString: name!),
            address: String(cString: address!),
            addressFormat: RepoAddressFormat(rawValue: Int(addressFormat))!,
            addressFormatVersion: String(cString: addressFormatVersion!),
            publicKey: String(cString: publicKey!),
            pkCryptoFormat: PKCryptoFormat(rawValue: Int(pkCryptoFormat))!,
            rootTree: String(cString: rootTree!),
            creator: String(cString: creator!)) : nil)
           cb.dispose()
        })
      }
  }

  public func lookupRepo(name: String, _ callback: @escaping (_: Repo?) -> Void) {
    name.withCString { pcstr in
      let callbackState = RepoCallbackState(self, lookup: callback)
      callbacks.append(callbackState)
      let statePtr = unsafeBitCast(Unmanaged.passUnretained(callbackState).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
      _RepoRegistryLookupRepoByName(reference, pcstr, statePtr, { (
        handle: UnsafeMutableRawPointer?, 
        status: CInt, 
        uuid: UnsafePointer<CChar>?, 
        type: CInt, 
        name: UnsafePointer<CChar>?, 
        address: UnsafePointer<CChar>?,
        addressFormat: CInt, 
        addressFormatVersion: UnsafePointer<CChar>?, 
        publicKey: UnsafePointer<CChar>?, 
        pkCryptoFormat: CInt, 
        rootTree: UnsafePointer<CChar>?, 
        creator: UnsafePointer<CChar>?) in
          let cb = unsafeBitCast(handle, to: RepoCallbackState.self)
          cb.lookupCallback!(
            status == 0 ? 
            Repo(
              uuid: String(cString: uuid!),
              type: RepoType(rawValue: Int(type))!,
              name: String(cString: name!),
              address: String(cString: address!),
              addressFormat: RepoAddressFormat(rawValue: Int(addressFormat))!,
              addressFormatVersion: String(cString: addressFormatVersion!),
              publicKey: String(cString: publicKey!),
              pkCryptoFormat: PKCryptoFormat(rawValue: Int(pkCryptoFormat))!,
              rootTree: String(cString: rootTree!),
              creator: String(cString: creator!)
            ) : nil)
          cb.dispose()
      })
    }
  }

  public func lookupRepo(uuid: String, _ callback: @escaping (_: Repo?) -> Void) {
    uuid.withCString { ucstr in
      let callbackState = RepoCallbackState(self, lookup: callback)
      callbacks.append(callbackState)
      let statePtr = unsafeBitCast(Unmanaged.passUnretained(callbackState).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
      _RepoRegistryLookupRepoByUUID(reference, ucstr, statePtr, { (
        handle: UnsafeMutableRawPointer?, 
        status: CInt, 
        uuid: UnsafePointer<CChar>?, 
        type: CInt, 
        name: UnsafePointer<CChar>?, 
        address: UnsafePointer<CChar>?,
        addressFormat: CInt, 
        addressFormatVersion: UnsafePointer<CChar>?, 
        publicKey: UnsafePointer<CChar>?, 
        pkCryptoFormat: CInt, 
        rootTree: UnsafePointer<CChar>?, 
        creator: UnsafePointer<CChar>?) in
          let cb = unsafeBitCast(handle, to: RepoCallbackState.self)
          cb.lookupCallback!(status == 0 ? Repo(
            uuid: String(cString: uuid!),
            type: RepoType(rawValue: Int(type))!,
            name: String(cString: name!),
            address: String(cString: address!),
            addressFormat: RepoAddressFormat(rawValue: Int(addressFormat))!,
            addressFormatVersion: String(cString: addressFormatVersion!),
            publicKey: String(cString: publicKey!),
            pkCryptoFormat: PKCryptoFormat(rawValue: Int(pkCryptoFormat))!,
            rootTree: String(cString: rootTree!),
            creator: String(cString: creator!)) : nil)
          cb.dispose()
      })
    }
  }

  public func listRepos(_ callback: @escaping (_: [Repo]?) -> Void) {
    let callbackState = RepoCallbackState(self, list: callback)
    callbacks.append(callbackState)
    let statePtr = unsafeBitCast(Unmanaged.passUnretained(callbackState).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    _RepoRegistryListRepos(reference, statePtr, { (
      handle: UnsafeMutableRawPointer?, count: CInt, 
      uuid: UnsafeMutablePointer<UnsafePointer<CChar>?>?, 
      type: UnsafeMutablePointer<CInt>?, 
      name: UnsafeMutablePointer<UnsafePointer<CChar>?>?, 
      address: UnsafeMutablePointer<UnsafePointer<CChar>?>?,
      addressFormat: UnsafeMutablePointer<CInt>?, 
      addressFormatVersion: UnsafeMutablePointer<UnsafePointer<CChar>?>?, 
      publicKey: UnsafeMutablePointer<UnsafePointer<CChar>?>?, 
      pkCryptoFormat: UnsafeMutablePointer<CInt>?, 
      rootTree: UnsafeMutablePointer<UnsafePointer<CChar>?>?, 
      creator: UnsafeMutablePointer<UnsafePointer<CChar>?>?
      ) in
        let cb = unsafeBitCast(handle, to: RepoCallbackState.self)
        if count > 0 {
          var repos: [Repo] = []
          for i in 0..<Int(count) {          
            repos.append(
              Repo(
                uuid: String(cString: uuid![i]!),
                type: RepoType(rawValue: Int(type![i]))!,
                name: String(cString: name![i]!),
                address: String(cString: address![i]!),
                addressFormat: RepoAddressFormat(rawValue: Int(addressFormat![i]))!,
                addressFormatVersion: String(cString: addressFormatVersion![i]!),
                publicKey: String(cString: publicKey![i]!),
                pkCryptoFormat: PKCryptoFormat(rawValue: Int(pkCryptoFormat![i]))!,
                rootTree: String(cString: rootTree![i]!),
                creator: String(cString: creator![i]!))
            )
          }
          cb.listCallback!(repos)
        } else {
          cb.listCallback!(nil)
        }
        cb.dispose()
    })
  }

  public func getRepoCount(_ callback: @escaping (_: Int) -> Void) {
    let callbackState = RepoCallbackState(self, count: callback)
    callbacks.append(callbackState)
    let statePtr = unsafeBitCast(Unmanaged.passUnretained(callbackState).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    _RepoRegistryGetRepoCount(reference, statePtr, { (handle: UnsafeMutableRawPointer?, count: CInt) in
      let cb = unsafeBitCast(handle, to: RepoCallbackState.self)
      cb.countCallback!(Int(count))
      cb.dispose()
    })
  }

  public func addWatcher(_ watcher: RepoWatcher) {
    let statePtr = unsafeBitCast(Unmanaged.passUnretained(self).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    let watcherPtr = watcher.unsafeReference
    _RepoRegistryAddWatcher(
      reference,
      statePtr,
      watcherPtr,
      // onRepoAdded
      { (handle: UnsafeMutableRawPointer?,
         uuid: UnsafePointer<CChar>?, 
         type: CInt, 
         name: UnsafePointer<CChar>?, 
         address: UnsafePointer<CChar>?,
         addressFormat: CInt, 
         addressFormatVersion: UnsafePointer<CChar>?, 
         publicKey: UnsafePointer<CChar>?, 
         pkCryptoFormat: CInt, 
         rootTree: UnsafePointer<CChar>?, 
         creator: UnsafePointer<CChar>?) in 
        let watcher = unsafeBitCast(handle, to: RepoWatcher.self)
       
        watcher.onRepoAdded(Repo(
            uuid: String(cString: uuid!),
            type: RepoType(rawValue: Int(type))!,
            name: String(cString: name!),
            address: String(cString: address!),
            addressFormat: RepoAddressFormat(rawValue: Int(addressFormat))!,
            addressFormatVersion: String(cString: addressFormatVersion!),
            publicKey: String(cString: publicKey!),
            pkCryptoFormat: PKCryptoFormat(rawValue: Int(pkCryptoFormat))!,
            rootTree: String(cString: rootTree!),
            creator: String(cString: creator!)))
      },
      // onRepoRemoved
      { (handle: UnsafeMutableRawPointer?,
         uuid: UnsafePointer<CChar>?, 
         type: CInt, 
         name: UnsafePointer<CChar>?, 
         address: UnsafePointer<CChar>?,
         addressFormat: CInt, 
         addressFormatVersion: UnsafePointer<CChar>?, 
         publicKey: UnsafePointer<CChar>?, 
         pkCryptoFormat: CInt, 
         rootTree: UnsafePointer<CChar>?, 
         creator: UnsafePointer<CChar>?) in 
        
        let watcher = unsafeBitCast(handle, to: RepoWatcher.self)
        watcher.onRepoRemoved(
          Repo(
            uuid: String(cString: uuid!),
            type: RepoType(rawValue: Int(type))!,
            name: String(cString: name!),
            address: String(cString: address!),
            addressFormat: RepoAddressFormat(rawValue: Int(addressFormat))!,
            addressFormatVersion: String(cString: addressFormatVersion!),
            publicKey: String(cString: publicKey!),
            pkCryptoFormat: PKCryptoFormat(rawValue: Int(pkCryptoFormat))!,
            rootTree: String(cString: rootTree!),
            creator: String(cString: creator!)))
      }
    )
  }

  public func removeWatcher(id: Int) {
    _RepoRegistryRemoveWatcher(reference, CInt(id))
    onWatcherRemoved(id: id)
  }

  public func removeWatcher(_ watcher: RepoWatcher) {
    for (id, w) in watchers {
      if w.watcher === watcher {
        removeWatcher(id: id)
        return
      }
    }
  }

  private func onWatcherAdded(id: Int, reference: UnsafeMutableRawPointer, watcher: RepoWatcher) {
    watchers[id] = RepoWatcherState(id: id, watcher: watcher, reference: reference)
  }

  private func onWatcherRemoved(id: Int) {
    watchers.removeValue(forKey: id)
  }

}

internal class RepoCallbackState {
  
  internal var haveCallback: ((_: Bool) -> Void)?
  internal var lookupCallback: ((_: Repo?) -> Void)?
  internal var listCallback: ((_: [Repo]?) -> Void)?
  internal var countCallback: ((_: Int) -> Void)?
  private weak var owner: RepoRegistry?

  init(_ owner: RepoRegistry, lookup: @escaping (_: Repo?) -> Void) {
    self.owner = owner
    self.lookupCallback = lookup
  }

  init(_ owner: RepoRegistry, list: @escaping (_: [Repo]?) -> Void) {
    self.owner = owner
    self.listCallback = list
  }

  init(_ owner: RepoRegistry, have: @escaping (_: Bool) -> Void) {
    self.owner = owner
    self.haveCallback = have
  }

  init(_ owner: RepoRegistry, count: @escaping (_: Int) -> Void) {
    self.owner = owner
    self.countCallback = count
  }

  func dispose() {
    for (index, elem) in owner!.callbacks.enumerated() {
      if elem === self {
        owner!.callbacks.remove(at: index)
        return
      }
    }
  }
}