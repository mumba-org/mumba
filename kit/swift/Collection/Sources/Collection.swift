// Copyright (c) 2022 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Foundation
import MumbaShims

public enum CollectionInstallState : Int {
  case NotInstalled = 0
  case Downloaded
  case Installed
  case Disabled
  case Error
}

public enum CollectionAvailabilityState : Int {
  case Unavailable = 0
  case Available
  case Deactivated
}

public struct CollectionEntry {
  public var uuid: String = String()
  public var name: String = String()
  public var description: String = String()
  public var version: String = String()
  public var license: String = String()
  public var publisher: String = String()
  public var publisherUrl: String = String()
  public var publisherPublicKey: String = String()
  public var logoPath: String = String()
  public var size: UInt64 = 0
  public var repoUUID: String = String()
  public var repoPublicKey: String = String()
  public var installState: CollectionInstallState = .NotInstalled
  public var availabilityState: CollectionAvailabilityState = .Unavailable
  public var installCounter: UInt64 = 0
  public var rating: UInt32 = 0
  public var appPublicKey: String = String()
  public var supportedPlatforms: [String] = []
  public var supportedLanguages: [String] = []

  public init() {}

  public init(
    uuid: String,
    name: String,
    description: String,
    version: String,
    license: String,
    publisher: String,
    publisherUrl: String,
    publisherPublicKey: String,
    logoPath: String,
    size: UInt64,
    repoUUID: String,
    repoPublicKey: String,
    installState: CollectionInstallState,
    availabilityState: CollectionAvailabilityState,
    installCounter: UInt64,
    rating: UInt32,
    appPublicKey: String,
    supportedPlatforms: [String],
    supportedLanguages: [String]
  ) {
    self.uuid = uuid
    self.name = name
    self.description = description
    self.version = version
    self.license = license
    self.publisher = publisher
    self.publisherUrl = publisherUrl
    self.publisherPublicKey = publisherPublicKey
    self.logoPath = logoPath
    self.size = size
    self.repoUUID = repoUUID
    self.repoPublicKey = repoPublicKey
    self.installState = installState
    self.availabilityState = availabilityState
    self.installCounter = installCounter
    self.rating = rating
    self.appPublicKey = appPublicKey
    self.supportedPlatforms = supportedPlatforms
    self.supportedLanguages = supportedLanguages
  }
}

public protocol CollectionWatcher : class {
  var unsafeReference: UnsafeMutableRawPointer { get }
  func onEntryAdded(_ : CollectionEntry)
  func onEntryRemoved(_ : CollectionEntry)
}

internal class CollectionWatcherState {
  var id: Int
  var watcher: CollectionWatcher
  var reference: UnsafeMutableRawPointer

  init(id: Int, watcher: CollectionWatcher, reference: UnsafeMutableRawPointer) {
    self.id = id
    self.watcher = watcher
    self.reference = reference
  }

  init(watcher: CollectionWatcher, reference: UnsafeMutableRawPointer) {
    self.id = -1
    self.watcher = watcher
    self.reference = reference
  }

  deinit {
    _CollectionWatcherDestroy(reference)
  }
}

public class Collection {
  
  internal var reference: CollectionRef
  internal var callbacks: [CollectionCallbackState]
  private var watchers: [Int : CollectionWatcherState]

  public init(reference: CollectionRef) {
    self.reference = reference
    callbacks = []
    watchers = [:]
  }

  deinit {
    _CollectionDestroy(reference)
  }

  public func addEntry(_ entry: CollectionEntry, callback: @escaping (_: Bool) -> Void) {
    let callbackState = CollectionCallbackState(self, have: callback)
    callbacks.append(callbackState)
    let statePtr = unsafeBitCast(Unmanaged.passUnretained(callbackState).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    entry.uuid.withCString { ustr in
      entry.name.withCString { nstr in
        entry.description.withCString { dstr in
          entry.version.withCString { vstr in
            entry.license.withCString { lstr in
              entry.publisher.withCString { pstr in
                entry.publisherUrl.withCString { pustr in
                  entry.publisherPublicKey.withCString { ppstr in
                    entry.logoPath.withCString { lstr in
                      entry.repoUUID.withCString { rustr in
                        entry.repoPublicKey.withCString { pkstr in
                          entry.appPublicKey.withCString { apkstr in
                            _CollectionAddEntry(reference, ustr, nstr, dstr, vstr, lstr, pstr, pustr, ppstr, lstr, entry.size, rustr, pkstr, CInt(entry.installState.rawValue), CInt(entry.availabilityState.rawValue), entry.installCounter, entry.rating, apkstr, 0, nil, 0, nil, statePtr, { (state: UnsafeMutableRawPointer?, status: Int32) in
                              let cb = unsafeBitCast(state, to: CollectionCallbackState.self)
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
          }
        }
      }
    }
  }

  public func addEntries(_ entries: [CollectionEntry]) {
    for entry in entries {
      addEntry(entry, callback: { _ in })
    }
  }

  public func removeEntry(address: String, callback: @escaping (_: Bool) -> Void) {
    let callbackState = CollectionCallbackState(self, have: callback)
    callbacks.append(callbackState)
    let statePtr = unsafeBitCast(Unmanaged.passUnretained(callbackState).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    address.withCString {
      _CollectionRemoveEntry(reference, $0, statePtr, { (state: UnsafeMutableRawPointer?, status: Int32) in 
        let cb = unsafeBitCast(state, to: CollectionCallbackState.self)
        cb.haveCallback!(status == 0)
        cb.dispose()
      })
    }
  }

  public func removeEntry(uuid: String, callback: @escaping (_: Bool) -> Void) {
    let callbackState = CollectionCallbackState(self, have: callback)
    callbacks.append(callbackState)
    let statePtr = unsafeBitCast(Unmanaged.passUnretained(callbackState).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    uuid.withCString {
      _CollectionRemoveEntryByUUID(reference, $0, statePtr, { (state: UnsafeMutableRawPointer?, status: Int32) in 
        let cb = unsafeBitCast(state, to: CollectionCallbackState.self)
        cb.haveCallback!(status == 0)
        cb.dispose()
      })
    }
  }

  public func haveEntry(address: String, _ callback: @escaping (_: Bool) -> Void) {
    let callbackState = CollectionCallbackState(self, have: callback)
    callbacks.append(callbackState)
    let statePtr = unsafeBitCast(Unmanaged.passUnretained(callbackState).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
  
    address.withCString { pcstr in
      _CollectionHaveEntry(reference, pcstr, statePtr, { (handle: UnsafeMutableRawPointer?, have: CInt) in
          let cb = unsafeBitCast(handle, to: CollectionCallbackState.self)
          cb.haveCallback!(have != 0)
          cb.dispose()
      })
    }
  }

  public func haveEntry(name: String, _ callback: @escaping (_: Bool) -> Void) {
    let callbackState = CollectionCallbackState(self, have: callback)
    callbacks.append(callbackState)
    name.withCString { pcstr in
      let callbackState = CollectionCallbackState(self, have: callback)
      callbacks.append(callbackState)
      let statePtr = unsafeBitCast(Unmanaged.passUnretained(callbackState).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
      _CollectionHaveEntryByName(reference, pcstr, statePtr, { (handle: UnsafeMutableRawPointer?, have: CInt) in
          let cb = unsafeBitCast(handle, to: CollectionCallbackState.self)
          cb.haveCallback!(have != 0)
          cb.dispose()
      })
    }
  }

  public func haveEntry(uuid: String, _ callback: @escaping (_: Bool) -> Void) {
    uuid.withCString { pcstr in
      let callbackState = CollectionCallbackState(self, have: callback)
      callbacks.append(callbackState)
      let statePtr = unsafeBitCast(Unmanaged.passUnretained(callbackState).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
      _CollectionHaveEntryByUUID(reference, pcstr, statePtr, { (handle: UnsafeMutableRawPointer?, have: CInt) in
          let cb = unsafeBitCast(handle, to: CollectionCallbackState.self)
          cb.haveCallback!(have != 0)
          cb.dispose()
      })
    }
  }

  public func lookupEntry(address: String, _ callback: @escaping (_: CollectionEntry?) -> Void) {
      address.withCString { pcstr in
        let callbackState = CollectionCallbackState(self, lookup: callback)
        callbacks.append(callbackState)
        let statePtr = unsafeBitCast(Unmanaged.passUnretained(callbackState).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
        _CollectionLookupEntry(reference, pcstr, statePtr, { (
          handle: UnsafeMutableRawPointer?, status: CInt, 
          uuid: UnsafePointer<CChar>?, name: UnsafePointer<CChar>?, description: UnsafePointer<CChar>?, version: UnsafePointer<CChar>?,
          license: UnsafePointer<CChar>?, publisher: UnsafePointer<CChar>?, publisher_url: UnsafePointer<CChar>?, 
          publisher_public_key: UnsafePointer<CChar>?, logo_path: UnsafePointer<CChar>?, size: UInt64, repo_uuid: UnsafePointer<CChar>?, 
          repo_public_key: UnsafePointer<CChar>?, install_state: CInt, availability_state: CInt, install_counter: UInt64, 
          rating: UInt32, app_public_key: UnsafePointer<CChar>?, 
          platform_count: CInt, platforms: UnsafeMutablePointer<UnsafePointer<CChar>?>?, 
          languages_count: CInt, languages: UnsafeMutablePointer<UnsafePointer<CChar>?>?
          ) in
           let cb = unsafeBitCast(handle, to: CollectionCallbackState.self)
           var supportedPlatforms: [String] = []
           var supportedLanguages: [String] = []

           for i in 0..<Int(platform_count) {
             supportedPlatforms.append(String(cString: platforms![i]!))
           }

           for i in 0..<Int(languages_count) {
             supportedLanguages.append(String(cString: languages![i]!))
           }

           cb.lookupCallback!(status == 0 ? CollectionEntry(
            uuid: String(cString: uuid!),
            name: String(cString: name!),
            description: String(cString: description!),
            version: String(cString: version!),
            license: String(cString: license!),
            publisher: String(cString: publisher!),
            publisherUrl: String(cString: publisher_url!),
            publisherPublicKey: String(cString: publisher_public_key!),
            logoPath: String(cString: logo_path!),
            size: size,
            repoUUID: String(cString: repo_uuid!),
            repoPublicKey: String(cString: repo_public_key!),
            installState: CollectionInstallState(rawValue: Int(install_state))!,
            availabilityState: CollectionAvailabilityState(rawValue: Int(availability_state))!,
            installCounter: install_counter,
            rating: rating,
            appPublicKey: String(cString: app_public_key!),
            supportedPlatforms: supportedPlatforms,
            supportedLanguages: supportedLanguages) : nil)
           cb.dispose()
        })
      }
    
  }

  public func lookupEntry(name: String, _ callback: @escaping (_: CollectionEntry?) -> Void) {
    name.withCString { pcstr in
      let callbackState = CollectionCallbackState(self, lookup: callback)
      callbacks.append(callbackState)
      let statePtr = unsafeBitCast(Unmanaged.passUnretained(callbackState).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
      _CollectionLookupEntryByName(reference, pcstr, statePtr, { (
        handle: UnsafeMutableRawPointer?, status: CInt, 
        uuid: UnsafePointer<CChar>?, name: UnsafePointer<CChar>?, description: UnsafePointer<CChar>?, version: UnsafePointer<CChar>?,
        license: UnsafePointer<CChar>?, publisher: UnsafePointer<CChar>?, publisher_url: UnsafePointer<CChar>?, 
        publisher_public_key: UnsafePointer<CChar>?, logo_path: UnsafePointer<CChar>?, size: UInt64, repo_uuid: UnsafePointer<CChar>?, 
        repo_public_key: UnsafePointer<CChar>?, install_state: CInt, availability_state: CInt, install_counter: UInt64, 
        rating: UInt32, app_public_key: UnsafePointer<CChar>?, 
        platform_count: CInt, platforms: UnsafeMutablePointer<UnsafePointer<CChar>?>?, 
        languages_count: CInt, languages: UnsafeMutablePointer<UnsafePointer<CChar>?>?) in
          let cb = unsafeBitCast(handle, to: CollectionCallbackState.self)
          var supportedPlatforms: [String] = []
          var supportedLanguages: [String] = []

          for i in 0..<Int(platform_count) {
            supportedPlatforms.append(String(cString: platforms![i]!))
          }

          for i in 0..<Int(languages_count) {
            supportedLanguages.append(String(cString: languages![i]!))
          }

          cb.lookupCallback!(status == 0 ? CollectionEntry(
            uuid: String(cString: uuid!),
            name: String(cString: name!),
            description: String(cString: description!),
            version: String(cString: version!),
            license: String(cString: license!),
            publisher: String(cString: publisher!),
            publisherUrl: String(cString: publisher_url!),
            publisherPublicKey: String(cString: publisher_public_key!),
            logoPath: String(cString: logo_path!),
            size: size,
            repoUUID: String(cString: repo_uuid!),
            repoPublicKey: String(cString: repo_public_key!),
            installState: CollectionInstallState(rawValue: Int(install_state))!,
            availabilityState: CollectionAvailabilityState(rawValue: Int(availability_state))!,
            installCounter: install_counter,
            rating: rating,
            appPublicKey: String(cString: app_public_key!),
            supportedPlatforms: supportedPlatforms,
            supportedLanguages: supportedLanguages) : nil)
          cb.dispose()
      })
    }
  }

  public func lookupEntry(uuid: String, _ callback: @escaping (_: CollectionEntry?) -> Void) {
    uuid.withCString { ucstr in
      let callbackState = CollectionCallbackState(self, lookup: callback)
      callbacks.append(callbackState)
      let statePtr = unsafeBitCast(Unmanaged.passUnretained(callbackState).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
      _CollectionLookupEntryByUUID(reference, ucstr, statePtr, { (
        handle: UnsafeMutableRawPointer?, status: CInt, 
        uuid: UnsafePointer<CChar>?, name: UnsafePointer<CChar>?, description: UnsafePointer<CChar>?, version: UnsafePointer<CChar>?,
        license: UnsafePointer<CChar>?, publisher: UnsafePointer<CChar>?, publisher_url: UnsafePointer<CChar>?, 
        publisher_public_key: UnsafePointer<CChar>?, logo_path: UnsafePointer<CChar>?, size: UInt64, repo_uuid: UnsafePointer<CChar>?, 
        repo_public_key: UnsafePointer<CChar>?, install_state: CInt, availability_state: CInt, install_counter: UInt64, 
        rating: UInt32, app_public_key: UnsafePointer<CChar>?, 
        platform_count: CInt, platforms: UnsafeMutablePointer<UnsafePointer<CChar>?>?, 
        languages_count: CInt, languages: UnsafeMutablePointer<UnsafePointer<CChar>?>?) in
          let cb = unsafeBitCast(handle, to: CollectionCallbackState.self)

          var supportedPlatforms: [String] = []
          var supportedLanguages: [String] = []

          for i in 0..<Int(platform_count) {
            supportedPlatforms.append(String(cString: platforms![i]!))
          }

          for i in 0..<Int(languages_count) {
            supportedLanguages.append(String(cString: languages![i]!))
          }  

          cb.lookupCallback!(status == 0 ? CollectionEntry(
            uuid: String(cString: uuid!),
            name: String(cString: name!),
            description: String(cString: description!),
            version: String(cString: version!),
            license: String(cString: license!),
            publisher: String(cString: publisher!),
            publisherUrl: String(cString: publisher_url!),
            publisherPublicKey: String(cString: publisher_public_key!),
            logoPath: String(cString: logo_path!),
            size: size,
            repoUUID: String(cString: repo_uuid!),
            repoPublicKey: String(cString: repo_public_key!),
            installState: CollectionInstallState(rawValue: Int(install_state))!,
            availabilityState: CollectionAvailabilityState(rawValue: Int(availability_state))!,
            installCounter: install_counter,
            rating: rating,
            appPublicKey: String(cString: app_public_key!),
            supportedPlatforms: supportedPlatforms,
            supportedLanguages: supportedLanguages) : nil)
          cb.dispose()
      })
    }
  }

  public func listEntries(_ callback: @escaping (_: [CollectionEntry]?) -> Void) {
    let callbackState = CollectionCallbackState(self, list: callback)
    callbacks.append(callbackState)
    let statePtr = unsafeBitCast(Unmanaged.passUnretained(callbackState).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    _CollectionListEntries(reference, statePtr, { (
      handle: UnsafeMutableRawPointer?, count: CInt, 
      uuid: UnsafeMutablePointer<UnsafePointer<CChar>?>?, name: UnsafeMutablePointer<UnsafePointer<CChar>?>?, description: UnsafeMutablePointer<UnsafePointer<CChar>?>?, version: UnsafeMutablePointer<UnsafePointer<CChar>?>?,
      license: UnsafeMutablePointer<UnsafePointer<CChar>?>?, publisher: UnsafeMutablePointer<UnsafePointer<CChar>?>?, publisher_url: UnsafeMutablePointer<UnsafePointer<CChar>?>?, 
      publisher_public_key: UnsafeMutablePointer<UnsafePointer<CChar>?>?, logo_path: UnsafeMutablePointer<UnsafePointer<CChar>?>?, size: UnsafeMutablePointer<UInt64>?, 
      repo_uuid: UnsafeMutablePointer<UnsafePointer<CChar>?>?, repo_public_key: UnsafeMutablePointer<UnsafePointer<CChar>?>?, install_state: UnsafeMutablePointer<CInt>?, 
      availability_state: UnsafeMutablePointer<CInt>?, install_counter: UnsafeMutablePointer<UInt64>?, 
      rating: UnsafeMutablePointer<UInt32>?, app_public_key: UnsafeMutablePointer<UnsafePointer<CChar>?>?, 
      platform_count: UnsafeMutablePointer<CInt>?, platforms: UnsafeMutablePointer<UnsafeMutablePointer<UnsafePointer<CChar>?>?>?, 
      languages_count: UnsafeMutablePointer<CInt>?, languages: UnsafeMutablePointer<UnsafeMutablePointer<UnsafePointer<CChar>?>?>?) in
        let cb = unsafeBitCast(handle, to: CollectionCallbackState.self)
        if count > 0 {
          var entries: [CollectionEntry] = []
          for i in 0..<Int(count) {
            var supportedPlatforms: [String] = []
            var supportedLanguages: [String] = []

            for x in 0..<Int(platform_count![i]) {
              supportedPlatforms.append(String(cString: platforms![i]![x]!))
            }

            for x in 0..<Int(languages_count![i]) {
              supportedLanguages.append(String(cString: languages![i]![x]!))
            }  
            
            entries.append(CollectionEntry(
              uuid: String(cString: uuid![i]!),
              name: String(cString: name![i]!),
              description: String(cString: description![i]!),
              version: String(cString: version![i]!),
              license: String(cString: license![i]!),
              publisher: String(cString: publisher![i]!),
              publisherUrl: String(cString: publisher_url![i]!),
              publisherPublicKey: String(cString: publisher_public_key![i]!),
              logoPath: String(cString: logo_path![i]!),
              size: size![i],
              repoUUID: String(cString: repo_uuid![i]!),
              repoPublicKey: String(cString: repo_public_key![i]!),
              installState: CollectionInstallState(rawValue: Int(install_state![i]))!,
              availabilityState: CollectionAvailabilityState(rawValue: Int(availability_state![i]))!,
              installCounter: install_counter![i],
              rating: rating![i],
              appPublicKey: String(cString: app_public_key![i]!),
              supportedPlatforms: supportedPlatforms,
              supportedLanguages: supportedLanguages
            ))
          }
          cb.listCallback!(entries)
        } else {
          cb.listCallback!(nil)
        }
        cb.dispose()
    })
  }

  public func getEntryCount(_ callback: @escaping (_: Int) -> Void) {
    let callbackState = CollectionCallbackState(self, count: callback)
    callbacks.append(callbackState)
    let statePtr = unsafeBitCast(Unmanaged.passUnretained(callbackState).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    _CollectionGetEntryCount(reference, statePtr, { (handle: UnsafeMutableRawPointer?, count: CInt) in
      let cb = unsafeBitCast(handle, to: CollectionCallbackState.self)
      cb.countCallback!(Int(count))
      cb.dispose()
    })
  }

  public func addWatcher(_ watcher: CollectionWatcher) {
    let statePtr = unsafeBitCast(Unmanaged.passUnretained(self).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    let watcherPtr = watcher.unsafeReference
    _CollectionAddWatcher(
      reference,
      statePtr,
      watcherPtr,
      // onEntryAdded
      { (handle: UnsafeMutableRawPointer?,
         uuid: UnsafePointer<CChar>?, 
         name: UnsafePointer<CChar>?, 
         description: UnsafePointer<CChar>?, 
         version: UnsafePointer<CChar>?,
         license: UnsafePointer<CChar>?, 
         publisher: UnsafePointer<CChar>?, 
         publisher_url: UnsafePointer<CChar>?, 
         publisher_public_key: UnsafePointer<CChar>?, 
         logo_path: UnsafePointer<CChar>?, 
         size: UInt64, 
         repo_uuid: UnsafePointer<CChar>?, 
         repo_public_key: UnsafePointer<CChar>?, install_state: CInt, availability_state: CInt, install_counter: UInt64, 
         rating: UInt32, app_public_key: UnsafePointer<CChar>?, 
         platform_count: CInt, platforms: UnsafeMutablePointer<UnsafePointer<CChar>?>?, 
         languages_count: CInt, languages: UnsafeMutablePointer<UnsafePointer<CChar>?>?) in 
        let watcher = unsafeBitCast(handle, to: CollectionWatcher.self)
        var supportedPlatforms: [String] = []
        var supportedLanguages: [String] = []

        for x in 0..<Int(platform_count) {
          supportedPlatforms.append(String(cString: platforms![x]!))
        }

        for x in 0..<Int(languages_count) {
          supportedLanguages.append(String(cString: languages![x]!))
        }  
            
        watcher.onEntryAdded(CollectionEntry(
            uuid: String(cString: uuid!),
            name: String(cString: name!),
            description: String(cString: description!),
            version: String(cString: version!),
            license: String(cString: license!),
            publisher: String(cString: publisher!),
            publisherUrl: String(cString: publisher_url!),
            publisherPublicKey: String(cString: publisher_public_key!),
            logoPath: String(cString: logo_path!),
            size: size,
            repoUUID: String(cString: repo_uuid!),
            repoPublicKey: String(cString: repo_public_key!),
            installState: CollectionInstallState(rawValue: Int(install_state))!,
            availabilityState: CollectionAvailabilityState(rawValue: Int(availability_state))!,
            installCounter: install_counter,
            rating: rating,
            appPublicKey: String(cString: app_public_key!),
            supportedPlatforms: supportedPlatforms,
            supportedLanguages: supportedLanguages))
      },
      // onEntryRemoved
      { (handle: UnsafeMutableRawPointer?,
         uuid: UnsafePointer<CChar>?, name: UnsafePointer<CChar>?, description: UnsafePointer<CChar>?, version: UnsafePointer<CChar>?,
         license: UnsafePointer<CChar>?, publisher: UnsafePointer<CChar>?, publisher_url: UnsafePointer<CChar>?, 
         publisher_public_key: UnsafePointer<CChar>?, logo_path: UnsafePointer<CChar>?, size: UInt64, repo_uuid: UnsafePointer<CChar>?, 
         repo_public_key: UnsafePointer<CChar>?, install_state: CInt, availability_state: CInt, install_counter: UInt64, 
         rating: UInt32, app_public_key: UnsafePointer<CChar>?, 
         platform_count: CInt, platforms: UnsafeMutablePointer<UnsafePointer<CChar>?>?, 
         languages_count: CInt, languages: UnsafeMutablePointer<UnsafePointer<CChar>?>?) in 
        var supportedPlatforms: [String] = []
        var supportedLanguages: [String] = []

        for x in 0..<Int(platform_count) {
          supportedPlatforms.append(String(cString: platforms![x]!))
        }

        for x in 0..<Int(languages_count) {
          supportedLanguages.append(String(cString: languages![x]!))
        } 
        let watcher = unsafeBitCast(handle, to: CollectionWatcher.self)
        watcher.onEntryRemoved(
          CollectionEntry(
            uuid: String(cString: uuid!),
            name: String(cString: name!),
            description: String(cString: description!),
            version: String(cString: version!),
            license: String(cString: license!),
            publisher: String(cString: publisher!),
            publisherUrl: String(cString: publisher_url!),
            publisherPublicKey: String(cString: publisher_public_key!),
            logoPath: String(cString: logo_path!),
            size: size,
            repoUUID: String(cString: repo_uuid!),
            repoPublicKey: String(cString: repo_public_key!),
            installState: CollectionInstallState(rawValue: Int(install_state))!,
            availabilityState: CollectionAvailabilityState(rawValue: Int(availability_state))!,
            installCounter: install_counter,
            rating: rating,
            appPublicKey: String(cString: app_public_key!),
            supportedPlatforms: supportedPlatforms,
            supportedLanguages: supportedLanguages))
      }
    )
  }

  public func removeWatcher(id: Int) {
    _CollectionRemoveWatcher(reference, CInt(id))
    onWatcherRemoved(id: Int(id))
  }

  public func removeWatcher(_ watcher: CollectionWatcher) {
    for (id, w) in watchers {
      if w.watcher === watcher {
        removeWatcher(id: id)
        return
      }
    }
  }

  private func onWatcherAdded(id: Int, reference: UnsafeMutableRawPointer, watcher: CollectionWatcher) {
    watchers[id] = CollectionWatcherState(id: id, watcher: watcher, reference: reference)
  }

  private func onWatcherRemoved(id: Int) {
    watchers.removeValue(forKey: id)
  }

}

internal class CollectionCallbackState {
  
  internal var haveCallback: ((_: Bool) -> Void)?
  internal var lookupCallback: ((_: CollectionEntry?) -> Void)?
  internal var listCallback: ((_: [CollectionEntry]?) -> Void)?
  internal var countCallback: ((_: Int) -> Void)?
  private weak var owner: Collection?

  init(_ owner: Collection, lookup: @escaping (_: CollectionEntry?) -> Void) {
    self.owner = owner
    self.lookupCallback = lookup
  }

  init(_ owner: Collection, list: @escaping (_: [CollectionEntry]?) -> Void) {
    self.owner = owner
    self.listCallback = list
  }

  init(_ owner: Collection, have: @escaping (_: Bool) -> Void) {
    self.owner = owner
    self.haveCallback = have
  }

  init(_ owner: Collection, count: @escaping (_: Int) -> Void) {
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