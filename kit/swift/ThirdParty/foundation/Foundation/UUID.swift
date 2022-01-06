//===----------------------------------------------------------------------===//
//
// This source file is part of the Swift.org open source project
//
// Copyright (c) 2014 - 2016 Apple Inc. and the Swift project authors
// Licensed under Apache License v2.0 with Runtime Library Exception
//
// See http://swift.org/LICENSE.txt for license information
// See http://swift.org/CONTRIBUTORS.txt for the list of Swift project authors
//
//===----------------------------------------------------------------------===//

import CoreFoundation

public typealias uuid_t = (UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8)
public typealias uuid_string_t = (Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8)

/// Represents UUID strings, which can be used to uniquely identify types, interfaces, and other items.
public struct UUID : ReferenceConvertible, Hashable, Equatable, CustomStringConvertible {
    public typealias ReferenceType = NSUUID
    
    public private(set) var uuid: uuid_t = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    
    /* Create a new UUID with RFC 4122 version 4 random bytes */
    public init() {
        withUnsafeMutablePointer(to: &uuid) {
            $0.withMemoryRebound(to: UInt8.self, capacity: MemoryLayout<uuid_t>.size) {
                _cf_uuid_generate_random($0)
            }
        }
    }
    
    fileprivate init(reference: NSUUID) {
        var bytes: uuid_t = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        withUnsafeMutablePointer(to: &bytes) {
            $0.withMemoryRebound(to: UInt8.self, capacity: MemoryLayout<uuid_t>.size) {
                reference.getBytes($0)
            }
        }
        uuid = bytes
    }
    
    /// Create a UUID from a string such as "E621E1F8-C36C-495A-93FC-0C247A3E6E5F".
    ///
    /// Returns nil for invalid strings.
    public init?(uuidString string: String) {
        let res = withUnsafeMutablePointer(to: &uuid) {
            $0.withMemoryRebound(to: UInt8.self, capacity: MemoryLayout<uuid_t>.size) {
                return _cf_uuid_parse(string, $0)
            }
        }
        if res != 0 {
            return nil
        }
    }
    
    /// Create a UUID from a `uuid_t`.
    public init(uuid: uuid_t) {
        self.uuid = uuid
    }
    
    /// Returns a string created from the UUID, such as "E621E1F8-C36C-495A-93FC-0C247A3E6E5F"
    public var uuidString: String {
        var bytes: uuid_string_t = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        return withUnsafePointer(to: uuid) { valPtr in
            valPtr.withMemoryRebound(to: UInt8.self, capacity: MemoryLayout<uuid_t>.size) { val in
                withUnsafeMutablePointer(to: &bytes) { strPtr in
                    strPtr.withMemoryRebound(to: CChar.self, capacity: MemoryLayout<uuid_string_t>.size) { str in
                        _cf_uuid_unparse_upper(val, str)
                        return String(cString: str, encoding: .utf8)!
                    }
                }
            }
        }
    }
    
    public var hashValue: Int {
        return withUnsafePointer(to: uuid) {
            $0.withMemoryRebound(to: UInt8.self, capacity: MemoryLayout<uuid_t>.size) {
                return Int(bitPattern: CFHashBytes(UnsafeMutablePointer(mutating: $0), CFIndex(MemoryLayout<uuid_t>.size)))
            }
        }
    }
    
    public var description: String {
        return uuidString
    }
    
    public var debugDescription: String {
        return description
    }
    
    // MARK: - Bridging Support
    
    fileprivate var reference: NSUUID {
        return withUnsafePointer(to: uuid) {
            $0.withMemoryRebound(to: UInt8.self, capacity: MemoryLayout<uuid_t>.size) {
                return NSUUID(uuidBytes: $0)
            }
        }
    }
    
    public static func ==(lhs: UUID, rhs: UUID) -> Bool {
        return lhs.uuid.0 == rhs.uuid.0 &&
            lhs.uuid.1 == rhs.uuid.1 &&
            lhs.uuid.2 == rhs.uuid.2 &&
            lhs.uuid.3 == rhs.uuid.3 &&
            lhs.uuid.4 == rhs.uuid.4 &&
            lhs.uuid.5 == rhs.uuid.5 &&
            lhs.uuid.6 == rhs.uuid.6 &&
            lhs.uuid.7 == rhs.uuid.7 &&
            lhs.uuid.8 == rhs.uuid.8 &&
            lhs.uuid.9 == rhs.uuid.9 &&
            lhs.uuid.10 == rhs.uuid.10 &&
            lhs.uuid.11 == rhs.uuid.11 &&
            lhs.uuid.12 == rhs.uuid.12 &&
            lhs.uuid.13 == rhs.uuid.13 &&
            lhs.uuid.14 == rhs.uuid.14 &&
            lhs.uuid.15 == rhs.uuid.15
    }
}

extension UUID : CustomReflectable {
    public var customMirror: Mirror {
        let c : [(label: String?, value: Any)] = []
        let m = Mirror(self, children:c, displayStyle: .struct)
        return m
    }
}

extension UUID : _ObjectiveCBridgeable {
    @_semantics("convertToObjectiveC")
    public func _bridgeToObjectiveC() -> NSUUID {
        return reference
    }
    
    public static func _forceBridgeFromObjectiveC(_ x: NSUUID, result: inout UUID?) {
        if !_conditionallyBridgeFromObjectiveC(x, result: &result) {
            fatalError("Unable to bridge \(NSUUID.self) to \(self)")
        }
    }
    
    public static func _conditionallyBridgeFromObjectiveC(_ input: NSUUID, result: inout UUID?) -> Bool {
        result = UUID(reference: input)
        return true
    }
    
    public static func _unconditionallyBridgeFromObjectiveC(_ source: NSUUID?) -> UUID {
        var result: UUID? = nil
        _forceBridgeFromObjectiveC(source!, result: &result)
        return result!
    }
}

extension NSUUID : _HasCustomAnyHashableRepresentation {
    // Must be @nonobjc to avoid infinite recursion during bridging.
    @nonobjc
    public func _toCustomAnyHashable() -> AnyHashable? {
        return AnyHashable(UUID._unconditionallyBridgeFromObjectiveC(self))
    }
}

extension UUID : Codable {
    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let uuidString = try container.decode(String.self)
        
        guard let uuid = UUID(uuidString: uuidString) else {
            throw DecodingError.dataCorrupted(DecodingError.Context(codingPath: decoder.codingPath,
                                                                    debugDescription: "Attempted to decode UUID from invalid UUID string."))
        }
        
        self = uuid
    }
    
    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(self.uuidString)
    }
}
