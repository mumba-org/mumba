// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public struct Queue<Element: AnyObject> {
    
    internal private(set) var storage: ContiguousArray<Element> = []
    
    public init() {}

    public mutating func push(_ key: Element) {
      storage.append(key)
    }

    public func peek() -> Element? {
      return storage.first
    }

    public var isEmpty: Bool {
      return storage.isEmpty
    }

    @discardableResult
    public mutating func pop() -> Element? {
      guard !storage.isEmpty else { 
        return nil 
      }
      return storage.removeFirst()
    }

    public mutating func clear() {
      storage = []
    }

    public mutating func swap(_ other: inout Queue) {
      Swift.swap(&self.storage, &other.storage)
    }
}

extension Queue: Equatable {
    public static func ==(lhs: Queue, rhs: Queue) -> Bool {
        return lhs.count == rhs.count && lhs.storage.elementsEqual(rhs.storage, by: {(a, b) -> Bool in return a === b })
    }
}

extension Queue: Sequence {
    public struct Iterator: IteratorProtocol {

        private var queue: Queue<Element>
        fileprivate init(queue: Queue<Element>) {
            self.queue = queue
        }

        public mutating func next() -> Element? {
            return queue.pop()
        }
    }

    public func makeIterator() -> Iterator {
        return Iterator(queue: self)
    }
}

internal extension Queue {
    var count: Int {
      return storage.count
    }
}

extension Queue: CustomStringConvertible {
    public var description: String {
        return "Queue(count: \(self.underestimatedCount)): \(Array(self))"
    }
}

// Stack

public struct Stack<Element> {
    
    internal private(set) var storage: ContiguousArray<Element> = []
    
    public init() {}

    public mutating func push(_ key: Element) {
      storage.append(key)
    }

    public func peek() -> Element? {
      return storage.last
    }

    public var isEmpty: Bool {
      return storage.isEmpty
    }

    @discardableResult
    public mutating func pop() -> Element? {
      guard !storage.isEmpty else { 
        return nil 
      }
      return storage.removeLast()
    }

    public mutating func clear() {
      storage = []
    }

    public mutating func swap(_ other: inout Stack) {
      Swift.swap(&self.storage, &other.storage)
    }
}

//extension Stack: Equatable {
extension Stack {
  public static func ==<T: SignedNumeric>(lhs: Stack<T>, rhs: Stack<T>) -> Bool {
    return lhs.count == rhs.count && lhs.storage.elementsEqual(rhs.storage, by: { return $0 == $1 })
  }
}
//}

extension Stack: Sequence {
    public struct Iterator: IteratorProtocol {

        private var stack: Stack<Element>
        fileprivate init(stack: Stack<Element>) {
            self.stack = stack
        }

        public mutating func next() -> Element? {
            return stack.pop()
        }
    }

    public func makeIterator() -> Iterator {
        return Iterator(stack: self)
    }
}

internal extension Stack {
    var count: Int {
      return storage.count
    }
}

extension Stack: CustomStringConvertible {
    public var description: String {
        return "Stack(count: \(self.underestimatedCount)): \(Array(self))"
    }
}