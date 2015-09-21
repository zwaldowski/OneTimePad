//
//  Base.swift
//  OneTimePad
//
//  Created by Zachary Waldowski on 9/7/15.
//  Copyright © 2015 Zachary Waldowski. All rights reserved.
//

import CommonCryptoShim.Private

protocol UnsafeInit {
    init()
}

extension COpaquePointer: UnsafeInit {}
extension Int: UnsafeInit {}

protocol CCPointer {
    var rawPointer: COpaquePointer { get }
}

extension CCPointer {
    
    static func call(@noescape fn: Void -> CCStatus) throws {
        switch fn() {
        case CCSuccess:
            break
        case let error:
            throw CryptoError(error)
        }
    }
    
    func call(@noescape fn: COpaquePointer -> CCStatus) throws {
        try self.dynamicType.call { fn(rawPointer) }
    }
    
    func call<Return: UnsafeInit>(@noescape fn: (COpaquePointer, UnsafeMutablePointer<Return>) -> CCStatus) throws -> Return {
        var ret = Return()
        try withUnsafeMutablePointer(&ret) { ptr in
            try self.dynamicType.call { fn(rawPointer, ptr) }
        }
        return ret
    }
    
}
