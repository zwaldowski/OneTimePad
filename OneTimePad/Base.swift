//
//  Base.swift
//  OneTimePad
//
//  Created by Zachary Waldowski on 9/7/15.
//  Copyright © 2015 Zachary Waldowski. All rights reserved.
//

import CommonCryptoShim.Private

protocol EmptyInit {
    init()
}

extension COpaquePointer: EmptyInit {}
extension Int: EmptyInit {}

final class CCPointer {
    typealias Destructor = @convention(c) COpaquePointer -> CCStatus
    
    private(set) var rawValue: COpaquePointer = nil
    let destructor: Destructor
    
    init(destructor: Destructor, @noescape _ initializer: UnsafeMutablePointer<COpaquePointer> -> CCStatus) throws {
        self.destructor = destructor
        try withUnsafeMutablePointer(&rawValue) { ptr in
            try CCPointer.call { initializer(ptr) }
        }
    }
    
    static func call(@noescape fn: Void -> CCStatus) throws {
        switch fn() {
        case .CCSuccess:
            break
        case let error:
            throw CryptoError(rawValue: error.rawValue)!
        }
    }
    
    func call(@noescape fn: COpaquePointer -> CCStatus) throws {
        try CCPointer.call { fn(rawValue) }
    }
    
    func call<Return: EmptyInit>(@noescape fn: (COpaquePointer, UnsafeMutablePointer<Return>) -> CCStatus) throws -> Return {
        var ret = Return()
        try withUnsafeMutablePointer(&ret) { ptr in
            try CCPointer.call { fn(rawValue, ptr) }
        }
        return ret
    }
    
    deinit {
        if rawValue != nil {
            destructor(rawValue)
        }
    }
}
