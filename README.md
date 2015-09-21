# OneTimePad

Bridging for CommonCrypto in the Swiftiest way possible (until Apple adds one, at least).

## Here be dragons!

This repository is a work-in-progress! Not all of CommonCrypto has been audited and/or wrapped yet.

## Bridging Technique

OneTimePad imports `libCommonCrypto` without using a static path to the Xcode app bundle. Through the use of custom-audited headers and a [private module map](http://clang.llvm.org/docs/Modules.html#private-module-map-files), the C headers are not leaked to users of this framework. Inspiration for this technique can be found [here](https://github.com/danieleggert/mixed-swift-objc-framework), and the details necessary for doing this yourself can be found [in this Gist](https://gist.github.com/zwaldowski/dcd218ae7334fba5833d).

This technique has only been tested with private C and Objective-C code, and has not been tested in privatizing Swift code. Do take note, if doing this with your own code, that this technique can cause unexpected symbol clashes with other frameworks in an app because C still has a global namespace. (With the libraries provided by Apple, such as `libCommonCrypto`, `libsqlite`, etc. this isn't a problem)

## License

OneTimePad is available with no warranty for use or misuse. See `LICENSE` for more details.
