#!/bin/bash
set -e

# Clean nix environment for iOS cross-compilation
unset LIBRARY_PATH
unset LD_LIBRARY_PATH
unset DYLD_LIBRARY_PATH
unset NIX_LDFLAGS
unset NIX_CFLAGS_COMPILE
unset SDKROOT

# Pin iOS deployment target so ring/cc-rs doesn't inherit a wrong version from Nix SDK
export IPHONEOS_DEPLOYMENT_TARGET="${IPHONEOS_DEPLOYMENT_TARGET:-15.1}"

echo "Building for iOS device (aarch64-apple-ios)..."
cargo build --target aarch64-apple-ios --release

echo "Building for iOS simulator (aarch64-apple-ios-sim)..."
SDKROOT=$(xcrun --sdk iphonesimulator --show-sdk-path) \
cargo build --target aarch64-apple-ios-sim --release

echo "Generating Swift bindings..."
cargo run --bin uniffi-bindgen -- generate \
    --library target/aarch64-apple-ios/release/libtlsn_mobile.a \
    --language swift \
    --out-dir target/swift

echo "Creating XCFramework..."
rm -rf target/TlsnMobile.xcframework

# Create module map. Nest the header + modulemap under a module-named subdir
# (tlsn_mobileFFI/) instead of the Headers root. A static-library xcframework with
# Headers/module.modulemap gets copied to BUILT_PRODUCTS_DIR/include/module.modulemap;
# if the app links a SECOND such xcframework (e.g. XMTP's LibXMTPSwiftFFI), both
# target the same include/module.modulemap and the build fails with
# "Multiple commands produce .../include/module.modulemap". Nesting moves ours to
# include/tlsn_mobileFFI/module.modulemap so they no longer collide.
# Clean any stale root-level headers from a previous run — a leftover
# target/headers/module.modulemap ends up at the xcframework Headers root and collides
# with a second FFI xcframework (XMTP) at include/module.modulemap. Only the NESTED
# tlsn_mobileFFI/module.modulemap may survive.
rm -rf target/headers
mkdir -p target/headers/tlsn_mobileFFI
cp target/swift/tlsn_mobileFFI.h target/headers/tlsn_mobileFFI/
cp target/swift/tlsn_mobileFFI.modulemap target/headers/tlsn_mobileFFI/module.modulemap

# Create XCFramework with both architectures
xcodebuild -create-xcframework \
    -library target/aarch64-apple-ios/release/libtlsn_mobile.a \
    -headers target/headers \
    -library target/aarch64-apple-ios-sim/release/libtlsn_mobile.a \
    -headers target/headers \
    -output target/TlsnMobile.xcframework

echo "Copying to Expo module..."
EXPO_MODULE_DIR="../../app/mobile/modules/tlsn-native"

# Copy Swift bindings
cp target/swift/tlsn_mobile.swift "$EXPO_MODULE_DIR/ios/"

# Copy XCFramework
rm -rf "$EXPO_MODULE_DIR/ios/TlsnMobile.xcframework"
cp -R target/TlsnMobile.xcframework "$EXPO_MODULE_DIR/ios/"

echo "Done! Output:"
echo "  - XCFramework: target/TlsnMobile.xcframework"
echo "  - Swift bindings: target/swift/tlsn_mobile.swift"
echo "  - Copied to: $EXPO_MODULE_DIR/ios/"
