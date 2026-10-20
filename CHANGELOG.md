# Motoko ECDSA changelog

## 8.0.2

* Bumped moc toolchain to 1.16.1 and pocket-ic to 15.0.0
* Bumped sha2 to 0.3.0 and core to 2.6.2
* Bumped dev dependencies test to 2.1.2 and bench-helper to 0.0.4
* Fixed deprecation warnings (`.vals()` -> `.values()`)

## 8.0.1

* Improved performance of EC operations
* 40% reduction for ECDSA verify on secp256k1
* 20% reduction for ECDSA verify on prime256v1

## 8.0.0

* Added docs
* Re-structured benches
* Bumped all dependencies
* Made PEM parsing more robust
