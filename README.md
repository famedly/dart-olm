# olm Dart Bindings

## Architecture
[Visualization](https://famedly.gitlab.io/libraries/dart-olm/#architecture).

## Using dart-olm
Beside dart-olm, the olm library itself needs to be available.
- On Flutter for Android and iOS, depend on [flutter_olm](https://pub.dev/packages/flutter_olm).
- On (Flutter) Web, add olm.js and include it with a script tag. We provide an [olm fork](https://gitlab.com/famedly/libraries/olm) to support all methods and unlimited memory. Use either an [upstream JS build](https://packages.matrix.org/npm/olm/) or [our fork's JS build](https://gitlab.com/famedly/libraries/olm/-/jobs/artifacts/master/download?job=build_js).
- For Windows, we provide a [32-bit DLL](https://gitlab.com/famedly/libraries/olm/-/jobs/artifacts/master/file/libolm.dll?job=build_win32) and a [64-bit DLL](https://gitlab.com/famedly/libraries/olm/-/jobs/artifacts/master/file/libolm.dll?job=build_win64).
- On Linux, some distributions provide libolm (`apt install libolm3` for Debian Bullseye, `pacman -S libolm` for Archlinux). Otherwise, `scripts/prepare_native.sh` compiles libolm if it is not installed. To use it, set the environment as in `scripts/test.sh`.
- On MacOS, install it with Homebrew (`brew install libolm`).

## For dart-olm developers
Look at or use the scripts `scripts/prepare.sh` and `scripts/test.sh`.
