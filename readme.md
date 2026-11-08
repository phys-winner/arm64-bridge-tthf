# Tiny Thief ARM64 Bridge

An ARM32-to-ARM64 compatibility bridge for Tiny Thief on Android, powered by Dynarmic.

This repository contains the native bridge and build/asset-processing scripts. It does not include the game, its Java/Smali code, assets, original native libraries, APKs, signing keys, or vendored dependencies. Supply your own legally obtained game files and a prepared apktool source tree.

## How it works

The bridge builds as `libtinythief.so` for `arm64-v8a`. It loads the original ARM32 game and FMOD libraries from APK assets and executes their ARMv7 code through Dynarmic's A32 frontend. JNI, OpenGL ES, OpenSL ES, and supported C/POSIX calls are forwarded to Android host implementations.

The implementation includes an ELF loader, guest memory and thread handling, JNI object translation, API thunks, and game-specific compatibility patches. New ARM64 ELF segments use 16 KiB alignment. Alignment alone does not establish compatibility on every device.

This is a game-specific bridge for the Tiny Thief 1.2.1 inputs used during development, not a general Android ARM32 runtime. Some patches depend on guest binary offsets. Other game versions require review and testing. A source build is not evidence of successful gameplay on a particular device.

## Repository layout

- `target_apk/loader_arm64/src/`: bridge C++ sources and headers.
- `target_apk/loader_arm64/CMakeLists.txt`: Android native build configuration.
- `target_apk/loader_arm64/pack.sh`: build, package, align, sign, and optionally install a prepared game tree.
- `target_apk/crypt_assets.py`: decrypt or encrypt the game's SWF/XML assets in place.

The root `.gitignore` uses an allowlist. Game files, local configuration, dependencies, build products, and research notes stay outside version control.

## Dependencies

Install dependencies separately; none are committed here.

| Dependency | Version / purpose |
| --- | --- |
| Android NDK | Tested toolchain baseline: 27.2.12479018; ARM64 target, API 26 |
| CMake and Ninja | CMake 3.22 or newer; Ninja build generator |
| [Boost](https://www.boost.org/) | 1.83 or newer; unpacked headers, selected with `BOOST_ROOT` |
| [Dynarmic](https://github.com/azahar-emu/dynarmic) | Pinned to `e77b1ba0b7da7cbe93021b01a663acfe7c4dd516` |
| Java and [Apktool](https://apktool.org/) | APK packaging; existing tree was prepared with Apktool 3.0.3 |
| Android SDK Build Tools | `zipalign` and `apksigner.jar` with 16 KiB alignment support |
| Bash | Git Bash on Windows, or Bash on Linux/macOS |
| Python and PyCryptodome | Only needed for `crypt_assets.py`; PyCryptodome 3.23.0 was used during development |

CMake fetches the pinned Dynarmic revision and its upstream submodules into the build directory. To use an existing checkout instead, initialize its submodules and supply `FETCHCONTENT_SOURCE_DIR_DYNARMIC`. Dynarmic's own dependencies remain external to this repository.

## Build the native bridge

From the repository root, with `cmake` and `ninja` on `PATH`, set `ANDROID_NDK_HOME` and `BOOST_ROOT` in your shell to your installed dependency directories, then run:

```bash
cmake -S target_apk/loader_arm64 -B build/bridge -G Ninja \
  "-DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK_HOME/build/cmake/android.toolchain.cmake" \
  "-DBOOST_ROOT=$BOOST_ROOT" \
  -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-26 \
  -DCMAKE_BUILD_TYPE=Release -DTT_RELEASE_NO_LOGS=ON
cmake --build build/bridge --parallel
```

The output is `build/bridge/libtinythief.so`. For an offline build, add `-DFETCHCONTENT_SOURCE_DIR_DYNARMIC="$DYNARMIC_SOURCE_DIR"` to configure, using a checkout of the pinned revision with its submodules already initialized. Boost is never downloaded automatically.

## Package a prepared game tree

A fresh clone cannot create a playable APK by itself. The packaging script expects a separately prepared apktool tree containing the matching Java/JNI integration, resources, game data, and these original ARM32 libraries:

```text
assets/arm32/libtinythief.so
assets/arm32/libfmodex.so
```

Merely decoding an arbitrary original APK does not reproduce the existing port's Java/Smali, resource, or SWF changes. Those game-derived files are intentionally excluded from this repository. The package name and JNI classes must match those registered in `jni_bridge.cpp`.

Set these environment variables locally before running the script; do not commit their values:

| Variable | Value |
| --- | --- |
| `ANDROID_NDK_HOME` | Android NDK directory |
| `BOOST_ROOT` | Unpacked Boost directory containing `boost/version.hpp` |
| `APKTOOL_JAR` | Apktool JAR file |
| `ZIPALIGN` | SDK `zipalign` executable |
| `APKSIGNER_JAR` | SDK `apksigner.jar` file |
| `SIGNING_KEY` | Your APK signing private key in PKCS#8 `.pk8` format |
| `SIGNING_CERT` | Matching X.509 PEM certificate |
| `APK_SOURCE_DIR` | Optional prepared apktool directory; defaults to `target_apk` |
| `DYNARMIC_SOURCE_DIR` | Optional existing Dynarmic checkout; otherwise CMake fetches it |
| `CMAKE`, `JAVA`, `STRIP` | Optional executable overrides; CMake/Java default to `PATH`, strip comes from the NDK |
| `ANDROID_SERIAL` | Optional adb device selection; required to disambiguate multiple devices |

```bash
bash target_apk/loader_arm64/pack.sh
# Explicit opt-in installation:
bash target_apk/loader_arm64/pack.sh install
```

The script replaces the prepared tree's `lib/arm64-v8a/libtinythief.so`, forces Apktool to rebuild, and writes `build/tt_arm64_signed.apk`. It verifies the APK signature and ZIP alignment. Use the same signing certificate as an installed build if you need to update it without uninstalling. No APK signing key or certificate is provided.

On Windows, use Git Bash and shell-compatible paths for your installed tools. Keep machine-specific values in your local environment.

## Asset encryption utility

```bash
python -m pip install pycryptodome==3.23.0
python target_apk/crypt_assets.py decrypt target_apk/assets
python target_apk/crypt_assets.py encrypt target_apk/assets
```

This utility modifies SWF/XML files in place. Back up your assets first. It uses the game's fixed AES-256-CBC format with a zero IV and PKCS#7 padding; this is legacy format compatibility, not a recommended encryption scheme. Already prepared assets do not need this step for packaging.

## License

The bridge and scripts in this repository are licensed under **GNU GPL version 3 or, at your option, any later version** (`GPL-3.0-or-later`). See [LICENSE](LICENSE) for the complete terms.

External dependencies retain their respective licenses, including Dynarmic's ISC license and Boost's Boost Software License 1.0. Preserve the required third-party notices when distributing builds. This project's license grants no rights to the proprietary game, FMOD, or other game-supplied content. This is an independent compatibility project, unaffiliated with the game's creators or publishers.
