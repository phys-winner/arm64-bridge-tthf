#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Build the bridge and package a separately supplied, prepared apktool tree.
set -euo pipefail

if [[ $# -gt 1 || ( $# -eq 1 && "$1" != install ) ]]; then
  echo "Usage: $0 [install]" >&2
  exit 2
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && { pwd -W 2>/dev/null || pwd; })"
APK="${APK_SOURCE_DIR:-$ROOT/target_apk}"
LOADER="$ROOT/target_apk/loader_arm64"
BUILD="$ROOT/build/bridge"
OUT="$ROOT/build/tt_arm64"
CMAKE="${CMAKE:-cmake}"
JAVA="${JAVA:-java}"

: "${ANDROID_NDK_HOME:?Set ANDROID_NDK_HOME to the Android NDK directory}"
: "${BOOST_ROOT:?Set BOOST_ROOT to an unpacked Boost release}"
: "${APKTOOL_JAR:?Set APKTOOL_JAR to apktool.jar}"
: "${ZIPALIGN:?Set ZIPALIGN to the SDK zipalign executable}"
: "${APKSIGNER_JAR:?Set APKSIGNER_JAR to apksigner.jar}"
: "${SIGNING_KEY:?Set SIGNING_KEY to your APK signing key (.pk8)}"
: "${SIGNING_CERT:?Set SIGNING_CERT to your APK signing certificate (.pem)}"

for input in "$APK/AndroidManifest.xml" "$APK/apktool.yml" \
  "$APK/assets/arm32/libtinythief.so" "$APK/assets/arm32/libfmodex.so" \
  "$ANDROID_NDK_HOME/build/cmake/android.toolchain.cmake" \
  "$BOOST_ROOT/boost/version.hpp" "$APKTOOL_JAR" "$ZIPALIGN" \
  "$APKSIGNER_JAR" "$SIGNING_KEY" "$SIGNING_CERT"; do
  [[ -f "$input" ]] || { echo "Missing input: $input" >&2; exit 1; }
done

dynarmic_args=()
if [[ -n "${DYNARMIC_SOURCE_DIR:-}" ]]; then
  dynarmic_args+=("-DFETCHCONTENT_SOURCE_DIR_DYNARMIC=$DYNARMIC_SOURCE_DIR")
fi

"$CMAKE" -S "$LOADER" -B "$BUILD" -G Ninja \
  "-DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK_HOME/build/cmake/android.toolchain.cmake" \
  "-DBOOST_ROOT=$BOOST_ROOT" \
  -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-26 \
  -DCMAKE_BUILD_TYPE=Release -DTT_RELEASE_NO_LOGS=ON "${dynarmic_args[@]}"
"$CMAKE" --build "$BUILD" --parallel

strip_tools=("$ANDROID_NDK_HOME"/toolchains/llvm/prebuilt/*/bin/llvm-strip{,.exe})
strip_tool="${STRIP:-}"
if [[ -z "$strip_tool" ]]; then
  for candidate in "${strip_tools[@]}"; do
    if [[ -f "$candidate" ]]; then strip_tool="$candidate"; break; fi
  done
fi
[[ -n "$strip_tool" ]] || { echo "Set STRIP to the NDK llvm-strip executable" >&2; exit 1; }
mkdir -p "$APK/lib/arm64-v8a"
"$strip_tool" --strip-unneeded "$BUILD/libtinythief.so" -o "$APK/lib/arm64-v8a/libtinythief.so"

"$JAVA" -jar "$APKTOOL_JAR" b -f "$APK" -o "$OUT.apk"
"$ZIPALIGN" -f -P 16 4 "$OUT.apk" "${OUT}_aligned.apk"
"$JAVA" -jar "$APKSIGNER_JAR" sign --key "$SIGNING_KEY" --cert "$SIGNING_CERT" \
  --out "${OUT}_signed.apk" "${OUT}_aligned.apk"
"$JAVA" -jar "$APKSIGNER_JAR" verify "${OUT}_signed.apk"
"$ZIPALIGN" -c -P 16 4 "${OUT}_signed.apk"
printf 'Signed APK: %s\n' "${OUT}_signed.apk"

if [[ "${1:-}" == install ]]; then
  adb install -r "${OUT}_signed.apk"
fi
