#!/bin/bash
# Build ff_antiban.so — Android ARM64
# Yêu cầu: NDK r25+, Dobby prebuilt

set -e

NDK="${ANDROID_NDK:-$HOME/android-ndk-r25c}"
CLANG="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android29-clang++"

# Thư mục Dobby (clone + build trước)
DOBBY_INC="./dobby/include"
DOBBY_LIB="./dobby/libdobby.a"

if [ ! -f "$CLANG" ]; then
    echo "ERROR: NDK không tìm thấy tại $NDK"
    echo "Download NDK r25c: https://developer.android.com/ndk/downloads"
    exit 1
fi

if [ ! -f "$DOBBY_LIB" ]; then
    echo "ERROR: libdobby.a không tìm thấy"
    echo "Build Dobby:"
    echo "  git clone https://github.com/jmpews/Dobby"
    echo "  cd Dobby && mkdir build && cd build"
    echo "  cmake .. -DCMAKE_TOOLCHAIN_FILE=$NDK/build/cmake/android.toolchain.cmake \\"
    echo "           -DANDROID_ABI=arm64-v8a \\"
    echo "           -DANDROID_PLATFORM=android-29"
    echo "  make -j4"
    exit 1
fi

echo "Building ff_antiban.so..."

"$CLANG" \
    -shared \
    -fPIC \
    -O2 \
    -std=c++17 \
    -I"$DOBBY_INC" \
    "$DOBBY_LIB" \
    -llog \
    -o ff_antiban.so \
    ff_antiban.cpp

echo "Done: ff_antiban.so"
echo ""
echo "Nhét vào APK:"
echo "  cp ff_antiban.so ff_unpacked/lib/arm64-v8a/"
echo "  patchelf --add-needed ff_antiban.so ff_unpacked/lib/arm64-v8a/libil2cpp.so"
