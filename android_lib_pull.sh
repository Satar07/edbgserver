#!/bin/bash

PKG_NAME=$1
SYSROOT="./android_sysroot"
TEMP_TAR="/data/local/tmp/sysroot_temp.tar"

PATHS_TO_PULL=(
    "/system/lib64"
    "/system/bin"
    "/vendor/lib64"
    "/apex/com.android.runtime"
    "/apex/com.android.art"
    "/apex/com.android.tethering"
)

adb get-state 1>/dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "adb not connected"
    exit 1
fi

APP_LIB_PATHS=()
if [ ! -z "$PKG_NAME" ]; then

    APK_PATH=$(adb shell pm path "$PKG_NAME" 2>/dev/null | head -n 1 | cut -d : -f 2)

    if [ -z "$APK_PATH" ]; then
        echo "cannot find'$PKG_NAME'"
        echo "------------------------------------------------"
        adb shell pm list package -3 | cut -d : -f 2
        exit 1
    fi

    APP_BASE_DIR=$(dirname "$APK_PATH")
    LIB_EXISTS=$(adb shell "ls -d $APP_BASE_DIR/lib 2>/dev/null")
    if [ ! -z "$LIB_EXISTS" ]; then
        APP_LIB_PATHS+=("$APP_BASE_DIR/lib")
        APP_LIB_PATHS+=("$APP_BASE_DIR/oat")
    fi
fi

TOTAL_PATHS=("${PATHS_TO_PULL[@]}" "${APP_LIB_PATHS[@]}")
adb shell "tar -cvf $TEMP_TAR ${TOTAL_PATHS[*]} 2>/dev/null"
mkdir -p "$SYSROOT"
adb pull "$TEMP_TAR" "$SYSROOT/sysroot.tar"
tar -xvf "$SYSROOT/sysroot.tar" -C "$SYSROOT"
rm "$SYSROOT/sysroot.tar"
adb shell rm "$TEMP_TAR"

echo "------------------------------------------------"
echo "[*] pwndbg> set sysroot $(realpath "$SYSROOT")"
