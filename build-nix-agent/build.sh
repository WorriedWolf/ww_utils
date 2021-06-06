#!/usr/bin/env bash
BASE_FOLDER=$(dirname "$(realpath -s "{BASH_SOURCE[0]}")")
echo "base folder: $BASE_FOLDER"
APP_FOLDER="$BASE_FOLDER/dist/opt/ww-capture-agent"
SRC_FOLDER="$BASE_FOLDER/../capture"
APP_FILENAME="app.py"
PACKAGE_NAME="$(basename "$APP_FOLDER").deb"

APP_SCRIPT_SRC="$SRC_FOLDER/$APP_FILENAME"
APP_SCRIPT_DIST="$APP_FOLDER/$APP_FILENAME"

if [ -f "$APP_SCRIPT_DIST" ]; then
    echo "$APP_SCRIPT_DIST exists"
else
    echo "$APP_SCRIPT_DIST does not exist. Linking now..."
    ln "$APP_SCRIPT_SRC" "$APP_SCRIPT_DIST"
fi

dpkg-deb --build dist
mv dist.deb "$PACKAGE_NAME"
