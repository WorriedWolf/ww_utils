#!/usr/bin/env bash
BASE_FOLDER=$(dirname "$(realpath -s "{BASH_SOURCE[0]}")")
echo "base folder: $BASE_FOLDER"
APP_FOLDER="$BASE_FOLDER/src/opt/ww-capture-agent"
ORIGIN_FOLDER="$BASE_FOLDER/../capture"
ORIGIN_FOLDER_DIST="$ORIGIN_FOLDER/dist"
APP_FILENAME="app"
PACKAGE_NAME="$(basename "$APP_FOLDER").deb"

APP_SCRIPT_ORIGIN="$ORIGIN_FOLDER_DIST/$APP_FILENAME"
APP_SCRIPT_DIST="$APP_FOLDER/$APP_FILENAME"

if [ -f "$APP_SCRIPT_DIST" ]; then
    echo "$APP_SCRIPT_DIST exists. Deleting..."
    rm "$APP_SCRIPT_DIST"
fi

echo "building with pyinstaller"
cd "$ORIGIN_FOLDER"
pyinstaller --onefile app.py
cd "$BASE_FOLDER"
echo "Copying $APP_SCRIPT_ORIGIN to $APP_SCRIPT_DIST..."
cp "$APP_SCRIPT_ORIGIN" "$APP_SCRIPT_DIST"

dpkg-deb --build src
mv src.deb "$PACKAGE_NAME"
