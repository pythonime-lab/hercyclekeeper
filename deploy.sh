#!/usr/bin/env bash
set -e

VERSION="v$(date +%Y%m%d)"
SW="period-tracker/service-worker.js"
HTML="period-tracker/index.html"

# Bump CACHE_VERSION in service worker
sed -i "s/const CACHE_VERSION = \"v[0-9]*\"/const CACHE_VERSION = \"$VERSION\"/" "$SW"
echo "CACHE_VERSION → $VERSION"

# Bump ?v= query params on CSS and JS in period-tracker index.html
sed -i "s/?v=v[0-9]*/?v=$VERSION/g; s/?v=[0-9]*/?v=$VERSION/g" "$HTML"
echo "Asset versions → $VERSION"

# Sync ASSETS_TO_CACHE versioned URLs with the new ?v= in index.html
sed -i "s|style\.css?v=v[0-9]*|style.css?v=$VERSION|g; \
        s|style\.css?v=[0-9]*|style.css?v=$VERSION|g; \
        s|style-desktop\.css?v=v[0-9]*|style-desktop.css?v=$VERSION|g; \
        s|style-desktop\.css?v=[0-9]*|style-desktop.css?v=$VERSION|g; \
        s|script\.js?v=v[0-9]*|script.js?v=$VERSION|g; \
        s|script\.js?v=[0-9]*|script.js?v=$VERSION|g; \
        s|indexeddb-storage\.js?v=v[0-9]*|indexeddb-storage.js?v=$VERSION|g; \
        s|indexeddb-storage\.js?v=[0-9]*|indexeddb-storage.js?v=$VERSION|g" "$SW"
echo "ASSETS_TO_CACHE synced → $VERSION"

firebase deploy
