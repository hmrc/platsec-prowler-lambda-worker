#!/bin/bash
set -euox pipefail

PROWLER_VERSION='2.4.1'

rm -rf prowler.zip
rm -rf src/platsec/compliance/lib/prowler/*
rm -rf "prowler-${PROWLER_VERSION}"

wget "https://github.com/toniblyx/prowler/archive/refs/tags/${PROWLER_VERSION}.zip" -O prowler.zip
unzip prowler.zip

mkdir -p src/platsec/compliance/lib/prowler
mv "prowler-${PROWLER_VERSION}/"* src/platsec/compliance/lib/prowler
rm -rf prowler.zip "prowler-${PROWLER_VERSION}"
