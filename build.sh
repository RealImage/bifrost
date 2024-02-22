#!/bin/bash

set -euo pipefail

app="$(basename "$PWD")"

pushd web
npm ci
popd

go install golang.org/x/tools/cmd/stringer@latest
go generate -x ./...

rm -rf bin
mkdir -p bin
pushd bin
trap popd EXIT

gobuild() {
  mkdir -p "$1/$2"
  pushd "$1/$2"
  env GOOS="$1" GOARCH="$2" go build ../../../cmd/...
  case "$1" in
    "windows")
      zip ../../"${app}_${1}_${2}".zip ./*.exe
      ;;
    "linux")
      tar -c --zstd --numeric-owner \
        -f ../../"${app}_${1}_${2}".tar.zst .
      ;;
    *)
      tar -c --numeric-owner \
        -f ../../"${app}_${1}_${2}".tar.gz .
      ;;
  esac
  rm ./*
  popd
  rmdir "${1:?}/${2:?}" "${1:?}"
}

export CGO_ENABLED=0

# Binaries for all platforms
gobuild linux amd64
gobuild linux arm64
gobuild darwin amd64
gobuild darwin arm64
gobuild windows amd64

# AWS Lambda zip file
GOOS=linux GOARCH=arm64 go build -o bootstrap -tags lambda.norpc ../cmd/bf
zip bifrost_lambda_function.zip bootstrap
rm bootstrap

sha1sum ./*.tar.* ./*.zip >sha1sums.txt
