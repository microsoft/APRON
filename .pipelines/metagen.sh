#!/bin/bash -e
# Copyright (c) 2023 Microsoft Corporation.
# Licensed under the MIT License.

set -x
set -e

pushd metagen
cargo build
popd

pushd extra

pushd corrupt-image
make
popd

pushd check-image-zero
make
popd

popd
