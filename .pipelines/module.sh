#!/bin/bash -e
# Copyright (c) 2023 Microsoft Corporation.
# Licensed under the MIT License.

set -x
set -e

BASE_KERNEL=linux-5.11.1

wget -q https://cdn.kernel.org/pub/linux/kernel/v5.x/${BASE_KERNEL}.tar.xz
tar xf ${BASE_KERNEL}.tar.xz

pushd ${BASE_KERNEL}

make defconfig
./scripts/kconfig/merge_config.sh .config ../.config/apron-kconfig-fragment
make scripts prepare modules_prepare
cp ../.config/Module.symvers .
make M=../module -j$(nproc)

popd
