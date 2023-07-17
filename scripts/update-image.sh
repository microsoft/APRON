#!/bin/bash

set -x

DEVICE_IP=10.0.0.98
INITRAMFS=initrd.img-5.11.1-apron
MNTPOINT=mnt
OLDSTORAGE=apron.img.old
STORAGE=apron.img
HASHDEV=${STORAGE}.hash
METADEV=${STORAGE}.meta
ROOTHASH=apron.roothash
UUID=85cbd85a-74e6-4099-8ecf-ec0d9a0104b3

mkdir -p $MNTPOINT
scp ${DEVICE_IP}:/boot/$INITRAMFS .
sudo mount $STORAGE $MNTPOINT
sudo cp $INITRAMFS $MNTPOINT/boot/
sudo umount $MNTPOINT
zerofree $STORAGE
veritysetup format $STORAGE $HASHDEV --uuid $UUID > $ROOTHASH
./apron-dedup $STORAGE > $METADEV
scp $HASHDEV $ROOTHASH $METADEV ${DEVICE_IP}:~/apron

cp apron_cfg_template.sh apron_cfg.sh
SALT=$(cat $ROOTHASH | grep 'Salt' | awk '{ print $2 }')
DIGEST=$(cat $ROOTHASH | grep 'Root' | awk '{ print $3 }')
echo "SALT=${SALT}" >> apron_cfg.sh
echo "DIGEST=${DIGEST}" >> apron_cfg.sh
