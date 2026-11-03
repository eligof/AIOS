#!/usr/bin/env bash
# shellcheck disable=SC2034
# AIOS live and install medium (spec §6.1): archiso's releng profile (archiso 92), UEFI only,
# booted by systemd-boot. `make iso-build` turns this directory into iso-build/.

iso_name="aios"
iso_label="AIOS_$(date --date="@${SOURCE_DATE_EPOCH:-$(date +%s)}" +%Y%m)"
iso_publisher="AIOS"
iso_application="AIOS live and install medium"
iso_version="$(date --date="@${SOURCE_DATE_EPOCH:-$(date +%s)}" +%Y.%m.%d)"
install_dir="aios"
bootmodes=('uefi.systemd-boot')
pacman_conf="pacman.conf"
airootfs_image_type="squashfs"
airootfs_image_tool_options=('-comp' 'xz' '-Xbcj' 'x86' '-b' '1M' '-Xdict-size' '1M')
file_permissions=(
  ["/etc/shadow"]="0:0:400"
  ["/root"]="0:0:750"
  ["/usr/local/bin/aios-install"]="0:0:755"
)
