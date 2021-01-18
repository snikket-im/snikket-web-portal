#!/bin/bash
set -euo pipefail
# usage: import-icons.sh ROOT ICONLIST FLAVOR SVGOUT
#
# positional arguments:
#
#   ROOT      path to the checkout of https://github.com/google/material-design-icons
#   ICONLIST  path to the icons.list file in the snikket-web-portal repository
#   FLAVOR    one of '', 'round', 'sharp', 'outlined', 'twoshade'
#   SVGOUT    path to the newly created SVG file
root="$1/src"
iconlist_file="$2"
flavor="$3"
output_file="$4"

printf '<svg aria-hidden="true" style="position: absolute; width: 0; height: 0; overflow: hidden;" version="1.1" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">\n<defs>\n' > "$output_file"
printf '<!-- These icons are sourced from Google’s Material Icons set,\nlicensed under the terms of the Apache 2.0 License -->\n' >> "$output_file"
printf '<!DOCTYPE html>\n<html><body>'

IFS=$'\n'
while read -r icondef; do
  path="$(cut -d':' -f1 <<<"$icondef")"
  name="$(cut -d':' -f2 <<<"$icondef")"
  src_path="$path/materialicons$flavor"
  if [ ! -d "$root/$src_path" ]; then
    printf 'warning: %q not found in flavor %q, falling back to default\n' "$path" "$flavor" >&2
    src_path="$path/materialicons"
  fi
  src_svg="$src_path/24px.svg"
  if [ ! -f "$root/$src_svg" ]; then
    printf 'error: failed to find source file for %q: %s: does not exist\n' "$path" "$src_svg" >&2
  fi
  printf '<!-- from: %s -->\n' "$src_svg" >> "$output_file"
  printf '<symbol id="icon-%s" viewBox="0 0 24 24">\n' "$name" >> "$output_file"
  xpath -q -e '/svg/*' "$root/$src_svg" >> "$output_file"
  printf '</symbol>\n' >> "$output_file"

  printf '<p><svg><use xlink:href="#icon-%s"></use></svg></p>\n' "$name"
done < "$iconlist_file"
printf '</defs></svg>\n' >> "$output_file"
