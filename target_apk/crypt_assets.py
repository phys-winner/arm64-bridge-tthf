#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Tiny Thief asset crypto: decrypt/encrypt *.swf and *.xml under assets/.

AES-256-CBC, zero IV, PKCS7 padding.
Key from libtinythief.so sub_72BE8: first 32 bytes of
"ypWnks9F4jrKjs1cQv3Tw32fi7epEvlutrue".
Native loader (assets:// scheme) decrypts only .swf and .xml; everything
else (mp3, png, ...) is stored plain.
"""
import argparse
from pathlib import Path

from Crypto.Cipher import AES

KEY = b"ypWnks9F4jrKjs1cQv3Tw32fi7epEvlu"
IV = b"\x00" * 16
EXTS = {".swf", ".xml"}
PLAIN_MAGIC = {".swf": (b"FWS", b"CWS", b"ZWS"), ".xml": b"<"}


def is_plain(data: bytes, ext: str) -> bool:
    if ext == ".xml":
        if data.startswith(b"\xef\xbb\xbf"):
            data = data[3:]  # UTF-8 BOM
        data = data.lstrip(b" \t\r\n")
    return data.startswith(PLAIN_MAGIC[ext])


def decrypt(data: bytes) -> bytes:
    if len(data) % 16:
        raise ValueError(f"length {len(data)} not multiple of 16")
    raw = AES.new(KEY, AES.MODE_CBC, IV).decrypt(data)
    pad = raw[-1]
    if not 1 <= pad <= 16 or raw[-pad:] != bytes([pad]) * pad:
        raise ValueError("bad PKCS7 padding")
    return raw[:-pad]


def encrypt(data: bytes) -> bytes:
    pad = 16 - len(data) % 16
    return AES.new(KEY, AES.MODE_CBC, IV).encrypt(data + bytes([pad]) * pad)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("action", choices=["decrypt", "encrypt"])
    ap.add_argument("assets", nargs="?", type=Path, default=Path("assets"),
                    help="assets dir (default: ./assets)")
    args = ap.parse_args()

    n = skipped = errors = 0
    for p in args.assets.rglob("*"):
        if not p.is_file() or p.suffix.lower() not in EXTS:
            continue
        data = p.read_bytes()
        ext = p.suffix.lower()
        if args.action == "decrypt":
            if is_plain(data, ext):
                skipped += 1
                continue
            try:
                data = decrypt(data)
            except ValueError as e:
                print(f"ERROR {p}: {e}")
                errors += 1
                continue
        else:
            if not is_plain(data, ext):
                skipped += 1
                continue
            data = encrypt(data)
        p.write_bytes(data)
        n += 1
        print(p)
    print(f"{args.action}ed {n} files, skipped {skipped}, errors {errors}")


if __name__ == "__main__":
    main()
