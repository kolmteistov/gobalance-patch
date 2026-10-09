#!/usr/bin/env python3
# get_desc.py — fetch a v3 hidden service descriptor through a Tor control
# port and save it to a file.
#
# This is exactly what every Tor client does (via the HSDirs) whenever
# someone visits an onion site — i.e. the descriptor is PUBLIC data, and
# this script needs no access to the service itself.
#
# Usage (requires `apt install python3-stem` and a running Tor with a ControlPort):
#   python3 get_desc.py <onion address> [--port 9052] [-o descriptor.txt]

import argparse

from stem.control import Controller


def main():
    ap = argparse.ArgumentParser(
        description="Fetch a v3 HS descriptor via the Tor control port")
    ap.add_argument("onion", help="56-char v3 onion address (with or without .onion)")
    ap.add_argument("--port", type=int, default=9052,
                    help="Tor control port (default: 9052)")
    ap.add_argument("-o", "--out", default="descriptor.txt",
                    help="output file (default: descriptor.txt)")
    args = ap.parse_args()

    onion = args.onion.strip().lower()
    if onion.endswith(".onion"):
        onion = onion[:-len(".onion")]

    with Controller.from_port(port=args.port) as controller:
        controller.authenticate()
        desc = controller.get_hidden_service_descriptor(onion)
        text = str(desc)

    with open(args.out, "w") as f:
        f.write(text)
    print("[+] %d bytes saved to %s" % (len(text), args.out))


if __name__ == "__main__":
    main()
