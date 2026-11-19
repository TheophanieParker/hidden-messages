"""
Hidden Messages
A Python experiment in image steganography.

Hides and retrieves UTF-8 text in PNG images using
least-significant-bit (LSB) encoding.

Uses only Python's standard library.
"""

import argparse
import struct
import zlib
from pathlib import Path


SIGNATURE = b"\x89PNG\r\n\x1a\n"
MAGIC = b"HMSG"


def chunk(kind, data):
    body = kind + data
    checksum = zlib.crc32(body) & 0xFFFFFFFF
    return struct.pack(">I", len(data)) + body + struct.pack(">I", checksum)


def make_image(path, width=256, height=256):
    """Create a sample RGB PNG image."""
    rows = []

    for y in range(height):
        row = bytearray([0])

        for x in range(width):
            red = (x * 255) // (width - 1)
            green = (y * 255) // (height - 1)
            blue = 160
            row.extend((red, green, blue))

        rows.append(bytes(row))

    raw = b"".join(rows)

    png = (
        SIGNATURE
        + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(raw))
        + chunk(b"IEND", b"")
    )

    Path(path).write_bytes(png)


def read_image(path):
    """Read an 8-bit RGB PNG with standard scanline filters."""
    data = Path(path).read_bytes()

    if not data.startswith(SIGNATURE):
        raise ValueError("Not a PNG image.")

    position = len(SIGNATURE)
    compressed = bytearray()
    width = height = None

    while position < len(data):
        length = struct.unpack(">I", data[position:position + 4])[0]
        kind = data[position + 4:position + 8]
        payload = data[position + 8:position + 8 + length]
        position += 12 + length

        if kind == b"IHDR":
            width, height, depth, colour, compression, filtering, interlace = (
                struct.unpack(">IIBBBBB", payload)
            )

            if (depth, colour, compression, filtering, interlace) != (8, 2, 0, 0, 0):
                raise ValueError("Only non-interlaced 8-bit RGB PNGs are supported.")

        elif kind == b"IDAT":
            compressed.extend(payload)

        elif kind == b"IEND":
            break

    if width is None:
        raise ValueError("Missing PNG header.")

    raw = zlib.decompress(bytes(compressed))
    stride = width * 3
    pixels = bytearray()
    previous = bytearray(stride)
    offset = 0

    for _ in range(height):
        filter_type = raw[offset]
        offset += 1
        scanline = bytearray(raw[offset:offset + stride])
        offset += stride

        for i in range(stride):
            left = scanline[i - 3] if i >= 3 else 0
            up = previous[i]
            upper_left = previous[i - 3] if i >= 3 else 0

            if filter_type == 0:
                predictor = 0
            elif filter_type == 1:
                predictor = left
            elif filter_type == 2:
                predictor = up
            elif filter_type == 3:
                predictor = (left + up) // 2
            elif filter_type == 4:
                p = left + up - upper_left
                distances = (abs(p - left), abs(p - up), abs(p - upper_left))
                predictor = (left, up, upper_left)[distances.index(min(distances))]
            else:
                raise ValueError("Unsupported PNG filter.")

            scanline[i] = (scanline[i] + predictor) & 255

        pixels.extend(scanline)
        previous = scanline

    return width, height, pixels


def write_image(path, width, height, pixels):
    stride = width * 3
    raw = bytearray()

    for y in range(height):
        raw.append(0)
        start = y * stride
        raw.extend(pixels[start:start + stride])

    png = (
        SIGNATURE
        + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(bytes(raw)))
        + chunk(b"IEND", b"")
    )

    Path(path).write_bytes(png)


def bits_from_bytes(data):
    for byte in data:
        for shift in range(7, -1, -1):
            yield (byte >> shift) & 1


def bytes_from_bits(bits):
    output = bytearray()

    for start in range(0, len(bits), 8):
        value = 0

        for bit in bits[start:start + 8]:
            value = (value << 1) | bit

        output.append(value)

    return bytes(output)


def hide(source, destination, message):
    width, height, pixels = read_image(source)
    text = message.encode("utf-8")

    payload = MAGIC + struct.pack(">I", len(text)) + text
    bits = list(bits_from_bytes(payload))

    if len(bits) > len(pixels):
        raise ValueError("Message is too long for this image.")

    for i, bit in enumerate(bits):
        pixels[i] = (pixels[i] & 0xFE) | bit

    write_image(destination, width, height, pixels)
    print(f"Hidden message saved to {destination}")


def reveal(source):
    _, _, pixels = read_image(source)

    if len(pixels) < 64:
        raise ValueError("Image is too small.")

    header = bytes_from_bits([value & 1 for value in pixels[:64]])

    if header[:4] != MAGIC:
        raise ValueError("No hidden message found.")

    length = struct.unpack(">I", header[4:8])[0]
    total_bits = (8 + length) * 8

    if total_bits > len(pixels):
        raise ValueError("Invalid message length.")

    payload = bytes_from_bits([value & 1 for value in pixels[:total_bits]])
    return payload[8:].decode("utf-8")


def main():
    parser = argparse.ArgumentParser(description="PNG steganography experiment.")
    commands = parser.add_subparsers(dest="command", required=True)

    sample = commands.add_parser("sample", help="Create a sample PNG.")
    sample.add_argument("--output", default="original.png")

    encode = commands.add_parser("hide", help="Hide a message in a PNG.")
    encode.add_argument("source")
    encode.add_argument("destination")
    encode.add_argument("message")

    decode = commands.add_parser("reveal", help="Retrieve a hidden message.")
    decode.add_argument("source")

    args = parser.parse_args()

    if args.command == "sample":
        make_image(args.output)
        print(f"Sample image saved to {args.output}")

    elif args.command == "hide":
        hide(args.source, args.destination, args.message)

    elif args.command == "reveal":
        print("Hidden message:", reveal(args.source))


if __name__ == "__main__":
    main()
