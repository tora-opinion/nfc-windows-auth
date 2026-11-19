"""Generate the Credential Provider tile bitmaps.

The artwork is an original transit-IC-style mark: a white card silhouette
emitting contactless waves on a green field. It deliberately avoids the Suica
logo and the Suica penguin, which are trademarks of JR East.

The bitmaps are written as fully opaque 32-bit BI_RGB BMPs so that the result
does not depend on how the shell interprets BMP alpha channels.
"""

import struct
from pathlib import Path

from PIL import Image, ImageDraw

SUPERSAMPLE = 8
OUTPUT_SIZES = (128, 192)

GREEN_TOP = (0, 176, 86)
GREEN_BOTTOM = (0, 130, 60)
WHITE = (255, 255, 255)


def _vertical_gradient(size: int) -> Image.Image:
    """Build the green background as a smooth vertical gradient."""
    gradient = Image.new('RGB', (1, size))
    pixels = gradient.load()
    for y in range(size):
        ratio = y / max(1, size - 1)
        pixels[0, y] = tuple(
            round(top + (bottom - top) * ratio)
            for top, bottom in zip(GREEN_TOP, GREEN_BOTTOM)
        )
    return gradient.resize((size, size), Image.NEAREST)


def _draw_artwork(size: int) -> Image.Image:
    """Render the card-and-waves mark at the requested pixel size."""
    canvas = size * SUPERSAMPLE
    image = _vertical_gradient(canvas)
    draw = ImageDraw.Draw(image)

    def units(value: float) -> float:
        return value * canvas

    # The card silhouette sits left of centre so the waves have room.
    card_box = (units(0.13), units(0.325), units(0.525), units(0.675))
    draw.rounded_rectangle(card_box, radius=units(0.045), fill=WHITE)

    # A small IC-chip hint inside the card. It reads as detail at tile size and
    # simply disappears at sign-in-option size, which is fine.
    chip_box = (units(0.185), units(0.415), units(0.285), units(0.515))
    draw.rounded_rectangle(chip_box, radius=units(0.014), fill=GREEN_BOTTOM)

    # Contactless waves radiating from the card's right edge.
    centre_x = units(0.515)
    centre_y = units(0.5)
    stroke = units(0.052)
    for radius_ratio in (0.135, 0.215, 0.295):
        radius = units(radius_ratio)
        draw.arc(
            (centre_x - radius, centre_y - radius, centre_x + radius, centre_y + radius),
            start=-52,
            end=52,
            fill=WHITE,
            width=round(stroke),
        )

    return image.resize((size, size), Image.LANCZOS)


def _write_bmp(image: Image.Image, destination: Path):
    """Write an opaque 32-bit BI_RGB BMP (bottom-up BGRA rows)."""
    width, height = image.size
    rgb = image.convert('RGB')

    rows = []
    for y in range(height - 1, -1, -1):
        row = bytearray()
        for x in range(width):
            red, green, blue = rgb.getpixel((x, y))
            row += bytes((blue, green, red, 255))
        rows.append(bytes(row))
    pixel_data = b''.join(rows)

    info_header = struct.pack(
        '<IiiHHIIiiII',
        40,             # biSize
        width,          # biWidth
        height,         # biHeight (positive: bottom-up)
        1,              # biPlanes
        32,             # biBitCount
        0,              # biCompression = BI_RGB
        len(pixel_data),
        0, 0, 0, 0,
    )
    offset = 14 + len(info_header)
    file_header = struct.pack(
        '<2sIHHI', b'BM', offset + len(pixel_data), 0, 0, offset
    )
    destination.write_bytes(file_header + info_header + pixel_data)


def main():
    assets = Path(__file__).resolve().parent
    for size in OUTPUT_SIZES:
        destination = assets / f'tile_{size}.bmp'
        _write_bmp(_draw_artwork(size), destination)
        print(f'wrote {destination.name} ({size}x{size})')


if __name__ == '__main__':
    main()
