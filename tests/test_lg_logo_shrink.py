"""lg/build.py shrinks the 512 px logos to 256 px for the TV (a quarter of the memory once decoded),
averaging by opacity so a logo's edge gets no dark fringe, and leaves PNGs it cannot read alone."""
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest
import zlib

sys.path.insert(0, str(Path(__file__).parents[1] / "lg"))
import build


def png(w, h, ch, pixels, filt=0):
    """A plain 8-bit PNG; pixels is a list of rows of channel tuples."""
    raw = bytearray()
    for row in pixels:
        line = bytes(v for px in row for v in px)
        if filt == 2:   # Up, to check the reader undoes it
            raw.append(2)
            prev = bytes(v for px in pixels[pixels.index(row) - 1] for v in px) if pixels.index(row) else bytes(len(line))
            raw += bytes((a - b) & 255 for a, b in zip(line, prev))
        else:
            raw.append(0)
            raw += line

    def chunk(kind, body):
        return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2 if ch == 3 else 6, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(bytes(raw))) + chunk(b"IEND", b""))


class Shrink(unittest.TestCase):
    def test_rgba_halves_by_opacity(self):
        red, clear = (200, 0, 0, 255), (0, 0, 255, 0)
        data = png(4, 4, 4, [[red, clear, red, red]] * 2 + [[clear] * 4] * 2)
        w, h, ch, rows = build._png_rows(build.shrink_png(data, most=2))
        self.assertEqual((w, h, ch), (2, 2, 4))
        # half see-through red: the clear pixels' blue does not leak in
        self.assertEqual(tuple(rows[0][0:4]), (200, 0, 0, 128))
        self.assertEqual(tuple(rows[0][4:8]), (200, 0, 0, 255))
        self.assertEqual(rows[1][3], 0)

    def test_rgb_and_filters_read_back(self):
        px = [[(x * 40, y * 40, 100) for x in range(4)] for y in range(4)]
        small = build.shrink_png(png(4, 4, 3, px, filt=2), most=2)
        w, h, ch, rows = build._png_rows(small)
        self.assertEqual((w, h, ch), (2, 2, 3))
        self.assertEqual(tuple(rows[1][3:6]), (100, 100, 100))   # the average of x 2..3, y 2..3

    def test_left_alone(self):
        self.assertIsNone(build.shrink_png(png(4, 4, 3, [[(1, 2, 3)] * 4] * 4), most=4))   # small enough
        self.assertIsNone(build.shrink_png(b"\xff\xd8 a jpeg"))
        palette = bytearray(png(4, 4, 3, [[(1, 2, 3)] * 4] * 4))
        palette[25] = 3   # colour type 3 (palette): not read
        self.assertIsNone(build._png_rows(bytes(palette)))

    def test_shrink_logos_writes_and_reuses(self):
        with tempfile.TemporaryDirectory() as d:
            logos, cache = os.path.join(d, "logos"), os.path.join(d, "cache")
            os.makedirs(logos)
            big = png(600, 600, 3, [[(10, 20, 30)] * 600] * 600)
            with open(os.path.join(logos, "big.png"), "wb") as f:
                f.write(big)
            with open(os.path.join(logos, "odd.png"), "wb") as f:
                f.write(b"not a png")
            self.assertEqual(build.shrink_logos(logos, cache), 1)
            with open(os.path.join(logos, "big.png"), "rb") as f:
                self.assertEqual(struct.unpack(">II", f.read()[16:24]), (200, 200))   # 600 / 3
            with open(os.path.join(logos, "odd.png"), "rb") as f:
                self.assertEqual(f.read(), b"not a png")
            # the next build takes it from the cache
            with open(os.path.join(logos, "big.png"), "wb") as f:
                f.write(big)
            self.assertEqual(build.shrink_logos(logos, cache), 1)
            self.assertEqual(len(os.listdir(cache)), 2)


if __name__ == "__main__":
    unittest.main()
