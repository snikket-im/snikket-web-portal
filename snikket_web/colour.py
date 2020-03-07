import functools
import hashlib

import hsluv

# This is essentially an implementation of XEP-0392.


def clip_rgb(r, g, b):
    return (
        min(max(r, 0), 1),
        min(max(g, 0), 1),
        min(max(b, 0), 1),
    )


@functools.lru_cache(128)
def text_to_colour(text):
    MASK = 0xffff
    h = hashlib.sha1()
    h.update(text.encode("utf-8"))
    hue = (int.from_bytes(h.digest()[:2], "little") & MASK) / MASK
    r, g, b = hsluv.hsluv_to_rgb((hue * 360, 75, 60))
    # print(text, cb, cr, r, g, b)
    r, g, b = clip_rgb(r, g, b)
    return r, g, b


def text_to_css(text):
    return "#{:02x}{:02x}{:02x}".format(
        *(round(v * 255) for v in text_to_colour(text))
    )
