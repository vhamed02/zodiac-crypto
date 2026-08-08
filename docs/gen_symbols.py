import math

R = 27.0
SW = 3.0
GRAD = "url(#gold)"
CELL = "#F4F5F8"

COLS, ROWS = 10, 5
CELL_W, CELL_H = 118, 116
MARGIN_X, HEADER, FOOTER = 44, 104, 46
W = MARGIN_X * 2 + COLS * CELL_W
H = HEADER + ROWS * CELL_H + FOOTER

NAMES = [
    "U+25CB", "U+25CF", "U+25B3", "U+25B2", "U+25BD", "U+25BC", "U+25A1", "U+25A0", "U+25C7", "U+25C6",
    "U+2606", "U+2605", "U+2726", "U+2727", "U+2729", "U+272A", "U+272B", "U+272C", "U+272D", "U+272E",
    "U+272F", "U+2295", "U+2297", "U+2299", "U+2296", "U+2298", "U+229A", "U+229B", "U+229D", "U+229E",
    "U+229F", "U+22A0", "U+22A1", "U+2316", "U+2301", "U+2302", "U+2318", "U+2317", "U+25C8", "U+25C9",
    "U+25CC", "U+25CD", "U+25D0", "U+25D1", "U+25D2", "U+25D3", "U+2662", "U+2667", "U+2664", "U+2660",
]


def pts(seq):
    return " ".join("%.2f,%.2f" % p for p in seq)


def poly(seq, fill="none", sw=SW, stroke=GRAD):
    return '<polygon points="%s" fill="%s" stroke="%s" stroke-width="%.2f" stroke-linejoin="round"/>' % (
        pts(seq), fill, "none" if fill != "none" and stroke is None else stroke, sw)


def polyf(seq, fill=GRAD):
    return '<polygon points="%s" fill="%s" stroke="none"/>' % (pts(seq), fill)


def circ(r, fill="none", sw=SW, stroke=GRAD, extra=""):
    return '<circle r="%.2f" fill="%s" stroke="%s" stroke-width="%.2f"%s/>' % (r, fill, stroke, sw, extra)


def disc(r, fill=GRAD):
    return '<circle r="%.2f" fill="%s"/>' % (r, fill)


def line(x1, y1, x2, y2, sw=SW):
    return '<line x1="%.2f" y1="%.2f" x2="%.2f" y2="%.2f" stroke="%s" stroke-width="%.2f" stroke-linecap="round"/>' % (
        x1, y1, x2, y2, GRAD, sw)


def path(d, fill="none", sw=SW, stroke=GRAD, rule=""):
    r = ' fill-rule="evenodd"' if rule else ""
    return '<path d="%s" fill="%s" stroke="%s" stroke-width="%.2f" stroke-linejoin="round" stroke-linecap="round"%s/>' % (
        d, fill, stroke, sw, r)


def star_pts(n, outer, inner, rot=-90.0):
    out = []
    for i in range(n * 2):
        r = outer if i % 2 == 0 else inner
        a = math.radians(rot + i * 180.0 / n)
        out.append((r * math.cos(a), r * math.sin(a)))
    return out


def tri(up, r):
    s = 1 if up else -1
    return [(0, -r * s), (r * 0.9, r * 0.56 * s), (-r * 0.9, r * 0.56 * s)]


def sq_pts(a):
    return [(-a, -a), (a, -a), (a, a), (-a, a)]


def dia_pts(w, h):
    return [(0, -h), (w, 0), (0, h), (-w, 0)]


def ring_and_glyph(inner):
    return [circ(R * 0.95)] + inner


def box_and_glyph(inner):
    a = R * 0.82
    return [poly(sq_pts(a))] + inner


def plus(k):
    return [line(-k, 0, k, 0), line(0, -k, 0, k)]


def cross(k):
    return [line(-k, -k, k, k), line(-k, k, k, -k)]


def half(r, which):
    if which == "left":
        d = "M 0,%.2f A %.2f,%.2f 0 0 0 0,%.2f Z" % (-r, r, r, r)
    elif which == "right":
        d = "M 0,%.2f A %.2f,%.2f 0 0 1 0,%.2f Z" % (-r, r, r, r)
    elif which == "upper":
        d = "M %.2f,0 A %.2f,%.2f 0 0 1 %.2f,0 Z" % (-r, r, r, r)
    else:
        d = "M %.2f,0 A %.2f,%.2f 0 0 0 %.2f,0 Z" % (-r, r, r, r)
    return '<path d="%s" fill="%s"/>' % (d, GRAD)


SPADE = ("M 0,-26 C -3,-13 -25,-8 -25,7 C -25,19 -13,24 -3,16 "
         "C -3,25 -8,31 -15,35 L 15,35 C 8,31 3,25 3,16 "
         "C 13,24 25,19 25,7 C 25,-8 3,-13 0,-26 Z")

CLUB_STEM = "M -13,35 C -5,29 -3,20 -3,12 L 3,12 C 3,20 5,29 13,35 Z"


def club_group(fill):
    return ('<g fill="%s"><circle cx="0" cy="-12" r="12.4"/><circle cx="-13" cy="7" r="12.4"/>'
            '<circle cx="13" cy="7" r="12.4"/><path d="%s"/></g>') % (fill, CLUB_STEM)


def punch(outer_fn, k=0.74):
    return [outer_fn(GRAD), '<g transform="scale(%.3f)">%s</g>' % (k, outer_fn(CELL))]


def spade_fn(fill):
    return '<path d="%s" fill="%s"/>' % (SPADE, fill)


def sym(i):
    if i == 0:
        return [circ(R * 0.9)]
    if i == 1:
        return [disc(R * 0.9)]
    if i == 2:
        return [poly(tri(True, R))]
    if i == 3:
        return [polyf(tri(True, R))]
    if i == 4:
        return [poly(tri(False, R))]
    if i == 5:
        return [polyf(tri(False, R))]
    if i == 6:
        return [poly(sq_pts(R * 0.82))]
    if i == 7:
        return [polyf(sq_pts(R * 0.82))]
    if i == 8:
        return [poly(dia_pts(R * 0.88, R * 0.98))]
    if i == 9:
        return [polyf(dia_pts(R * 0.88, R * 0.98))]
    if i == 10:
        return [poly(star_pts(5, R, R * 0.42))]
    if i == 11:
        return [polyf(star_pts(5, R, R * 0.42))]
    if i == 12:
        return [polyf(star_pts(4, R, R * 0.3))]
    if i == 13:
        return [poly(star_pts(4, R * 0.96, R * 0.3), sw=SW * 0.9)]
    if i == 14:
        return [poly(star_pts(5, R * 0.96, R * 0.4), sw=SW * 0.66)]
    if i == 15:
        return [circ(R * 0.98), poly(star_pts(5, R * 0.6, R * 0.25), sw=SW * 0.8)]
    if i == 16:
        hole = star_pts(12, R * 0.3, R * 0.3)
        return ['<path d="M %s Z M %s Z" fill="%s" fill-rule="evenodd"/>' % (
            " L ".join("%.2f,%.2f" % p for p in star_pts(5, R, R * 0.42)),
            " L ".join("%.2f,%.2f" % p for p in hole), GRAD)]
    if i == 17:
        return [poly(star_pts(5, R * 0.98, R * 0.42), sw=SW * 0.85), disc(R * 0.3)]
    if i == 18:
        return [poly(star_pts(5, R, R * 0.42), sw=SW * 0.85), polyf(star_pts(5, R * 0.7, R * 0.29))]
    if i == 19:
        return [poly(star_pts(5, R, R * 0.42), sw=SW * 1.5), polyf(star_pts(5, R * 0.6, R * 0.25))]
    if i == 20:
        return ['<g clip-path="url(#clipLeft)">%s</g>' % polyf(star_pts(5, R, R * 0.42)),
                poly(star_pts(5, R, R * 0.42), sw=SW * 0.9)]
    if i == 21:
        return ring_and_glyph(plus(R * 0.5))
    if i == 22:
        return ring_and_glyph(cross(R * 0.38))
    if i == 23:
        return ring_and_glyph([disc(R * 0.22)])
    if i == 24:
        return ring_and_glyph([line(-R * 0.5, 0, R * 0.5, 0)])
    if i == 25:
        return ring_and_glyph([line(-R * 0.48, R * 0.48, R * 0.48, -R * 0.48)])
    if i == 26:
        return ring_and_glyph([circ(R * 0.45, sw=SW * 0.9)])
    if i == 27:
        spokes = []
        for k in range(3):
            a = math.radians(90 + k * 60)
            x, y = R * 0.5 * math.cos(a), R * 0.5 * math.sin(a)
            spokes.append(line(-x, -y, x, y, sw=SW * 0.9))
        return ring_and_glyph(spokes)
    if i == 28:
        return ring_and_glyph([line(-R * 0.3, 0, R * 0.3, 0, sw=SW * 1.25)])
    if i == 29:
        return box_and_glyph(plus(R * 0.44))
    if i == 30:
        return box_and_glyph([line(-R * 0.44, 0, R * 0.44, 0)])
    if i == 31:
        return box_and_glyph(cross(R * 0.34))
    if i == 32:
        return box_and_glyph([disc(R * 0.2)])
    if i == 33:
        ticks = [line(0, -R, 0, -R * 0.52), line(0, R * 0.52, 0, R),
                 line(-R, 0, -R * 0.52, 0), line(R * 0.52, 0, R, 0)]
        return [circ(R * 0.5, sw=SW * 0.9)] + ticks + [disc(R * 0.11)]
    if i == 34:
        return [path("M 8,-26 L -14,4 L -1,4 L -8,26 L 14,-4 L 1,-4 Z", fill=GRAD, sw=0, stroke="none")]
    if i == 35:
        return [path("M -20,26 L -20,-2 L 0,-22 L 20,-2 L 20,26 Z")]
    if i == 36:
        a = R * 0.44
        loops = "".join('<circle cx="%.2f" cy="%.2f" r="%.2f" fill="none" stroke="%s" stroke-width="%.2f"/>'
                        % (sx * a, sy * a, a * 0.78, GRAD, SW * 0.92)
                        for sx, sy in ((-1, -1), (1, -1), (-1, 1), (1, 1)))
        return [poly(sq_pts(a), sw=SW * 0.92), loops]
    if i == 37:
        k = R * 0.86
        return [line(-k * 0.42, -k, -k * 0.42 - 4, k, sw=SW * 0.95),
                line(k * 0.42, -k, k * 0.42 - 4, k, sw=SW * 0.95),
                line(-k, -k * 0.4, k, -k * 0.4, sw=SW * 0.95),
                line(-k, k * 0.4, k, k * 0.4, sw=SW * 0.95)]
    if i == 38:
        return [poly(dia_pts(R * 0.88, R * 0.98)), polyf(dia_pts(R * 0.36, R * 0.4))]
    if i == 39:
        return [circ(R * 0.9, sw=SW * 0.95), disc(R * 0.46)]
    if i == 40:
        return ['<circle r="%.2f" fill="none" stroke="%s" stroke-width="%.2f" stroke-linecap="round" '
                'stroke-dasharray="0.1 8.4"/>' % (R * 0.9, GRAD, SW * 1.15)]
    if i == 41:
        stripes = "".join('<line x1="%.2f" y1="%.2f" x2="%.2f" y2="%.2f" stroke="%s" stroke-width="%.2f"/>'
                          % (x, -R, x, R, GRAD, 2.4)
                          for x in [-R * 0.62, -R * 0.31, 0, R * 0.31, R * 0.62])
        return ['<g clip-path="url(#clipCircle)">%s</g>' % stripes, circ(R * 0.9, sw=SW * 0.95)]
    if i in (42, 43, 44, 45):
        which = {42: "left", 43: "right", 44: "lower", 45: "upper"}[i]
        return [half(R * 0.9, which), circ(R * 0.9, sw=SW * 0.95)]
    if i == 46:
        return [poly(dia_pts(R * 0.66, R * 1.0))]
    if i == 47:
        lobes = "".join('<circle cx="%.1f" cy="%.1f" r="11.5" fill="none" stroke="%s" stroke-width="%.2f"/>'
                        % (cx, cy, GRAD, SW * 1.0)
                        for cx, cy in ((0, -12), (-13, 7), (13, 7)))
        stem = path("M -12,34 C -5,29 -3,21 -3,13 M 12,34 C 5,29 3,21 3,13 M -12,34 L 12,34", sw=SW)
        return [lobes, stem]
    if i == 48:
        return [path(SPADE, sw=SW * 1.05)]
    if i == 49:
        return [spade_fn(GRAD)]
    raise ValueError(i)


def build():
    out = []
    out.append('<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d" '
               'role="img" aria-label="The 50 zodiac-crypto symbols">' % (W, H, W, H))
    out.append("""<defs>
<linearGradient id="gold" gradientUnits="userSpaceOnUse" x1="-30" y1="-30" x2="30" y2="30">
<stop offset="0" stop-color="#3B4657"/><stop offset="0.55" stop-color="#212B3B"/><stop offset="1" stop-color="#0E1521"/>
</linearGradient>
<linearGradient id="rule" x1="0" y1="0" x2="1" y2="0">
<stop offset="0" stop-color="#0E1521" stop-opacity="0"/><stop offset="0.5" stop-color="#0E1521" stop-opacity="0.35"/>
<stop offset="1" stop-color="#0E1521" stop-opacity="0"/>
</linearGradient>
<clipPath id="clipCircle"><circle r="%.2f"/></clipPath>
<clipPath id="clipLeft"><rect x="%.2f" y="%.2f" width="%.2f" height="%.2f"/></clipPath>
</defs>""" % (R * 0.9, -R * 1.2, -R * 1.2, R * 1.2, R * 2.4))

    out.append('<rect width="%d" height="%d" rx="22" fill="#FFFFFF"/>' % (W, H))
    out.append('<rect x="1" y="1" width="%.1f" height="%.1f" rx="21" fill="none" '
               'stroke="#D5D9E2" stroke-width="2"/>' % (W - 2, H - 2))

    out.append('<text x="%d" y="52" fill="#0E1521" font-family="Georgia, \'Times New Roman\', serif" '
               'font-size="26" letter-spacing="6">ZODIAC SYMBOL TABLE</text>' % MARGIN_X)
    out.append('<text x="%d" y="76" fill="#6B7688" font-family="ui-monospace, SFMono-Regular, Menlo, monospace" '
               'font-size="13" letter-spacing="1.6">50 symbols · indices 0–49 · 32 drawn at random per key '
               '· P(50,32) ≈ 4.9×10^47</text>' % MARGIN_X)
    out.append('<rect x="%d" y="90" width="%d" height="1.5" fill="url(#rule)"/>' % (MARGIN_X, W - MARGIN_X * 2))

    for i in range(50):
        col, row = i % COLS, i // COLS
        x = MARGIN_X + col * CELL_W
        y = HEADER + row * CELL_H
        out.append('<rect x="%.1f" y="%.1f" width="%.1f" height="%.1f" rx="16" fill="%s" '
                   'stroke="#E4E7EE" stroke-width="1.25"/>' % (x + 3, y + 3, CELL_W - 6, CELL_H - 6, CELL))
        out.append('<text x="%.1f" y="%.1f" fill="#8A93A5" font-family="ui-monospace, SFMono-Regular, Menlo, monospace" '
                   'font-size="11">%02d</text>' % (x + 14, y + 24, i))
        out.append('<text x="%.1f" y="%.1f" fill="#B4BBC8" font-family="ui-monospace, SFMono-Regular, Menlo, monospace" '
                   'font-size="8.5" text-anchor="end">%s</text>' % (x + CELL_W - 14, y + 24, NAMES[i]))
        out.append('<g transform="translate(%.1f,%.1f)">%s</g>' % (
            x + CELL_W / 2, y + CELL_H / 2 + 8, "".join(sym(i))))

    out.append('<text x="%d" y="%d" fill="#8A93A5" font-family="ui-monospace, SFMono-Regular, Menlo, monospace" '
               'font-size="11.5" letter-spacing="0.6">A recovery key is an ordered permutation of 32 of these 50 '
               'symbols — order matters.</text>' % (MARGIN_X, H - 20))
    out.append("</svg>")
    return "\n".join(out)


with open("docs/symbols.svg", "w", encoding="utf-8") as fh:
    fh.write(build())
print("written")
