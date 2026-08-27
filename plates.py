#!/usr/bin/env python3
"""
The Plate System, set in monospace.

A port of the poster-series design system to plain text. The rules that
transfer are the ones that were never about pixels:

  §1  one field, two threshold states — dense resolves to sparse
  §5  every plate different; one plate silent
  §6  hard banding, static grain, fixed cell size
  §7  cluster points, seed the RNG
  §11 captions describe what they label

The rules that had to be adapted:

  §2  five colours          -> five densities.  A character cell is either
                              ground or one of four band glyphs.  Hue carried
                              intensity in the poster; weight carries it here.
  §3  three typefaces       -> one typeface, three treatments: tracked for
                              display, plain for body, caps for metadata.
  §3.4 duotone emphasis     -> the second voice changes TRACKING, not colour.
                              Still "the other half of the claim", not "less
                              important" — which is the point of the rule.
  §4.1 sheet margin+shadow  -> the fenced code block's own border and ground.

The posterised-field technique behind plates 01 and 06 — a fixed lattice, hard
quantised bands, density resolving into isolated structure — was learned from
the work of the studio wild (craft.wild.as). The method is theirs; the palette,
the copy and this code are not.

Deterministic: same input, same README, every run.

    python3 plates.py            rebuild README.md
    python3 plates.py --census   band coverage, for checking the rationing
"""
import math
import random

# ---------------------------------------------------------------- constants

COLS = 80          # fixed measure. The §6.3.4 "fixed cell size" rule.
FREQ = 0.075       # noise frequency in cells
GRAIN = 0.17       # static per-cell dither — the §6.3.3 dissolve
SEED = 20260827

# §6.2 band table. Below the first cut the cell is UNPAINTED and the ground
# shows through; that transparency is what lets one field sit on any plate.
BANDS = [(0.30, "░"), (0.46, "▒"), (0.62, "▓"), (0.78, "█")]
GROUND = " "

CAP_W = 30         # caption column width
META_W = COLS - CAP_W * 2

# ------------------------------------------------------------ value noise

def _make_noise(seed):
    lat = {}

    def lattice(i, j, k):
        key = (i, j, k)
        if key not in lat:
            r = random.Random((i * 73856093) ^ (j * 19349663) ^ (k * 83492791) ^ seed)
            lat[key] = r.random()
        return lat[key]

    def smooth(t):
        return t * t * (3 - 2 * t)

    def noise(x, y, z):
        xi, yi, zi = math.floor(x), math.floor(y), math.floor(z)
        xf, yf, zf = x - xi, y - yi, z - zi
        u, v, w = smooth(xf), smooth(yf), smooth(zf)
        lerp = lambda a, b, t: a + (b - a) * t
        c = [[[lattice(xi + dx, yi + dy, zi + dz) for dz in (0, 1)]
              for dy in (0, 1)] for dx in (0, 1)]
        x00 = lerp(c[0][0][0], c[1][0][0], u)
        x10 = lerp(c[0][1][0], c[1][1][0], u)
        x01 = lerp(c[0][0][1], c[1][0][1], u)
        x11 = lerp(c[0][1][1], c[1][1][1], u)
        return lerp(lerp(x00, x10, v), lerp(x01, x11, v), w)

    return noise


def _cell_hash(x, y, seed=7):
    """Stable per-cell dither. Must not vary between runs, or the band edges
    stop breaking into individually surviving cells and become clean contours."""
    return random.Random((x * 374761393) ^ (y * 668265263) ^ seed).random()


def _ramp(u, v):
    """Diagonal falloff, mass upper-left, dissolving down and right."""
    return max(0.0, 1 - (u * 0.42 + v * 0.62)) ** 1.35 * 1.9


def field(rows, cut=0.0, cols=COLS, seed=SEED, gain=1.0):
    """The heat field as characters.

    `cut` is the single threshold that produces both visible states of the
    system (§1). At cut=0 every band renders: the mosaic. Raise it and almost
    everything decays, leaving isolated survivors: the schematic.

    Character cells are about twice as tall as they are wide, so the noise is
    sampled at double frequency vertically to keep features from smearing.
    """
    noise = _make_noise(seed)
    out = []
    for y in range(rows):
        line = []
        for x in range(cols):
            u, v = x / cols, y / rows
            base = (0.62 * noise(x * FREQ, y * FREQ * 2.0, 0)
                    + 0.38 * noise(x * FREQ * 2.6, y * FREQ * 5.2, 9))
            shape = 0.30 + 0.70 * min(1.0, _ramp(u, v))
            value = (base ** 2.0) * shape * 1.70 * gain
            value += (_cell_hash(x, y) - 0.5) * GRAIN

            glyph = GROUND
            if value >= cut:
                for lo, ch in BANDS:
                    if value >= lo:
                        glyph = ch
            line.append(glyph)
        out.append("".join(line).rstrip())
    return out


def coverage(rows, cut=0.0):
    """Band census, for checking §2's rationing of the hottest band."""
    lines = field(rows, cut)
    total = rows * COLS
    counts = {g: 0 for _, g in BANDS}
    counts[GROUND] = 0
    for line in lines:
        padded = line.ljust(COLS)
        for ch in padded:
            counts[ch] = counts.get(ch, 0) + 1
    return {k: v / total for k, v in counts.items()}

# ------------------------------------------------------------ typography

def track(s):
    """Display treatment. One space between every character, which turns the
    single word-space into three. §3.3 gives mono positive tracking; here that
    tracking is the only thing standing in for a change of size."""
    return " ".join(s)


def head(cap_a, cap_b, meta):
    """§4.3 furniture: caption blocks top-left in two columns, metadata pinned
    to the last column. The metadata column is explicit, never flowed, so a
    plate with one caption cannot shunt it into the wrong place."""
    n = max(len(cap_a), len(cap_b), len(meta))
    rows = []
    for i in range(n):
        a = cap_a[i] if i < len(cap_a) else ""
        b = cap_b[i] if i < len(cap_b) else ""
        m = meta[i] if i < len(meta) else ""
        rows.append((a.ljust(CAP_W) + b.ljust(CAP_W) + m.rjust(META_W)).rstrip())
    return rows


def stub(cells):
    """§4.3 ticket-stub table. Label above value, cells divided by rules.
    Used on the opening and closing plates only — on all of them it is
    monotonous."""
    n = len(cells)
    inner = COLS - (n + 1)
    w = inner // n
    widths = [w] * n
    widths[-1] += inner - w * n

    top = "┌" + "┬".join("─" * x for x in widths) + "┐"
    bot = "└" + "┴".join("─" * x for x in widths) + "┘"
    lines = [top]
    depth = max(len(c) - 1 for c in cells)
    for row in range(depth + 1):
        parts = []
        for c, x in zip(cells, widths):
            text = c[row] if row < len(c) else ""
            if len(text) > x - 2:
                raise SystemExit(f"stub cell {text!r} exceeds {x - 2} cols")
            parts.append(" " + text.ljust(x - 1))
        lines.append("│" + "│".join(parts) + "│")
    lines.append(bot)
    return lines


def registration(width=COLS):
    """The measurement bar. Furniture, not image — this is what makes the
    reading plate a plate rather than a paragraph."""
    bar = []
    for i in range(width):
        if i % 10 == 0:
            bar.append("┼")
        elif i % 5 == 0:
            bar.append("┬")
        else:
            bar.append("─")
    bar[0] = "├"
    bar[-1] = "┤"
    nums = [" "] * width
    for i in range(0, width, 10):
        label = f"{i:02d}"
        for j, ch in enumerate(label):
            if i + j < width:
                nums[i + j] = ch
    return ["".join(bar), "".join(nums).rstrip()]


def columns(left, right, gutter=4, indent=2):
    """Two columns of set text, §5 plate 03."""
    w = (COLS - indent - gutter) // 2
    out = []
    for i in range(max(len(left), len(right))):
        a = left[i] if i < len(left) else ""
        b = right[i] if i < len(right) else ""
        out.append((" " * indent + a.ljust(w) + " " * gutter + b).rstrip())
    return out

# ------------------------------------------------------------ schematics

def _blank(rows, cols=COLS):
    return [[" "] * cols for _ in range(rows)]


def _draw_line(grid, a, b):
    """Edges between nodes. Glyph follows the slope; because a character cell
    is roughly 2:1, a visually diagonal run is two columns per row."""
    (x0, y0), (x1, y1) = a, b
    dx, dy = x1 - x0, y1 - y0
    steps = max(abs(dx), abs(dy) * 2)
    if steps == 0:
        return
    if abs(dy) * 2 >= abs(dx):
        glyph = "│" if dx == 0 else ("╲" if dx * dy > 0 else "╱")
    else:
        glyph = "─"
    for s in range(1, steps):
        x = round(x0 + dx * s / steps)
        y = round(y0 + dy * s / steps)
        if 0 <= y < len(grid) and 0 <= x < len(grid[0]) and grid[y][x] == " ":
            grid[y][x] = glyph


def _put(grid, x, y, s):
    for i, ch in enumerate(s):
        if 0 <= y < len(grid) and 0 <= x + i < len(grid[0]):
            grid[y][x + i] = ch


DIRS = {
    (1, 0): "─", (-1, 0): "─",
    (0, 1): "│", (0, -1): "│",
    (1, 1): "╲", (-1, -1): "╲",
    (1, -1): "╱", (-1, 1): "╱",
}


def constellation(rows, clusters, seed, node="●", centre="◉", strays=4):
    """§7.2 clusters, never a uniform scatter: uniform random reads as noise,
    clustered points read as designed. Seeded, so the diagram is identical on
    every reload — a constellation that reshuffles reads as a screensaver.

    Satellites are placed ON one of eight rays from their cluster centre, at a
    seeded distance. That constraint is what keeps every edge a clean unbroken
    run of one glyph instead of a stepped approximation of a line.
    """
    rng = random.Random(seed)
    grid = _blank(rows)
    boxes = []

    for cx, cy, label, n in clusters:
        dirs = [d for d in DIRS]
        rng.shuffle(dirs)
        xs, ys = [cx], [cy]
        for dx, dy in dirs[:n]:
            reach = rng.randint(3, 7) if dy == 0 else rng.randint(2, 4)
            x, y = cx + dx * reach, cy + dy * reach
            if not (1 <= x < COLS - 1 and 0 <= y < rows):
                continue
            for i in range(1, reach):
                gx, gy = cx + dx * i, cy + dy * i
                if grid[gy][gx] == " ":
                    grid[gy][gx] = DIRS[(dx, dy)]
            grid[y][x] = node
            xs.append(x)
            ys.append(y)
        grid[cy][cx] = centre
        boxes.append((min(xs), max(xs), min(ys), max(ys), cx, cy, label))

    for _ in range(strays):
        x, y = rng.randrange(2, COLS - 2), rng.randrange(rows)
        if grid[y][x] == " ":
            grid[y][x] = "·"

    # Labels are placed last, into a run of cells that is actually free, so a
    # label can never land on top of an edge it does not belong to.
    for lo, hi, top, bot, cx, cy, label in boxes:
        text = "── " + label
        for row in (cy, cy - 1, cy + 1, cy - 2, cy + 2):
            if not 0 <= row < rows:
                continue
            on_row = [x for x in range(lo, hi + 1) if grid[row][x] != " "]
            start = (max(on_row) if on_row else hi) + 1
            if start + len(text) >= COLS:
                start = lo - 2 - len(text)
                text = label + " ──"
            if start < 0:
                continue
            if all(grid[row][start + i] == " " for i in range(len(text))):
                _put(grid, start, row, text)
                break

    return [l for l in ("".join(r).rstrip() for r in grid)]


# ------------------------------------------------------------- the plates

def plate_01():
    """paper · dense heat field · opens loud"""
    out = head(
        ["FIELD STUDY, PLATE ONE.",
         "DENSITY PLOT, SAMPLED",
         "CONTINUOUSLY. BANDING IS",
         "QUANTISED; INTERMEDIATE",
         "VALUES ARE NOT RENDERED."],
        ["BANDS, COOL TO HOT:",
         "░ ▒ ▓ █. CELLS BELOW THE",
         "FIRST CUT ARE UNPAINTED",
         "AND THE GROUND SHOWS",
         "THROUGH."],
        ["UDAYA VIJAY ANAND", "NEW YORK, NY", "PLATE 01 / 06"])
    out += [""] + field(11) + [""]
    out += [track("udaya vijay anand.")]
    out += ["",
            "  software that acts on your behalf",
            "  — and can prove it kept your trust.",
            ""]
    out += stub([
        ["NOW", "MS QUANTUM SCI & TECH", "COLUMBIA"],
        ["BEFORE", "CYBERSECURITY", "PURDUE"],
        ["FOCUS", "TRUST INFRASTRUCTURE", "FOR AI AGENTS"],
    ])
    return out


def plate_02():
    """cobalt · filled-node constellation · first schematic state"""
    out = head(
        ["SCHEMATIC, PLATE TWO.",
         "THREE LIVE WORKSTREAMS",
         "SHOWN AS LABELLED NODES."],
        ["UNLABELLED NODES ARE",
         "SUPPORTING WORK. DIAGRAM",
         "IS ILLUSTRATIVE AND NOT",
         "TO SCALE; NODE POSITIONS",
         "CARRY NO ORDINAL MEANING."],
        ["UDAYA VIJAY ANAND", "NEW YORK, NY", "PLATE 02 / 06"])
    out += [""] + constellation(11, [
        (10, 6, "ERYS", 5),
        (34, 3, "WARRANT", 4),
        (58, 7, "KNOW", 4),
    ], seed=4102) + [""]
    out += [track("three things in build.")]
    out += ["",
            "  each one is a piece of the same argument:",
            "  — if software acts for you, that should be provable.",
            ""]
    out += columns(
        ["ERYS — an ambient macOS agent",
         "that watches your work, remembers",
         "what you committed to, and follows",
         "through on it. erys.app",
         "",
         "WARRANT — a delegation-proof layer",
         "for AI agents, built on post-quantum",
         "signatures."],
        ["KNOW — professional network",
         "intelligence for B2B teams,",
         "co-founded with a friend.",
         "useknow.io",
         "",
         "If an agent acts for you, there",
         "should be cryptographic proof you",
         "allowed it."])
    return out


def plate_03():
    """paper · registration bar and two columns · the reading plate"""
    out = head(
        ["READING PLATE. NO DIAGRAM;",
         "A RULED BAR AND TWO",
         "COLUMNS OF SET TEXT."],
        ["PROVENANCE OF THE WORK,",
         "STATED PLAINLY."],
        ["UDAYA VIJAY ANAND", "NEW YORK, NY", "PLATE 03 / 06"])
    out += [""] + registration() + [""]
    out += columns(
        ["I spent my undergrad in security:",
         "incident response at KPMG,",
         "vulnerability assessment at DBS",
         "Bank, and a first-author USENIX",
         "Security paper on adversarial",
         "attacks against LLM-powered",
         "security tooling.",
         "",
         "That work is why I care about",
         "agent trust now."],
        ["Autonomous software is only useful",
         "if you can verify what it did and",
         "prove what it was allowed to do.",
         "",
         "The quantum degree is the same",
         "thread pulled further. Post-quantum",
         "cryptography is the foundation the",
         "next decade of trust gets built on,",
         "and I want to understand it from",
         "the physics up."])
    out += ["", track("security first."), "",
            "  then the physics underneath it.", ""]
    return out


def plate_04():
    """ink · bracketed manifold · different marker, different topology"""
    out = head(
        ["SCHEMATIC, PLATE FOUR.",
         "NODES ARE CURRENT",
         "RESEARCH DIRECTIONS."],
        ["EDGES ARE ASSOCIATION,",
         "NOT DEPENDENCY. ORDER",
         "IS ARBITRARY."],
        ["UDAYA VIJAY ANAND", "NEW YORK, NY", "PLATE 04 / 06"])
    out += ["",
            "                    ┌── ■  TRUST INFRASTRUCTURE FOR AUTONOMOUS AGENTS",
            "                    │",
            "                    ├── ■  POST-QUANTUM CRYPTOGRAPHY, ML-DSA IN PARTICULAR",
            "                    │",
            "      ◉─────────────┤",
            "                    │",
            "                    ├── ■  OFFENSIVE SECURITY, AND HOW AI CHANGES IT",
            "                    │",
            "                    └── ■  AMBIENT COMPUTING THAT RESPECTS ITS USER",
            ""]
    out += [track("four directions, one thread.")]
    out += ["",
            "  can you prove what your software did,",
            "  — and that it was allowed to do it?",
            ""]
    return out


def plate_05():
    """paper · nothing at all · unique by absence

    Every series needs one plate that stops performing. This one carries the
    most candid copy and is given no visual on purpose."""
    out = head(
        ["PLATE FIVE CARRIES NO",
         "DIAGRAM."],
        [],
        ["UDAYA VIJAY ANAND", "NEW YORK, NY", "PLATE 05 / 06"])
    out += ["", track("off the terminal."), ""]
    out += columns(
        ["I run a portrait photography",
         "practice called Sora, shot on a",
         "Sony A7III, mostly 85mm.",
         "thesora.io",
         "",
         "I was a competitive inline speed",
         "skater in India and I am slowly",
         "finding my way back to it in",
         "New York."],
        ["I have a long-running fascination",
         "with the Mahabharata, especially",
         "the Tamil retellings.",
         "",
         "None of this is on the roadmap.",
         "That is rather the point of it."])
    out += [""]
    return out


def plate_06():
    """cobalt · the plate-01 field, starved · closes the loop

    Same generator, same seed, one raised threshold. The closing image is
    literally what survived the opening one — §1 made visible."""
    out = head(
        ["FIELD STUDY, PLATE SIX.",
         "THE PLATE-ONE FIELD AT A",
         "RAISED THRESHOLD. SAME",
         "SEED, SAME GENERATOR."],
        ["ONE PARAMETER SEPARATES",
         "THIS PLATE FROM THE",
         "FIRST. WHAT REMAINS IS",
         "WHAT SURVIVED."],
        ["UDAYA VIJAY ANAND", "NEW YORK, NY", "PLATE 06 / 06"])
    survivors = field(11, cut=0.62)
    while survivors and not survivors[-1].strip():
        survivors.pop()
    out += [""] + survivors + [""]
    out += [track("build quietly.")]
    out += ["", "  ship anyway.", ""]
    out += stub([
        ["LINKEDIN", "/in/udsy"],
        ["INSTAGRAM", "@udsyx"],
        ["EMAIL", "udayatejas2004@gmail.com"],
    ])
    return out

# ---------------------------------------------------------------- assembly

LINKS = {
    2: '<a href="https://erys.app">ERYS.APP</a>&ensp;·&ensp;'
       '<a href="https://useknow.io">USEKNOW.IO</a>',
    5: '<a href="https://thesora.io">THESORA.IO</a>',
    6: '<a href="https://www.linkedin.com/in/udsy/">LINKEDIN</a>&ensp;·&ensp;'
       '<a href="https://instagram.com/udsyx">INSTAGRAM</a>&ensp;·&ensp;'
       '<a href="mailto:udayatejas2004@gmail.com">EMAIL</a>',
}


def build():
    plates = [plate_01, plate_02, plate_03, plate_04, plate_05, plate_06]
    doc = ["<!-- The Plate System, set in monospace. Six plates, one field,",
           "     two threshold states. Generated by plates.py — edit that,",
           "     not this, and re-run it. -->",
           ""]
    for i, fn in enumerate(plates, 1):
        lines = fn()
        while lines and not lines[-1].strip():
            lines.pop()
        over = [(n, len(l)) for n, l in enumerate(lines) if len(l) > COLS]
        if over:
            raise SystemExit(f"plate {i}: lines exceed {COLS} cols: {over}")
        doc.append("```")
        doc.extend(lines)
        doc.append("```")
        if i in LINKS:
            doc.append("")
            doc.append(f"<p align=\"right\"><sub><samp>{LINKS[i]}</samp></sub></p>")
        doc.append("")
    return "\n".join(doc).rstrip() + "\n"


if __name__ == "__main__":
    import sys
    if "--census" in sys.argv:
        for label, cut in (("plate 01", 0.0), ("plate 06", 0.62)):
            c = coverage(11, cut)
            parts = " ".join(f"{k!r}:{v:.1%}" for k, v in sorted(c.items()))
            print(label, parts)
    else:
        open("README.md", "w", encoding="utf-8").write(build())
        print("wrote README.md")
