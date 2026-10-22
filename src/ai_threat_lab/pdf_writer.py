"""Pure-Python PDF 1.4 generation engine with zero external dependencies.

Features:
- Standard A4 pages (595.28 x 841.89 points)
- Full native Polish diacritics support (ą, ć, ę, ł, ń, ó, ś, ź, ż, Ą, Ć, Ę, Ł, Ń, Ó, Ś, Ź, Ż)
- Native typographic punctuation: em-dashes (—), en-dashes (–), bullets (•),
  directional quotes („, ”, “, ”, ‘, ’), ellipsis (…), Euro (€), trademark (™)
- /Differences encoding and /ToUnicode CMap ensuring perfect copy-paste, rendering,
  and text extraction across all standard PDF viewers without external font downloads
- Helvetica, Helvetica-Bold, Helvetica-Oblique, Courier, Courier-Bold typefaces
- Colored cards, severity badges, divider rules, and highlighted code snippet boxes
- Word-wrapping with long-word/path chunking and automatic page splitting
- Zero external libraries or network dependencies
"""

from __future__ import annotations

import io
import unicodedata
from typing import Callable

# A4 dimensions in points (72 points per inch)
PAGE_WIDTH = 595.28
PAGE_HEIGHT = 841.89

# Unicode codepoints mapped to custom single-byte character codes (128-255 range)
UNICODE_CHAR_MAP: dict[str, int] = {
    # Polish diacritics (uppercase & lowercase)
    "Ą": 165,
    "ą": 185,
    "Ć": 198,
    "ć": 230,
    "Ę": 202,
    "ę": 234,
    "Ł": 163,
    "ł": 179,
    "Ń": 209,
    "ń": 241,
    "Ó": 211,
    "ó": 243,
    "Ś": 140,
    "ś": 156,
    "Ź": 143,
    "ź": 159,
    "Ż": 175,
    "ż": 191,
    # Typographic punctuation & symbols
    "€": 128,  # Euro symbol U+20AC
    "„": 132,  # Double low-9 quote U+201E
    "…": 133,  # Horizontal ellipsis U+2026
    "‘": 145,  # Left single quote U+2018
    "’": 146,  # Right single quote / apostrophe U+2019
    "“": 147,  # Left double quote U+201C
    "”": 148,  # Right double quote U+201D
    "•": 149,  # Bullet U+2022
    "–": 150,  # En-dash U+2013
    "—": 151,  # Em-dash U+2014
    "™": 153,  # Trade mark U+2122
}

PL_CHAR_MAP = UNICODE_CHAR_MAP

# Standard Adobe Glyph Names for Differences encoding
ADOBE_DIFFERENCES = (
    "128 /Euro "
    "132 /quotedblbase "
    "133 /ellipsis "
    "140 /Sacute "
    "143 /Zacute "
    "145 /quoteleft "
    "146 /quoteright "
    "147 /quotedblleft "
    "148 /quotedblright "
    "149 /bullet "
    "150 /endash "
    "151 /emdash "
    "153 /trademark "
    "156 /sacute "
    "159 /zacute "
    "163 /Lslash "
    "165 /Aogonek "
    "175 /Zdotaccent "
    "179 /lslash "
    "185 /aogonek "
    "191 /zdotaccent "
    "198 /Cacute "
    "202 /Eogonek "
    "209 /Nacute "
    "211 /Oacute "
    "230 /cacute "
    "234 /eogonek "
    "241 /nacute "
    "243 /oacute"
)

# /ToUnicode CMap stream content
TO_UNICODE_CMAP = b"""/CIDInit /ProcSet findresource begin
12 dict begin
begincmap
/CIDSystemInfo << /Registry (Adobe) /Ordering (UCS) /Supplement 0 >> def
/CMapName /Custom-ToUnicode def
/CMapType 2 def
1 begincodespacerange
<00> <FF>
endcodespacerange
28 beginbfrange
<80> <80> <20AC>
<84> <84> <201E>
<85> <85> <2026>
<8C> <8C> <015A>
<8F> <8F> <0179>
<91> <91> <2018>
<92> <92> <2019>
<93> <93> <201C>
<94> <94> <201D>
<95> <95> <2022>
<96> <96> <2013>
<97> <97> <2014>
<99> <99> <2122>
<9C> <9C> <015B>
<9F> <9F> <017A>
<A3> <A3> <0141>
<A5> <A5> <0104>
<AF> <AF> <017B>
<B3> <B3> <0142>
<B9> <B9> <0105>
<BF> <BF> <017C>
<C6> <C6> <0106>
<CA> <CA> <0118>
<D1> <D1> <0143>
<D3> <D3> <00D3>
<E6> <E6> <0107>
<EA> <EA> <0119>
<F1> <F1> <0144>
<F3> <F3> <00F3>
endbfrange
endcmap
CMapName currentdict /CMap defineresource pop
end
end"""

# Safe fallback translations for Unicode symbols
FALLBACK_CHAR_MAP: dict[str, str] = {
    "\u00a0": " ",
    "\u202f": " ",
    "\u200b": "",
    "\u200c": "",
    "\u200d": "",
    "→": "->",
    "←": "<-",
    "⇒": "=>",
    "↔": "<->",
    "✓": "[OK]",
    "✔": "[OK]",
    "✗": "[X]",
    "✘": "[X]",
    "★": "*",
    "☆": "*",
    "▶": ">",
    "▼": "v",
    "▲": "^",
    "◀": "<",
    "≥": ">=",
    "≤": "<=",
    "≠": "!=",
    "≈": "~=",
    "±": "+/-",
    "×": "x",
    "÷": "/",
    "µ": "u",
    "©": "(C)",
    "®": "(R)",
    "§": "§",
    "°": "deg",
}

# Character width ratios relative to font size (Helvetica ~0.52, Courier fixed = 0.6)
_HELVETICA_NARROW = set("ijlI!.,:;'/| ")
_HELVETICA_WIDE = set("mwMW@%&#")


def char_width(char: str, font: str, size: float) -> float:
    """Estimate character display width in points."""
    if "Courier" in font:
        return 0.60 * size
    if char == "—":
        return 0.95 * size
    if char in "–…":
        return 0.60 * size
    if char in "•":
        return 0.40 * size
    if char in "„”“”‘’":
        return 0.35 * size
    if char in _HELVETICA_NARROW:
        return 0.28 * size
    if char in _HELVETICA_WIDE:
        return 0.85 * size
    if char.isupper():
        return 0.66 * size
    return 0.52 * size


def string_width(text: str, font: str, size: float) -> float:
    """Calculate total width of a string in points."""
    return sum(char_width(c, font, size) for c in text)


def escape_pdf_string(text: str) -> bytes:
    """Encode string to PDF byte representation and escape special syntax characters."""
    out = bytearray()
    for ch in text:
        # 1. Direct extended character map
        b = UNICODE_CHAR_MAP.get(ch)
        if b is not None:
            if b in (ord("("), ord(")"), ord("\\")):
                out.append(ord("\\"))
            out.append(b)
            continue

        # 2. Known symbol fallbacks (arrows, checks, etc.)
        fallback = FALLBACK_CHAR_MAP.get(ch)
        if fallback is not None:
            for sub_ch in fallback:
                b_sub = UNICODE_CHAR_MAP.get(sub_ch)
                if b_sub is not None:
                    if b_sub in (ord("("), ord(")"), ord("\\")):
                        out.append(ord("\\"))
                    out.append(b_sub)
                else:
                    try:
                        for cb in sub_ch.encode("latin-1"):
                            if cb in (ord("("), ord(")"), ord("\\")):
                                out.append(ord("\\"))
                            out.append(cb)
                    except UnicodeEncodeError:
                        out.append(ord("?"))
            continue

        # 3. Standard Latin-1 characters
        try:
            char_bytes = ch.encode("latin-1")
            for cb in char_bytes:
                if cb in (ord("("), ord(")"), ord("\\")):
                    out.append(ord("\\"))
                out.append(cb)
        except UnicodeEncodeError:
            # 4. Transliterate decomposed unicode instead of silent '?'
            decomposed = unicodedata.normalize("NFKD", ch)
            ascii_sub = decomposed.encode("ascii", "ignore").decode("ascii")
            if ascii_sub:
                for cb in ascii_sub.encode("ascii"):
                    if cb in (ord("("), ord(")"), ord("\\")):
                        out.append(ord("\\"))
                    out.append(cb)
            else:
                out.append(ord("?"))

    return bytes(out)


def split_long_word(word: str, max_width: float, font: str, size: float) -> list[str]:
    """Split a single word or path token so it never exceeds max_width."""
    if string_width(word, font, size) <= max_width:
        return [word]
    chunks: list[str] = []
    current_chunk: list[str] = []
    current_w = 0.0
    for char in word:
        cw = char_width(char, font, size)
        if current_chunk and current_w + cw > max_width:
            chunks.append("".join(current_chunk))
            current_chunk = [char]
            current_w = cw
        else:
            current_chunk.append(char)
            current_w += cw
    if current_chunk:
        chunks.append("".join(current_chunk))
    return chunks


class PDFPage:
    """Single page operation stream."""

    def __init__(self, page_number: int):
        self.page_number = page_number
        self.ops: list[str] = []

    def raw_op(self, op: str) -> None:
        self.ops.append(op)


class PDFDocument:
    """Multi-page PDF 1.4 document builder."""

    def __init__(self, width: float = PAGE_WIDTH, height: float = PAGE_HEIGHT):
        self.width = width
        self.height = height
        self.pages: list[PDFPage] = []
        self._current_page: PDFPage | None = None
        self.margin_x = 45.0
        self.margin_top = 45.0
        self.margin_bottom = 45.0
        self.content_width = self.width - (2 * self.margin_x)
        self.cursor_y = self.height - self.margin_top

        # Font definitions: Font Name -> Resource Tag
        self.fonts = {
            "Helvetica": "F1",
            "Helvetica-Bold": "F2",
            "Helvetica-Oblique": "F3",
            "Courier": "F4",
            "Courier-Bold": "F5",
        }

    @property
    def current_page(self) -> PDFPage:
        if self._current_page is None:
            self.new_page()
        return self._current_page  # type: ignore

    def new_page(self) -> PDFPage:
        """Start a new page and reset vertical cursor."""
        page = PDFPage(len(self.pages) + 1)
        self.pages.append(page)
        self._current_page = page
        self.cursor_y = self.height - self.margin_top
        return page

    def ensure_space(self, required_height: float) -> None:
        """Advance to a new page if remaining vertical space is insufficient."""
        if self.cursor_y - required_height < self.margin_bottom:
            self.new_page()

    def rect(
        self,
        x: float,
        y: float,
        w: float,
        h: float,
        fill: tuple[float, float, float] | None = None,
        stroke: tuple[float, float, float] | None = None,
        line_width: float = 1.0,
    ) -> None:
        """Draw a rectangle."""
        ops = []
        if stroke is not None:
            ops.append(f"{line_width:.2f} w {stroke[0]:.3f} {stroke[1]:.3f} {stroke[2]:.3f} RG")
        if fill is not None:
            ops.append(f"{fill[0]:.3f} {fill[1]:.3f} {fill[2]:.3f} rg")
        ops.append(f"{x:.2f} {y:.2f} {w:.2f} {h:.2f} re")
        if fill is not None and stroke is not None:
            ops.append("B")
        elif fill is not None:
            ops.append("f")
        elif stroke is not None:
            ops.append("S")
        self.current_page.raw_op(" ".join(ops))

    def line(
        self,
        x1: float,
        y1: float,
        x2: float,
        y2: float,
        stroke: tuple[float, float, float] = (0.8, 0.8, 0.8),
        line_width: float = 1.0,
    ) -> None:
        """Draw a line segment."""
        op = (
            f"{line_width:.2f} w {stroke[0]:.3f} {stroke[1]:.3f} {stroke[2]:.3f} RG "
            f"{x1:.2f} {y1:.2f} m {x2:.2f} {y2:.2f} l S"
        )
        self.current_page.raw_op(op)

    def text(
        self,
        x: float,
        y: float,
        text_str: str,
        font: str = "Helvetica",
        size: float = 10.0,
        color: tuple[float, float, float] = (0.0, 0.0, 0.0),
    ) -> None:
        """Draw a single line of text."""
        font_tag = self.fonts.get(font, "F1")
        escaped = escape_pdf_string(text_str)
        # Construct operator using byte literals to handle 8-bit encoded characters safely
        rgb = f"{color[0]:.3f} {color[1]:.3f} {color[2]:.3f} rg"
        pos = f"BT /{font_tag} {size:.2f} Tf {x:.2f} {y:.2f} Td ("
        prefix = f"{rgb} {pos}".encode("ascii")
        suffix = b") Tj ET"
        self.current_page.raw_op((prefix + escaped + suffix).decode("latin-1"))

    def wrap_text(
        self, text_str: str, max_width: float, font: str = "Helvetica", size: float = 10.0
    ) -> list[str]:
        """Wrap text into lines that strictly do not exceed max_width."""
        lines: list[str] = []
        space_w = char_width(" ", font, size)
        for paragraph in text_str.split("\n"):
            words = paragraph.split(" ")
            current_line: list[str] = []
            current_width = 0.0

            for w in words:
                if not w:
                    continue
                sub_words = split_long_word(w, max_width, font, size)
                for sub_w in sub_words:
                    sub_w_width = string_width(sub_w, font, size)
                    if not current_line:
                        current_line.append(sub_w)
                        current_width = sub_w_width
                    elif current_width + space_w + sub_w_width <= max_width:
                        current_line.append(sub_w)
                        current_width += space_w + sub_w_width
                    else:
                        lines.append(" ".join(current_line))
                        current_line = [sub_w]
                        current_width = sub_w_width
            if current_line or not paragraph:
                lines.append(" ".join(current_line))
        return lines

    def draw_text_block(
        self,
        x: float,
        y: float,
        text_str: str,
        max_width: float,
        font: str = "Helvetica",
        size: float = 10.0,
        line_height: float = 14.0,
        color: tuple[float, float, float] = (0.15, 0.15, 0.15),
        auto_page_break: bool = True,
    ) -> float:
        """Draw wrapped text block downwards from y; returns total height consumed."""
        lines = self.wrap_text(text_str, max_width, font=font, size=size)
        curr_y = y
        total_height = 0.0
        for line in lines:
            if auto_page_break and curr_y - line_height < self.margin_bottom:
                self.new_page()
                curr_y = self.height - self.margin_top
            self.text(x, curr_y, line, font=font, size=size, color=color)
            curr_y -= line_height
            total_height += line_height
        self.cursor_y = curr_y
        return total_height

    def badge(
        self,
        x: float,
        y: float,
        label: str,
        bg_color: tuple[float, float, float],
        text_color: tuple[float, float, float],
        border_color: tuple[float, float, float] | None = None,
        font_size: float = 8.5,
        padding_h: float = 6.0,
        height: float = 16.0,
    ) -> float:
        """Draw a pill/badge and return its total width."""
        w = string_width(label, "Helvetica-Bold", font_size) + (2 * padding_h)
        # Background box
        self.rect(
            x, y - (height - 3), w, height, fill=bg_color, stroke=border_color, line_width=0.75
        )
        # Centered text vertically
        text_y = y - (height - 3) + 4.5
        self.text(
            x + padding_h, text_y, label, font="Helvetica-Bold", size=font_size, color=text_color
        )
        return w

    def render(
        self,
        header_fn: Callable[[int, int, PDFDocument], None] | None = None,
        footer_fn: Callable[[int, int, PDFDocument], None] | None = None,
    ) -> bytes:
        """Assemble all pages, fonts, streams, and xref tables into PDF 1.4 binary data."""
        total_pages = len(self.pages)

        # Execute header and footer callbacks on each page with known total_pages
        if header_fn or footer_fn:
            for i, page in enumerate(self.pages, 1):
                self._current_page = page
                if header_fn:
                    header_fn(i, total_pages, self)
                if footer_fn:
                    footer_fn(i, total_pages, self)

        # Build PDF objects:
        # Object 1: Catalog
        # Object 2: Pages tree
        # Object 3..3+N-1: Page objects
        # Object Content streams for each page
        # Object Font Definitions (F1..F5)
        # Object ToUnicode CMap
        buf = io.BytesIO()
        buf.write(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")

        offsets: dict[int, int] = {}
        obj_id = 1

        def write_obj(content: bytes) -> int:
            nonlocal obj_id
            curr_id = obj_id
            offsets[curr_id] = buf.tell()
            buf.write(f"{curr_id} 0 obj\n".encode("ascii"))
            buf.write(content)
            buf.write(b"\nendobj\n")
            obj_id += 1
            return curr_id

        # ToUnicode object
        tounicode_id = write_obj(
            f"<< /Length {len(TO_UNICODE_CMAP)} >>\nstream\n".encode("ascii")
            + TO_UNICODE_CMAP
            + b"\nendstream"
        )

        # Font Encoding with Differences
        encoding_dict = (
            f"<< /Type /Encoding /BaseEncoding /WinAnsiEncoding "
            f"/Differences [ {ADOBE_DIFFERENCES} ] >>"
        )

        font_objects: dict[str, int] = {}
        for font_name, tag in self.fonts.items():
            font_def = (
                f"<< /Type /Font /Subtype /Type1 /BaseFont /{font_name} "
                f"/Encoding {encoding_dict} /ToUnicode {tounicode_id} 0 R >>"
            )
            font_objects[font_name] = write_obj(font_def.encode("ascii"))

        # Content streams for each page
        content_ids: list[int] = []
        for page in self.pages:
            content_bytes = "\n".join(page.ops).encode("latin-1")
            cid = write_obj(
                f"<< /Length {len(content_bytes)} >>\nstream\n".encode("ascii")
                + content_bytes
                + b"\nendstream"
            )
            content_ids.append(cid)

        # Page objects placeholder IDs
        page_ids: list[int] = [obj_id + i for i in range(len(self.pages))]
        pages_tree_id = obj_id + len(self.pages)
        catalog_id = pages_tree_id + 1

        # Resources dictionary
        font_refs = " ".join(f"/{tag} {font_objects[name]} 0 R" for name, tag in self.fonts.items())
        resources_dict = f"<< /Font << {font_refs} >> >>"

        # Write Page objects
        for i, page in enumerate(self.pages):
            page_obj = (
                f"<< /Type /Page /Parent {pages_tree_id} 0 R "
                f"/MediaBox [0 0 {self.width:.2f} {self.height:.2f}] "
                f"/Resources {resources_dict} "
                f"/Contents {content_ids[i]} 0 R >>"
            )
            write_obj(page_obj.encode("ascii"))

        # Write Pages tree object
        kids_str = " ".join(f"{pid} 0 R" for pid in page_ids)
        pages_tree_obj = f"<< /Type /Pages /Kids [ {kids_str} ] /Count {len(self.pages)} >>"
        write_obj(pages_tree_obj.encode("ascii"))

        # Write Catalog object
        catalog_obj = f"<< /Type /Catalog /Pages {pages_tree_id} 0 R >>"
        write_obj(catalog_obj.encode("ascii"))

        # Write XRef table
        xref_offset = buf.tell()
        total_objs = obj_id
        buf.write(f"xref\n0 {total_objs}\n".encode("ascii"))
        buf.write(b"0000000000 65535 f\r\n")
        for i in range(1, total_objs):
            buf.write(f"{offsets[i]:010d} 00000 n\r\n".encode("ascii"))

        # Trailer
        trailer_dict = (
            f"trailer\n<< /Size {total_objs} /Root {catalog_id} 0 R >>\n"
            f"startxref\n{xref_offset}\n%%EOF\n"
        )
        buf.write(trailer_dict.encode("ascii"))

        return buf.getvalue()
