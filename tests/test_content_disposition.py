"""A caller-controlled object key must not be able to extend a response header.

``download_file`` built ``Content-Disposition`` as
``f'attachment; filename="{object_key.split("/")[-1]}"'``. ``object_keys``
rejects control characters, so CRLF header-splitting was never reachable — but
it does not reject ``"``, and neither does ``SAFE_STRING_PATTERN``. A key of the
form ``a";x="b`` closed the quoted-string early and injected an additional
header PARAMETER into a header the caller does not own.

These tests parse the emitted header with ``werkzeug.http.parse_options_header``
— an independent, already-vendored HTTP parser, not the code under test — and
assert on the PARAMETERS that come out rather than on the raw string. A
substring assertion would pass against an implementation that merely stripped
the quote, and would say nothing about whether an extra parameter survived.
"""

from __future__ import annotations

import pytest
from werkzeug.http import parse_options_header

from routes.files import _content_disposition

# The key that proved the defect. Object-key validation accepts it: it has no
# control characters, no leading "/", no "." or ".." segment.
INJECTING_KEY = 'a";x="b'


def parse_disposition(header: str) -> tuple[str, dict[str, str]]:
    """Parse a Content-Disposition header the way a real client would."""
    disposition, params = parse_options_header(header)
    return disposition, params


def quoted_filename(header: str) -> str:
    """The RFC 9110 quoted-string ``filename=`` value, read on its own.

    ⚠️ ``parse_options_header`` folds an RFC 2231 ``filename*`` into the SAME
    ``filename`` key and prefers it. So ``params["filename"]`` on the full header
    measures the percent-encoded ``filename*`` parameter, and says nothing about
    whether the quoted-string half escaped its ``"`` correctly — which is the
    half a client that does not understand ``filename*`` will read, and the half
    the injection defect lived in. ``test_the_two_parameters_are_measured_apart``
    below shows the two readings genuinely differ.

    Dropping ``filename*`` before parsing isolates the quoted-string.

    ⚠️ ``rpartition``, not ``partition``: the quoted-string may legitimately
    CONTAIN the literal ``; filename*=UTF-8\'\'`` — one of the crafted names below
    is exactly that — and splitting on the first occurrence would cut the header
    in half mid-value. The real parameter is always last, and always the one the
    builder appended, because ``quote(…, safe="")`` percent-encodes every byte
    that could reproduce that prefix inside it.
    """
    head, sep, _ = header.rpartition("; filename*=UTF-8''")
    _, params = parse_options_header(head if sep else header)
    return params["filename"]


class TestContentDispositionConstruction:
    def test_a_quote_in_the_key_cannot_add_a_parameter(self) -> None:
        """The defect, stated as the property that was violated."""
        disposition, params = parse_disposition(_content_disposition(INJECTING_KEY))

        assert disposition == "attachment"
        assert "x" not in params, (
            f"the key injected an extra header parameter x={params.get('x')!r}"
        )
        assert set(params) <= {"filename"}, params

    def test_the_quote_survives_as_part_of_the_name(self) -> None:
        """Escaping, not stripping: the value must still round-trip.

        A fix that deleted ``"`` from the name would also pass the test above
        while silently renaming the object the caller asked for.
        """
        _, params = parse_disposition(_content_disposition(INJECTING_KEY))
        assert params["filename"] == INJECTING_KEY
        # ⚠️ …and the same again on the QUOTED-STRING parameter specifically.
        # The line above reads ``filename*``, because werkzeug folds the two into
        # one key; on its own it would stay green against an implementation whose
        # quoted-string half was still injectable.
        assert quoted_filename(_content_disposition(INJECTING_KEY)) == INJECTING_KEY

    def test_the_quoted_string_is_escaped_at_the_byte_level(self) -> None:
        """The narrowest possible statement of the fix: the emitted bytes.

        No parser in the loop at all, so this cannot be satisfied by a parser
        preferring ``filename*``. Each ``"`` of the key must appear
        backslash-escaped INSIDE the quoted-string.
        """
        header = _content_disposition(INJECTING_KEY)
        assert header.startswith('attachment; filename="a\\";x=\\"b"'), header

    def test_the_two_parameters_are_measured_apart(self) -> None:
        """Control on ``quoted_filename``: it must not be a second way to read
        ``filename*``. For a non-ASCII name the two readings differ — the
        quoted-string drops the non-ASCII bytes (latin-1 safety), ``filename*``
        keeps them. If this ever fails, the helper collapsed into the parser it
        exists to bypass, and the assertions above became duplicates.
        """
        header = _content_disposition("unicode-Ω.bin")
        _, folded = parse_disposition(header)
        assert folded["filename"] == "unicode-Ω.bin"
        assert quoted_filename(header) == "unicode-.bin"

    def test_a_backslash_survives_as_part_of_the_name(self) -> None:
        """Backslash is the quoted-string escape character, so it needs escaping
        for the same reason ``"`` does — and ``object_keys`` permits it too."""
        name = r"back\slash.txt"
        _, params = parse_disposition(_content_disposition(name))
        assert params["filename"] == name
        assert quoted_filename(_content_disposition(name)) == name

    def test_an_ordinary_name_is_unchanged(self) -> None:
        """Non-vacuity: the common case must not be mangled by the escaping."""
        disposition, params = parse_disposition(_content_disposition("file.txt"))
        assert disposition == "attachment"
        assert params["filename"] == "file.txt"

    def test_a_unicode_key_is_carried_by_filename_star_and_is_latin1_safe(self) -> None:
        """``validate_object_key`` explicitly accepts ``unicode-Ω-ключ.bin``.

        Starlette encodes header values as latin-1, so emitting those bytes in
        the plain ``filename=`` parameter would raise on the way out. RFC 5987
        ``filename*`` carries the real name; the ASCII fallback stays encodable.
        """
        name = "unicode-Ω-ключ.bin"
        header = _content_disposition(name)
        header.encode("latin-1")  # must not raise — this is what Starlette does
        assert "filename*=UTF-8''unicode-%CE%A9-%D0%BA%D0%BB%D1%8E%D1%87.bin" in header

    def test_an_empty_last_segment_still_names_the_attachment(self) -> None:
        """``a/b/`` is a legal key whose last segment is empty."""
        disposition, params = parse_disposition(_content_disposition(""))
        assert disposition == "attachment"
        assert params["filename"] == "download"

    @pytest.mark.parametrize(
        "name",
        [INJECTING_KEY, 'x"; filename="evil.exe', "a\"; attachment; filename*=UTF-8''evil"],
    )
    def test_no_crafted_name_yields_more_than_the_two_intended_parameters(self, name: str) -> None:
        disposition, params = parse_disposition(_content_disposition(name))
        assert disposition == "attachment"
        assert set(params) <= {"filename"}, params
        assert params["filename"] == name
        assert quoted_filename(_content_disposition(name)) == name


class TestControlCharactersCannotReachTheHeader:
    """``_content_disposition`` must not depend on a validator in another module.

    ``validate_object_key`` rejects control characters today, so no reachable
    request carries one — these names are constructed directly. The point is that
    the header builder's safety should be its own property: if the key validator
    is ever relaxed, or a second caller appears that does not validate, the
    failure mode here is response splitting, not a mangled filename.
    """

    @pytest.mark.parametrize(
        "name",
        [
            "a\r\nX-Injected: 1",
            "a\nSet-Cookie: sid=1",
            "a\rb.txt",
            "tab\there.txt",
            "nul\x00byte.txt",
            "del\x7fbyte.txt",
        ],
    )
    def test_no_control_character_reaches_the_quoted_string(self, name: str) -> None:
        header = _content_disposition(name)
        quoted = quoted_filename(header)
        assert not any(c < " " or c == "\x7f" for c in quoted), repr(quoted)

    @pytest.mark.parametrize("name", ["a\r\nX-Injected: 1", "a\nSet-Cookie: sid=1", "a\rb.txt"])
    def test_a_crlf_name_cannot_split_the_header(self, name: str) -> None:
        """The whole emitted header must stay a single line.

        ``filename*`` percent-encodes CR/LF, so this is really an assertion about
        the quoted-string half — and a control that the encoding of the other
        half did not regress either.
        """
        header = _content_disposition(name)
        assert "\r" not in header and "\n" not in header, repr(header)
        disposition, params = parse_disposition(header)
        assert disposition == "attachment"
        assert set(params) <= {"filename"}, params

    def test_the_filter_is_not_vacuous(self) -> None:
        """Non-vacuity: a stripped name must differ from the input, or the
        parametrised assertions above would hold for a no-op filter."""
        assert quoted_filename(_content_disposition("a\r\nb.txt")) == "ab.txt"


class TestDownloadRouteEmitsTheSafeHeader:
    """End-to-end: the route, not just the helper."""

    def test_download_of_an_injecting_key_emits_no_extra_parameter(
        self, app_client, fake_minio
    ) -> None:
        key = f"folder/{INJECTING_KEY}"
        upload = app_client.post(
            "/api/files/upload",
            data={"bucket": "kag-ingestion", "object_key": key},
            files={"file": ("f", b"payload", "text/plain")},
        )
        # Control: the key really is accepted by object-key validation, so this
        # is a reachable request and not a hypothetical one.
        assert upload.status_code == 200, upload.text

        response = app_client.get(f"/api/files/kag-ingestion/{key}")
        assert response.status_code == 200
        assert response.content == b"payload"

        disposition, params = parse_disposition(response.headers["content-disposition"])
        assert disposition == "attachment"
        assert "x" not in params, params
        assert params["filename"] == INJECTING_KEY
