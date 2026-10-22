"""evasion_indicators: rule-based findings, bounded and conservative.

All samples are built in memory from harmless text (alert boxes, plain strings). Nothing here can
exploit a PDF reader; the strings only look like the techniques the module is meant to spot.
"""

import os
import time
import unittest
import zlib

import helpers
import evasion_indicators as E


def pdf(body: bytes, tail: bytes = b"", header: bytes = b"%PDF-1.3\n") -> bytes:
    return header + body + b"trailer\n<< /Root 1 0 R >>\n%%EOF\n" + tail


def flate_obj(num: int, payload: bytes, extra: bytes = b"") -> bytes:
    comp = zlib.compress(payload)
    return (b"%d 0 obj\n<< /Filter /FlateDecode /Length %d %s>>\nstream\n" % (num, len(comp), extra)
            + comp + b"\nendstream\nendobj\n")


def ids(res):
    return {f["id"] for f in res["findings"]}


class Findings(unittest.TestCase):
    def test_plain_pdf_has_no_findings(self):
        r = E.analyze_bytes(helpers.PDF_PLAIN)
        self.assertEqual(r["findings"], [])
        self.assertEqual(r["strong_ids"], [])
        self.assertIsNone(r["error"])

    def test_script_in_clear_text_is_left_to_the_model(self):
        # keywords are visible, so the 32 features already see them: no evasion finding
        self.assertEqual(E.analyze_bytes(helpers.PDF_JS)["strong_ids"], [])

    def test_hex_escaped_keywords_are_found(self):
        data = pdf(b"1 0 obj\n<< /Open#41ction 4 0 R >>\nendobj\n4 0 obj\n<< /S /J#61vaScr#69pt /J#53 (app.alert\\(1\\)) >>\nendobj\n")
        r = E.analyze_bytes(data)
        self.assertIn("obfuscated_keywords", r["strong_ids"])
        ev = " ".join(next(f for f in r["findings"] if f["id"] == "obfuscated_keywords")["evidence"])
        self.assertIn("/J#61vaScr#69pt means /JavaScript", ev)
        self.assertIn("/Open#41ction means /OpenAction", ev)

    def test_harmless_hex_escapes_are_not_flagged(self):
        data = pdf(b"1 0 obj\n<< /Type /Font /BaseFont /Arial#20Bold /Name /F#31 >>\nendobj\n")
        self.assertEqual(E.analyze_bytes(data)["strong_ids"], [])
        self.assertNotIn("obfuscated_keywords", ids(E.analyze_bytes(data)))

    def test_hidden_filter_names_are_reported_but_not_strong(self):
        data = pdf(b"1 0 obj\n<< /Filter /Flate#44ecode >>\nstream\nxx\nendstream\nendobj\n")
        r = E.analyze_bytes(data)
        self.assertIn("obfuscated_filters", ids(r))
        self.assertNotIn("obfuscated_filters", r["strong_ids"])

    def test_exploit_technique_in_compressed_script_is_strong(self):
        js = b"var s = unescape('%61%6c%65%72%74'); eval(unescape('%61%6c%65%72%74') + '(1)');"
        data = pdf(b"1 0 obj\n<< /OpenAction 4 0 R >>\nendobj\n4 0 obj\n<< /S /JavaScript /JS 5 0 R >>\nendobj\n" + flate_obj(5, js))
        self.assertIn("js_exploit_techniques", E.analyze_bytes(data)["strong_ids"])

    def test_same_text_without_a_script_action_is_only_informational(self):
        js = b"eval(unescape('%61%6c'))"
        data = pdf(b"1 0 obj\n<< /Type /Catalog >>\nendobj\n" + flate_obj(5, js))
        r = E.analyze_bytes(data)
        self.assertEqual(r["strong_ids"], [])
        self.assertIn("js_pattern_no_action", ids(r))

    def test_page_text_that_quotes_exploit_words_is_ignored(self):
        content = b"BT /F1 12 Tf (this document explains eval(unescape( and util.printf) Tj ET"
        data = pdf(b"1 0 obj\n<< /Type /Catalog >>\nendobj\n" + flate_obj(5, content))
        self.assertEqual(E.analyze_bytes(data)["findings"], [])

    def test_risky_function_alone_is_medium_not_strong(self):
        js = b"var x = util.printf('%d', 1);"
        data = pdf(b"1 0 obj\n<< /OpenAction 4 0 R >>\nendobj\n4 0 obj\n<< /S /JavaScript /JS 5 0 R >>\nendobj\n" + flate_obj(5, js))
        r = E.analyze_bytes(data)
        self.assertIn("js_risky_api", ids(r))
        self.assertEqual(r["strong_ids"], [])

    def test_embedded_executable_is_strong(self):
        fake_exe = b"MZ\x90\x00" + b"\x00" * 60 + b"PE\x00\x00" + b"This program cannot be run in DOS mode."
        data = pdf(b"1 0 obj\n<< /Type /EmbeddedFile >>\nstream\n" + fake_exe + b"\nendstream\nendobj\n")
        self.assertIn("embedded_executable", E.analyze_bytes(data)["strong_ids"])
        # also when it is compressed
        data2 = pdf(flate_obj(7, fake_exe, b"/Type /EmbeddedFile "))
        self.assertIn("embedded_executable", E.analyze_bytes(data2)["strong_ids"])

    def test_program_headers_are_recognised_without_any_telltale_text(self):
        # only the binary signature (no "This program cannot be run" text), raw and compressed
        pe = b"MZ\x90\x00" + b"\x00" * 60 + b"PE\x00\x00" + b"\x4c\x01" * 20
        elf = b"\x7fELF" + b"\x02\x01\x01" + b"\x00" * 40
        for blob in (pe, elf):
            raw = pdf(b"1 0 obj\n<< /Type /EmbeddedFile >>\nstream\n" + blob + b"\nendstream\nendobj\n")
            self.assertIn("embedded_executable", E.analyze_bytes(raw)["strong_ids"], blob[:4])
            packed = pdf(flate_obj(7, blob, b"/Type /EmbeddedFile "))
            self.assertIn("embedded_executable", E.analyze_bytes(packed)["strong_ids"], blob[:4])

    def test_a_stream_that_merely_starts_with_mz_is_not_an_executable(self):
        data = pdf(b"1 0 obj\n<< /Type /EmbeddedFile >>\nstream\nMZ is just two letters here, no PE header\nendstream\nendobj\n")
        self.assertNotIn("embedded_executable", ids(E.analyze_bytes(data)))

    def test_launch_of_a_shell_is_strong_but_a_plain_launch_is_not(self):
        shell = pdf(b"1 0 obj\n<< /S /Launch /Win << /F (cmd.exe) /P (/c echo hello) >> >>\nendobj\n")
        self.assertIn("launch_shell", E.analyze_bytes(shell)["strong_ids"])
        plain = pdf(b"1 0 obj\n<< /S /Launch /F (readme.txt) >>\nendobj\n")
        self.assertNotIn("launch_shell", ids(E.analyze_bytes(plain)))

    def test_links_to_ip_addresses_and_shorteners(self):
        data = pdf(b"1 0 obj\n<< /S /URI /URI (http://203.0.113.9/x) >>\nendobj\n"
                   b"2 0 obj\n<< /S /URI /URI (https://bit.ly/abc) >>\nendobj\n"
                   b"3 0 obj\n<< /S /URI /URI (https://example.com/page) >>\nendobj\n")
        r = E.analyze_bytes(data)
        self.assertIn("uri_ip", ids(r))
        self.assertIn("uri_shortener", ids(r))
        self.assertEqual(r["strong_ids"], [])
        evidence = " ".join(" ".join(f["evidence"]) for f in r["findings"])
        self.assertNotIn("example.com", evidence)

    def test_remote_actions_and_filter_chain_are_medium(self):
        data = pdf(b"1 0 obj\n<< /S /SubmitForm /F (x) >>\nendobj\n"
                   b"2 0 obj\n<< /Filter [/ASCIIHexDecode /ASCII85Decode /FlateDecode] >>\nstream\nxx\nendstream\nendobj\n")
        r = E.analyze_bytes(data)
        self.assertIn("remote_actions", ids(r))
        self.assertIn("filter_chain", ids(r))
        self.assertEqual(r["strong_ids"], [])

    def test_large_appended_payload_is_found_but_a_trailing_newline_is_not(self):
        self.assertIn("appended_data", ids(E.analyze_bytes(pdf(b"1 0 obj\n<<>>\nendobj\n", tail=os.urandom(2048)))))
        self.assertNotIn("appended_data", ids(E.analyze_bytes(pdf(b"1 0 obj\n<<>>\nendobj\n", tail=b"\r\n\r\n"))))
        self.assertNotIn("appended_data", ids(E.analyze_bytes(pdf(b"1 0 obj\n<<>>\nendobj\n", tail=b"x" * 200))))

    def test_bytes_before_the_header(self):
        data = pdf(b"1 0 obj\n<<>>\nendobj\n", header=b"JUNKJUNK%PDF-1.4\n")
        self.assertIn("bytes_before_header", ids(E.analyze_bytes(data)))

    def test_unfiltered_random_stream_is_reported(self):
        data = pdf(b"1 0 obj\n<< /Length 2000 >>\nstream\n" + os.urandom(2000) + b"\nendstream\nendobj\n")
        self.assertIn("random_stream", ids(E.analyze_bytes(data)))
        # ... but not for encrypted documents, where every stream looks random
        enc = pdf(b"1 0 obj\n<< /Encrypt 9 0 R >>\nendobj\n2 0 obj\n<< /Length 2000 >>\nstream\n" + os.urandom(2000) + b"\nendstream\nendobj\n")
        self.assertNotIn("random_stream", ids(E.analyze_bytes(enc)))


class Robustness(unittest.TestCase):
    def test_garbage_and_empty_input_never_raise(self):
        for blob in (b"", b"%PDF-", os.urandom(4096), b"stream\n" * 50, b"/" * 5000, b"#" * 5000):
            r = E.analyze_bytes(blob)
            self.assertIn("findings", r)

    def test_missing_file_returns_an_error_instead_of_raising(self):
        r = E.analyze(os.path.join(helpers.ROOT, "no-such-file.pdf"))
        self.assertEqual(r["findings"], [])
        self.assertIsNotNone(r["error"])

    def test_decompression_bomb_is_capped_quickly(self):
        bomb = zlib.compress(b"\x00" * (60 * 1024 * 1024), 1)        # 60 MB of zeros in a few KB
        data = pdf(b"1 0 obj\n<< /Filter /FlateDecode >>\nstream\n" + bomb + b"\nendstream\nendobj\n")
        t0 = time.time()
        r = E.analyze_bytes(data)
        self.assertLess(time.time() - t0, 3.5)
        self.assertLessEqual(r["scanned"]["inflated_bytes"], E.MAX_INFLATE_TOTAL)
        self.assertTrue(r["scanned"]["truncated"])

    def test_many_streams_stay_within_the_time_budget(self):
        body = b"".join(b"%d 0 obj\n<< >>\nstream\nabc\nendstream\nendobj\n" % i for i in range(3000))
        t0 = time.time()
        E.analyze_bytes(pdf(body))
        self.assertLess(time.time() - t0, 4.0)

    def test_regex_does_not_blow_up_on_pathological_names(self):
        t0 = time.time()
        E.analyze_bytes(pdf(b"/" + b"a" * 2_000_000 + b"\n" + (b"/a#" * 200_000)))
        self.assertLess(time.time() - t0, 4.0)

    def test_output_never_contains_raw_binary(self):
        data = pdf(b"1 0 obj\n<< /Open#41ction 4 0 R >>\nendobj\n", tail=bytes(range(256)) * 10)
        for f in E.analyze_bytes(data)["findings"]:
            for e in f["evidence"] + [f["detail"], f["title"]]:
                self.assertTrue(all(32 <= ord(ch) < 127 for ch in e), e)


if __name__ == "__main__":
    unittest.main()
