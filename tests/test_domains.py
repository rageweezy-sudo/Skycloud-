import unittest

from account_privacy.core.domains import normalize_origin, registrable_domain, service_domain


class DomainTests(unittest.TestCase):
    def test_origin_drops_credentials_path_and_tracking(self):
        self.assertEqual(
            normalize_origin(" HTTPS://user:secret@Bücher.DE.:443/reset?token=secret#token "),
            "https://xn--bcher-kva.de",
        )
        self.assertEqual(normalize_origin("http://example.com:8080/a"), "http://example.com:8080")

    def test_invalid_hosts_and_schemes(self):
        for value in (
            "", "example.com", "javascript:example.com", "https://localhost",
            "https://a..example.com", "https://-a.com", "https://bad_name.com",
            "https://example.com:0", "https://example.com:65536",
            "https://127.0.0.1", "https://[::1]", "https://[bad]",
            "https://example.com:/", "https://foo%2ebar.com", "https://example.com\\@evil.net",
            "https://exam\nple.com", "https://example.com\x00",
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                normalize_origin(value)

    def test_registrable_domain_includes_private_suffixes(self):
        self.assertEqual(registrable_domain("a.b.EXAMPLE.co.uk."), "example.co.uk")
        self.assertEqual(registrable_domain("www.alice.github.io"), "alice.github.io")
        self.assertNotEqual(registrable_domain("alice.github.io"), registrable_domain("bob.github.io"))
        self.assertEqual(registrable_domain("portal.bücher.de"), "xn--bcher-kva.de")
        self.assertEqual(registrable_domain("faß.de"), "xn--fa-hia.de")

    def test_psl_wildcards_and_exceptions(self):
        self.assertEqual(registrable_domain("a.b.kawasaki.jp"), "a.b.kawasaki.jp")
        self.assertEqual(registrable_domain("a.city.kawasaki.jp"), "city.kawasaki.jp")
        with self.assertRaises(ValueError):
            registrable_domain("b.kawasaki.jp")

    def test_alias_is_explicit_and_falls_back_to_registrable_domain(self):
        aliases = {"orders.example.net": "example.com"}
        self.assertEqual(service_domain("orders.example.net", aliases), "example.com")
        self.assertEqual(service_domain("other.example.net", aliases), "example.net")
        self.assertEqual(service_domain("notexample.net", aliases), "notexample.net")
