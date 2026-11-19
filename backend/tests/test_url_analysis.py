from backend.app.url_analysis import analyze_links


def test_link_analysis_reports_host_without_path_or_query() -> None:
    links = analyze_links(
        "Check https://user:secret@192.0.2.1/login?token=private now."
    )

    assert len(links) == 1
    assert links[0].host == "192.0.2.1"
    assert set(links[0].signals) == {"embedded_credentials", "ip_address_host"}
    assert "secret" not in links[0].model_dump_json()
    assert "login" not in links[0].model_dump_json()
    assert "private" not in links[0].model_dump_json()


def test_link_analysis_flags_punycode_host() -> None:
    links = analyze_links("https://xn--pple-43d.com/account")

    assert len(links) == 1
    assert links[0].signals == ["punycode_hostname"]


def test_link_analysis_reports_http_without_claiming_host_is_malicious() -> None:
    links = analyze_links("http://example.com/path")

    assert len(links) == 1
    assert links[0].host == "example.com"
    assert links[0].signals == ["unencrypted_http"]


def test_link_analysis_deduplicates_urls_and_strips_trailing_punctuation() -> None:
    links = analyze_links(
        "https://example.com/path. https://example.com/path."
    )

    assert len(links) == 1
    assert links[0].host == "example.com"
    assert links[0].signals == []
