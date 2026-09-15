from html.parser import HTMLParser


class ConsoleAssets(HTMLParser):
    def __init__(self):
        super().__init__()
        self.scripts = []
        self.styles = []
        self.inline = []

    def handle_starttag(self, tag, attributes):
        attrs = dict(attributes)
        if tag == "script":
            self.scripts.append(attrs.get("src"))
        if tag == "link" and attrs.get("rel") == "stylesheet":
            self.styles.append(attrs["href"])
        if tag == "style" or "style" in attrs or any(key.startswith("on") for key in attrs):
            self.inline.append(tag)


def test_console_assets_are_compatible_with_csp(client):
    response = client.get("/")
    parser = ConsoleAssets()
    parser.feed(response.text)
    assert parser.scripts and all(parser.scripts)
    assert parser.styles and not parser.inline
    for url in parser.scripts + parser.styles:
        asset = client.get(url)
        assert asset.status_code == 200
        assert asset.text.strip()
        assert "javascript" in asset.headers["content-type"] or "text/css" in asset.headers["content-type"]
    policy = response.headers["content-security-policy"]
    assert "script-src 'self'" in policy
    assert "style-src 'self'" in policy
    assert "img-src 'self' blob:" in policy
    assert "unsafe-inline" not in policy
