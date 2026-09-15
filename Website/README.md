# RemotePocket website

The RemotePocket website is a static site in English and Italian. Its HTML and CSS source files are in `dist/`; no build step is required.

## Preview locally

From the repository root:

```bash
python3 -m http.server 8765 --bind 127.0.0.1 --directory Website/dist
```

Open [the local preview](http://127.0.0.1:8765/). The English pages are at `/` and the Italian pages at `/it/`.

## Publish

Copy the contents of `dist/` to your static hosting provider or web server. Preserve its directory structure so that page, language and stylesheet links continue to work.

The website links to the RemotePocket application, which is deployed separately. Before publishing, update the application and contact links in all four HTML files to match your deployment.

## License

The website is licensed under `GPL-3.0-or-later`. See [LICENSE](../LICENSE). The copy in `dist/license.txt` is included for website visitors.
