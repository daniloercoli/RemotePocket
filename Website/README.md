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

This first public version is a standalone showcase for `remotepocket.ercoliconsulting.eu`. Service buttons are disabled and marked as coming soon in all four HTML pages. Active source-code links point to [the RemotePocket project on GitHub](https://github.com/daniloercoli/RemotePocket). Hosting these static files requires no RemotePocket backend, database or Android service.

Registration and sign-in will be enabled in a later release, once the application is deployed separately and ready for external use. At that point, update the buttons, availability notices and launch copy in both languages. Verify contact links before publishing.

## License

The website is licensed under `GPL-3.0-or-later`. See [LICENSE](../LICENSE). The copy in `dist/license.txt` is included for website visitors.
