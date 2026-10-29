# Vendored libraries

Loaded as ES modules from `/static/vendor/` – no build step, no CDN, nothing inline (the CSP only allows
scripts from this origin).

| File | Package | npm integrity of the package |
|---|---|---|
| `preact.module.js` | preact 10.29.8, `dist/preact.module.js` | `sha512-ej2aVZ+vZ8WO7tvlQWRM9N63A0KzF9q4mWJfDUHgYaIofWY9hu74QdnQrjoPMmZi2/nZ5gN0bJCQF49xQqx09Q==` |
| `hooks.module.js` | preact 10.29.8, `hooks/dist/hooks.module.js` | (same package) |
| `htm.module.js` | htm 3.1.1, `dist/htm.module.js` | `sha512-983Vyg8NwUE7JkZ6NmOqpCZ+sh1bKv2iYTlUkzlWmA5JD2acKoxd4KVxbMmxX/85mtfdnDmTFoNKcg5DGAvxNQ==` |

Changes to the published files: in `hooks.module.js` the import `from"preact"` reads `from"./preact.module.js"`
(an import map would need an inline script), and the `sourceMappingURL` comments are removed.

To update: `npm pack preact@<version> htm@<version>`, compare the tarball's sha512 with `npm view <pkg>@<version>
dist.integrity`, copy the three files and repeat the two changes above. Licenses: preact MIT
(`LICENSE-preact`), htm Apache-2.0 (`LICENSE-htm`).
