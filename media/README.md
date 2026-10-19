# Sentinel AI media

Generated original illustration set for the Sentinel AI website and desktop client. The reusable system uses navy/graphite materials, blue technology details, orange warning accents, restrained green health cues, soft studio light and uncluttered 3D scenes. WebP files are optimized for shipping; contact sheets and source prompts are not included in the public site output.

## Folders

- `website/` — hero, phishing analysis, local privacy, DNS signals, threat intelligence and setup illustrations used on the public product page.
- `app/empty-states/` — nine context-specific empty-state illustrations. Use only where the corresponding state exists; absence of a detection must never be described as proof of safety.
- `app/onboarding/` — five scenes for welcome, protection setup, privacy choice, local preparation and completion.
- `app/status/` — supporting system status scenes for local client states.
- `objects/` — reusable isolated 3D objects for compact product surfaces.
- `admin/` — device-management artwork reserved for an administrator experience; this repository currently has no administrator panel, so it is not shown in the User client or public product page.

Keep descriptive alt text in HTML, do not add text into the raster images, and use `loading="lazy"` outside the first viewport. The hero should load eagerly. Both Vite builds copy this directory into their own `dist/media` output so paths work on GitHub Pages and in the packaged Electron app.
