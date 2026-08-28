# Imdade Rohani Live Chat Files API

Private Cloudflare R2 upload and download API for the live-chat system on
`https://qrc.imdaderohani.in`.

## Included configuration

- Worker name: `imdaderohani-live-chat-files-api`
- R2 binding: `LIVE_CHAT_FILES`
- R2 bucket: `imdaderohani-live-chat-files`
- Allowed website: `https://qrc.imdaderohani.in`
- Firebase Authentication token verification
- Private image, PDF, audio and video storage
- Private text, coding, Word, Excel, PowerPoint and ZIP document storage

## Deploy from GitHub through Cloudflare

1. Unzip this project and upload all files to a GitHub repository.
2. In Cloudflare, open **Workers & Pages** and select the existing Worker
   `imdaderohani-live-chat-files-api`.
3. Connect the GitHub repository in the Worker's Builds/Settings area.
4. Use `npm install` as the build command if Cloudflare asks for one.
5. Use `npm run deploy` as the deploy command.

The R2 binding is declared in `wrangler.jsonc`, so every GitHub deployment uses
the existing private bucket.

## Local commands

```bash
npm install
npm run check
npm run dev
npm run deploy
```

Do not make the R2 bucket public. Files are served only after Firebase user
authorization.
GitHub deployment enabled.
Deployment successfully verified.
