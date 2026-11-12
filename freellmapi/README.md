# FreeLLMAPI (pinned v0.16.26)

Docker Compose setup for [FreeLLMAPI](https://github.com/tashfeenahmed/freellmapi),
pinned to **v0.16.26**. Every upgrade backs up your data first.

## Fresh install or upgrade

Requires Docker Desktop (or Docker Engine with Compose v2).

```powershell
# Windows
.\upgrade.ps1
```
```bash
# macOS / Linux
./upgrade.sh
```

On first run the script creates `.env` with a new `ENCRYPTION_KEY`. **Back that
file up**: without it, the provider keys stored in the database can't be decrypted.
Then open http://localhost:3001 and finish setup.

If an install already exists, the script stops it, copies the data volume and
`.env` into `backups/<timestamp>/`, switches to the new image and waits for the
health check. Database migrations run on their own at startup.

### Moving from an existing (non-Docker) install

Desktop app: download v0.16.26 from the
[releases page](https://github.com/tashfeenahmed/freellmapi/releases/tag/v0.16.26).
Source checkout: `git fetch --tags && git checkout v0.16.26 && npm ci && npm run build`,
then restart. Back up `server/data/` and `.env` first.

## Rolling back

```bash
docker compose down
# restore backups/<timestamp>/data into the volume, then:
./upgrade.sh v0.16.25
```

## Why v0.16.26

- Fixes monthly per-model token totals being lost after analytics log retention
  (which could under-count usage against free-tier caps).
- Per-chain routing strategy (optional; existing behaviour unchanged).
- Outcrawl web search provider.
- Verified: build passes; 5,833 tests pass (server, CLI, client); server boots
  and runs the new migration.
