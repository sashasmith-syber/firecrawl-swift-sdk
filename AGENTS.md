# AGENTS.md

## Cursor Cloud specific instructions

### Overview

This is the **Firecrawl Swift SDK** — a server-side Swift library wrapping the Firecrawl API v2 for web scraping, crawling, searching, data extraction, and website mapping. There is also a TypeScript/Deno integration layer under `integration/`.

### Swift SDK (primary)

- **Build (CI-matching):** `swift build --build-tests --configuration debug -Xswiftc -enable-testing -Xswiftc -warnings-as-errors`
- **Test:** `swift test --skip-build --configuration debug --disable-xctest`
- All 35 unit tests are pure serialization/deserialization tests — no API key or external services needed.
- Swift 6.3+ is installed at `/opt/swift-6.3-RELEASE-ubuntu24.04/usr/bin` and added to PATH via `~/.bashrc`. The `Package.swift` uses `swift-tools-version: 6.2`, which is compatible with Swift 6.3.
- The original `Package.swift` had invalid `.linux` / `.windows` platform specifiers and was missing explicit NIO dependency declarations. These were fixed as part of environment setup.
- `libstdc++-14-dev` is required for BoringSSL (transitive dependency via swift-nio-ssl). Swift's bundled clang selects GCC 14 headers, and they must be present.

### Integration layer (Deno/TypeScript)

- **Test:** `cd integration && deno test --no-check tests/`
- The `--no-check` flag is needed because the GGWaveService has pre-existing TypeScript type issues with Deno 2.x's stricter `BufferSource` types.
- Deno is installed at `~/.deno/bin/deno` and added to PATH via `~/.bashrc`.
- Integration tests (GGWave encode/decode) run locally without any external services.

### Environment variables (for runtime/integration, not needed for unit tests)

- `FIRECRAWL_API_KEY` — required if making real API calls
- `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY` — required for Supabase edge functions
- `STRIPE_WEBHOOK_SECRET` — optional, for billing webhooks
- `GGWAVE_ENCRYPTION_KEY` — optional, 64-char hex for GGWave acoustic comms
