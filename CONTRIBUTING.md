# Contributing

## Development checks

Use Node.js 22 and stable Rust on Windows for the complete native test surface.

```bash
npm ci
npm run quality
npm run quality:rust
npm run benchmark
```

Changes to encrypted formats must include a checked-in compatibility fixture.
Changes to persistence must include a crash or concurrency regression test.
Frontend changes must include an interaction test and preserve keyboard and
reduced-motion behavior.

Keep commits focused, never commit a personal vault, and do not weaken a failing
performance or security gate merely to make it green.
