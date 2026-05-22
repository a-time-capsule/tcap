# tcap

To install dependencies:

```bash
bun install
```

To run:

```bash
bun run index.ts
```

## Lint

ESLint 10 (flat config in `eslint.config.js`) runs in CI as a separate `lint` job in `.github/workflows/tests.yml`.

```bash
bun run lint
```

Config rationale and how to tighten the gate: [../docs/linting.md](../docs/linting.md).

This project was created using `bun init` in bun v1.3.2. [Bun](https://bun.com) is a fast all-in-one JavaScript runtime.
