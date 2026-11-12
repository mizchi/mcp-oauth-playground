default:
    @just --list

install:
    pnpm install
    pnpm exec void prepare

dev:
    pnpm dev

dev-local:
    pnpm dev:local

dev-hono:
    pnpm dev:hono

dev-hono-local:
    pnpm dev:hono:local

test:
    pnpm test

test-audit:
    pnpm test:audit

audit-auth *args:
    node scripts/mcp-auth-audit.mjs {{args}}

e2e:
    pnpm test:e2e

e2e-hono:
    pnpm test:e2e:hono

e2e-gist:
    pnpm test:e2e:gist

test-production:
    pnpm test:production

test-production-hono:
    pnpm test:production:hono

check:
    pnpm exec void prepare
    pnpm typecheck
    pnpm typecheck:hono
    pnpm exec vp check

build:
    pnpm build

build-hono:
    pnpm build:hono

deploy:
    pnpm exec void deploy --platform cloudflare
