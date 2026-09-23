# simple_app

Minimal guarded actix-web application, using the real adapter surface:
[`actix_guard_rs::GuardTransform`] registered with `web::scope::wrap`. Every detection decision comes from the guard-core-rs
engine; the example itself holds no security logic.

## Routes

| Route | Guard | Behavior |
|---|---|---|
| `GET /health` | excluded | `200 ok`, answered before the guard |
| `GET /` | guarded | `200`, greeting text |
| `GET /search?q=...` | guarded | `200 search ok`, or `403` when the query trips the engine |
| `POST /echo` | guarded | echoes the request body; `403` for a threat, `413` over the body cap |
| anything else | guarded | `404 not found` |

`/health` demonstrates excluded-path behavior: the guarded routes live in a
`web::scope` that carries the guard middleware and `/health` is registered on
the `App` outside that scope. That is the same effect the Python distro's
excluded-paths configuration has.

## Running

```sh
docker compose -f examples/simple_app/docker-compose.yml up --build -d --wait
```

The compose stack builds the example from the repository root and pulls the
engine source from the sibling checkout at `../guard-core-rs` (a compose
`additional_contexts` entry named `engine`). Locally, run from a directory
layout with both repositories checked out side by side. There is no Redis
service: guard-core-rs currently ships the CPU-bound detection pipeline only,
with no Redis, rate limit, or ban surface to wire up.

Run natively instead (requires the sibling `../guard-core-rs` checkout):

```sh
cargo build -p actix-guard-simple-app
APP_ADDR=127.0.0.1:8080 target/debug/actix-guard-simple-app
```

## Smoke assertions

The `live-smoke` GitHub Actions workflow runs exactly these against the
compose stack (on port 8080; set `SMOKE_PORT` to remap the host port):

| Assertion | Expected |
|---|---|
| `GET /` | `200` |
| `GET /health` | `200` (excluded path) |
| `GET /search?q=hello` | `200` |
| `GET /search?q=<script>alert(1)</script>` | `403`, body `{"detail":"Suspicious activity detected"}` |
| `GET /files/../../etc/passwd` (`--path-as-is`) | `403`, body `{"detail":"Suspicious activity detected"}` |
| `POST /echo` with a 300 KB body | `413`, body `{"detail":"Payload too large"}` (default cap: 262144 bytes) |
| `POST /echo` with body `hello world` | `200`, body echoed |

Quick manual check:

```sh
curl -is -G http://localhost:8080/search --data-urlencode 'q=<script>alert(1)</script>'
curl -is --path-as-is http://localhost:8080/files/../../etc/passwd
```

Tear down with:

```sh
docker compose -f examples/simple_app/docker-compose.yml down -v --remove-orphans
```
