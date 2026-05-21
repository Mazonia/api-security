# Contributing

## Getting Started

1. Fork the repository and clone your fork
2. Install host dependencies: `pip install httpx rich python-jose`
3. Start the stack: `docker compose up -d --build`
4. Verify everything works: `curl http://localhost:9000/monitor/health`

## Making Changes

- **API changes** — edit `vulnerable-api/main.py` or `hardened-api/main.py`, then restart the affected container: `docker compose restart vulnerable-api`
- **Monitoring / dashboard** — edit files in `monitoring/`, then `docker compose restart monitoring`
- **New OWASP test** — add a module to `testing-engine/owasp_tests/` following the pattern of existing test files
- **Host scripts** — `demo.py`, `rate_limit_demo.py`, `evaluate.py` run directly on the host; no container rebuild needed

## Routing Rule

Any host-side script that should appear on the monitoring dashboard **must** send requests to `http://localhost:9000` (the proxy), not directly to port 8000 or 8001. Use the header `X-Target: hardened` to route to the hardened API through the proxy.

## Pull Requests

- Keep changes focused — one vulnerability or feature per PR
- Test both the vulnerable and hardened API behaviour after your change
- Update `DEMO_SCRIPT.md` if the demonstration workflow changes

## Reporting Issues

Open a GitHub issue describing:
1. What you expected to happen
2. What actually happened
3. Steps to reproduce (include `docker compose ps` and `docker compose logs <service>` output)
