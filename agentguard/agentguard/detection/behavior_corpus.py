"""行为基线内置训练语料：日常开发会话（创新检测实施方案 §5）。

与评测用的正常夹具（agents/cc_fixtures.py 的 BENIGN）分开维护：基线只在这里训练，
正常夹具作为留出集度量误报率。每个会话为 (提示词, 工作目录, [(工具, 参数), …])。
真实会话由服务端记录（behavior.BehaviorRecorder），在控制台「行为基线」页选择后参与训练。
"""

P = "/home/dev/project"
API = "/home/dev/work/api"
WEB = "/Users/alex/src/web"
GO = "/home/dev/go/src/svc"


def bash(command):
    return ("Bash", {"command": command})


def read(path):
    return ("Read", {"file_path": path})


def edit(path, old="a", new="b"):
    return ("Edit", {"file_path": path, "old_string": old, "new_string": new})


def write(path, content="x"):
    return ("Write", {"file_path": path, "content": content})


def grep(pattern, path):
    return ("Grep", {"pattern": pattern, "path": path})


def glob(pattern):
    return ("Glob", {"pattern": pattern})


def fetch(url):
    return ("WebFetch", {"url": url, "prompt": "summarize"})


def search(query):
    return ("WebSearch", {"query": query})


def todo():
    return ("TodoWrite", {"todos": [{"content": "step", "status": "pending"}]})


def mcp(server, tool, **args):
    return (f"mcp__{server}__{tool}", args)


def agent(prompt):
    return ("Agent", {"subagent_type": "Explore", "prompt": prompt})


SESSIONS = [
    ("fix the failing unit test in the auth module", P, [
        bash("pytest -q tests/test_auth.py"), read(f"{P}/tests/test_auth.py"), read(f"{P}/src/auth.py"),
        edit(f"{P}/src/auth.py"), bash("pytest -q tests/test_auth.py"), bash("pytest -q")]),
    ("the login endpoint returns 500, debug it", API, [
        grep("def login", API), read(f"{API}/app/routes/login.py"), bash("tail -n 100 logs/app.log"),
        read(f"{API}/app/services/session.py"), edit(f"{API}/app/services/session.py"),
        bash("curl -s http://localhost:8000/api/login -d '{}'"), bash("pytest -q tests/test_login.py")]),
    ("add a slugify helper and tests", P, [
        glob("src/**/*.py"), read(f"{P}/src/utils/__init__.py"), write(f"{P}/src/utils/slug.py"),
        write(f"{P}/tests/test_slug.py"), bash("pytest -q tests/test_slug.py"), bash("git add -A"),
        bash("git commit -m 'add slugify'")]),
    ("refactor the user service, rename get_user to fetch_user", API, [
        grep("get_user", API), read(f"{API}/app/services/user.py"), edit(f"{API}/app/services/user.py"),
        edit(f"{API}/app/routes/user.py"), edit(f"{API}/tests/test_user.py"), bash("ruff check ."),
        bash("pytest -q")]),
    ("upgrade react to the latest minor version", WEB, [
        read(f"{WEB}/package.json"), fetch("https://registry.npmjs.org/react"), bash("npm install react@^18.3.1"),
        bash("npm test -- --watch=false"), bash("npm run build"), bash("git diff --stat")]),
    ("how do I use asyncio.gather with a timeout?", P, [
        search("python asyncio gather timeout"), fetch("https://docs.python.org/3/library/asyncio-task.html"),
        read(f"{P}/src/worker.py"), edit(f"{P}/src/worker.py"), bash("python3 -m pytest -q tests/test_worker.py")]),
    ("set up the dev environment", P, [
        read(f"{P}/README.md"), bash("python3 -m venv .venv"), bash(".venv/bin/pip install -r requirements.txt"),
        read(f"{P}/.env.example"), bash("cp .env.example .env.local"), bash("docker compose up -d db"),
        bash("make migrate"), bash("pytest -q")]),
    ("lint and format the frontend", WEB, [
        bash("npx eslint src --fix"), bash("npx prettier --write src"), bash("npx tsc --noEmit"),
        bash("git status --short")]),
    ("find where the payment webhook is handled", API, [
        agent("find the payment webhook handler"), grep("webhook", API), read(f"{API}/app/routes/webhooks.py"),
        bash("git log --oneline -5 -- app/routes/webhooks.py"), todo()]),
    ("create a feature branch and open a PR for the pagination fix", P, [
        bash("git checkout -b fix/pagination"), edit(f"{P}/src/api/list.py"), bash("pytest -q tests/test_list.py"),
        bash("git add -A && git commit -m 'fix pagination off-by-one'"), bash("git push -u origin fix/pagination"),
        bash("gh pr create --fill")]),
    ("the docker build is slow, speed it up", P, [
        read(f"{P}/Dockerfile"), search("docker build cache pip install layer"),
        fetch("https://docs.docker.com/build/cache/"), edit(f"{P}/Dockerfile"), bash("docker build -t app:dev ."),
        bash("docker images | head")]),
    ("go: add a health endpoint", GO, [
        read(f"{GO}/main.go"), grep("HandleFunc", GO), edit(f"{GO}/main.go"), bash("go build ./..."),
        bash("go test ./..."), bash("go run . & sleep 1 && curl -s http://localhost:8080/healthz")]),
    ("rust: fix clippy warnings", GO, [
        bash("cargo clippy --all-targets"), read(f"{GO}/src/lib.rs"), edit(f"{GO}/src/lib.rs"),
        bash("cargo clippy --all-targets"), bash("cargo test")]),
    ("write docs for the config options", P, [
        read(f"{P}/config/settings.py"), read(f"{P}/docs/index.md"), write(f"{P}/docs/configuration.md"),
        bash("mkdocs build"), bash("git add docs && git commit -m 'docs: configuration'")]),
    ("why is CI failing on main?", P, [
        bash("gh run list --limit 5"), bash("gh run view --log-failed"), read(f"{P}/.github/workflows/ci.yml"),
        edit(f"{P}/.github/workflows/ci.yml"), bash("git commit -am 'ci: pin python' && git push")]),
    ("bump the version and build a release", P, [
        read(f"{P}/pyproject.toml"), edit(f"{P}/pyproject.toml"), bash("python3 -m build"),
        bash("ls -la dist/"), bash("git tag v1.4.0 && git push --tags")]),
    ("investigate high memory in the worker", API, [
        bash("ps aux | grep worker"), bash("docker stats --no-stream"), read(f"{API}/app/worker.py"),
        search("python memory leak tracemalloc"), fetch("https://docs.python.org/3/library/tracemalloc.html"),
        edit(f"{API}/app/worker.py"), bash("python3 -m pytest -q tests/test_worker.py")]),
    ("the app cannot connect to the database, check the configuration", API, [
        read(f"{API}/docker-compose.yml"), read(f"{API}/.env"), bash("docker compose ps"),
        bash("docker compose logs --tail=50 db"), bash("curl -s http://localhost:8000/health"),
        edit(f"{API}/docker-compose.yml"), bash("docker compose up -d")]),
    ("add a migration for the orders table", API, [
        read(f"{API}/app/models/order.py"), edit(f"{API}/app/models/order.py"),
        bash("alembic revision --autogenerate -m 'orders status'"), glob("migrations/versions/*.py"),
        bash("alembic upgrade head"), bash("pytest -q tests/test_orders.py")]),
    ("explain how the caching layer works", P, [
        grep("cache", P), read(f"{P}/src/cache.py"), read(f"{P}/src/cache_backends/redis.py"),
        fetch("https://redis.io/docs/latest/develop/use/client-side-caching/")]),
    ("clean up unused imports and dead code", P, [
        bash("ruff check --select F401 ."), bash("ruff check --select F401 --fix ."), bash("vulture src | head -50"),
        edit(f"{P}/src/legacy.py"), bash("pytest -q")]),
    ("add e2e tests with playwright", WEB, [
        fetch("https://playwright.dev/docs/intro"), bash("npm install -D @playwright/test"),
        bash("npx playwright install chromium"), write(f"{WEB}/e2e/login.spec.ts"), bash("npx playwright test")]),
    ("deploy the staging environment", P, [
        read(f"{P}/deploy/staging.yml"), bash("make test"), bash("make deploy-staging"),
        bash("kubectl -n staging get pods"), bash("kubectl -n staging logs deploy/api --tail=50"),
        bash("curl -s https://staging.example.com/health")]),
    ("summarize the changes since the last release", P, [
        bash("git log --oneline v1.3.0..HEAD"), bash("git diff --stat v1.3.0..HEAD"), read(f"{P}/CHANGELOG.md"),
        edit(f"{P}/CHANGELOG.md")]),
    ("optimize the slow SQL query in reports", API, [
        grep("def monthly_report", API), read(f"{API}/app/reports.py"),
        search("postgres explain analyze group by index"), fetch("https://www.postgresql.org/docs/current/using-explain.html"),
        bash("docker compose exec db psql -U app -c 'EXPLAIN ANALYZE SELECT 1'"), edit(f"{API}/app/reports.py"),
        bash("pytest -q tests/test_reports.py")]),
    ("add type hints to the utils package", P, [
        glob("src/utils/*.py"), read(f"{P}/src/utils/text.py"), edit(f"{P}/src/utils/text.py"),
        read(f"{P}/src/utils/dates.py"), edit(f"{P}/src/utils/dates.py"), bash("mypy src/utils")]),
    ("the frontend shows a blank page, debug it", WEB, [
        bash("npm run dev &"), bash("curl -s http://localhost:5173 | head -20"), read(f"{WEB}/src/main.tsx"),
        read(f"{WEB}/vite.config.ts"), edit(f"{WEB}/src/main.tsx"), bash("npm run build")]),
    ("review the open PR #42", P, [
        bash("gh pr view 42"), bash("gh pr diff 42"), read(f"{P}/src/api/export.py"), bash("gh pr checkout 42"),
        bash("pytest -q tests/test_export.py"), bash("git checkout main")]),
    ("write a script to backfill missing slugs", API, [
        read(f"{API}/app/models/article.py"), write(f"{API}/scripts/backfill_slugs.py"),
        bash("python3 scripts/backfill_slugs.py --dry-run"), bash("python3 scripts/backfill_slugs.py")]),
    ("upgrade python dependencies with known vulnerabilities", P, [
        bash("pip-audit -r requirements.txt"), fetch("https://pypi.org/project/urllib3/"),
        edit(f"{P}/requirements.txt"), bash(".venv/bin/pip install -r requirements.txt"), bash("pytest -q")]),
    ("set up pre-commit hooks for the repo", P, [
        fetch("https://pre-commit.com/"), write(f"{P}/.pre-commit-config.yaml"), bash("pip install pre-commit"),
        bash("pre-commit install"), bash("pre-commit run --all-files")]),
    ("check the CVE advisory for our log library", P, [
        search("CVE log4j-like vulnerability python logging library"), fetch("https://nvd.nist.gov/vuln/detail/CVE-2026-1234"),
        grep("structlog", P), read(f"{P}/requirements.txt"), edit(f"{P}/requirements.txt"), bash("pytest -q")]),
    ("split the large component into smaller ones", WEB, [
        read(f"{WEB}/src/components/Dashboard.tsx"), write(f"{WEB}/src/components/DashboardHeader.tsx"),
        write(f"{WEB}/src/components/DashboardChart.tsx"), edit(f"{WEB}/src/components/Dashboard.tsx"),
        bash("npx tsc --noEmit"), bash("npm test -- --watch=false")]),
    ("generate an OpenAPI client", WEB, [
        bash("curl -s http://localhost:8000/openapi.json -o openapi.json"),
        bash("npx openapi-typescript openapi.json -o src/api/schema.ts"), read(f"{WEB}/src/api/schema.ts"),
        bash("npx tsc --noEmit")]),
    ("benchmark the parser", GO, [
        read(f"{GO}/parser/parser.go"), write(f"{GO}/parser/parser_bench_test.go"),
        bash("go test -bench=. ./parser"), edit(f"{GO}/parser/parser.go"), bash("go test -bench=. ./parser")]),
    ("rebase my branch onto main and resolve conflicts", P, [
        bash("git fetch origin"), bash("git rebase origin/main"), bash("git status"), read(f"{P}/src/app.py"),
        edit(f"{P}/src/app.py"), bash("git add src/app.py && git rebase --continue"), bash("pytest -q"),
        bash("git push --force-with-lease")]),
    ("add logging to the import job", API, [
        read(f"{API}/app/jobs/importer.py"), search("python logging best practices structured"),
        edit(f"{API}/app/jobs/importer.py"), bash("python3 -m app.jobs.importer --dry-run"),
        bash("tail -n 20 /tmp/importer.log")]),
    ("update the README with setup instructions", P, [
        read(f"{P}/README.md"), read(f"{P}/Makefile"), edit(f"{P}/README.md"), bash("git diff README.md")]),
    ("run the full test suite and fix anything broken", P, [
        bash("make test"), read(f"{P}/tests/test_api.py"), edit(f"{P}/src/api/routes.py"), bash("make test"),
        bash("make lint")]),
    ("containerize the go service", GO, [
        read(f"{GO}/go.mod"), fetch("https://docs.docker.com/language/golang/build-images/"),
        write(f"{GO}/Dockerfile"), bash("docker build -t svc:dev ."), bash("docker run --rm -d -p 8080:8080 svc:dev"),
        bash("curl -s http://localhost:8080/healthz")]),
    ("translate error messages to chinese", WEB, [
        grep("errorMessages", WEB), read(f"{WEB}/src/i18n/en.json"), write(f"{WEB}/src/i18n/zh.json"),
        edit(f"{WEB}/src/i18n/index.ts"), bash("npm test -- --watch=false")]),
    ("profile the api startup time", API, [
        bash("python3 -X importtime -c 'import app' 2> /tmp/import.log"), bash("sort -t'|' -k2 -n /tmp/import.log | tail"),
        read(f"{API}/app/__init__.py"), edit(f"{API}/app/__init__.py"),
        bash("python3 -X importtime -c 'import app' 2>&1 | tail -3")]),
    # 受管 MCP、代码托管、用户明确要求的上传。
    ("search the internal docs for the deploy runbook and follow it", P, [
        mcp("docs", "search", q="deploy runbook"), mcp("docs", "get_page", id="runbook-42"), bash("make test"),
        bash("make deploy-staging")]),
    ("look up the jira ticket and implement it", API, [
        mcp("jira", "get_issue", key="API-311"), grep("rate_limit", API), read(f"{API}/app/middleware.py"),
        edit(f"{API}/app/middleware.py"), bash("pytest -q tests/test_middleware.py"),
        mcp("jira", "add_comment", key="API-311", body="fixed in branch")]),
    ("check the latest release of requests on github", P, [
        bash("curl -s https://api.github.com/repos/psf/requests/releases/latest"),
        fetch("https://github.com/psf/requests/blob/main/HISTORY.md"), edit(f"{P}/requirements.txt"),
        bash(".venv/bin/pip install -r requirements.txt")]),
    ("clone the sdk repo and compare its retry logic with ours", P, [
        bash("git clone https://github.com/example/sdk.git /tmp/sdk"), grep("retry", "/tmp/sdk"),
        read("/tmp/sdk/src/retry.py"), read(f"{P}/src/retry.py"), edit(f"{P}/src/retry.py"), bash("pytest -q")]),
    ("run the tests and upload the coverage report to codecov", P, [
        bash("pytest --cov --cov-report=xml"), bash("curl -s -X POST -F file=@coverage.xml https://codecov.io/upload"),
        bash("git status")]),
    ("post the benchmark results to our team dashboard", GO, [
        bash("go test -bench=. ./... > /tmp/bench.txt"), read("/tmp/bench.txt"),
        bash("curl -s -X POST --data-binary @/tmp/bench.txt https://dash.example.com/api/bench")]),
    ("open an issue on github for the flaky test", P, [
        bash("pytest -q tests/test_flaky.py --count 5"), mcp("github", "create_issue", title="flaky test"),
        mcp("github", "list_issues", state="open")]),
]
