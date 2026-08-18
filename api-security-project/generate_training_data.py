"""
generate_training_data.py — synthesise a labelled corpus of code snippets for training /
evaluating MazAPI's static-analysis layer and for regression-testing its regex patterns.

Output: data/training_data.jsonl  (one JSON object per line)
  {"code": "...", "label": "vulnerable"|"benign", "category": "...",
   "language": "javascript"|"typescript"|"python", "why": "one sentence"}

We produce ~1,000 VULNERABLE snippets and ~1,000 BENIGN snippets. The benign set is
deliberately adversarial: each benign snippet *resembles* a vulnerable pattern but is
actually safe (env vars, placeholders, parameterised queries, constant-time comparisons,
allow-listed URLs, etc.). These are the false-positive traps the Phase-2 context
validator in scanner.ts must survive.

Deterministic: seeded RNG + fixed templates, so re-running yields an identical file.

Usage:  python generate_training_data.py
"""
import json
import os
import random

SEED = 1337
OUT_PATH = os.path.join(os.path.dirname(__file__), "data", "training_data.jsonl")
PER_CATEGORY = 50  # vulnerable snippets per category (and an equal number of benign traps)

rng = random.Random(SEED)

# Token-ish fillers so snippets vary but stay deterministic under the fixed seed.
NAMES   = ["userController", "authService", "paymentHandler", "orderRepo", "profileApi",
           "tokenStore", "configLoader", "webhookSink", "reportBuilder", "sessionMgr"]
ROUTES  = ["/login", "/users", "/orders", "/transfer", "/admin/users", "/profile",
           "/api/v1/items", "/search", "/webhook", "/reset-password"]
FAKEKEY = lambda n=32: "".join(rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") for _ in range(n))


def pick(seq):
    return seq[rng.randrange(len(seq))]


# Each generator returns (code, why). Categories mirror scanner.ts so the corpus is
# directly useful for tuning those patterns.
# ── VULNERABLE generators ────────────────────────────────────────────────────────

def vuln_hardcoded_key(lang):
    k = "sk-" + FAKEKEY(48) if rng.random() < 0.5 else "AIza" + FAKEKEY(35)
    if lang == "python":
        return f'OPENAI_API_KEY = "{k}"\nclient = OpenAI(api_key=OPENAI_API_KEY)', "API key hardcoded as a string literal"
    return f'const apiKey = "{k}";\nconst client = new OpenAI({{ apiKey }});', "API key hardcoded as a string literal"


def vuln_sql_injection(lang):
    if lang == "python":
        return ('def get_user(req):\n'
                '    uid = req.args.get("id")\n'
                '    return db.execute("SELECT * FROM users WHERE id = " + uid)'), "user input concatenated into SQL"
    return ('function getUser(req, res) {\n'
            '  const q = "SELECT * FROM users WHERE id = " + req.params.id;\n'
            '  return db.query(q);\n}'), "user input concatenated into SQL"


def vuln_ssrf(lang):
    if lang == "python":
        return ('@app.route("/fetch")\ndef fetch():\n'
                '    url = request.args.get("url")\n'
                '    return requests.get(url).text'), "user-controlled URL passed to an HTTP client"
    return ('app.get("/fetch", (req, res) => {\n'
            '  const url = req.query.url;\n'
            '  fetch(url).then(r => r.text()).then(t => res.send(t));\n});'), "user-controlled URL passed to fetch"


def vuln_weak_hash(lang):
    if lang == "python":
        return 'import hashlib\npwd_hash = hashlib.md5(password.encode()).hexdigest()', "MD5 used for password hashing"
    return 'const crypto = require("crypto");\nconst h = crypto.createHash("md5").update(password).digest("hex");', "MD5 used for password hashing"


def vuln_jwt_none(lang):
    if lang == "python":
        return 'payload = jwt.decode(token, key, algorithms=["none", "HS256"])', "JWT decoder accepts alg:none"
    return 'const payload = jwt.verify(token, key, { algorithms: ["none", "HS256"] });', "JWT verifier accepts alg:none"


def vuln_cors_wildcard(lang):
    if lang == "python":
        return 'CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)', "wildcard CORS with credentials"
    return 'app.use(cors({ origin: "*", credentials: true }));', "wildcard CORS with credentials"


def vuln_timing_compare(lang):
    if lang == "python":
        return 'if provided_token == stored_token:\n    grant_access()', "secret compared with == (timing attack)"
    return 'if (providedToken === storedToken) {\n  grantAccess();\n}', "secret compared with === (timing attack)"


def vuln_debug_mode(lang):
    if lang == "python":
        return 'app.run(host="0.0.0.0", port=5000, debug=True)', "debug mode enabled"
    return 'const config = { debug: true, env: "production" };', "debug mode enabled in production config"


def vuln_localstorage_token(lang):
    return 'localStorage.setItem("access_token", resp.token);', "auth token stored in localStorage"


def vuln_mass_assignment(lang):
    if lang == "python":
        return 'user = User(**request.json)\ndb.session.add(user)', "request body spread directly into ORM model"
    return 'const user = await User.create(req.body);', "req.body passed directly to ORM create"


def vuln_path_traversal(lang):
    if lang == "python":
        return ('@app.route("/file")\ndef read_file():\n'
                '    return open(request.args.get("name")).read()'), "user input used as a file path"
    return ('app.get("/file", (req, res) => {\n'
            '  res.send(fs.readFileSync(req.query.name));\n});'), "user input used as a file path"


def vuln_unauth_health(lang):
    if lang == "python":
        return '@app.route("/actuator/env")\ndef env():\n    return jsonify(dict(os.environ))', "ops endpoint exposes env unauthenticated"
    return 'app.get("/metrics", (req, res) => res.json(collectMetrics()));', "metrics endpoint exposed without auth"


def vuln_eval(lang):
    if lang == "python":
        return 'result = eval(request.args.get("expr"))', "eval on user input"
    return 'const result = eval(req.query.expr);', "eval on user input"


def vuln_agent_shell_tool(lang):
    if lang == "python":
        return '@tool\ndef run_cmd(cmd: str):\n    return subprocess.run(f"bash -c {cmd}", shell=True)', "agent tool executes unsanitized shell command"
    return 'server.tool("run_cmd", async (args) => child_process.execSync(args.cmd));', "MCP tool executes unsanitized shell command"


def vuln_agent_financial(lang):
    if lang == "python":
        return '@tool\ndef refund_order(order_id: str, amount: int):\n    return stripe.Refund.create(charge=order_id, amount=amount)', "agent tool triggers autonomous financial mutations without human approval"
    return 'server.tool("refund", async (args) => stripe.refunds.create({ charge: args.id }));', "agent tool triggers autonomous financial mutations without human approval"


def vuln_rag_tenant_leak(lang):
    if lang == "python":
        return 'def search_docs(query):\n    return pinecone_index.query(vector=embed(query), top_k=5)', "vector similarity query lacks tenant isolation metadata filter"
    return 'async function searchDocs(q) {\n  return chroma.similaritySearch(q, 5);\n}', "vector similarity query lacks tenant isolation metadata filter"


def vuln_confused_deputy(lang):
    if lang == "python":
        return '@tool\ndef delete_account(user_id: str):\n    db.users.delete_one({"_id": user_id})', "agent tool executes deletion without verifying calling user authorization"
    return 'server.tool("delete_user", async (args) => db.users.delete({ id: args.id }));', "agent tool executes deletion without verifying calling user authorization"


VULN_GENS = {
    "hardcoded-key":        vuln_hardcoded_key,
    "sql-injection":        vuln_sql_injection,
    "ssrf":                 vuln_ssrf,
    "weak-hash":            vuln_weak_hash,
    "jwt-none":             vuln_jwt_none,
    "cors-wildcard":        vuln_cors_wildcard,
    "timing-compare":       vuln_timing_compare,
    "debug-mode":           vuln_debug_mode,
    "localstorage-token":   vuln_localstorage_token,
    "mass-assignment":      vuln_mass_assignment,
    "path-traversal":       vuln_path_traversal,
    "unauth-ops-endpoint":  vuln_unauth_health,
    "code-injection":       vuln_eval,
    "agent-shell-tool":     vuln_agent_shell_tool,
    "agent-financial":      vuln_agent_financial,
    "rag-tenant-leak":      vuln_rag_tenant_leak,
    "confused-deputy":      vuln_confused_deputy,
}


# ── BENIGN generators (false-positive traps — look risky, are actually safe) ──────

def benign_hardcoded_key(lang):
    if lang == "python":
        return 'OPENAI_API_KEY = os.environ["OPENAI_API_KEY"]', "key loaded from environment, not hardcoded"
    return 'const apiKey = process.env.OPENAI_API_KEY;', "key loaded from environment, not hardcoded"


def benign_placeholder_key(lang):
    if lang == "python":
        return 'API_KEY = "your-api-key-here"  # replace before running', "obvious placeholder, not a real secret"
    return 'const API_KEY = "YOUR_API_KEY_HERE"; // set via env in prod', "obvious placeholder, not a real secret"


def benign_sql_param(lang):
    if lang == "python":
        return ('def get_user(req):\n'
                '    return db.execute("SELECT * FROM users WHERE id = %s", (req.args.get("id"),))'), "parameterised query, input not concatenated"
    return ('function getUser(req) {\n'
            '  return db.query("SELECT * FROM users WHERE id = ?", [req.params.id]);\n}'), "parameterised query, input not concatenated"


def benign_ssrf_allowlist(lang):
    if lang == "python":
        return ('ALLOWED = {"api.partner.com"}\n'
                'host = urlparse(request.args.get("url")).hostname\n'
                'if host in ALLOWED:\n    requests.get(request.args.get("url"))'), "URL host is allow-listed before fetch"
    return ('const ALLOWED = new Set(["api.partner.com"]);\n'
            'if (ALLOWED.has(new URL(req.query.url).hostname)) fetch(req.query.url);'), "URL host is allow-listed before fetch"


def benign_strong_hash(lang):
    if lang == "python":
        return 'import bcrypt\npwd_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())', "bcrypt used for password hashing"
    return 'const hash = await bcrypt.hash(password, 12);', "bcrypt used for password hashing"


def benign_jwt_strict(lang):
    if lang == "python":
        return 'payload = jwt.decode(token, key, algorithms=["RS256"])', "only RS256 accepted, no alg:none"
    return 'const payload = jwt.verify(token, key, { algorithms: ["RS256"] });', "only RS256 accepted, no alg:none"


def benign_cors_scoped(lang):
    if lang == "python":
        return 'CORS(app, resources={r"/api/*": {"origins": ["https://app.example.com"]}})', "CORS restricted to a trusted origin"
    return 'app.use(cors({ origin: "https://app.example.com", credentials: true }));', "CORS restricted to a trusted origin"


def benign_timing_safe(lang):
    if lang == "python":
        return 'import hmac\nif hmac.compare_digest(provided_token, stored_token):\n    grant_access()', "constant-time comparison via compare_digest"
    return 'if (crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b))) grantAccess();', "constant-time comparison via timingSafeEqual"


def benign_debug_envgated(lang):
    if lang == "python":
        return 'app.run(host="0.0.0.0", debug=os.environ.get("FLASK_DEBUG") == "1")', "debug driven by env, off by default"
    return 'const config = { debug: process.env.NODE_ENV !== "production" };', "debug driven by env, off in production"


def benign_cookie_token(lang):
    return 'res.cookie("token", t, { httpOnly: true, secure: true, sameSite: "strict" });', "token in HttpOnly secure cookie, not localStorage"


def benign_explicit_fields(lang):
    if lang == "python":
        return ('data = request.json\n'
                'user = User(name=data["name"], email=data["email"])'), "only allow-listed fields read from body"
    return ('const { name, email } = req.body;\nconst user = await User.create({ name, email });'), "only allow-listed fields read from body"


def benign_path_basename(lang):
    if lang == "python":
        return ('name = os.path.basename(request.args.get("name"))\n'
                'return open(os.path.join(SAFE_DIR, name)).read()'), "path sanitised with basename + fixed dir"
    return ('const name = path.basename(req.query.name);\n'
            'res.send(fs.readFileSync(path.join(SAFE_DIR, name)));'), "path sanitised with basename + fixed dir"


def benign_auth_health(lang):
    if lang == "python":
        return '@app.route("/metrics")\n@require_internal_token\ndef metrics():\n    return collect()', "ops endpoint gated by auth decorator"
    return 'app.get("/metrics", requireInternalToken, (req, res) => res.json(metrics()));', "ops endpoint gated by middleware"


def benign_json_parse(lang):
    if lang == "python":
        return 'data = json.loads(request.args.get("payload", "{}"))', "json.loads, not eval"
    return 'const data = JSON.parse(req.query.payload || "{}");', "JSON.parse, not eval"


def benign_agent_shell_safe(lang):
    if lang == "python":
        return '@tool\ndef run_cmd(cmd_name: str):\n    if cmd_name in ALLOWED_COMMANDS:\n        return subprocess.run([cmd_name], shell=False)', "tool validates command against allowlist and uses array invocation"
    return 'server.tool("run_cmd", async (args) => { if (ALLOWED.has(args.cmd)) child_process.execFile(args.cmd, []); });', "tool validates command against allowlist and uses execFile"


def benign_agent_hitl_financial(lang):
    if lang == "python":
        return '@tool\ndef request_refund(order_id: str):\n    return create_pending_human_approval_ticket(order_id)', "financial action creates pending human-in-the-loop approval ticket"
    return 'server.tool("request_refund", async (args) => queueForHumanReview(args.id));', "financial action creates pending human-in-the-loop approval ticket"


def benign_rag_tenant_filtered(lang):
    if lang == "python":
        return 'def search_docs(query, current_org_id):\n    return pinecone_index.query(vector=embed(query), filter={"org_id": current_org_id})', "vector query enforces metadata tenant filter"
    return 'async function searchDocs(q, orgId) {\n  return chroma.similaritySearch(q, 5, { org_id: orgId });\n}', "vector query enforces metadata tenant filter"


def benign_tool_auth_checked(lang):
    if lang == "python":
        return '@tool\ndef delete_account(user_id: str, context_user_id: str):\n    if user_id == context_user_id:\n        db.users.delete(user_id)', "tool verifies calling user authorization before mutating state"
    return 'server.tool("delete_user", async (args, ctx) => { if (args.id === ctx.userId) db.users.delete(args.id); });', "tool verifies calling user authorization before mutating state"


BENIGN_GENS = {
    "hardcoded-key":        [benign_hardcoded_key, benign_placeholder_key],
    "sql-injection":        [benign_sql_param],
    "ssrf":                 [benign_ssrf_allowlist],
    "weak-hash":            [benign_strong_hash],
    "jwt-none":             [benign_jwt_strict],
    "cors-wildcard":        [benign_cors_scoped],
    "timing-compare":       [benign_timing_safe],
    "debug-mode":           [benign_debug_envgated],
    "localstorage-token":   [benign_cookie_token],
    "mass-assignment":      [benign_explicit_fields],
    "path-traversal":       [benign_path_basename],
    "unauth-ops-endpoint":  [benign_auth_health],
    "code-injection":       [benign_json_parse],
    "agent-shell-tool":     [benign_agent_shell_safe],
    "agent-financial":      [benign_agent_hitl_financial],
    "rag-tenant-leak":      [benign_rag_tenant_filtered],
    "confused-deputy":      [benign_tool_auth_checked],
}

LANGS = ["javascript", "typescript", "python"]


def emit(records, code, label, category, language, why):
    records.append({"code": code, "label": label, "category": category, "language": language, "why": why})


def build():
    records = []
    for category, gen in VULN_GENS.items():
        for i in range(PER_CATEGORY):
            lang = LANGS[i % len(LANGS)]
            # localstorage is JS/TS only; skip python for that one to stay realistic
            if category == "localstorage-token" and lang == "python":
                lang = "javascript"
            code, why = gen(lang)
            # light, deterministic variation so identical templates aren't duplicated verbatim
            tag = f"  // {pick(NAMES)} @ {pick(ROUTES)}" if lang != "python" else f"  # {pick(NAMES)} @ {pick(ROUTES)}"
            emit(records, code + tag, "vulnerable", category, lang, why)

    for category, gens in BENIGN_GENS.items():
        for i in range(PER_CATEGORY):
            lang = LANGS[i % len(LANGS)]
            if category == "localstorage-token" and lang == "python":
                lang = "javascript"
            gen = gens[i % len(gens)]
            code, why = gen(lang)
            tag = f"  // {pick(NAMES)} @ {pick(ROUTES)}" if lang != "python" else f"  # {pick(NAMES)} @ {pick(ROUTES)}"
            emit(records, code + tag, "benign", category, lang, why)

    # Deterministic shuffle so vulnerable/benign are interleaved but reproducible
    rng.shuffle(records)
    return records


def main():
    os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
    records = build()
    with open(OUT_PATH, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    vuln = sum(1 for r in records if r["label"] == "vulnerable")
    benign = len(records) - vuln
    print(f"Wrote {len(records)} snippets -> {OUT_PATH}")
    print(f"  vulnerable : {vuln}")
    print(f"  benign     : {benign}")
    print(f"  categories : {len(VULN_GENS)}")
    print(f"  languages  : {', '.join(LANGS)}")


if __name__ == "__main__":
    main()
