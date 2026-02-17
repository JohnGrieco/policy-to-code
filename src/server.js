import express from 'express';
import Database from 'better-sqlite3';
import { nanoid } from 'nanoid';
import fs from 'node:fs';
import path from 'node:path';

const PORT = process.env.PORT ? Number(process.env.PORT) : 3000;
const DB_PATH = process.env.DB_PATH || './data/policy_to_code.sqlite';

const app = express();
app.use(express.urlencoded({ extended: true }));

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  next();
});

function escapeHtml(s) {
  return String(s ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

function page(title, body) {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${escapeHtml(title)}</title>
  <style>
    :root { --bg:#0b1020; --card:#121a33; --text:#e8ecff; --muted:#aab3da; --link:#8ab4ff; --border:#28345e; --danger:#ff6b6b; }
    body { margin:0; font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial; background:var(--bg); color:var(--text); }
    a { color:var(--link); text-decoration:none; }
    a:hover { text-decoration:underline; }
    header { padding:16px 20px; border-bottom:1px solid var(--border); background:rgba(18,26,51,0.6); position:sticky; top:0; backdrop-filter: blur(6px); }
    header .row { display:flex; gap:16px; align-items:center; justify-content:space-between; }
    main { max-width: 1100px; margin: 0 auto; padding: 20px; }
    .card { background:var(--card); border:1px solid var(--border); border-radius:12px; padding:16px; margin: 12px 0; }
    .grid { display:grid; gap:12px; }
    .grid2 { grid-template-columns: 1fr 1fr; }
    @media (max-width: 900px){ .grid2 { grid-template-columns: 1fr; } }
    label { display:block; font-size: 12px; color: var(--muted); margin-bottom: 6px; }
    input, textarea, select { width:100%; box-sizing:border-box; padding:10px 12px; border-radius:10px; border:1px solid var(--border); background:#0e1530; color:var(--text); }
    textarea { min-height: 90px; resize: vertical; }
    button { padding:10px 12px; border-radius:10px; border:1px solid var(--border); background:#1a2650; color:var(--text); cursor:pointer; }
    button:hover { filter: brightness(1.08); }
    .muted { color: var(--muted); }
    .row { display:flex; gap:10px; align-items:center; }
    .row.wrap { flex-wrap: wrap; }
    .pill { display:inline-block; padding: 2px 8px; border:1px solid var(--border); border-radius:999px; font-size:12px; color:var(--muted); }
    .right { margin-left:auto; }
    .danger { color: var(--danger); }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; }
    .hr { height:1px; background: var(--border); margin: 12px 0; }
    .small { font-size: 12px; }
    .kvs { display:grid; grid-template-columns: 160px 1fr; gap: 6px 12px; }
  </style>
</head>
<body>
<header>
  <div class="row">
    <div class="row wrap">
      <strong>Policy-to-Code</strong>
      <span class="pill">MVP</span>
      <a href="/">Policies</a>
      <a href="/policies/new">New Policy</a>
    </div>
    <div class="row muted small">${escapeHtml(new Date().toISOString())}</div>
  </div>
</header>
<main>
${body}
</main>
</body>
</html>`;
}

function ensureDir(p) {
  const dir = path.dirname(p);
  fs.mkdirSync(dir, { recursive: true });
}

function initDb() {
  ensureDir(DB_PATH);
  const db = new Database(DB_PATH);
  db.pragma('journal_mode = WAL');
  db.exec(`
    CREATE TABLE IF NOT EXISTS policies (
      id TEXT PRIMARY KEY,
      title TEXT NOT NULL,
      jurisdiction TEXT,
      program TEXT,
      source_citation TEXT,
      effective_date TEXT,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS requirements (
      id TEXT PRIMARY KEY,
      policy_id TEXT NOT NULL,
      statement TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'draft',
      tags TEXT,
      created_at TEXT NOT NULL,
      FOREIGN KEY(policy_id) REFERENCES policies(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS decisions (
      id TEXT PRIMARY KEY,
      requirement_id TEXT NOT NULL,
      decision TEXT NOT NULL,
      rationale TEXT,
      alternatives TEXT,
      owner TEXT,
      status TEXT NOT NULL DEFAULT 'draft',
      approved_at TEXT,
      created_at TEXT NOT NULL,
      FOREIGN KEY(requirement_id) REFERENCES requirements(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS rules (
      id TEXT PRIMARY KEY,
      decision_id TEXT NOT NULL,
      name TEXT NOT NULL,
      version TEXT NOT NULL DEFAULT '0.1',
      definition_text TEXT NOT NULL,
      inputs TEXT,
      exceptions TEXT,
      created_at TEXT NOT NULL,
      FOREIGN KEY(decision_id) REFERENCES decisions(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS test_cases (
      id TEXT PRIMARY KEY,
      rule_id TEXT NOT NULL,
      name TEXT NOT NULL,
      given_json TEXT NOT NULL,
      expected_json TEXT NOT NULL,
      notes TEXT,
      created_at TEXT NOT NULL,
      FOREIGN KEY(rule_id) REFERENCES rules(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_requirements_policy_id ON requirements(policy_id);
    CREATE INDEX IF NOT EXISTS idx_decisions_requirement_id ON decisions(requirement_id);
    CREATE INDEX IF NOT EXISTS idx_rules_decision_id ON rules(decision_id);
    CREATE INDEX IF NOT EXISTS idx_test_cases_rule_id ON test_cases(rule_id);
  `);
  return db;
}

const db = initDb();

// ---------- queries ----------
const q = {
  listPolicies: db.prepare('SELECT * FROM policies ORDER BY created_at DESC'),
  getPolicy: db.prepare('SELECT * FROM policies WHERE id = ?'),
  insertPolicy: db.prepare(`INSERT INTO policies (id, title, jurisdiction, program, source_citation, effective_date, created_at)
    VALUES (@id,@title,@jurisdiction,@program,@source_citation,@effective_date,@created_at)`),

  listRequirements: db.prepare('SELECT * FROM requirements WHERE policy_id = ? ORDER BY created_at ASC'),
  getRequirement: db.prepare('SELECT * FROM requirements WHERE id = ?'),
  insertRequirement: db.prepare(`INSERT INTO requirements (id, policy_id, statement, status, tags, created_at)
    VALUES (@id,@policy_id,@statement,@status,@tags,@created_at)`),

  listDecisionsByRequirement: db.prepare('SELECT * FROM decisions WHERE requirement_id = ? ORDER BY created_at ASC'),
  getDecision: db.prepare('SELECT * FROM decisions WHERE id = ?'),
  insertDecision: db.prepare(`INSERT INTO decisions (id, requirement_id, decision, rationale, alternatives, owner, status, approved_at, created_at)
    VALUES (@id,@requirement_id,@decision,@rationale,@alternatives,@owner,@status,@approved_at,@created_at)`),

  listRulesByDecision: db.prepare('SELECT * FROM rules WHERE decision_id = ? ORDER BY created_at ASC'),
  getRule: db.prepare('SELECT * FROM rules WHERE id = ?'),
  insertRule: db.prepare(`INSERT INTO rules (id, decision_id, name, version, definition_text, inputs, exceptions, created_at)
    VALUES (@id,@decision_id,@name,@version,@definition_text,@inputs,@exceptions,@created_at)`),

  listTestCasesByRule: db.prepare('SELECT * FROM test_cases WHERE rule_id = ? ORDER BY created_at ASC'),
  insertTestCase: db.prepare(`INSERT INTO test_cases (id, rule_id, name, given_json, expected_json, notes, created_at)
    VALUES (@id,@rule_id,@name,@given_json,@expected_json,@notes,@created_at)`)
};

// ---------- routes ----------
app.get('/', (req, res) => {
  const policies = q.listPolicies.all();
  const body = `
    <div class="card">
      <h1 style="margin:0">Policies</h1>
      <p class="muted">Create a policy, break it into requirements, capture decisions (ADRs), define rules, add test cases, and export an audit-ready report.</p>
    </div>
    <div class="card">
      <div class="row">
        <h2 style="margin:0">All policies</h2>
        <div class="right"><a href="/policies/new">+ New Policy</a></div>
      </div>
      <div class="hr"></div>
      ${policies.length ? `<ul>
        ${policies.map(p => `<li style="margin: 8px 0">
          <a href="/policies/${p.id}"><strong>${escapeHtml(p.title)}</strong></a>
          <div class="muted small">${escapeHtml(p.jurisdiction || '—')} • ${escapeHtml(p.program || '—')} • effective: ${escapeHtml(p.effective_date || '—')}</div>
        </li>`).join('')}
      </ul>` : `<p class="muted">No policies yet.</p>`}
    </div>
  `;
  res.type('html').send(page('Policies', body));
});

app.get('/policies/new', (req, res) => {
  const body = `
    <div class="card">
      <h1 style="margin:0">New Policy</h1>
      <p class="muted">Government-specific policy intake. Keep it structured.</p>
    </div>

    <form class="card grid" method="post" action="/policies">
      <div>
        <label>Title</label>
        <input name="title" required placeholder="e.g., HR1 Work Requirements" />
      </div>
      <div class="grid grid2">
        <div>
          <label>Jurisdiction</label>
          <input name="jurisdiction" placeholder="e.g., Federal / State of X" />
        </div>
        <div>
          <label>Program</label>
          <input name="program" placeholder="e.g., Medicaid" />
        </div>
      </div>
      <div class="grid grid2">
        <div>
          <label>Effective date (ISO)</label>
          <input name="effective_date" placeholder="YYYY-MM-DD" />
        </div>
        <div>
          <label>Source citation / URL</label>
          <input name="source_citation" placeholder="Law, CFR, memo link, etc." />
        </div>
      </div>
      <div class="row">
        <button type="submit">Create policy</button>
        <a class="muted" href="/">Cancel</a>
      </div>
    </form>
  `;
  res.type('html').send(page('New Policy', body));
});

app.post('/policies', (req, res) => {
  const id = nanoid();
  const now = new Date().toISOString();
  q.insertPolicy.run({
    id,
    title: req.body.title?.trim(),
    jurisdiction: req.body.jurisdiction?.trim() || null,
    program: req.body.program?.trim() || null,
    source_citation: req.body.source_citation?.trim() || null,
    effective_date: req.body.effective_date?.trim() || null,
    created_at: now
  });
  res.redirect(`/policies/${id}`);
});

app.get('/policies/:policyId', (req, res) => {
  const policy = q.getPolicy.get(req.params.policyId);
  if (!policy) return res.status(404).type('html').send(page('Not found', `<div class="card"><h1>Not found</h1></div>`));

  const requirements = q.listRequirements.all(policy.id);

  const body = `
    <div class="card">
      <div class="row wrap">
        <div>
          <h1 style="margin:0">${escapeHtml(policy.title)}</h1>
          <div class="muted small">Policy ID: <span class="mono">${escapeHtml(policy.id)}</span></div>
        </div>
        <div class="right row wrap">
          <a href="/policies/${policy.id}/export">Export report</a>
        </div>
      </div>
      <div class="hr"></div>
      <div class="kvs">
        <div class="muted">Jurisdiction</div><div>${escapeHtml(policy.jurisdiction || '—')}</div>
        <div class="muted">Program</div><div>${escapeHtml(policy.program || '—')}</div>
        <div class="muted">Effective</div><div>${escapeHtml(policy.effective_date || '—')}</div>
        <div class="muted">Citation</div><div>${policy.source_citation ? `<a href="${escapeHtml(policy.source_citation)}" target="_blank" rel="noreferrer">${escapeHtml(policy.source_citation)}</a>` : '—'}</div>
      </div>
    </div>

    <div class="card">
      <h2 style="margin:0">Requirements</h2>
      <p class="muted">Each requirement should be atomic and testable.</p>
      <form class="grid" method="post" action="/policies/${policy.id}/requirements">
        <div>
          <label>Requirement statement</label>
          <textarea name="statement" required placeholder="e.g., Individuals age 19–55 must meet 80 hours/month work requirement unless exempt."></textarea>
        </div>
        <div class="grid grid2">
          <div>
            <label>Status</label>
            <select name="status">
              <option value="draft">draft</option>
              <option value="approved">approved</option>
              <option value="superseded">superseded</option>
            </select>
          </div>
          <div>
            <label>Tags (comma-separated)</label>
            <input name="tags" placeholder="eligibility,work-requirements" />
          </div>
        </div>
        <div class="row">
          <button type="submit">Add requirement</button>
        </div>
      </form>
      <div class="hr"></div>
      ${requirements.length ? requirements.map(r => {
        const decisions = q.listDecisionsByRequirement.all(r.id);
        return `
          <div class="card" style="background:#0e1530">
            <div class="row wrap">
              <div>
                <div class="pill">Requirement</div>
                <h3 style="margin:8px 0 4px 0">${escapeHtml(r.statement)}</h3>
                <div class="muted small">status: <span class="mono">${escapeHtml(r.status)}</span>${r.tags ? ` • tags: ${escapeHtml(r.tags)}` : ''}</div>
              </div>
            </div>

            <div class="hr"></div>

            <div class="grid grid2">
              <div>
                <h4 style="margin:0">Decisions (ADRs)</h4>
                ${decisions.length ? `<ul>${decisions.map(d => `<li style="margin:8px 0"><a href="/decisions/${d.id}">${escapeHtml(d.decision.slice(0, 80))}${d.decision.length>80?'…':''}</a> <span class="muted small">(${escapeHtml(d.status)})</span></li>`).join('')}</ul>` : `<p class="muted small">No decisions yet.</p>`}

                <form class="grid" method="post" action="/requirements/${r.id}/decisions">
                  <div>
                    <label>Decision</label>
                    <textarea name="decision" required placeholder="Approved interpretation / technical decision."></textarea>
                  </div>
                  <div>
                    <label>Rationale</label>
                    <textarea name="rationale" placeholder="Why this interpretation/implementation."></textarea>
                  </div>
                  <div class="grid grid2">
                    <div>
                      <label>Owner</label>
                      <input name="owner" placeholder="name / role" />
                    </div>
                    <div>
                      <label>Status</label>
                      <select name="status">
                        <option value="draft">draft</option>
                        <option value="approved">approved</option>
                        <option value="superseded">superseded</option>
                      </select>
                    </div>
                  </div>
                  <div>
                    <label>Alternatives considered</label>
                    <textarea name="alternatives" placeholder="Options and why rejected."></textarea>
                  </div>
                  <div class="row"><button type="submit">Add decision</button></div>
                </form>
              </div>

              <div>
                <h4 style="margin:0">Rules + Test Cases</h4>
                <p class="muted small">Create a decision first, then add rules and test cases.</p>
                ${decisions.length ? `<ul>
                  ${decisions.map(d => {
                    const rules = q.listRulesByDecision.all(d.id);
                    return `<li style="margin:10px 0">
                      <div><a href="/decisions/${d.id}"><strong>${escapeHtml(d.decision.slice(0, 60))}${d.decision.length>60?'…':''}</strong></a> <span class="muted small">(${escapeHtml(d.status)})</span></div>
                      ${rules.length ? `<ul>${rules.map(rule => {
                        const tcs = q.listTestCasesByRule.all(rule.id);
                        return `<li class="small" style="margin:6px 0">
                          <a href="/rules/${rule.id}">${escapeHtml(rule.name)}</a>
                          <span class="muted">v${escapeHtml(rule.version)} • ${tcs.length} test(s)</span>
                        </li>`;
                      }).join('')}</ul>` : `<div class="muted small">No rules yet.</div>`}
                    </li>`;
                  }).join('')}
                </ul>` : ''}
              </div>
            </div>
          </div>
        `;
      }).join('') : `<p class="muted">No requirements yet.</p>`}
    </div>
  `;

  res.type('html').send(page(policy.title, body));
});

app.post('/policies/:policyId/requirements', (req, res) => {
  const policyId = req.params.policyId;
  const policy = q.getPolicy.get(policyId);
  if (!policy) return res.status(404).send('Policy not found');

  const id = nanoid();
  const now = new Date().toISOString();
  q.insertRequirement.run({
    id,
    policy_id: policyId,
    statement: req.body.statement?.trim(),
    status: req.body.status?.trim() || 'draft',
    tags: req.body.tags?.trim() || null,
    created_at: now
  });
  res.redirect(`/policies/${policyId}`);
});

app.post('/requirements/:reqId/decisions', (req, res) => {
  const requirement = q.getRequirement.get(req.params.reqId);
  if (!requirement) return res.status(404).send('Requirement not found');

  const id = nanoid();
  const now = new Date().toISOString();
  const status = req.body.status?.trim() || 'draft';
  q.insertDecision.run({
    id,
    requirement_id: requirement.id,
    decision: req.body.decision?.trim(),
    rationale: req.body.rationale?.trim() || null,
    alternatives: req.body.alternatives?.trim() || null,
    owner: req.body.owner?.trim() || null,
    status,
    approved_at: status === 'approved' ? now : null,
    created_at: now
  });

  res.redirect(`/policies/${requirement.policy_id}`);
});

app.get('/decisions/:decisionId', (req, res) => {
  const decision = q.getDecision.get(req.params.decisionId);
  if (!decision) return res.status(404).type('html').send(page('Not found', `<div class="card"><h1>Not found</h1></div>`));

  const requirement = q.getRequirement.get(decision.requirement_id);
  const policy = q.getPolicy.get(requirement.policy_id);
  const rules = q.listRulesByDecision.all(decision.id);

  const body = `
    <div class="card">
      <div class="row wrap">
        <div>
          <div class="pill">Decision (ADR)</div>
          <h1 style="margin:8px 0 4px 0">${escapeHtml(decision.decision)}</h1>
          <div class="muted small">status: <span class="mono">${escapeHtml(decision.status)}</span> • owner: ${escapeHtml(decision.owner || '—')} • decision id: <span class="mono">${escapeHtml(decision.id)}</span></div>
        </div>
        <div class="right"><a href="/policies/${policy.id}">← Back to policy</a></div>
      </div>
      <div class="hr"></div>
      <div class="muted small">Requirement</div>
      <div>${escapeHtml(requirement.statement)}</div>

      <div class="hr"></div>
      <div class="grid grid2">
        <div>
          <div class="muted small">Rationale</div>
          <div>${decision.rationale ? escapeHtml(decision.rationale).replaceAll('\n','<br/>') : '<span class="muted">—</span>'}</div>
        </div>
        <div>
          <div class="muted small">Alternatives</div>
          <div>${decision.alternatives ? escapeHtml(decision.alternatives).replaceAll('\n','<br/>') : '<span class="muted">—</span>'}</div>
        </div>
      </div>
    </div>

    <div class="card">
      <div class="row">
        <h2 style="margin:0">Rules</h2>
        <div class="right"><span class="muted small">Define implementation logic for the decision.</span></div>
      </div>
      <div class="hr"></div>
      ${rules.length ? `<ul>${rules.map(r => {
        const tcs = q.listTestCasesByRule.all(r.id);
        return `<li style="margin:10px 0">
          <a href="/rules/${r.id}"><strong>${escapeHtml(r.name)}</strong></a>
          <span class="muted small">v${escapeHtml(r.version)} • ${tcs.length} test(s)</span>
        </li>`;
      }).join('')}</ul>` : `<p class="muted">No rules yet.</p>`}

      <div class="hr"></div>
      <form class="grid" method="post" action="/decisions/${decision.id}/rules">
        <div class="grid grid2">
          <div>
            <label>Rule name</label>
            <input name="name" required placeholder="e.g., WorkRequirementEligibility" />
          </div>
          <div>
            <label>Version</label>
            <input name="version" placeholder="0.1" />
          </div>
        </div>
        <div>
          <label>Definition (start as pseudo / structured text)</label>
          <textarea name="definition_text" required placeholder="IF age < 19 THEN exempt\nIF pregnant THEN exempt\nIF hours < 80 THEN non-compliant..."></textarea>
        </div>
        <div class="grid grid2">
          <div>
            <label>Inputs (comma-separated)</label>
            <input name="inputs" placeholder="age,pregnant,hoursWorked" />
          </div>
          <div>
            <label>Exceptions / edge cases</label>
            <input name="exceptions" placeholder="missing hours; conflicting sources" />
          </div>
        </div>
        <div class="row"><button type="submit">Add rule</button></div>
      </form>
    </div>
  `;

  res.type('html').send(page('Decision', body));
});

app.post('/decisions/:decisionId/rules', (req, res) => {
  const decision = q.getDecision.get(req.params.decisionId);
  if (!decision) return res.status(404).send('Decision not found');

  const id = nanoid();
  const now = new Date().toISOString();
  q.insertRule.run({
    id,
    decision_id: decision.id,
    name: req.body.name?.trim(),
    version: req.body.version?.trim() || '0.1',
    definition_text: req.body.definition_text?.trim(),
    inputs: req.body.inputs?.trim() || null,
    exceptions: req.body.exceptions?.trim() || null,
    created_at: now
  });

  res.redirect(`/decisions/${decision.id}`);
});

app.get('/rules/:ruleId', (req, res) => {
  const rule = q.getRule.get(req.params.ruleId);
  if (!rule) return res.status(404).type('html').send(page('Not found', `<div class="card"><h1>Not found</h1></div>`));

  const decision = q.getDecision.get(rule.decision_id);
  const requirement = q.getRequirement.get(decision.requirement_id);
  const policy = q.getPolicy.get(requirement.policy_id);
  const testCases = q.listTestCasesByRule.all(rule.id);

  const body = `
    <div class="card">
      <div class="row wrap">
        <div>
          <div class="pill">Rule</div>
          <h1 style="margin:8px 0 4px 0">${escapeHtml(rule.name)} <span class="muted">v${escapeHtml(rule.version)}</span></h1>
          <div class="muted small">rule id: <span class="mono">${escapeHtml(rule.id)}</span></div>
        </div>
        <div class="right"><a href="/decisions/${decision.id}">← Back to decision</a></div>
      </div>
      <div class="hr"></div>
      <div class="muted small">Definition</div>
      <pre class="mono" style="white-space:pre-wrap; background:#0b1020; padding:12px; border-radius:12px; border:1px solid var(--border)">${escapeHtml(rule.definition_text)}</pre>
      <div class="row wrap small muted">
        <div>Inputs: <span class="mono">${escapeHtml(rule.inputs || '—')}</span></div>
        <div>Exceptions: <span class="mono">${escapeHtml(rule.exceptions || '—')}</span></div>
      </div>
      <div class="hr"></div>
      <div class="muted small">Traceability</div>
      <div class="small">
        Policy: <a href="/policies/${policy.id}">${escapeHtml(policy.title)}</a><br/>
        Requirement: ${escapeHtml(requirement.statement)}<br/>
        Decision: ${escapeHtml(decision.decision)}
      </div>
    </div>

    <div class="card">
      <div class="row">
        <h2 style="margin:0">Test Cases</h2>
        <div class="right muted small">Given/Expected stored as JSON strings (start simple; we can evolve).</div>
      </div>
      <div class="hr"></div>

      ${testCases.length ? `<ul>${testCases.map(tc => `
        <li style="margin: 12px 0">
          <strong>${escapeHtml(tc.name)}</strong>
          ${tc.notes ? `<div class="muted small">${escapeHtml(tc.notes)}</div>` : ''}
          <div class="grid grid2" style="margin-top:8px">
            <div>
              <div class="muted small">Given</div>
              <pre class="mono" style="white-space:pre-wrap; background:#0b1020; padding:10px; border-radius:12px; border:1px solid var(--border)">${escapeHtml(tc.given_json)}</pre>
            </div>
            <div>
              <div class="muted small">Expected</div>
              <pre class="mono" style="white-space:pre-wrap; background:#0b1020; padding:10px; border-radius:12px; border:1px solid var(--border)">${escapeHtml(tc.expected_json)}</pre>
            </div>
          </div>
        </li>
      `).join('')}</ul>` : `<p class="muted">No test cases yet.</p>`}

      <div class="hr"></div>
      <form class="grid" method="post" action="/rules/${rule.id}/test-cases">
        <div>
          <label>Name</label>
          <input name="name" required placeholder="e.g., Pregnant exemption" />
        </div>
        <div class="grid grid2">
          <div>
            <label>Given (JSON)</label>
            <textarea name="given_json" required placeholder='{"age":25,"pregnant":true,"hoursWorked":0}'></textarea>
          </div>
          <div>
            <label>Expected (JSON)</label>
            <textarea name="expected_json" required placeholder='{"status":"exempt"}'></textarea>
          </div>
        </div>
        <div>
          <label>Notes</label>
          <input name="notes" placeholder="optional" />
        </div>
        <div class="row"><button type="submit">Add test case</button></div>
      </form>
    </div>
  `;

  res.type('html').send(page('Rule', body));
});

app.post('/rules/:ruleId/test-cases', (req, res) => {
  const rule = q.getRule.get(req.params.ruleId);
  if (!rule) return res.status(404).send('Rule not found');

  const id = nanoid();
  const now = new Date().toISOString();
  q.insertTestCase.run({
    id,
    rule_id: rule.id,
    name: req.body.name?.trim(),
    given_json: req.body.given_json?.trim(),
    expected_json: req.body.expected_json?.trim(),
    notes: req.body.notes?.trim() || null,
    created_at: now
  });

  res.redirect(`/rules/${rule.id}`);
});

app.get('/policies/:policyId/export', (req, res) => {
  const policy = q.getPolicy.get(req.params.policyId);
  if (!policy) return res.status(404).type('text').send('Not found');

  const requirements = q.listRequirements.all(policy.id);

  let out = '';
  out += `# Policy Implementation Report\n\n`;
  out += `- **Title:** ${policy.title}\n`;
  out += `- **Policy ID:** ${policy.id}\n`;
  out += `- **Jurisdiction:** ${policy.jurisdiction || '—'}\n`;
  out += `- **Program:** ${policy.program || '—'}\n`;
  out += `- **Effective date:** ${policy.effective_date || '—'}\n`;
  out += `- **Citation:** ${policy.source_citation || '—'}\n\n`;

  out += `## Requirements\n\n`;

  for (const r of requirements) {
    out += `### Requirement: ${r.id}\n\n`;
    out += `${r.statement}\n\n`;
    out += `- Status: ${r.status}\n`;
    if (r.tags) out += `- Tags: ${r.tags}\n`;
    out += `\n`;

    const decisions = q.listDecisionsByRequirement.all(r.id);
    if (!decisions.length) {
      out += `> No decisions recorded yet.\n\n`;
      continue;
    }

    for (const d of decisions) {
      out += `#### Decision (ADR): ${d.id}\n\n`;
      out += `- Status: ${d.status}\n`;
      out += `- Owner: ${d.owner || '—'}\n`;
      if (d.approved_at) out += `- Approved at: ${d.approved_at}\n`;
      out += `\n`;
      out += `**Decision:**\n\n${d.decision}\n\n`;
      if (d.rationale) out += `**Rationale:**\n\n${d.rationale}\n\n`;
      if (d.alternatives) out += `**Alternatives:**\n\n${d.alternatives}\n\n`;

      const rules = q.listRulesByDecision.all(d.id);
      if (!rules.length) {
        out += `> No rules recorded for this decision yet.\n\n`;
        continue;
      }

      for (const rule of rules) {
        out += `##### Rule: ${rule.name} (v${rule.version})\n\n`;
        out += `- Rule ID: ${rule.id}\n`;
        if (rule.inputs) out += `- Inputs: ${rule.inputs}\n`;
        if (rule.exceptions) out += `- Exceptions: ${rule.exceptions}\n`;
        out += `\n`;
        out += "```\n" + rule.definition_text + "\n```\n\n";

        const tcs = q.listTestCasesByRule.all(rule.id);
        out += `**Test Cases (${tcs.length})**\n\n`;
        if (!tcs.length) {
          out += `> No test cases recorded yet.\n\n`;
        } else {
          for (const tc of tcs) {
            out += `- ${tc.name}\n`;
            out += `  - Given: \`${tc.given_json}\`\n`;
            out += `  - Expected: \`${tc.expected_json}\`\n`;
            if (tc.notes) out += `  - Notes: ${tc.notes}\n`;
          }
          out += `\n`;
        }
      }
    }
  }

  res.type('text/markdown').send(out);
});

app.listen(PORT, () => {
  console.log(`Policy-to-Code web app listening on http://127.0.0.1:${PORT}`);
  console.log(`DB: ${DB_PATH}`);
});
