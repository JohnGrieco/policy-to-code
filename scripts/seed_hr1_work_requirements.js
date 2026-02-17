#!/usr/bin/env node
import Database from 'better-sqlite3';
import fs from 'node:fs';
import path from 'node:path';
import { nanoid } from 'nanoid';

const DB_PATH = process.env.DB_PATH || './data/policy_to_code.sqlite';

function ensureDir(p) {
  fs.mkdirSync(path.dirname(p), { recursive: true });
}

function initSchema(db) {
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

    CREATE TABLE IF NOT EXISTS mappings (
      id TEXT PRIMARY KEY,
      target_type TEXT NOT NULL,
      target_id TEXT NOT NULL,
      type TEXT NOT NULL,
      ref TEXT NOT NULL,
      notes TEXT,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS evidence (
      id TEXT PRIMARY KEY,
      target_type TEXT NOT NULL,
      target_id TEXT NOT NULL,
      kind TEXT NOT NULL,
      ref TEXT NOT NULL,
      status TEXT,
      notes TEXT,
      created_at TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_requirements_policy_id ON requirements(policy_id);
    CREATE INDEX IF NOT EXISTS idx_decisions_requirement_id ON decisions(requirement_id);
    CREATE INDEX IF NOT EXISTS idx_rules_decision_id ON rules(decision_id);
    CREATE INDEX IF NOT EXISTS idx_test_cases_rule_id ON test_cases(rule_id);
    CREATE INDEX IF NOT EXISTS idx_mappings_target ON mappings(target_type, target_id);
    CREATE INDEX IF NOT EXISTS idx_mappings_type ON mappings(type);
    CREATE INDEX IF NOT EXISTS idx_evidence_target ON evidence(target_type, target_id);
    CREATE INDEX IF NOT EXISTS idx_evidence_kind ON evidence(kind);
  `);
}

function nowIso() {
  return new Date().toISOString();
}

function pick(arr, i) {
  return arr[i % arr.length];
}

ensureDir(DB_PATH);
const db = new Database(DB_PATH);
initSchema(db);

const q = {
  getPolicyByTitle: db.prepare('SELECT * FROM policies WHERE title = ?'),
  insertPolicy: db.prepare(`INSERT INTO policies (id,title,jurisdiction,program,source_citation,effective_date,created_at)
    VALUES (@id,@title,@jurisdiction,@program,@source_citation,@effective_date,@created_at)`),

  insertRequirement: db.prepare(`INSERT INTO requirements (id, policy_id, statement, status, tags, created_at)
    VALUES (@id,@policy_id,@statement,@status,@tags,@created_at)`),

  insertDecision: db.prepare(`INSERT INTO decisions (id, requirement_id, decision, rationale, alternatives, owner, status, approved_at, created_at)
    VALUES (@id,@requirement_id,@decision,@rationale,@alternatives,@owner,@status,@approved_at,@created_at)`),

  insertRule: db.prepare(`INSERT INTO rules (id, decision_id, name, version, definition_text, inputs, exceptions, created_at)
    VALUES (@id,@decision_id,@name,@version,@definition_text,@inputs,@exceptions,@created_at)`),

  insertTestCase: db.prepare(`INSERT INTO test_cases (id, rule_id, name, given_json, expected_json, notes, created_at)
    VALUES (@id,@rule_id,@name,@given_json,@expected_json,@notes,@created_at)`),

  insertMapping: db.prepare(`INSERT INTO mappings (id, target_type, target_id, type, ref, notes, created_at)
    VALUES (@id,@target_type,@target_id,@type,@ref,@notes,@created_at)`),

  insertEvidence: db.prepare(`INSERT INTO evidence (id, target_type, target_id, kind, ref, status, notes, created_at)
    VALUES (@id,@target_type,@target_id,@kind,@ref,@status,@notes,@created_at)`)
};

const TITLE = 'HR1 Work Requirements Policy';
let policy = q.getPolicyByTitle.get(TITLE);
if (!policy) {
  const policyRow = {
    id: nanoid(),
    title: TITLE,
    jurisdiction: 'US (Federal)',
    program: 'HR1 / Benefits Eligibility',
    source_citation: 'HR1 §101-§109 (Work Requirements)',
    effective_date: '2026-01-01',
    created_at: nowIso()
  };
  q.insertPolicy.run(policyRow);
  policy = policyRow;
  console.log('Created policy:', policy.id);
} else {
  console.log('Policy already exists:', policy.id);
}

const owners = ['Policy', 'Engineering', 'Compliance', 'Operations'];
const statuses = ['draft', 'in_review', 'approved'];

const requirementTemplates = [
  'Verify applicant identity and residency before evaluating work requirements.',
  'Determine whether the applicant is exempt from work requirements based on age, disability, pregnancy, or caregiver status.',
  'Calculate required work hours per month based on household composition and program tier.',
  'Ingest and validate employer wage records and/or timesheets as evidence of work participation.',
  'Apply grace periods for newly enrolled applicants (first 60 days).',
  'Handle partial-month eligibility with prorated work hour requirements.',
  'Detect and flag inconsistent reporting between self-attestation and wage records.',
  'Issue notices to applicants when non-compliance is detected and provide appeal window.',
  'Record appeals and pause adverse action until appeal resolution.',
  'Apply sanctions after repeated non-compliance and track sanction period.',
  'Provide audit trail: decisions, rule versions, tests, and evidence must be traceable.',
  'Export an audit-ready report for the policy covering requirement-to-evidence traceability.'
];

const tagsFor = (i) => {
  const base = ['hr1', 'work-req', 'eligibility'];
  if (i % 3 === 0) base.push('identity');
  if (i % 3 === 1) base.push('exemptions');
  if (i % 3 === 2) base.push('compliance');
  return base.join(',');
};

const tx = db.transaction(() => {
  const created = [];

  for (let i = 0; i < requirementTemplates.length; i++) {
    const reqId = nanoid();

    // Create intentional gaps so the dashboard has interesting “Gaps”
    const status = pick(statuses, i);

    q.insertRequirement.run({
      id: reqId,
      policy_id: policy.id,
      statement: requirementTemplates[i],
      status,
      tags: tagsFor(i),
      created_at: nowIso()
    });

    // Decisions: most requirements get a decision, some don’t
    const createDecision = i !== 10; // leave one without a decision
    if (!createDecision) {
      created.push({ reqId, decisionId: null, ruleId: null, note: 'gap: no decision' });
      continue;
    }

    const decisionId = nanoid();
    const approved = i % 4 !== 1; // 3/4 approved

    q.insertDecision.run({
      id: decisionId,
      requirement_id: reqId,
      decision: `Decision for R${i + 1}: ${requirementTemplates[i]}`,
      rationale: 'Automate with deterministic rules; fall back to manual review for ambiguous cases.',
      alternatives: 'Manual-only review; third-party eligibility engine.',
      owner: pick(owners, i),
      status: approved ? 'approved' : 'draft',
      approved_at: approved ? nowIso() : null,
      created_at: nowIso()
    });

    // Rules: some decisions have rules, some don’t
    const createRule = i % 5 !== 2; // leave gaps
    if (!createRule) {
      created.push({ reqId, decisionId, ruleId: null, note: 'gap: no rule' });
      continue;
    }

    const ruleId = nanoid();
    q.insertRule.run({
      id: ruleId,
      decision_id: decisionId,
      name: `HR1-R${String(i + 1).padStart(2, '0')}-Rule`,
      version: '0.1',
      definition_text: `IF requirement R${i + 1} applies THEN evaluate according to HR1 policy guidance.\n\nImplementation notes: deterministic checks + clear exception paths.`,
      inputs: JSON.stringify({
        applicant: ['dob', 'disability_status', 'pregnancy_status', 'caregiver_status'],
        evidence: ['wage_records', 'timesheets', 'self_attestation'],
        context: ['coverage_month', 'program_tier']
      }, null, 2),
      exceptions: JSON.stringify({
        exemptions: ['age', 'disability', 'pregnancy', 'caregiver'],
        grace_period_days: 60,
        appeal_hold: true
      }, null, 2),
      created_at: nowIso()
    });

    // Test cases: some rules have tests, some don’t
    const createTests = i % 4 !== 3;
    if (createTests) {
      const tc1 = {
        id: nanoid(),
        rule_id: ruleId,
        name: 'Meets requirement - standard case',
        given_json: JSON.stringify({ applicant: { id: 'A-100', disability_status: false }, evidence: { hours_worked: 90 }, context: { required_hours: 80 } }, null, 2),
        expected_json: JSON.stringify({ eligible: true, reason: 'meets_work_requirement' }, null, 2),
        notes: 'baseline happy path',
        created_at: nowIso()
      };
      const tc2 = {
        id: nanoid(),
        rule_id: ruleId,
        name: 'Does not meet requirement - insufficient hours',
        given_json: JSON.stringify({ applicant: { id: 'A-101', disability_status: false }, evidence: { hours_worked: 20 }, context: { required_hours: 80 } }, null, 2),
        expected_json: JSON.stringify({ eligible: false, reason: 'insufficient_hours', notice_required: true }, null, 2),
        notes: 'non-compliance path',
        created_at: nowIso()
      };
      q.insertTestCase.run(tc1);
      q.insertTestCase.run(tc2);
    }

    // Mappings (impact): attach to decision and rule
    const mappingTypes = ['service', 'api', 'data', 'integration', 'security'];
    q.insertMapping.run({
      id: nanoid(),
      target_type: 'decision',
      target_id: decisionId,
      type: pick(mappingTypes, i),
      ref: pick(['eligibility-service', 'case-service', 'audit-service', 'notice-service'], i),
      notes: 'Affected component for implementation traceability.',
      created_at: nowIso()
    });
    q.insertMapping.run({
      id: nanoid(),
      target_type: 'rule',
      target_id: ruleId,
      type: pick(mappingTypes, i + 2),
      ref: pick(['POST /eligibility/evaluate', 'GET /evidence/wages', 'topic:compliance-events', 'db:case_events'], i + 1),
      notes: 'System touchpoint for the rule.',
      created_at: nowIso()
    });

    // Evidence: some rules/decisions have evidence, some don’t
    const addEvidence = i % 3 !== 1;
    if (addEvidence) {
      q.insertEvidence.run({
        id: nanoid(),
        target_type: 'decision',
        target_id: decisionId,
        kind: 'doc',
        ref: `ADR-${String(i + 1).padStart(3, '0')}`, 
        status: 'approved',
        notes: 'Architecture decision record.',
        created_at: nowIso()
      });
      q.insertEvidence.run({
        id: nanoid(),
        target_type: 'rule',
        target_id: ruleId,
        kind: 'pr',
        ref: `https://github.com/JohnGrieco/policy-to-code/pull/${100 + i}`,
        status: 'draft',
        notes: 'Implementation PR link placeholder for demo data.',
        created_at: nowIso()
      });
    }

    created.push({ reqId, decisionId, ruleId, note: 'ok' });
  }

  return created;
});

const created = tx();

const counts = {
  requirements: db.prepare('SELECT count(*) c FROM requirements WHERE policy_id = ?').get(policy.id).c,
  decisions: db.prepare('SELECT count(*) c FROM decisions WHERE requirement_id IN (SELECT id FROM requirements WHERE policy_id = ?)').get(policy.id).c,
  rules: db.prepare('SELECT count(*) c FROM rules WHERE decision_id IN (SELECT id FROM decisions WHERE requirement_id IN (SELECT id FROM requirements WHERE policy_id = ?))').get(policy.id).c,
  tests: db.prepare('SELECT count(*) c FROM test_cases WHERE rule_id IN (SELECT id FROM rules WHERE decision_id IN (SELECT id FROM decisions WHERE requirement_id IN (SELECT id FROM requirements WHERE policy_id = ?)))').get(policy.id).c,
  mappings: db.prepare('SELECT count(*) c FROM mappings').get().c,
  evidence: db.prepare('SELECT count(*) c FROM evidence').get().c
};

console.log('Seed complete for policy:', policy.title);
console.log('Counts:', counts);

const gaps = created.filter(x => x.note !== 'ok');
if (gaps.length) {
  console.log('Intentional gaps (for dashboard realism):');
  for (const g of gaps) console.log('-', g.note, g.reqId);
}
