# policy-to-code

Government-specific traceability MVP: **Policy → Requirements → Decisions (ADRs) → Rules → Test Cases → Export (audit report)**.

This repo is currently a “bootstrap + build” workspace.

## MVP (current)

- Create **Policies**
- Add **Requirements**
- Capture **Decisions (ADRs)**
- Define **Rules** (versioned text for now)
- Add **Test Cases** (Given/Expected JSON)
- Export a **Policy Implementation Report** (Markdown)

## Run locally

```bash
cd policy-to-code
npm install
npm run dev
```

Then open: http://127.0.0.1:3000

### Data storage

By default the app uses SQLite at:

- `./data/policy_to_code.sqlite`

Override with:

- `DB_PATH=/some/path.sqlite npm run dev`

## Next milestones

- Better exports (HTML/PDF “audit packet”)
- Architecture mapping (services/APIs/tables/integrations)
- Evidence objects (manual first)
- Azure DevOps integration (later)
