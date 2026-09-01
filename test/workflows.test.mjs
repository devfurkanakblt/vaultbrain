import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { DocumentVault } from "../dist/documents.js";
import { parseFrontmatter } from "../dist/frontmatter.js";
import { createFromTemplate, openDailyNote, parseLocalDate, renderTemplateText } from "../dist/templates.js";

const PASSPHRASE = "workflow-test-passphrase";

function tempVault() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "vault-brain-workflow-test-"));
}

test("Obsidian-style YAML frontmatter imports nested properties and exports valid YAML", () => {
  const vault = new DocumentVault(tempVault(), PASSPHRASE);
  const markdown = [
    "---",
    "title: Project Delta",
    "aliases:",
    "  - Delta",
    "  - D Project",
    "tags: [project, '#urgent']",
    "due: 2026-09-15",
    "nested:",
    "  active: true",
    "  score: 9.5",
    "description: |",
    "  first line",
    "  second line",
    "---",
    "# Delta",
    "Body with #inline-tag.",
  ].join("\n");
  const note = vault.importMarkdown("Projects/Delta.md", markdown);
  assert.equal(note.title, "Project Delta");
  assert.deepEqual(note.aliases, ["Delta", "D Project"]);
  assert.deepEqual(note.tags, ["project", "urgent", "inline-tag"]);
  assert.equal(note.properties.due, "2026-09-15");
  assert.deepEqual(note.properties.nested, { active: true, score: 9.5 });
  assert.equal(note.properties.description, "first line\nsecond line\n");

  const portable = vault.exportMarkdown(note.id);
  const parsed = parseFrontmatter(portable);
  assert.equal(parsed.attributes.vbrain_id, note.id);
  assert.equal(parsed.attributes.due, "2026-09-15");
  assert.deepEqual(parsed.attributes.nested, { active: true, score: 9.5 });
  assert.equal(parsed.body, note.body);
});

test("frontmatter rejects duplicate, aliased and prototype-shaping input", () => {
  assert.throws(() => parseFrontmatter("---\na: 1\na: 2\n---\nbody"), /Invalid YAML/iu);
  assert.throws(() => parseFrontmatter("---\na: &shared [1, 2]\nb: *shared\n---\nbody"));
  assert.throws(() => parseFrontmatter("---\n__proto__: unsafe\n---\nbody"), /Unsafe frontmatter key/iu);
});

test("templates render deterministic safe variables into body and properties", () => {
  const vault = new DocumentVault(tempVault(), PASSPHRASE);
  const template = vault.put({
    path: "Templates/Meeting.md",
    title: "Meeting Template",
    body: "# {{title}}\nDate: {{date:YYYY-MM-DD}}\nClient: {{client}}\nUnknown: {{kept}}",
    tags: ["template", "meeting"],
    properties: { client: "{{client}}", scheduled: "{{date:YYYY-MM-DD}}" },
  });
  const created = createFromTemplate(vault, template.id, "Meetings/Kickoff", {
    title: "Kickoff",
    date: parseLocalDate("2026-09-15"),
    variables: { client: "Acme" },
    tags: ["important"],
  });
  assert.match(created.body, /^# Kickoff/mu);
  assert.match(created.body, /Date: 2026-09-15/u);
  assert.match(created.body, /Client: Acme/u);
  assert.match(created.body, /Unknown: \{\{kept\}\}/u);
  assert.deepEqual(created.tags, ["meeting", "important"]);
  assert.deepEqual(created.properties, { client: "Acme", scheduled: "2026-09-15" });

  assert.equal(
    renderTemplateText("{{date:YYYY/MM/DD}} {{time:HH:mm}}", {
      title: "x",
      path: "x.md",
      date: new Date(2026, 8, 15, 9, 7),
    }),
    "2026/09/15 09:07",
  );
});

test("daily notes are date-valid, templated and idempotent", () => {
  const vault = new DocumentVault(tempVault(), PASSPHRASE);
  const template = vault.put({
    path: "Templates/Daily.md",
    title: "Daily Template",
    body: "# {{date:YYYY-MM-DD}}\n\nToday is {{title}}.",
    tags: ["template"],
    properties: { generated: "{{date:YYYY-MM-DD}}" },
  });
  const date = parseLocalDate("2026-08-30");
  const first = openDailyNote(vault, date, {
    folder: "Journal",
    filenameFormat: "YYYY/MM/DD",
    template: template.id,
  });
  const second = openDailyNote(vault, date, {
    folder: "Journal",
    filenameFormat: "YYYY/MM/DD",
    template: template.id,
  });
  assert.equal(first.created, true);
  assert.equal(second.created, false);
  assert.equal(first.note.id, second.note.id);
  assert.equal(first.note.path, "Journal/2026/08/30.md");
  assert.match(first.note.body, /# 2026-08-30/u);
  assert.deepEqual(first.note.tags, ["daily"]);
  assert.equal(first.note.properties.date, "2026-08-30");
  assert.equal(first.note.properties.generated, "2026-08-30");
  assert.throws(() => parseLocalDate("2026-02-30"), /Invalid calendar date/iu);
});
