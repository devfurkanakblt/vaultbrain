//! Save-path measurement for the desktop core.
//!
//! Every budget in `docs/PRODUCT.md` is a desktop interaction, and the desktop
//! runs this crate — but until now the only performance harness in the
//! repository was `scripts/benchmark.mjs`, which measures the TypeScript
//! library behind the CLI and the MCP server. The desktop save path had no
//! measurement at all, which is how it came to carry the same whole-index
//! rewrite the 2026-09-19 review found in TypeScript without anyone noticing.
//!
//! This module closes that gap. It drives the same operations the desktop
//! commands drive, against a disposable vault, and reports p50/p95 the way the
//! TypeScript benchmark does so the two are comparable.
//!
//! Compiled only under the `benchmark` feature, so none of it ships in the
//! desktop binary.

use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

use uuid::Uuid;

use crate::{
    analyze_markdown, empty_object, encrypt, note_aad, note_path, now, open_session,
    rebuild_derived, save_existing_note, save_index, write_atomic, DocumentIndex, IndexedNote,
    NoteDocument, VaultSession,
};

const PASSPHRASE: &str = "benchmark-only-passphrase";

/// One measured operation, in milliseconds.
#[derive(Debug, Clone, Copy)]
pub struct Stats {
    pub p50: f64,
    pub p95: f64,
    pub max: f64,
}

impl Stats {
    fn from(mut samples: Vec<f64>) -> Self {
        samples.sort_by(|left, right| left.partial_cmp(right).unwrap());
        let at = |quantile: f64| {
            let index = ((samples.len() as f64) * quantile).ceil() as usize;
            samples[index.saturating_sub(1).min(samples.len() - 1)]
        };
        Self {
            p50: at(0.5),
            p95: at(0.95),
            max: *samples.last().unwrap(),
        }
    }
}

/// What one tier measured.
#[derive(Debug)]
pub struct Report {
    pub notes: usize,
    pub bulk_create_ms: f64,
    pub unlock_and_index_ms: f64,
    pub save: Stats,
    pub index_bytes: u64,
}

fn millis(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}

/// A corpus shaped like the one `scripts/benchmark.mjs` builds, so the two
/// harnesses measure comparable work: wikilinked, tagged, with properties.
fn corpus_note(index: usize) -> NoteDocument {
    let timestamp = now();
    let body = if index > 0 {
        format!(
            "# Note {index}\ntoken{} and some recall text.\nPrevious: [[Corpus/Note-{:06}]].\n#group-{}\n",
            index % 100,
            index - 1,
            index % 20
        )
    } else {
        format!(
            "# Note {index}\ntoken0 and some recall text.\nRoot.\n#group-0\n"
        )
    };
    NoteDocument {
        version: 1,
        id: Uuid::new_v4().to_string(),
        path: format!("Corpus/Note-{index:06}.md"),
        title: format!("Note {index}"),
        body,
        aliases: vec![],
        tags: vec![],
        properties: empty_object(),
        created_at: timestamp.clone(),
        updated_at: timestamp,
        revision: 1,
        frontmatter_source: None,
    }
}

/// Builds the corpus without going through `store_note` per note.
///
/// The desktop has no bulk path, and driving 100,000 single saves through the
/// very path this benchmark exists to measure would take hours at the current
/// cost. The objects and the index are written exactly as `store_note` leaves
/// them; only the per-note index rewrite is skipped.
fn build_corpus(session: &mut VaultSession, notes: usize) -> Result<Vec<String>, String> {
    let mut ids = Vec::with_capacity(notes);
    let mut index = DocumentIndex::empty();
    for position in 0..notes {
        let note = corpus_note(position);
        ids.push(note.id.clone());
        let payload = encrypt(
            &serde_json::to_vec(&note).map_err(|error| error.to_string())?,
            session.key.as_ref(),
            &note_aad(&note.id),
        )?;
        write_atomic(
            &note_path(&session.root_dir, &note.id)?,
            &serde_json::to_vec(&payload).map_err(|error| error.to_string())?,
        )?;
        let (links, headings) = analyze_markdown(&note.body)?;
        index.notes.insert(
            note.id.clone(),
            IndexedNote {
                note,
                links,
                headings,
            },
        );
    }
    session.index = index;
    rebuild_derived(&mut session.index);
    save_index(session)?;
    Ok(ids)
}

/// Opens an existing vault the way a desktop unlock does — snapshot plus
/// change log — and reports what it found.
///
/// The cross-core test in `test/cross-core-index-log.test.mjs` uses this to
/// prove the Rust core replays a log the TypeScript core wrote. The two cores
/// share the format, so each has to be able to demonstrate it reads the
/// other's work.
pub fn inspect(vault_path: &str, passphrase: &str) -> Result<String, String> {
    let session = open_session(vault_path, passphrase)?;
    let mut paths: Vec<&str> = session
        .index
        .notes
        .values()
        .map(|note| note.note.path.as_str())
        .collect();
    paths.sort_unstable();
    let unresolved: usize = session.index.unresolved.values().map(Vec::len).sum();
    Ok(format!(
        "{{\"notes\": {}, \"unresolved\": {}, \"paths\": {}}}",
        session.index.notes.len(),
        unresolved,
        serde_json::to_string(&paths).map_err(|error| error.to_string())?
    ))
}

/// Edits one existing note through the real desktop save path, leaving the
/// change in the log rather than compacting it.
pub fn edit(vault_path: &str, passphrase: &str, note_path: &str, body: &str) -> Result<(), String> {
    let mut session = open_session(vault_path, passphrase)?;
    let id = session
        .index
        .notes
        .values()
        .find(|note| note.note.path == note_path)
        .map(|note| note.note.id.clone())
        .ok_or_else(|| format!("no note at {note_path}"))?;
    let mut note = session.index.notes[&id].note.clone();
    note.body = body.to_string();
    save_existing_note(&mut session, note)?;
    Ok(())
}

/// Times the phases of a save, so a number that is over budget says which
/// part of the path to look at rather than only that it is slow.
pub fn phases(vault_path: &str, passphrase: &str, saves: usize) -> Result<String, String> {
    let mut session = open_session(vault_path, passphrase)?;
    let ids: Vec<String> = session.index.notes.keys().take(saves).cloned().collect();
    if ids.is_empty() {
        return Err("the vault has no notes to edit".into());
    }

    let mut object = Vec::new();
    let mut archive = Vec::new();
    let mut apply = Vec::new();
    let mut commit = Vec::new();
    let mut audit = Vec::new();
    let mut journal = Vec::new();

    for (iteration, id) in ids.iter().enumerate() {
        let previous = session.index.notes[id].note.clone();
        let mut note = previous.clone();
        note.body = format!("# phase {iteration}
");
        note.revision = previous.revision + 1;
        note.updated_at = now();
        let (links, headings) = analyze_markdown(&note.body)?;
        let indexed = IndexedNote {
            note: note.clone(),
            links,
            headings,
        };

        let mark = Instant::now();
        crate::begin_note_journal(&session, std::slice::from_ref(&note.id))?;
        journal.push(millis(mark.elapsed()));

        let mark = Instant::now();
        crate::archive_note(&session, &previous)?;
        archive.push(millis(mark.elapsed()));

        let mark = Instant::now();
        let payload = encrypt(
            &serde_json::to_vec(&note).map_err(|error| error.to_string())?,
            session.key.as_ref(),
            &note_aad(&note.id),
        )?;
        write_atomic(
            &note_path(&session.root_dir, &note.id)?,
            &serde_json::to_vec(&payload).map_err(|error| error.to_string())?,
        )?;
        object.push(millis(mark.elapsed()));

        let mark = Instant::now();
        crate::apply_indexed_note(&mut session.index, indexed.clone());
        apply.push(millis(mark.elapsed()));

        let mark = Instant::now();
        crate::commit_index(
            &mut session,
            Some(crate::index_log::IndexLogRecord::Note {
                note: Box::new(indexed),
            }),
        )?;
        commit.push(millis(mark.elapsed()));

        let mark = Instant::now();
        crate::end_journal(&session)?;
        crate::audit_write(&session, "documents", &note.id)?;
        audit.push(millis(mark.elapsed()));
    }

    let line = |name: &str, samples: Vec<f64>| {
        let stats = Stats::from(samples);
        format!("\"{name}\": {{ \"p50\": {:.3}, \"p95\": {:.3} }}", stats.p50, stats.p95)
    };
    Ok(format!(
        "{{ {}, {}, {}, {}, {}, {} }}",
        line("journal", journal),
        line("archive", archive),
        line("object", object),
        line("applyIndex", apply),
        line("commitLog", commit),
        line("endAndAudit", audit),
    ))
}

/// Measures one tier against a disposable vault under `root`.
pub fn measure(root: &Path, notes: usize, saves: usize) -> Result<Report, String> {
    let vault_dir = root.join(format!("bench-{notes}"));
    fs::create_dir_all(&vault_dir).map_err(|error| error.to_string())?;
    let vault_path = vault_dir.to_string_lossy().to_string();

    let created = Instant::now();
    let mut session = open_session(&vault_path, PASSPHRASE)?;
    let ids = build_corpus(&mut session, notes)?;
    let bulk_create_ms = millis(created.elapsed());
    drop(session);

    // Cold unlock: a fresh session reads and authenticates the index.
    let unlock_started = Instant::now();
    let mut session = open_session(&vault_path, PASSPHRASE)?;
    let unlock_and_index_ms = millis(unlock_started.elapsed());
    if session.index.notes.len() != notes {
        return Err(format!(
            "unlock produced {} notes, expected {notes}",
            session.index.notes.len()
        ));
    }

    let mut samples = Vec::with_capacity(saves);
    for iteration in 0..saves {
        let id = &ids[iteration % ids.len()];
        let mut note = session
            .index
            .notes
            .get(id)
            .ok_or("benchmark note vanished")?
            .note
            .clone();
        note.body = format!("# edited {iteration}\n\nbody {iteration}\n");
        // Through `with_vault_write`, which is what the `save_note` desktop
        // command does: take the vault lock, then bring the in-memory index up
        // to date with anything another process wrote, then save. Timing
        // `save_existing_note` alone would leave out the refresh this phase
        // exists to make cheap, and report a save the desktop never performs.
        let started = Instant::now();
        crate::with_vault_write(&mut session, |session| save_existing_note(session, note))?;
        samples.push(millis(started.elapsed()));
    }

    let index_bytes = fs::metadata(session.root_dir.join("index.enc"))
        .map(|meta| meta.len())
        .unwrap_or(0);

    Ok(Report {
        notes,
        bulk_create_ms,
        unlock_and_index_ms,
        save: Stats::from(samples),
        index_bytes,
    })
}
