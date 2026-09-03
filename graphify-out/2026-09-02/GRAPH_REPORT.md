# Graph Report - vaultbrain  (2026-09-02)

## Corpus Check
- 160 files · ~133,409 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 1684 nodes · 4510 edges · 156 communities (95 shown, 50 thin omitted)
- Extraction: 98% EXTRACTED · 2% INFERRED · 0% AMBIGUOUS · INFERRED: 74 edges (avg confidence: 0.86)
- Token cost: 0 input · 0 output

## Community Hubs (Navigation)
- sync.ts
- canvas.ts
- scripts
- with_vault_write
- permissions
- VaultSession
- String
- Result
- lib.rs
- types.ts
- DocumentVault
- assertNotSymlink
- grants.ts
- reject_symlink
- App
- tauri.conf.json
- App.tsx
- graph-layout.ts
- semantic.ts
- Vec
- theme.ts
- cli.ts
- .installPlugin
- compilerOptions
- keychain.ts
- documents.ts
- store.ts
- HashMap
- withVaultLock
- plugins.ts
- PropertyTable.tsx
- .putCanvas
- .putIntoIndex
- CanvasBoard
- ContextPanel.tsx
- host.ts
- PluginHost
- host.test.ts
- compilerOptions
- crypto.ts
- decryptDocument
- templates.ts
- plugin-signatures.ts
- App.test.tsx
- NoteLifecycle.tsx
- benchmark.mjs
- make-fixtures.mjs
- PluginManager.tsx
- AttachmentLibrary.tsx
- devDependencies
- schema.ts
- main.json
- kdf
- kdf
- kdf
- ResizeObserverStub
- durability.test.mjs
- QuickSwitcher.tsx
- CanvasDocument
- .prettierrc.json
- semantic.test.mjs
- 128x128@2x application icon
- concentric rings
- concentric rings
- 64x64 application icon
- concentric rings
- concentric rings
- concentric rings
- concentric rings
- concentric rings
- concentric rings
- concentric rings
- concentric rings
- concentric rings
- concentric rings
- concentric rings
- concentric rings
- concentric rings
- 29x29 @2x iOS app icon
- 29x29 @2x iOS app icon
- 29x29 @3x iOS app icon
- 40x40 @1x iOS app icon
- 40x40 @2x iOS app icon
- 40x40 @2x iOS app icon
- 40x40 @3x iOS app icon
- 512 @2x iOS app icon
- 60x60 @2x iOS app icon
- 60x60 @3x iOS app icon
- 76x76 @1x iOS app icon
- 76x76 @2x iOS app icon
- 83.5x83.5 @2x iOS app icon
- concentric rings
- 150x150 square application logo
- concentric rings
- 310x310 square application logo
- grants.test.mjs
- SyncChangeBody
- VaultBrain application logo
- VaultBrain application logo
- package.test.mjs
- @codemirror/lang-markdown
- @codemirror/language
- @codemirror/state
- @codemirror/view
- Semantic extraction
- eslint
- @eslint/js
- @fontsource/ibm-plex-mono
- @fontsource-variable/ibm-plex-sans
- @fontsource-variable/newsreader
- Dependabot updates
- globals
- jsdom
- lucide-react
- prettier
- react
- react-dom
- react-markdown
- remark-gfm
- @tauri-apps/api
- @tauri-apps/cli
- @testing-library/jest-dom
- @testing-library/react
- tsx
- @types/node
- @types/react-dom
- typescript-eslint
- vite
- @vitejs/plugin-react
- vitest
- Keyhole symbol
- Keyhole symbol
- Keyhole symbol
- Keyhole symbol
- Keyhole symbol
- Keyhole symbol
- Keyhole symbol
- Keyhole symbol
- Keyhole symbol
- Keyhole symbol
- Keyhole symbol
- Keyhole symbol
- Keyhole symbol
- Release workflow
- vault-brain-desktop

## God Nodes (most connected - your core abstractions)
1. `DocumentVault` - 118 edges
2. `VaultSession` - 67 edges
3. `AppState` - 50 edges
4. `permissions` - 49 edges
5. `with_vault_write()` - 42 edges
6. `App()` - 40 edges
7. `store_note()` - 39 edges
8. `open_session()` - 39 edges
9. `assertNotSymlink()` - 35 edges
10. `resolveInside()` - 35 edges

## Surprising Connections (you probably didn't know these)
- `PluginManager()` --indirect_call--> `isPluginCapability()`  [INFERRED]
  desktop/src/PluginManager.tsx → src/plugins.ts
- `choose()` --calls--> `parsePluginManifest()`  [EXTRACTED]
  desktop/src/PluginManager.tsx → src/plugins.ts
- `grantedCapabilities()` --indirect_call--> `isPluginCapability()`  [INFERRED]
  desktop/src/plugins/host.ts → src/plugins.ts
- `PluginManager()` --calls--> `describeCapabilities()`  [EXTRACTED]
  desktop/src/PluginManager.tsx → src/plugins.ts
- `HostBoot` --references--> `PluginManifest`  [EXTRACTED]
  desktop/src/plugins/protocol.ts → src/plugins.ts

## Import Cycles
- None detected.

## Communities (156 total, 50 thin omitted)

### Community 0 - "sync.ts"
Cohesion: 0.06
Nodes (53): RFC-8785, openDocumentVault(), DocumentPayload, AttachmentInfo, NoteDocument, NoteInput, assertSyncSnapshotSize(), assertUnicode() (+45 more)

### Community 1 - "canvas.ts"
Cohesion: 0.05
Nodes (59): assertCanvasSize(), CanvasEdge, CanvasEnd, CanvasFileNode, CanvasGroupNode, CanvasInput, CanvasLinkNode, CanvasNode (+51 more)

### Community 2 - "scripts"
Cohesion: 0.04
Nodes (48): commander, @modelcontextprotocol/sdk, bin, vbrain, bugs, url, dependencies, commander (+40 more)

### Community 3 - "with_vault_write"
Cohesion: 0.12
Nodes (49): FnOnce, a_deleted_note_keeps_its_history_and_can_be_restored(), a_plugin_object_cannot_be_read_as_a_note(), a_rename_cannot_take_a_path_another_note_owns(), a_stale_desktop_editor_cannot_overwrite_a_newer_process(), a_template_renders_its_body_and_properties(), an_interrupted_plugin_write_is_recovered_on_unlock(), archive_note() (+41 more)

### Community 4 - "permissions"
Cohesion: 0.04
Nodes (49): allow-add-attachment, allow-create-from-template, allow-create-note, allow-delete-attachment, allow-delete-canvas, allow-delete-note, allow-delete-plugin, allow-delete-saved-view (+41 more)

### Community 5 - "VaultSession"
Cohesion: 0.13
Nodes (40): Default, DocumentIndex, Option, Self, a_plugin_round_trips_encrypted_and_starts_disabled(), a_typescript_signed_package_verifies_in_the_rust_core(), begin_plugin_journal(), get_plugin() (+32 more)

### Community 6 - "String"
Cohesion: 0.13
Nodes (44): HashSet, add_owner(), analyze_markdown(), archive_canvas(), begin_canvas_journal(), canvas_aad(), canvas_history_aad(), canvas_object_path() (+36 more)

### Community 7 - "Result"
Cohesion: 0.14
Nodes (41): Mutex, Result, add_attachment(), AppState, archived_revisions(), create_from_template(), DailyNote, delete_attachment() (+33 more)

### Community 8 - "lib.rs"
Cohesion: 0.09
Nodes (35): AppHandle, an_unknown_capability_is_refused_rather_than_trimmed(), Bookmark, build_graph(), cluster_nodes(), communities_are_deterministic_and_keep_disjoint_groups_apart(), derive_key(), edge() (+27 more)

### Community 9 - "types.ts"
Cohesion: 0.08
Nodes (28): AttachmentLibraryProps, demoAttachments, demoCanvases, demoHistory, demoMentions(), demoNotes, demoPluginPolicy, demoPlugins (+20 more)

### Community 10 - "DocumentVault"
Cohesion: 0.12
Nodes (7): CanvasSummary, canvasSummary(), countOccurrences(), DocumentVault, historyAad(), summary(), SemanticSearchOptions

### Community 11 - "assertNotSymlink"
Cohesion: 0.12
Nodes (26): appendAudit(), AuditEntry, auditKey(), auditKeyCache, AuditMeta, auditPath(), AuditVerification, calculateHash() (+18 more)

### Community 12 - "grants.ts"
Cohesion: 0.13
Nodes (33): AccessRequest, addGrant(), AgentGrant, approveRequest(), ConfirmationRequest, ConfirmPolicy, consumeApproval(), decide() (+25 more)

### Community 13 - "reject_symlink"
Cohesion: 0.14
Nodes (33): Drop, Path, PathBuf, a_missing_chunk_is_reported_instead_of_returning_a_short_file(), an_attachment_written_by_the_typescript_core_still_opens(), attachment_chunk_aad(), attachment_dir(), attachment_id() (+25 more)

### Community 14 - "App"
Cohesion: 0.08
Nodes (14): App(), commitWorkspace(), deleteLayout(), openLayout(), restoreDeleted(), restoreRevision(), saveLayout(), showWorkspace() (+6 more)

### Community 15 - "tauri.conf.json"
Cohesion: 0.06
Nodes (30): icons/128x128@2x.png, icons/128x128.png, icons/32x32.png, icons/icon.icns, icons/icon.ico, msi, nsis, app (+22 more)

### Community 16 - "App.tsx"
Cohesion: 0.10
Nodes (19): IDLE_CHOICES, LockReason, LockScreen(), submit(), MarkdownEditor, MarkdownPreview, NewNoteDialog(), readVaultHistory() (+11 more)

### Community 17 - "graph-layout.ts"
Cohesion: 0.12
Nodes (18): boundsOf(), clampStep(), EMPTY_FRAME, LayoutEdge, layoutGraph(), LayoutOptions, nodesInView(), Point (+10 more)

### Community 18 - "semantic.ts"
Cohesion: 0.12
Nodes (18): NoteSummary, SearchHit, dot(), EmbeddingAdapter, finiteNumber(), LocalGenerationOptions, LocalModelAdapter, loopbackBaseUrl() (+10 more)

### Community 19 - "Vec"
Cohesion: 0.14
Nodes (28): append_signature_frame(), decode_base64_url(), decrypt(), delete_saved_view(), EncryptedPayload, excerpt_around(), find_mentions(), get_unlinked_mentions() (+20 more)

### Community 20 - "theme.ts"
Cohesion: 0.17
Nodes (21): applyTheme(), channels(), contrastRatio(), DEFAULT_THEME, EDITOR_FONTS, EditorFont, isHexColor(), loadTheme() (+13 more)

### Community 21 - "cli.ts"
Cohesion: 0.12
Nodes (20): docs, grant, parseScope(), plugins, program, sync, GrantDecision, GrantScope (+12 more)

### Community 22 - ".installPlugin"
Cohesion: 0.22
Nodes (5): encryptDocument(), pluginAad(), pluginStoreAad(), PluginPackage, summarizePlugin()

### Community 23 - "compilerOptions"
Cohesion: 0.09
Nodes (22): compilerOptions, allowJs, allowSyntheticDefaultImports, esModuleInterop, forceConsistentCasingInFileNames, isolatedModules, jsx, lib (+14 more)

### Community 24 - "keychain.ts"
Cohesion: 0.14
Nodes (15): accountFor(), canRun(), darwinBackend, forgetPassphrase(), keychain(), KeychainBackend, linuxBackend, recallPassphrase() (+7 more)

### Community 25 - "documents.ts"
Cohesion: 0.15
Nodes (20): DocumentIndex, IndexedCanvas, IndexedNote, LegacyDocumentIndex, normalizeProperties(), normalizeStringList(), OutgoingLink, RevisionInfo (+12 more)

### Community 26 - "store.ts"
Cohesion: 0.20
Nodes (19): KVEntry, parseKV(), serializeKV(), assertValueSize(), normalizeDescription(), normalizeEntryKey(), normalizeVaultName(), buildSchema() (+11 more)

### Community 27 - "HashMap"
Cohesion: 0.16
Nodes (19): DateTime, From, HashMap, Local, Map, format_local_date(), get_plugin_storage(), parse_local_date() (+11 more)

### Community 28 - "withVaultLock"
Cohesion: 0.17
Nodes (10): PluginSecurityPolicy, held, isStale(), lockHolder(), LockRecord, readRecord(), sleeper, sleepSync() (+2 more)

### Community 29 - "plugins.ts"
Cohesion: 0.18
Nodes (18): byteLength(), CAPABILITY_DESCRIPTIONS, CAPABILITY_SET, capabilityFor(), describeCapabilities(), HOST_METHOD_CAPABILITIES, HostMethod, isPluginCapability() (+10 more)

### Community 30 - "PropertyTable.tsx"
Cohesion: 0.15
Nodes (12): display(), editableValue(), parseCell(), PropertyTable(), beginEdit(), commitEdit(), rows, savedView (+4 more)

### Community 31 - ".putCanvas"
Cohesion: 0.25
Nodes (5): canvasBasename(), CanvasDocument, normalizeCanvasPath(), canvasAad(), normalizeText()

### Community 32 - ".putIntoIndex"
Cohesion: 0.25
Nodes (3): encryptedDocumentPath(), noteAad(), normalizeLinkTarget()

### Community 33 - "CanvasBoard"
Cohesion: 0.23
Nodes (14): CanvasBoard(), addAttachment(), addGroup(), addLink(), addNode(), addNote(), addText(), change() (+6 more)

### Community 34 - "ContextPanel.tsx"
Cohesion: 0.16
Nodes (12): ContextPanel(), remember(), toggle(), toggleAll(), OutlineItem, readFolded(), mention, note (+4 more)

### Community 35 - "host.ts"
Cohesion: 0.20
Nodes (15): grantedCapabilities(), manifestOf(), PluginHostBindings, RunningPlugin, HostBoot, HostInvoke, HostReply, PluginEmit (+7 more)

### Community 37 - "host.test.ts"
Cohesion: 0.18
Nodes (6): FakeWorker, harness(), request(), summary(), bootstrap(), sandboxSource()

### Community 38 - "compilerOptions"
Cohesion: 0.13
Nodes (14): src/**/*.ts, compilerOptions, declaration, esModuleInterop, module, moduleResolution, outDir, resolveJsonModule (+6 more)

### Community 39 - "crypto.ts"
Cohesion: 0.22
Nodes (14): AnyEncryptedPayload, base64Bytes(), decrypt(), deriveKey(), encrypt(), EncryptedPayload, ENVELOPE_VERSION, envelopeVersion() (+6 more)

### Community 40 - "decryptDocument"
Cohesion: 0.24
Nodes (4): decryptDocument(), decryptDocumentBytes(), attachmentChunkAad(), attachmentManifestAad()

### Community 41 - "templates.ts"
Cohesion: 0.25
Nodes (13): PropertyValue, ParsedFrontmatter, normalizeNotePath(), createFromTemplate(), DailyNoteOptions, formatLocalDate(), openDailyNote(), pad() (+5 more)

### Community 42 - "plugin-signatures.ts"
Cohesion: 0.24
Nodes (12): decodeBase64Url(), ED25519_PKCS8_PREFIX, ED25519_SPKI_PREFIX, frame(), generatePluginSigningKey(), pluginSignaturePayload(), pluginSignerKeyId(), publicKeyFromRaw() (+4 more)

### Community 43 - "App.test.tsx"
Cohesion: 0.15
Nodes (8): bridgeMock, sampleAttachment, sampleCanvas, sampleNote, secondNote, CanvasInput, SearchHit, WorkspaceState

### Community 44 - "NoteLifecycle.tsx"
Cohesion: 0.21
Nodes (9): HistoryDialog(), parseVariables(), RenameDialog(), stamp(), TemplateDialog(), submit(), TrashDialog(), DeletedNote (+1 more)

### Community 45 - "benchmark.mjs"
Cohesion: 0.18
Nodes (9): budget, measureMany(), noteCount, percentile(), resolvedRoot, resolvedTemp, root, shouldAssert (+1 more)

### Community 46 - "make-fixtures.mjs"
Cohesion: 0.17
Nodes (9): attachmentDir, attachmentVault, documentDir, FIXTURE_PASSPHRASE, fixtures, here, legacyDir, legacyPlaintext (+1 more)

### Community 47 - "PluginManager.tsx"
Cohesion: 0.27
Nodes (7): PluginManager(), choose(), PluginManagerProps, readableBytes(), base, PluginSecurityPolicy, PluginSummary

### Community 48 - "AttachmentLibrary.tsx"
Cohesion: 0.27
Nodes (7): AttachmentLibrary(), decrypt(), upload(), base64ToBlob(), bytesToBase64(), readableBytes(), vaultBridge

### Community 49 - "devDependencies"
Cohesion: 0.22
Nodes (9): @codemirror/commands, @lezer/highlight, devDependencies, @codemirror/commands, @lezer/highlight, @types/react, typescript, @types/react (+1 more)

### Community 50 - "schema.ts"
Cohesion: 0.38
Nodes (6): dateFromNoteKey(), filterNotesByDate(), parseBoundary(), Schema, SchemaEntry, searchSchema()

### Community 51 - "main.json"
Cohesion: 0.29
Nodes (6): description, identifier, main, local, $schema, windows

### Community 52 - "kdf"
Cohesion: 0.29
Nodes (6): kdf, N, name, salt, verifier, version

### Community 53 - "kdf"
Cohesion: 0.29
Nodes (6): kdf, N, name, salt, verifier, version

### Community 54 - "kdf"
Cohesion: 0.29
Nodes (6): kdf, N, name, salt, verifier, version

### Community 57 - "durability.test.mjs"
Cohesion: 0.40
Nodes (3): copyFixture(), FIXTURES, tempDir()

### Community 58 - "QuickSwitcher.tsx"
Cohesion: 0.60
Nodes (3): matchedAlias(), QuickSwitcher(), score()

### Community 59 - "CanvasDocument"
Cohesion: 0.40
Nodes (5): DocumentVault, Encrypted local-first vault, CanvasDocument, Canvas index integration, documents-canvas-v1 fixture

### Community 60 - ".prettierrc.json"
Cohesion: 0.40
Nodes (4): printWidth, semi, singleQuote, trailingComma

### Community 62 - "128x128@2x application icon"
Cohesion: 0.50
Nodes (4): 128x128@2x application icon, concentric neon signal rings, cybersecurity and access control, stylized keyhole lock symbol

### Community 63 - "concentric rings"
Cohesion: 0.50
Nodes (4): concentric rings, 128x128 application icon, location pin, targeting or navigation

### Community 64 - "concentric rings"
Cohesion: 0.50
Nodes (4): concentric rings, 32x32 application icon, location pin, targeting or navigation

### Community 65 - "64x64 application icon"
Cohesion: 0.50
Nodes (4): 64x64 application icon, concentric neon signal rings, cybersecurity and access control, stylized keyhole lock symbol

### Community 66 - "concentric rings"
Cohesion: 0.50
Nodes (4): concentric rings, src_tauri_icons_android_mipmap_xxhdpi_ic_launcher application icon, location pin, targeting or navigation

### Community 67 - "concentric rings"
Cohesion: 0.50
Nodes (4): concentric rings, src_tauri_icons_android_mipmap_xxhdpi_ic_launcher_foreground application icon, location pin, targeting or navigation

### Community 68 - "concentric rings"
Cohesion: 0.50
Nodes (4): concentric rings, src_tauri_icons_android_mipmap_xxhdpi_ic_launcher_round application icon, location pin, targeting or navigation

### Community 69 - "concentric rings"
Cohesion: 0.50
Nodes (4): concentric rings, src_tauri_icons_android_mipmap_xxxhdpi_ic_launcher application icon, location pin, targeting or navigation

### Community 70 - "concentric rings"
Cohesion: 0.50
Nodes (4): concentric rings, src_tauri_icons_android_mipmap_xxxhdpi_ic_launcher_foreground application icon, location pin, targeting or navigation

### Community 71 - "concentric rings"
Cohesion: 0.50
Nodes (4): concentric rings, src_tauri_icons_android_mipmap_xxxhdpi_ic_launcher_round application icon, location pin, targeting or navigation

### Community 72 - "concentric rings"
Cohesion: 0.50
Nodes (4): concentric rings, src_tauri_icons_app_icon application icon, location pin, targeting or navigation

### Community 73 - "concentric rings"
Cohesion: 0.50
Nodes (4): concentric rings, src_tauri_icons_icon application icon, location pin, targeting or navigation

### Community 74 - "concentric rings"
Cohesion: 0.50
Nodes (4): concentric rings, src_tauri_icons_ios_appicon_20x20_1x application icon, location pin, targeting or navigation

### Community 75 - "concentric rings"
Cohesion: 0.50
Nodes (4): concentric rings, src_tauri_icons_ios_appicon_20x20_2x_1 application icon, location pin, targeting or navigation

### Community 76 - "concentric rings"
Cohesion: 0.50
Nodes (4): concentric rings, src_tauri_icons_ios_appicon_20x20_2x application icon, location pin, targeting or navigation

### Community 77 - "concentric rings"
Cohesion: 0.50
Nodes (4): concentric rings, src_tauri_icons_ios_appicon_20x20_3x application icon, location pin, targeting or navigation

### Community 78 - "concentric rings"
Cohesion: 0.50
Nodes (4): concentric rings, src_tauri_icons_ios_appicon_29x29_1x application icon, location pin, targeting or navigation

### Community 79 - "29x29 @2x iOS app icon"
Cohesion: 0.50
Nodes (4): 29x29 @2x iOS app icon, concentric neon signal rings, cybersecurity and access control, stylized keyhole lock symbol

### Community 80 - "29x29 @2x iOS app icon"
Cohesion: 0.50
Nodes (4): 29x29 @2x iOS app icon, concentric neon signal rings, cybersecurity and access control, stylized keyhole lock symbol

### Community 81 - "29x29 @3x iOS app icon"
Cohesion: 0.50
Nodes (4): 29x29 @3x iOS app icon, concentric neon signal rings, cybersecurity and access control, stylized keyhole lock symbol

### Community 82 - "40x40 @1x iOS app icon"
Cohesion: 0.50
Nodes (4): 40x40 @1x iOS app icon, concentric neon signal rings, cybersecurity and access control, stylized keyhole lock symbol

### Community 83 - "40x40 @2x iOS app icon"
Cohesion: 0.50
Nodes (4): 40x40 @2x iOS app icon, concentric neon signal rings, cybersecurity and access control, stylized keyhole lock symbol

### Community 84 - "40x40 @2x iOS app icon"
Cohesion: 0.50
Nodes (4): 40x40 @2x iOS app icon, concentric neon signal rings, cybersecurity and access control, stylized keyhole lock symbol

### Community 85 - "40x40 @3x iOS app icon"
Cohesion: 0.50
Nodes (4): 40x40 @3x iOS app icon, concentric neon signal rings, cybersecurity and access control, stylized keyhole lock symbol

### Community 86 - "512 @2x iOS app icon"
Cohesion: 0.50
Nodes (4): 512 @2x iOS app icon, concentric neon signal rings, cybersecurity and access control, stylized keyhole lock symbol

### Community 87 - "60x60 @2x iOS app icon"
Cohesion: 0.50
Nodes (4): 60x60 @2x iOS app icon, concentric neon signal rings, cybersecurity and access control, stylized keyhole lock symbol

### Community 88 - "60x60 @3x iOS app icon"
Cohesion: 0.50
Nodes (4): 60x60 @3x iOS app icon, concentric neon signal rings, cybersecurity and access control, stylized keyhole lock symbol

### Community 89 - "76x76 @1x iOS app icon"
Cohesion: 0.50
Nodes (4): 76x76 @1x iOS app icon, concentric neon signal rings, cybersecurity and access control, stylized keyhole lock symbol

### Community 90 - "76x76 @2x iOS app icon"
Cohesion: 0.50
Nodes (4): 76x76 @2x iOS app icon, concentric neon signal rings, cybersecurity and access control, stylized keyhole lock symbol

### Community 91 - "83.5x83.5 @2x iOS app icon"
Cohesion: 0.50
Nodes (4): 83.5x83.5 @2x iOS app icon, concentric neon signal rings, cybersecurity and access control, stylized keyhole lock symbol

### Community 92 - "concentric rings"
Cohesion: 0.50
Nodes (4): concentric rings, Square142x142 application logo, location pin, targeting or navigation

### Community 93 - "150x150 square application logo"
Cohesion: 0.50
Nodes (4): 150x150 square application logo, concentric neon signal rings, cybersecurity and access control, stylized keyhole lock symbol

### Community 94 - "concentric rings"
Cohesion: 0.50
Nodes (4): concentric rings, Square30x30 application logo, location pin, targeting or navigation

### Community 95 - "310x310 square application logo"
Cohesion: 0.50
Nodes (4): 310x310 square application logo, concentric neon signal rings, cybersecurity and access control, stylized keyhole lock symbol

### Community 97 - "SyncChangeBody"
Cohesion: 0.67
Nodes (3): Phase 6 encrypted sync, Conflict semantics, SyncChangeBody

### Community 98 - "VaultBrain application logo"
Cohesion: 0.67
Nodes (3): Keyhole symbol, Lime green accent, VaultBrain application logo

### Community 99 - "VaultBrain application logo"
Cohesion: 0.67
Nodes (3): Keyhole symbol, Lime green circular ring, VaultBrain application logo

## Knowledge Gaps
- **455 isolated node(s):** `printWidth`, `semi`, `singleQuote`, `trailingComma`, `sampleNote` (+450 more)
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 585 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **50 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `PluginCapability` connect `host.ts` to `documents.ts`, `cli.ts`, `plugins.ts`, `PluginManager.tsx`?**
  _High betweenness centrality (0.061) - this node is a cross-community bridge._
- **Why does `DocumentVault` connect `DocumentVault` to `sync.ts`, `.putIntoIndex`, `canvas.ts`, `decryptDocument`, `templates.ts`, `assertNotSymlink`, `cli.ts`, `.installPlugin`, `documents.ts`, `withVaultLock`, `.putCanvas`?**
  _High betweenness centrality (0.031) - this node is a cross-community bridge._
- **Why does `parsePluginManifest()` connect `plugins.ts` to `documents.ts`, `cli.ts`, `.installPlugin`, `PluginManager.tsx`?**
  _High betweenness centrality (0.021) - this node is a cross-community bridge._
- **What connects `printWidth`, `semi`, `singleQuote` to the rest of the system?**
  _455 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `sync.ts` be split into smaller, more focused modules?**
  _Cohesion score 0.058823529411764705 - nodes in this community are weakly interconnected._
- **Should `canvas.ts` be split into smaller, more focused modules?**
  _Cohesion score 0.053763440860215055 - nodes in this community are weakly interconnected._
- **Should `scripts` be split into smaller, more focused modules?**
  _Cohesion score 0.04081632653061224 - nodes in this community are weakly interconnected._