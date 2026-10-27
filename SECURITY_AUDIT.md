# Security audit — BatStats

> **Lead** (agent, Claude Opus 5) — audit of `mlm-games/BatStats` at upstream `4da5814`
> (version 6.3.6, versionCode 804), performed 2026-10-28. This fork carries the fixes.

## Scope and method

Static review of the whole app module: the manifest and every exported component, the two
privileged execution paths (Shizuku user service and `su`), every shell command string the app can
produce, the Room layer, the import/export boundary, `PendingIntent` construction, backup
configuration, build/signing configuration, and the CI supply chain. No device or emulator run was
part of this pass.

## Verdict

There is no remote attack surface: **the app requests no `INTERNET` permission**, contains no HTTP
client, no WebView and no outbound I/O of any kind, so none of the collected data can leave the
device except through the user's own export. There is no injectable shell command, no injectable
SQL, and no mutable `PendingIntent`.

The defects below are local: one privilege-boundary design weakness that gives the app's privileged
helper far more authority than it needs, one privacy leak through platform backup, and a set of
hardening and supply-chain gaps.

## Findings

### 1. Privileged helper executed arbitrary shell commands with no caller check — High (design)

`app/src/main/java/app/batstats/battery/shizuku/ShellUserService.kt`

The Shizuku user service runs in a separate process owned by the ADB shell user, or by root when
Shizuku itself was started as root. Its `onTransact` read a command string off the parcel and
passed it straight to `ProcessBuilder("sh", "-c", cmd)`. Two gates were missing:

- **No caller identity check.** `Binder.getCallingUid()` was never consulted, so every transaction
  was served regardless of who sent it.
- **No limit on what could be executed.** The app only ever sends four fixed `dumpsys` commands,
  but the interface accepted any string — an arbitrary command execution primitive at shell or root
  authority.

The only thing standing between that primitive and another app was Shizuku's own refusal to hand
this service's binder to a different package. That is a single external control, in a component
this app does not own, protecting shell/root execution. I did not audit Shizuku's enforcement, and
the point of the finding is that the app offered no second line of defence of its own.

**Fixed** by adding both gates: transactions are refused unless the caller is this app or the
process that spawned the service, and commands are matched exactly against an allow-list of the
five read-only diagnostic commands the app actually uses. A leaked binder handle is now worth no
more than the battery dumps its holder could request on their own.

The allow-list is the gate that bounds the damage, and it is unconditional. The uid pin is
secondary and depends on Shizuku instantiating the service through its `Context` constructor: if
it uses the no-argument one instead, the app's own uid cannot be resolved in that process and the
uid check defers to the allow-list rather than locking the app out. Which constructor Shizuku
picks has not been confirmed on a device, so treat the uid pin as best-effort and the allow-list
as the control.

### 2. Battery history was uploaded to cloud backup — Medium (privacy)

`app/src/main/AndroidManifest.xml`, `app/src/main/res/xml/*`

`android:allowBackup="true"` was set, and `backup_rules.xml` and `data_extraction_rules.xml` were
present but **never referenced from the manifest** — both were still the unedited Android Studio
templates. With no rules in effect, every file the app owns was eligible for backup, including
`battery.db`.

That database is not inert telemetry. It holds per-app energy buckets (`app_energy_stats`),
screen-on state per sample, and complete charge/discharge sessions — a fine-grained record of when
the device is used and which apps were running. For an app whose entire value proposition is local
battery analysis, shipping that history to Google's backup transport by default contradicts the
reason to install it.

**Fixed** by wiring both rule files into the manifest and excluding `battery.db` (and its WAL/SHM/
journal siblings) from cloud backup and from `adb backup` archives. Device-to-device transfer is
deliberately left intact so migrating phones still keeps history, and the in-app JSON/CSV export
remains the explicit way to copy it anywhere else.

### 3. Battery receiver registered as implicitly exported — Low

`app/src/main/java/app/batstats/battery/data/BatteryRepository.kt`

`startSampling()` called the two-argument `context.registerReceiver(...)`, which leaves the
receiver exported. `ACTION_BATTERY_CHANGED` is a protected broadcast, so a third-party app cannot
actually spoof it, and the practical risk is therefore low — but the protection is entirely the
platform's, and the same codebase already does this correctly in `AdvancedDrainTracker`, which
passes `RECEIVER_NOT_EXPORTED`. The inconsistency is the defect.

**Fixed** by routing the registration through `ContextCompat.registerReceiver` with
`RECEIVER_NOT_EXPORTED`.

### 4. Third-party reusable workflows pinned to a mutable tag — Medium (supply chain)

`.github/workflows/`

All three workflows called reusable workflows from `mlm-games/ci@v1`. A git tag is mutable: whoever
controls that repository can move `v1` and change what executes, with no change landing in this
repository and nothing to review. `android.yml` passed the release keystore and its passwords
(`KEYSTORE`, `KEYSTORE_PASSPHRASE`, `STORE_PASSWORD`, `KEY_ALIAS`, `KEY_PASSWORD`) into that
third-party workflow, so a moved tag reaches the app signing key.

Separately, `dependabot-auto-merge.yml` merged dependency bumps on `pull_request` with no human
review, so a compromised or typosquatted Gradle dependency could reach `main` unseen. Upstream's
own history shows this path is busy: the last several commits on `main` are auto-merged dependabot
PRs.

**Fixed in this fork** by pinning the remaining CI workflow to the commit `v1` currently resolves
to (`2a5a9b9`), and by deleting both `android.yml` (an upstream Play Store release path that needs
secrets this fork does not and should not hold) and `dependabot-auto-merge.yml`. Dependabot itself
is left enabled; its PRs now simply require a human.

Pinning stops the contents from changing silently; it does not vouch for them. The reusable
workflow at that commit was not reviewed, and it may well use mutable refs of its own internally.
What the pin buys is that any future change has to be an explicit commit in this repository.

### 5. v1 JAR signing enabled at minSdk 26 — Low

`app/build.gradle.kts`

`enableV1Signing = true` while `minSdk = 26`. v1 signatures are only needed to install on API < 24,
so the flag bought nothing and kept the APK in the shape CVE-2017-13156 (Janus) exploits — a
prepended DEX leaves a v1 signature valid. The v2 signature in the same APK is what actually
protects current devices, so this was latent rather than live. `enableV3Signing = false` also meant
no support for rotating the signing key later.

**Fixed**: v1 off, v2 and v3 on.

### 6. Import read the whole file unbounded and could leave a half-imported database — Low

`app/src/main/java/app/batstats/battery/data/ExportImport.kt`

`importJson` did `it.readBytes()` on a user-picked `content://` URI with no size limit, so a large
file (possibly handed over by another app through the picker) turns the import into an
out-of-memory kill. `importCsv` indexed up to `p[9]` after `line.split(',')` without checking the
field count and called `toLong()`/`enumValueOf()` on raw fields; the resulting exception was
swallowed by `runCatching`, which returned `false` to the user **after** every row before the bad
one had already been inserted. A malformed or truncated export therefore reported failure while
silently mutating the history it was supposed to restore.

**Fixed**: imports read at most 32 MiB, rows are fully parsed and validated before anything is
written, malformed rows are skipped rather than aborting, and all inserts run inside a single Room
transaction.

## Checked and clean

- **No network surface at all.** No `INTERNET` permission, no WebView, no HTTP client, no
  `usesCleartextTraffic`. The `androidbrowserhelper` dependency is declared but unreferenced in
  source — dead weight, not an exposure.
- **No command injection.** Every command reaching a privileged shell is a compile-time literal;
  nothing interpolates a package name, file name or setting into a command string. The only
  interpolation near a shell path builds a `/sys/devices/system/cpu/cpu<Int>/cpufreq` filesystem
  path from a parsed integer, and is read with `File`, not a shell.
- **No SQL injection.** Every Room query is parameterized; `execSQL` appears only inside migrations
  with literal DDL.
- **All `PendingIntent`s use `FLAG_IMMUTABLE`** (four sites: widget click, notification content,
  notification reset action, foreground-service start).
- **No external-storage writes, no world-readable file modes, no `openFileOutput`.** Export writes
  only through a `content://` URI the user picked. `res/xml/filepaths.xml` is an unused leftover —
  no `FileProvider` is declared.
- **`ShizukuProvider` exported with `INTERACT_ACROSS_USERS_FULL`** is the documented Shizuku
  integration, not an unguarded export.
- **`BootReceiver` exported** is required to receive `BOOT_COMPLETED`, which is a protected
  broadcast a third-party app cannot send.
- **No secrets in the tree.** No committed keystore, no jars under `app/libs/`, signing material
  read from the environment.
