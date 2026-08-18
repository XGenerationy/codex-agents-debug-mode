'use strict';

// All logic for actions/debug-evidence lives here; action.yml is wiring only.
// Subcommands: start | run | report | bind-artifact | teardown | finish, driven by
// DEBUG_ACTION_* env vars. State travels via action-state.json at the
// OUTPUT-DIR ROOT — deliberately outside the evidence child, because it
// carries this run's session token and NO ENUMERATED PATH NAMES IT. That is
// a claim about the upload step's path NAMES, never about the bytes (Codex
// T8 r2 #2, replacing the categorical promise this header used to make): the
// pinned uploader follows symlinks unconditionally, so a swap inside the
// staging window can still put these bytes into the archive under one of the
// enumerated payload names.

const {
  appendFileSync, closeSync, constants, fstatSync, lstatSync, mkdirSync,
  openSync, readFileSync, realpathSync, renameSync, rmSync, unlinkSync,
  writeFileSync, writeSync,
} = require('node:fs');
const { spawn, spawnSync } = require('node:child_process');
const {
  createHash, createPublicKey, randomBytes, randomUUID, verify,
} = require('node:crypto');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');

const { canonicalResponderRecord, probeLaunchToken, probeReadyCollector } = require(path.join(__dirname, '..', '..', 'scripts', 'debug_server.js'));
const { protectWindowsPrivateFile } = require(path.join(__dirname, '..', '..', 'scripts', 'pr_closeout_fs.js'));
const { parseSessionText, readSessionLive } = require(path.join(__dirname, '..', '..', 'scripts', 'debug_evidence.js'));
const { buildReport, renderJson, renderMarkdown } = require(path.join(__dirname, '..', '..', 'scripts', 'debug_report.js'));

const STATE_FILE = 'action-state.json';
const EVIDENCE_SUBDIR = 'debug-evidence-files';
const BOOT_SHIM = path.join(__dirname, 'collector_boot.js');
const NAME_PATTERN = /^[A-Za-z0-9_-]+$/;

// THE PLATFORM PREREQUISITE, detected rather than assumed (Codex T6 r5,
// classification corrected after the r6 Critical).
//
// Every in-process guarantee this action rests on — the trusted `run` process,
// the verification key held only in its memory, the collector's private
// signing key — assumes the host FORBIDS same-UID ptrace attachment. A
// same-user process that can attach may, per the kernel documentation, inject
// code: a hostile native wrapped command could rewrite `run`'s memory or read
// the collector's signing state (its pid is in the state file), and
// "authenticated evidence" would mean nothing.
//
// Only Yama mode 3 forbids attachment unconditionally. Modes 1 and 2 restrict
// it to a descendant or to a privileged process, and BOTH are bypassable with
// CAP_SYS_PTRACE — which is not a theoretical escape here, because standard
// VM-based GitHub-hosted Linux runners give workflow commands PASSWORDLESS
// SUDO. A command that can `sudo` can grant itself the capability and attach.
// Reading the current process's own capabilities would not detect this: the
// escalation path is sudo, not an inherited capability. So modes 1 and 2 are
// `privilege-bypassable`, and calling either "restricted" (as this code did)
// rested the action's core authentication guarantee on a boundary that one
// `sudo` removes.
//
// DELIBERATELY NOT RECORDED HERE: which Yama mode any current runner image
// ships (Codex T8 r2 #4, which removed exactly that assertion from this
// comment). It is a moving external property this job never measures, and
// the conclusion does not need it — passwordless sudo is what makes 1 and 2
// bypassable, whichever of them a given host is in, and the live sudo
// reading below denies strict on such a host without consulting the mode
// at all.
//
// The action cannot create the boundary. It classifies honestly, and
// `startSubcommand` refuses to run the wrapped command at all unless the
// prerequisite is POSITIVELY ESTABLISHED — which is `unconditional` and
// nothing else. Every other value, including one this code does not recognise
// (a future mode, a typo), a file it could not read, and a platform with no
// Yama at all, is `unknown`: never read in the host's favour.
const PTRACE_SCOPE_PATH = '/proc/sys/kernel/yama/ptrace_scope';
// A Map, not an object literal: the key here is HOST DATA read off a file, and
// an object lookup resolves inherited properties — `__proto__`, `constructor`,
// `toString` would each return something other than undefined and so never
// reach the `unknown` fallback, putting a function or an object into state and
// into diagnostics (Codex T6 r7 #2). A Map has no such keys to inherit.
const PTRACE_MODES = new Map([
  ['0', 'permissive'],
  ['1', 'privilege-bypassable'],
  ['2', 'privilege-bypassable'],
  ['3', 'unconditional'],
]);
// A DEFAULT PARAMETER CANNOT MODEL "not available here" (Codex T6 r9 #4).
// `{ getuid: undefined }` activates the default, so a caller meaning "this
// platform has no geteuid" silently gets the live host's — green on Windows for
// the wrong reason, and a failure on the Linux runner that matters. Reading the
// key's PRESENCE makes an explicit undefined mean what every reader assumes it
// means, while an omitted key still wires the real API.
const seam = (options, key, fallback) => (Object.hasOwn(options, key) ? options[key] : fallback);

const readPtraceScope = (options = {}) => {
  const platform = seam(options, 'platform', process.platform);
  const readFile = seam(options, 'readFile', readFileSync);
  if (platform !== 'linux') return 'unknown';
  let raw;
  try {
    raw = readFile(PTRACE_SCOPE_PATH, 'utf8');
  } catch {
    return 'unknown';
  }
  const text = String(raw).trim();
  // A single recognised digit, and nothing else. `''` parses to 0 under
  // Number(), which would read an empty or truncated file as the weakest
  // policy and then report it as a fact; `4`/`999` are modes this code has
  // never heard of and must not guess at either way.
  return PTRACE_MODES.get(text) ?? 'unknown';
};

// AND MODE 3 IS NOT SUFFICIENT EITHER (Codex T6 r8, Critical — this reverses
// the hardening advice round 7 shipped). Yama governs `ptrace`, and nothing
// else. A principal that can reach ROOT does not need ptrace at all: it can
// load a privileged tracing BPF program and overwrite another task's userspace
// memory with `bpf_probe_write_user()`, or insert a kernel module. (An earlier
// draft of this comment also listed reading /proc/<pid>/mem directly. That was
// WRONG and is removed rather than qualified: opening that file goes through
// mm_access -> ptrace_may_access with PTRACE_MODE_ATTACH_FSCREDS, which is the
// very check Yama hooks, so mode 3 does forbid it. A factual error inside a
// security argument is the failure mode this review has been hunting since
// round 4 — Codex T6 r9 #5.) So mode 3 is necessary, not sufficient, and the
// round-7 advice — set ptrace_scope 3 with sudo and strict becomes reachable
// — was FALSE: the same passwordless sudo that sets the sysctl opens the BPF
// route. Hosted execution therefore stays best-effort.
//
// Strict admission is consequently a CONJUNCTION of four readings, all of
// which must be positively clear:
//
//   1. Yama ptrace_scope 3            (classic attachment forbidden)
//   2. effective uid != 0             (not already root)
//   3. no sudo binary present       (EXISTENCE, conventional paths + PATH)
//   4. no dangerous capability held (no route already granted)
//
// These are the escalation routes this action checks, not a proof that no
// route exists. A setuid binary on PATH, a mounted container socket, a
// writable privileged service or an unpatched local kernel bug grants the same
// power and none of them is visible from here. What the conjunction buys is
// that the OBSERVABLE routes are closed; what it cannot buy is a guarantee,
// which is why the wording on every surface says "checked" and never "proved".
const PROC_SELF_STATUS_PATH = '/proc/self/status';

// Bit positions from the kernel's capability.h. CAP_BPF is 39 — above bit 32,
// which is why the masks here are BigInt: a Number bitwise op truncates to 32
// bits and would silently read CAP_BPF as absent, i.e. would miss precisely the
// capability this round is about.
const DANGEROUS_CAPABILITIES = new Map([
  ['CAP_SYS_MODULE', 16n],
  ['CAP_SYS_PTRACE', 19n],
  ['CAP_SYS_ADMIN', 21n],
  ['CAP_BPF', 39n],
]);
const DANGEROUS_CAPABILITY_MASK = [...DANGEROUS_CAPABILITIES.values()]
  .reduce((mask, bit) => mask | (1n << bit), 0n);
// PERMITTED as well as EFFECTIVE: a permitted-but-not-effective capability is
// one `capset` away from being effective, so treating it as absent would be
// reading a loaded gun as unloaded.
const CAPABILITY_FIELDS = ['CapPrm', 'CapEff'];

const readEffectiveUid = (options = {}) => {
  const getuid = seam(options, 'getuid', process.geteuid);
  // Absent on Windows, and absent is not "safe": it means this code cannot
  // tell, which denies.
  if (typeof getuid !== 'function') return 'unknown';
  let uid;
  try {
    uid = getuid.call(process);
  } catch {
    return 'unknown';
  }
  if (!Number.isInteger(uid) || uid < 0) return 'unknown';
  return uid === 0 ? 'root' : 'non-root';
};

// SUDO: DETECTED BY EXISTENCE, NEVER BY BEHAVIOUR (Codex T6 r9, Critical).
//
// Round 8 ran `sudo -n true` and read a denial as "no sudo route here". That
// was unsound in two independent ways, and both of them fail in the granting
// direction — the only direction that matters:
//
//   1. SUDOERS RULES ARE COMMAND-SPECIFIC. A principal holding
//      `NOPASSWD: /usr/bin/env` is denied `true` and would have CLEARED
//      admission, while retaining a perfectly good route to root. Probing one
//      command can never establish the absence of a rule for another.
//   2. THE PROBE ITSELF WAS FORGEABLE. A fake `sudo` earlier on PATH could
//      print "a password is required", exit 1, and thereby GRANT strict
//      admission — while the real /usr/bin/sudo stayed one absolute path away
//      for the wrapped command to use. (The round-8 note claiming a spoofed
//      sudo could only deny was wrong.)
//
// So this asks one question with no interpretation in it: does a sudo binary
// EXIST? Any sudo binary at a conventional absolute path or anywhere on the
// inherited PATH denies strict admission. Nothing is executed and no output is
// parsed. Establishing that a present sudo grants the principal nothing would
// need an independently trusted account of the sudoers policy, and nothing
// available here is one — so strict now means a genuinely locked environment,
// which is what "real isolation" meant all along.
//
// AND A FIXED LIST OF THREE IS NOT THE SURFACE (Codex T6 r10, Critical). Run
// against a NixOS-style layout — sudo at /run/current-system/sw/bin/sudo — the
// three-path version answered `absent`, which would have GRANTED strict
// admission on a host where the wrapped command can simply become root.
//
// The round-9 ruling forbade EXECUTING a PATH-resolved binary and trusting what
// it printed. It did not make PATH INSPECTION unsafe, and the two are not the
// same act: reading the variable and lstat-ing what it names runs no code and
// believes no output. So the inspection is the union of the conventional
// absolute paths AND every sudo candidate on the inherited PATH, lstat-ed and
// never executed.
//
// The union is the load-bearing part. A hostile PATH must only ever be able to
// ADD candidates: empty, unset, or stripped to one harmless directory, the
// conventional locations are still checked, so no manipulation of the variable
// can shrink the inspection into a false `absent`.
const SUDO_CONVENTIONAL_PATHS = ['/usr/bin/sudo', '/bin/sudo', '/usr/local/bin/sudo'];
const SUDO_BINARY_NAME = 'sudo';

// POSIX PATH semantics, and deliberately not path.join: this code runs its
// tests on Windows, where path.join would turn '/usr/bin' into a backslashed
// drive path and quietly stop matching anything.
//
// An entry this code cannot resolve to a stable absolute path is a candidate it
// could NOT check, and is reported as such rather than skipped: POSIX reads an
// EMPTY entry as the working directory, and a relative entry resolves against a
// cwd this code has no business reasoning about. Both are real places a sudo
// could sit, so both deny.
// A FIXED LITERAL, never the component itself (Codex T6 r11, ruling (b)). The
// reason is worth reporting — "unknown" alone leaves a caller guessing why a
// clean-looking host was refused — but PATH is attacker-influenced text, and
// this value travels into the step log, the admission record and the uploaded
// artifact. Interpolating it would hand a wrapped command a writable line in
// the evidence about that command.
const SUDO_PATH_UNRESOLVABLE = 'unknown: empty-or-relative PATH entry';

const sudoCandidatePaths = (pathValue) => {
  const candidates = [...SUDO_CONVENTIONAL_PATHS];
  let unresolvable = false;
  // AN EXPLICITLY EMPTY PATH IS NOT AN ABSENT ONE (Codex T6 r11, Critical).
  // POSIX and bash both read a NULL COMPONENT as the current working
  // directory, and '' is a single null component — so PATH='' says "look in
  // the cwd", which is a place a sudo can sit and this code cannot resolve.
  // Skipping the parse for '' returned `absent` and GRANTED strict admission
  // on exactly that host. Only an ABSENT variable (undefined/null, i.e. not a
  // string at all) means "conventional locations only".
  if (typeof pathValue === 'string') {
    for (const entry of pathValue.split(':')) {
      if (!entry.startsWith('/')) {
        unresolvable = true;
        continue;
      }
      const directory = entry.replace(/\/+$/, '');
      candidates.push(`${directory}/${SUDO_BINARY_NAME}`);
    }
  }
  // A Set, because the same directory can appear on PATH twice, or once there
  // and once in the conventional list, and a doubled finding reads as two
  // sudos.
  return { candidates: [...new Set(candidates)], unresolvable };
};
// lstat, not stat: a DANGLING symlink at /usr/bin/sudo makes stat throw ENOENT,
// which would read as "absent" while the path is plainly rigged. lstat sees the
// link itself.
const defaultSudoStat = (candidate) => {
  try {
    lstatSync(candidate);
    return 'present';
  } catch (error) {
    return error?.code === 'ENOENT' ? 'absent' : 'unreadable';
  }
};
const detectSudoBinary = (options = {}) => {
  const platform = seam(options, 'platform', process.platform);
  const statPath = seam(options, 'statPath', defaultSudoStat);
  const pathValue = seam(options, 'pathValue', process.env.PATH);
  // These paths are a Linux claim. Anywhere else this code has no idea what
  // the escalation surface looks like, and "no idea" denies.
  if (platform !== 'linux') return 'unknown';
  const { candidates, unresolvable } = sudoCandidatePaths(pathValue);
  const found = [];
  let unreadable = false;
  for (const candidate of candidates) {
    let reading;
    try {
      reading = statPath(candidate);
    } catch {
      unreadable = true;
      continue;
    }
    if (reading === 'present') found.push(candidate);
    else if (reading !== 'absent') unreadable = true;
  }
  // FIXED-SIZE, SINGLE-LINE METADATA — never the paths themselves (Codex T6
  // r13). This reading is producer-derived: every byte of `found` came from
  // the inherited PATH, and it travels into the admission record, the refusal
  // diagnostic, the step log and the uploaded artifact. Joined verbatim it was
  // unbounded and could contain anything: a legitimate 362-character nested
  // candidate produced a 579-character caveat that report.md truncated at the
  // render cap, and a candidate containing a NEWLINE produced
  // `present: /tmp/evil\nFORGED-LINE/sudo`, which passed validation and split
  // the supposedly single-line record into two.
  //
  // The proximate cause was ours: round 10 widened this reading's vocabulary
  // from `\/\S+` to `\/[^,]+` so directories containing spaces would validate.
  // A vocabulary widened for a display convenience is a hole, and this is the
  // second time raw PATH bytes have had to be taken back out of the evidence
  // (the `unknown` reason was the first, in round 11).
  //
  // So the reading carries a COUNT and a DIGEST and nothing else. The digest is
  // SHA-256 over the sorted, NUL-joined matched candidates: two hosts with the
  // same sudo set hash identically, and an operator can recompute it from their
  // own listing — without this action disclosing a list, which would rebuild
  // the injection surface for no decision they cannot already make. The
  // actionable fact is "sudo exists here, so strict is impossible on this
  // host"; Task 8 documents where the inspection looks.
  if (found.length > 0) {
    const fingerprint = createHash('sha256').update([...found].sort().join('\0')).digest('hex');
    return `present: ${found.length} at sha256=${fingerprint}`;
  }
  // An unreadable candidate outranks an unresolvable entry only because it is
  // the more specific failure; both deny, so the order costs nothing.
  if (unreadable) return 'unknown';
  return unresolvable ? SUDO_PATH_UNRESOLVABLE : 'absent';
};

const readOwnCapabilities = (options = {}) => {
  const platform = seam(options, 'platform', process.platform);
  const readFile = seam(options, 'readFile', readFileSync);
  if (platform !== 'linux') return 'unknown';
  let raw;
  try {
    raw = readFile(PROC_SELF_STATUS_PATH, 'utf8');
  } catch {
    return 'unknown';
  }
  const text = String(raw);
  const held = [];
  for (const field of CAPABILITY_FIELDS) {
    const match = new RegExp(`^${field}:\\s*([0-9a-fA-F]+)\\s*$`, 'm').exec(text);
    // A field this code could not find or could not parse is a reading it does
    // not have, never a zero.
    if (match === null) return 'unknown';
    let bits;
    try {
      bits = BigInt(`0x${match[1]}`);
    } catch {
      return 'unknown';
    }
    for (const [name, bit] of DANGEROUS_CAPABILITIES) {
      if ((bits & (1n << bit)) !== 0n && !held.includes(name)) held.push(name);
    }
  }
  return held.length === 0 ? 'clear' : held.join('+');
};

// THE FOUR READINGS, and the vocabulary each is allowed to speak. A value
// outside its set is not a reading this code produced, so it is unreadable —
// never clear.
//
// ANCHORED AND FIXED-SIZE, all four (Codex T6 r13). Three of these were
// bounded by their producers already; that was believed rather than enforced,
// and the fourth was neither. A vocabulary is the only place "fixed-size,
// single-line" can be made true rather than aspirational, so each one below
// admits an ENUMERATED set or an anchored pattern with a bounded length, and
// nothing else. Every regex is anchored at both ends, which is also what
// excludes embedded newlines: with no multiline flag set, the end anchor
// matches end of INPUT, never end of line.
const PTRACE_VALUES = new Set(['unconditional', 'privilege-bypassable', 'permissive', 'unknown']);
const UID_VALUES = new Set(['non-root', 'root', 'unknown']);
// Count then digest. 'present: ' is 9 characters, ' at sha256=' is 11 and the
// digest is 64, so a reading is 84 PLUS THE COUNT DIGITS — 85 at one digit and
// 94 at ten. (Earlier rounds quoted 85 as the maximum; that was the
// single-digit case mistaken for the widest, and an ordinary two-digit count
// already exceeds it.)
//
// Ten digits, because the count is the length of an Array — and TEN DIGITS IS
// TOTAL, not merely generous. A JavaScript Array cannot exceed 2^32-1 =
// 4294967295 elements, which is exactly ten digits, and pushing past that throws
// before any count could be formatted. So there is no host, however contrived,
// whose reading this vocabulary rejects: the producer and the vocabulary are
// closed over each other, provably (Codex T6 r16). DO NOT "tidy" this to a
// smaller bound — five digits was the previous tidy answer, and a probe with
// 99,999 PATH entries plus the three conventional paths produced
// `present: 100002 …`, which that vocabulary then rejected as a value this
// action does not produce (Codex T6 r15 #1). Fail-closed, but it broke the
// closure the anchor exists to state and degraded a correct best-effort reading
// to "unreadable". Widened rather than CLAMPED: a clamp would invent a
// semantics — what would "100002" mean if it were capped? — that we would then
// have to document and defend.
const SUDO_PRESENT = /^present: [1-9][0-9]{0,9} at sha256=[0-9a-f]{64}$/;
const SUDO_VALUES = new Set(['absent', 'unknown', SUDO_PATH_UNRESOLVABLE]);
// Derived from the SAME Map the producer joins, so the vocabulary cannot drift
// wider than what can actually be produced: every non-empty subset, in the
// Map's own order, plus the two scalar readings. Fifteen combinations, the
// longest 51 characters.
const CAPABILITY_VALUES = (() => {
  const names = [...DANGEROUS_CAPABILITIES.keys()];
  const values = new Set(['clear', 'unknown']);
  for (let mask = 1; mask < (1 << names.length); mask += 1) {
    values.add(names.filter((_, index) => (mask & (1 << index)) !== 0).join('+'));
  }
  return values;
})();
// THE STRUCTURAL INVARIANT, stated once and enforced for every reading — not
// re-derived per field (round-13 residual). The anchored vocabularies above
// describe the readings that exist TODAY; three of the four were bounded by
// luck of construction rather than by design, and nothing said so. A fifth
// reading added tomorrow with an unbounded value AND a matching unbounded
// vocabulary would reintroduce the class this cycle has already hit twice:
// round 11's `unknown` reason and round 13's `present:` value, both of which
// carried raw PATH bytes into the evidence.
//
// A reading is a string, at most 128 characters, and PRINTABLE ASCII
// throughout. Today's widest reading is sudo at 94 (84 fixed characters plus up
// to ten count digits), so 128 is generous headroom and still far too small to
// hold an interpolated path.
//
// Printable ASCII rather than "no control characters" (Codex T6 r15 #2). Round
// 14 advertised "no control characters at all" and "true single-line" and
// delivered neither: its gate excluded C0 (U+0000-U+001F) plus DEL, and NOTHING
// ELSE. C1 (U+0080-U+009F) was never covered — which is exactly why U+0085 NEL
// got through, NEL being a C1 control rather than something beyond the control
// characters. (Corrected in round 16: this comment said the old gate excluded
// "C0/C1", which would have caught NEL and is not what the code did.) Also
// admitted: the U+2028/U+2029 line separators, the U+202E right-to-left override
// that reverses how a record READS without changing what it says, and zero-width
// characters that hide differences between two records a human is asked to
// compare. Current vocabularies happen to reject all of them, so this was never
// an admission bypass — but a gate whose stated invariant is false is not
// future-proofing, which is the only reason this gate exists rather than a
// per-field check. Every reading this action produces is ASCII by construction,
// so the restriction costs nothing and closes the class.
const READING_MAX_LENGTH = 128;
const PRINTABLE_ASCII = /^[\u0020-\u007E]*$/;
const structurallyValid = (value) => typeof value === 'string'
  && value.length <= READING_MAX_LENGTH
  && PRINTABLE_ASCII.test(value);

// THE GATE, AND THE ORDERING IS ENFORCED BY REACHABILITY. The vocabulary
// predicate is captured in this closure and is deliberately NOT a property of
// the field it returns — so there is no path from a caller to the vocabulary
// that skips the structural check. A future edit cannot consult one first by
// accident, because it has nothing to consult: `read` is the only way in.
//
// It classifies rather than returning a boolean, because "this host failed the
// check" and "our own probe returned something malformed" are different
// problems with different fixes, and an operator has to be able to tell them
// apart. It never throws, whatever it is handed.
const admissionField = (key, label, clear, vocabulary) => ({
  key,
  label,
  clear,
  read: (value) => {
    if (!structurallyValid(value)) return 'malformed';
    if (!vocabulary(value)) return 'unrecognised';
    return value === clear ? 'clear' : 'blocked';
  },
});

const ADMISSION_FIELDS = [
  admissionField('ptrace', 'same-UID ptrace policy', 'unconditional', (value) => PTRACE_VALUES.has(value)),
  admissionField('uid', 'effective uid', 'non-root', (value) => UID_VALUES.has(value)),
  admissionField('sudo', 'sudo binary', 'absent', (value) => SUDO_VALUES.has(value) || SUDO_PRESENT.test(value)),
  admissionField('capabilities', 'privileged capabilities', 'clear', (value) => CAPABILITY_VALUES.has(value)),
];

// DERIVED FROM THE READINGS, NEVER READ OFF THE RECORD (Codex T6 r9 #2). The
// admission record round-trips through a state file any same-user process can
// rewrite, and the round-8 predicate asked that file exactly one question —
// "is your blockers list empty?" — which it could simply answer. A forged
// `{ptrace:'permissive', uid:'root', …, blockers: []}` was ADMITTED. So the
// list is recomputed from the four fields every time it is consulted, the
// fields are validated against the vocabularies above, and the persisted list
// is never an input in either direction.
const admissionBlockers = (admission) => {
  if (admission === null || typeof admission !== 'object' || Array.isArray(admission)) {
    return ADMISSION_FIELDS.map((field) => `${field.label}: no usable admission record`);
  }
  return ADMISSION_FIELDS.flatMap((field) => {
    // hasOwn, so an inherited property cannot supply a reading.
    const value = Object.hasOwn(admission, field.key) ? admission[field.key] : undefined;
    switch (field.read(value)) {
      case 'clear':
        return [];
      // Both rejections deny and both name the field. They share the
      // "unreadable record" stem because the consequence is identical, and
      // differ in the parenthetical because the remedy is not: one is a host
      // this action cannot read, the other is a value it did not produce.
      case 'malformed':
        return [`${field.label}: unreadable record (malformed reading — not a bounded printable-ASCII string)`];
      case 'unrecognised':
        return [`${field.label}: unreadable record (outside this action's vocabulary)`];
      default:
        return [`${field.label}: ${value}`];
    }
  });
};

// A PROBE THAT CANNOT BE CALLED IS A READING THIS CODE DOES NOT HAVE, not an
// exception (Codex T6 r10 #3). The round-9 seam() fix made an explicit
// `undefined` mean "absent" for the lower-level readers, but this aggregate
// invoked whatever seam() handed back immediately — so an undefined probe threw
// TypeError, escaped to main's catch, and surfaced as exit 1. That reads as
// "the action crashed", not "this host was refused", and the difference matters
// to whoever has to act on it. Anything that is not a callable returning a
// string is 'unknown', which denies.
const callProbe = (probe) => {
  if (typeof probe !== 'function') return 'unknown';
  let value;
  try {
    value = probe();
  } catch {
    return 'unknown';
  }
  return typeof value === 'string' ? value : 'unknown';
};

// ONE evaluator, ONE predicate, and every consumer reads them rather than
// re-deriving the rule (the discipline that fixed the mode lookup in r7).
const evaluateAdmission = (options = {}) => {
  const record = {
    ptrace: callProbe(seam(options, 'readPtrace', readPtraceScope)),
    uid: callProbe(seam(options, 'readEuid', readEffectiveUid)),
    sudo: callProbe(seam(options, 'detectSudo', detectSudoBinary)),
    capabilities: callProbe(seam(options, 'readCapabilities', readOwnCapabilities)),
  };
  // Recorded for the diagnostics that quote it, and recomputed by every
  // consumer regardless — so the two can never disagree.
  return { ...record, blockers: admissionBlockers(record) };
};

const admissionEstablished = (admission) => admissionBlockers(admission).length === 0;

const describeAdmission = (admission) => {
  const blockers = admissionBlockers(admission);
  return blockers.length > 0 ? blockers.join('; ') : 'every checked route clear';
};

// THE ADMISSION RECORD, in one builder, used verbatim by all three surfaces:
// `start`'s pre-command step log, `run`'s log beside the digest, and the
// rendered report. One builder because the whole value of the record is that a
// reader can COMPARE the copies — and copies that were assembled separately
// would differ for innocent reasons and destroy that.
//
// Emitted on EVERY regime, admitted runs included (Codex T6 r9 #3). An
// artifact-only stamp is worth nothing on its own: a compromised best-effort
// run can forge whatever the artifact says. What makes the artifact's copy
// mean something is that `start` streamed an identical one BEFORE the wrapped
// command existed, where no later process can retract or rewrite it.
const admissionCaveats = (admission, evidenceTrust, nonce) => {
  const established = admissionEstablished(admission);
  const regime = evidenceTrust === 'strict' || evidenceTrust === 'best-effort' ? evidenceTrust : 'unrecognised';
  // BOTH HALVES, and the strict half is checked against the literal (Codex T6
  // r10 #2). The readings are a fact about the host; the REGIME is a decision
  // the caller made, and an authenticated claim needs both. Deriving it from
  // the readings alone let a best-effort run on a clean host advertise the
  // authenticated trust unit — flatly contradicting action.yml and the spec,
  // which promise that nothing under best-effort authenticates anything. An
  // unrecognised regime (a rewritten state file, an older record) is not a
  // strict one, so it fails closed to diagnostic.
  const authenticated = evidenceTrust === 'strict' && established;
  return [
    // Identity and regime on one line, FINDINGS on the next. The findings are
    // the only part whose length depends on the host — four bounded readings
    // rather than one, but still enough, with the identity prefix, to crowd the
    // authoring margin. Splitting them keeps each statement short by
    // construction instead of by luck (Codex T6 r13).
    `ADMISSION RECORD (streamed by start before the wrapped command existed): invocation=${nonce ?? 'unrecorded'};`
    + ` evidence-trust=${regime}; in-process boundary=${established ? 'ESTABLISHED' : 'NOT established'};`
    + ` admission=${authenticated ? 'STRICT (authenticated)' : 'DIAGNOSTIC ONLY'}.`,
    `Findings: ${describeAdmission(admission)}.`,
    // SPLIT, because a single caveat of this length did not survive being
    // rendered (Codex T6 r11 #2). debug_report.js caps each rendered caveat at
    // 500 characters, so the 676-character version reached report.md ending
    // "These are the escala…" — deleting the limitation itself and leaving the
    // human artifact reading STRONGER than the JSON and the step logs. The cap
    // is right and stays; the text is what has to fit through it, so each
    // statement below stands alone and is comfortably short.
    'Checked: Yama ptrace mode, effective uid, sudo binary presence, and this process\'s own permitted/effective capabilities.',
    'The sudo check covers the conventional absolute paths and every sudo candidate on the inherited PATH, lstat-ed and never executed.'
    + ' Any sudo binary at a conventional absolute path or anywhere on the inherited PATH denies strict admission,'
    + ' because sudoers rules are command-specific and no probe of one command can establish the absence of a rule for another.',
    'These are the escalation routes this action checks, not a proof that no route exists:'
    + ' a setuid binary, a mounted container socket, or a writable privileged service grants the same power unobserved.',
    // Each branch contributes SHORT entries rather than one long one. A single
    // sentence per caveat is what keeps every statement whole once the renderer
    // applies its per-caveat cap, and it is why this is a flat spread instead of
    // a nested ternary returning one string.
    ...(authenticated
      ? ['The trust unit is this admission record, plus the matching digest from run\'s step log, plus the artifact — all three together, and none of them alone.']
      : established
        ? [
          `The host readings came back clear, but this run was NOT admitted under strict (evidence-trust=${regime}), so nothing here is authenticated.`,
          'The capture, its digest and this report are diagnostic claims only, because the regime that was selected accepts a wrapped command able to rewrite the process that produced them.',
        ]
        : [
          'The in-process guarantees were NOT established on this host, so a same-user process may be able to attach to the collector or to the capturing step,'
          + ' or to rewrite their memory without ptrace at all where it can reach root.',
          'This run was NOT admitted under strict, and the capture, its digest and this report are diagnostic claims only;'
          + ' the copy of this record in start\'s own step log is the only one the wrapped command could not reach.',
        ]),
    // THE LIMIT OF THE UNIT ITSELF (Codex T6 r10 #4). Naming three pieces
    // invites a reader to assume something checked that they belong together.
    // This action verifies none of that correspondence: the comparison is
    // external, manual, and only meaningful between copies carrying the SAME
    // invocation — which is why the nonce is on the first line of every copy.
    // The nonce ENFORCES nothing: it lets a reader detect a mismatch that would
    // otherwise be invisible, and that is the whole of its contribution (Codex
    // T6 r11 #4). Binding the pieces here would need `start` to hand `run`
    // something unforgeable, which is the very problem the platform
    // prerequisite exists to solve.
    `This action verifies none of that correspondence. Compare the copies by hand, and only against the start record with the same invocation=${nonce ?? 'unrecorded'}.`,
    'A digest paired with a different invocation\'s admission record proves nothing at all.'
    + ' The nonce does not enforce the pairing — nothing here does; it lets a reader detect a mismatch that would otherwise be invisible.',
  ];
};

// PATH SAFETY, not entropy. The invocation nonce is a directory-name segment
// now, and it arrives from this step's environment: the unguessability comes
// from randomUUID in `start`, while this pattern is what stops a '..', a
// separator or an empty string from turning a staging directory into a
// traversal. Bounded length so a hostile value cannot produce a name the
// filesystem rejects in some more confusing way.
const NONCE_PATTERN = /^[A-Za-z0-9_-]{1,64}$/;

// The staged evidence child is INVOCATION-SCOPED (Codex T6 r1 #3). A fixed
// child name is a rendezvous point for invocations that share an output-dir —
// the default one under runner.temp, or a reused custom directory on a
// self-hosted runner — and everything downstream keys off those three
// filenames: one invocation's entry clear destroys another's evidence, a
// concurrent restage lands in the exact names the upload step enumerates, and
// a stale entry that cannot be unlinked (a DIRECTORY where session.log
// belongs) fails `report` while the always() upload still expands that
// directory's descendants into the artifact. With the invocation in the name,
// no two invocations ever address the same path.
const resolveEvidenceDir = (outputDir, nonce) => {
  if (!NONCE_PATTERN.test(String(nonce ?? ''))) {
    throw new Error('invocation nonce is missing or not a safe path segment; refusing to resolve a staging directory');
  }
  return path.join(outputDir, `${EVIDENCE_SUBDIR}-${nonce}`);
};

// Same helper contract as actions/closeout: the env-file path is the first
// argument so tests inject a temp file instead of the real GITHUB_OUTPUT.
const writeOutputs = (outputFile, pairs) => {
  const lines = Object.entries(pairs)
    .map(([name, value]) => `${name}=${String(value ?? '').replace(/\r?\n|\r/g, ' ')}`)
    .join('\n');
  appendFileSync(outputFile, `${lines}\n`);
};

const defaultStdoutWrite = (text) => process.stdout.write(text);

// Register a value with the RUNNER's own redactor, so every later log line
// that happens to contain it is replaced with '***' by Actions itself.
//
// This is not belt-and-braces over redactKnownSecrets: that one only cleans
// strings THIS process chooses to print, and the leak Codex reproduced comes
// from a printer we do not control. `NODE_DEBUG=http` anywhere in the job env
// makes Node's own http client dump every request header — `Authorization:
// Bearer <launch token>` included — straight to stderr, before any of our
// code sees it (Codex T4 #1). Only the runner can censor that, and only for
// values it was told about first, which is why both call sites mask BEFORE
// the token is put on the wire.
//
// Gated on the literal 'true' because outside Actions the ::add-mask::
// command is not interpreted by anything: it would just print the secret it
// was meant to hide onto a developer's terminal or into a test's stdout.
const maskValue = (env, value, write = defaultStdoutWrite) => {
  if (env?.GITHUB_ACTIONS !== 'true' || !value) return;
  write(`::add-mask::${value}\n`);
};

const redactKnownSecrets = (text, secrets) => {
  let result = String(text);
  for (const secret of secrets) {
    if (typeof secret === 'string' && secret.length >= 8) {
      result = result.split(secret).join('[REDACTED]');
    }
  }
  return result;
};

// Is `candidate` the directory `parent` itself, or somewhere under it? The
// relative path escapes only when it IS '..' or starts with '..' + separator;
// a bare `startsWith('..')` test does NOT mean that, because it also matches
// an ordinary child whose name merely begins with two dots — so
// `<workspace>/..cache` read as "outside the workspace" and sailed through
// the containment check it was supposed to fail (Codex T3 #3).
const isInsideDirectory = (parent, candidate) => {
  const relative = path.relative(path.resolve(parent), path.resolve(candidate));
  return relative === ''
    || (!relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative));
};

const validateActionInputs = ({
  runCommand, sessionName, failOnCommandFailure, port, maxEvents, maxBytes,
  hypothesisId, workingDirectory = '.', outputDir = '', workspace = '',
  evidenceTrust = 'strict',
}) => {
  const errors = [];
  if (!runCommand || !runCommand.trim()) errors.push('run: a command is required');
  // Two literals, exactly. This input decides whether the action runs an
  // arbitrary command on a host where it cannot defend its own capture, so a
  // value it cannot interpret is an error rather than something to round to
  // the nearest meaning.
  if (evidenceTrust !== 'strict' && evidenceTrust !== 'best-effort') {
    errors.push("evidence-trust: must be 'strict' or 'best-effort'");
  }
  if (!NAME_PATTERN.test(sessionName)) errors.push('session-name: must match [A-Za-z0-9_-]+');
  if (failOnCommandFailure !== 'true' && failOnCommandFailure !== 'false') {
    errors.push("fail-on-command-failure: must be 'true' or 'false'");
  }
  const portNumber = Number(port);
  if (!Number.isInteger(portNumber) || portNumber < 1 || portNumber > 65535) {
    errors.push('port: must be an integer between 1 and 65535');
  }
  for (const [name, value] of [['max-events', maxEvents], ['max-bytes', maxBytes]]) {
    if (value !== '' && (!/^\d+$/.test(value) || Number(value) < 1)) {
      errors.push(`${name}: must be a positive integer or empty`);
    }
  }
  if (hypothesisId !== '' && !NAME_PATTERN.test(hypothesisId)) {
    errors.push('hypothesis-id: must match [A-Za-z0-9_-]+ or be empty');
  }
  if (/[\r\n]/.test(workingDirectory) || /[\r\n]/.test(outputDir)) {
    errors.push('working-directory/output-dir: must not contain a CR or LF');
  }
  if (workspace && isInsideDirectory(workspace, outputDir)) {
    errors.push('output-dir: must be outside the repository workspace');
  }
  return errors;
};

// The state file carries this run's SESSION TOKEN, so it is written the
// way actions/closeout writes its own private evidence (same discipline,
// deliberately re-stated rather than imported — the two actions stay
// independently deployable): never through a pre-existing link, never with a
// window in which the bytes exist at a wider mode.
//
// 1. lstat the target: an existing symlink or non-regular entry is REFUSED,
//    never followed — a plain writeFileSync would happily write the token
//    through a symlink a local user pre-planted at this well-known path.
// 2. Stage into a temp sibling opened O_WRONLY|O_CREAT|O_EXCL at 0600, so the
//    open either creates a fresh inode or fails closed on anything already
//    there (a hard link included, which no-follow alone would not catch).
// 3. rename() over the target: path-based and atomic, and it REPLACES a
//    destination entry rather than writing through it. Windows cannot always
//    rename over an existing file, so EEXIST/EPERM there falls back to
//    unlink-then-rename; Linux runners always take the atomic path.
//
// The staged bytes are written with writeFileSync — which loops until the
// whole payload lands — rather than a bare writeSync, whose return value is a
// COUNT that a caller must honour: a legal short write (1 of 85 bytes, say)
// silently renamed truncated JSON into place, so `start` reported success
// while readState() returned null forever after and teardown, finding no
// usable pid, orphaned the collector (Codex T3 r2). The staged size is then
// verified against the payload before the commit, so the invariant holds for
// ANY writer, not merely the one this code happens to call today: a committed
// action-state.json always parses to the full state.
const writeState = (outputDir, state, { writeAll = writeFileSync } = {}) => {
  mkdirSync(outputDir, { recursive: true });
  const target = path.join(outputDir, STATE_FILE);
  let existing = null;
  try {
    existing = lstatSync(target);
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
  }
  if (existing && !existing.isFile()) {
    throw new Error(`refusing to write action state through a non-regular file (symlink, directory, or special): ${target}`);
  }
  const tempPath = path.join(outputDir, `.${STATE_FILE}.${process.pid}.${Date.now()}.tmp`);
  const payload = `${JSON.stringify(state)}\n`;
  const expectedBytes = Buffer.byteLength(payload, 'utf8');
  const fd = openSync(tempPath, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL, 0o600);
  let staged = false;
  try {
    writeAll(fd, payload);
    const stagedBytes = fstatSync(fd).size;
    if (stagedBytes !== expectedBytes) {
      throw new Error(`refusing to commit a partially written action state (${stagedBytes} of ${expectedBytes} bytes): ${tempPath}`);
    }
    staged = true;
  } finally {
    // Close before any cleanup: Windows refuses to unlink a file that is
    // still open, which would strand a half-written staging file.
    closeSync(fd);
    if (!staged) {
      try { unlinkSync(tempPath); } catch { /* best-effort cleanup */ }
    }
  }
  try {
    renameSync(tempPath, target);
  } catch (error) {
    if (error?.code !== 'EEXIST' && error?.code !== 'EPERM') {
      try { unlinkSync(tempPath); } catch { /* best-effort cleanup */ }
      throw error;
    }
    try {
      unlinkSync(target);
      renameSync(tempPath, target);
    } catch (retryError) {
      try { unlinkSync(tempPath); } catch { /* best-effort cleanup */ }
      throw retryError;
    }
  }
};

// Lock parameters. The retry budget (~450ms) is deliberately far below the
// staleness threshold: a live holder finishes a state write in microseconds,
// so anything still held after half a second is contention worth failing on
// rather than waiting out, while anything held for THIRTY seconds is not a
// holder at all — it is a crashed invocation's litter.
const LOCK_FILE = 'action-state.lock';
const LOCK_RETRY_LIMIT = 10;
const LOCK_RETRY_DELAY_MS = 50;
const LOCK_STALE_MS = 30_000;

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// The lock's current bytes, or null when it is gone. Never throws for the
// ordinary "someone deleted it" case, because both callers race deletion by
// construction.
const readLockToken = (lockPath) => {
  try {
    return readFileSync(lockPath, 'utf8');
  } catch (error) {
    if (error?.code === 'ENOENT') return null;
    throw error;
  }
};

// Take the WHOLE staleness observation from one descriptor: the timestamp the
// verdict is computed from and the bytes that verdict will be checked against
// must describe the same file.
//
// Statting the path and then reading the path are two independent lookups. A
// replacement landing between them yields a verdict assembled from the OLD
// file's mtime and the NEW file's content — evidence that never coexisted, and
// a wider race than the final check-to-unlink window (Codex T4 r4). One open
// pins one inode and both facts come off it.
//
// O_RDONLY follows symlinks where the lstat it replaces did not, which is
// harmless here: a lock can never be CREATED through a link, because
// O_CREAT|O_EXCL fails outright on one, and the unlink below removes the link
// itself rather than anything it points at. (O_NOFOLLOW is not portable to
// Windows, so it is not an option.)
const observeLock = (lockPath) => {
  let fd;
  try {
    fd = openSync(lockPath, constants.O_RDONLY);
  } catch (error) {
    if (error?.code === 'ENOENT') return null; // released while we looked
    throw error;
  }
  try {
    return { mtimeMs: fstatSync(fd).mtimeMs, content: readFileSync(fd, 'utf8') };
  } finally {
    closeSync(fd);
  }
};

// Create the lock and stamp it with WHO holds it. Returns true when this
// caller now owns the path, or false when someone else already holds it.
//
// The ownership stamp is what makes an unlink decidable: without it every
// deleter is blind, and "remove the lock file" cannot distinguish the lock it
// created from a successor's that merely lives at the same path.
const tryAcquireLock = (lockPath, ownership) => {
  let fd;
  try {
    fd = openSync(lockPath, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL, 0o600);
  } catch (error) {
    if (error?.code === 'EEXIST') return false;
    throw error;
  }
  // Full-write discipline, same as writeState (T3 r2): a lock whose ownership
  // bytes landed short would match NOBODY, so its own holder could not
  // release it and every later invocation would have to wait out the whole
  // staleness threshold to make progress.
  try {
    writeFileSync(fd, ownership);
    const staged = fstatSync(fd).size;
    const expected = Buffer.byteLength(ownership, 'utf8');
    if (staged !== expected) {
      throw new Error(`refusing to hold a partially stamped lock (${staged} of ${expected} bytes): ${lockPath}`);
    }
  } catch (error) {
    closeSync(fd);
    try { unlinkSync(lockPath); } catch { /* best-effort cleanup */ }
    throw error;
  }
  // Release the descriptor before returning: the lock is the path + ownership
  // bytes, not an open handle. Windows refuses to unlink a name this process
  // still has open (Validate Node 20, 2026-08-16), so a live holder that kept
  // `fd` would make the ownership-verified release and the reaper-successor
  // test both EPERM. Unix already allowed unlink of a held lock; closing here
  // matches that model on every platform.
  closeSync(fd);
  return true;
};

// A real critical section for the state file, honored by every writer.
//
// writeState alone is not enough. Its rename is atomic, but atomic means the
// file is never torn — not that a decision made by reading it is still valid
// when the write lands. `run` re-read the state, compared nonces, then wrote;
// a second invocation could commit in that gap and the first would rename its
// stale snapshot straight over the top, restoring a dead pid and port over a
// live collector's and orphaning it (Codex T4 r2). Check-then-act cannot be
// fixed by checking harder; the read and the write have to be indivisible,
// which is what holding this lock across BOTH of them buys.
//
// O_CREAT|O_EXCL is the primitive: the open either creates the lock or fails
// EEXIST, with no window between testing and taking it.
const withStateLock = async (outputDir, fn, { onStaleObserved = null } = {}) => {
  mkdirSync(outputDir, { recursive: true });
  const lockPath = path.join(outputDir, LOCK_FILE);
  // Unique per acquisition, not per process: one process may take this lock
  // several times, and a recycled pid must never be able to impersonate an
  // earlier holder.
  const ownership = `${process.pid}\n${randomUUID()}\n`;
  let held = false;
  let reaped = false;
  let attempts = 0;
  while (!held) {
    held = tryAcquireLock(lockPath, ownership);
    if (held) break;
    // Someone holds it. Reap it ONCE, and only when it is old enough that no
    // live invocation could still own it — a runner that was cancelled or
    // OOM-killed mid-write leaves this file behind forever, and without a
    // stale sweep every later job on that output-dir would fail to start.
    if (!reaped) {
      const observation = observeLock(lockPath);
      if (observation && Date.now() - observation.mtimeMs > LOCK_STALE_MS) {
        reaped = true;
        // The EXACT bytes staleness was judged against, off the same inode as
        // the timestamp. Everything below is about not deleting anything else.
        const observed = observation.content;
        if (onStaleObserved) await onStaleObserved({ lockPath, observed });
        // Two reapers can both find the same stale lock. One wins the
        // O_EXCL re-create; if the loser then unlinks blindly it deletes the
        // WINNER's fresh lock and a third writer walks in — the clobber this
        // whole round exists to close (Codex T4 r3). Re-read immediately
        // before deleting: if the path no longer holds the bytes we judged,
        // it belongs to someone live now, so leave it and keep retrying.
        if (readLockToken(lockPath) === observed) {
          try {
            unlinkSync(lockPath);
          } catch (error) {
            if (error?.code !== 'ENOENT') throw error;
          }
        }
        continue; // retry against the path, freed or not
      }
    }
    attempts += 1;
    if (attempts >= LOCK_RETRY_LIMIT) {
      throw new Error(`could not acquire the action state lock at ${lockPath} after ${attempts} attempts over ~${attempts * LOCK_RETRY_DELAY_MS}ms`);
    }
    await sleep(LOCK_RETRY_DELAY_MS);
  }
  try {
    return await fn();
  } finally {
    try {
      // Ownership-verified release. A holder that ran long enough to be
      // judged stale no longer owns this path — a reaper deleted its lock and
      // a successor created their own. Unlinking on the way out would evict
      // that live successor, which is the same clobber by a different route,
      // so release only what is still demonstrably ours (Codex T4 r3).
      if (readLockToken(lockPath) === ownership) unlinkSync(lockPath);
    } catch { /* best-effort release */ }
  }
};

const readState = (outputDir) => {
  try {
    return JSON.parse(readFileSync(path.join(outputDir, STATE_FILE), 'utf8'));
  } catch {
    return null;
  }
};

// Missing identity is a refusal, not a waiver (Codex T6 r1 #2). Every step
// after `start` is handed `steps.start.outputs.invocation-nonce`, so an empty
// one means this invocation's `start` never got far enough to emit it — and
// whatever state is sitting in the output-dir was therefore written by
// somebody else. The old lenient reading ("no nonce, so skip the check") let a
// fresh job pointed at a REUSED output-dir act on a stranger's record: kill a
// pid that may since have been recycled to an unrelated process, or mirror an
// exit code no step of this job produced.
//
// The check is deliberately made BEFORE readState in every caller: "do not
// act" and "do not read" are the same rule when the only thing a read can
// produce is a decision.
// Presence AND shape: the same value names this invocation's staging
// directory, so a nonce that could not be a path segment is no more usable
// than an absent one, and both fail the same way rather than one of them
// throwing out of resolveEvidenceDir.
const requireInvocationNonce = (env, subcommand) => {
  if (NONCE_PATTERN.test(String(env.DEBUG_ACTION_INVOCATION_NONCE ?? ''))) return false;
  process.stderr.write(`debug-evidence-action: ${subcommand}: this step received no usable invocation nonce; refusing to read or act on recorded state.\n`);
  return true;
};

const rejectForeignNonce = (state, env, subcommand) => {
  if (env.DEBUG_ACTION_INVOCATION_NONCE && state.nonce !== env.DEBUG_ACTION_INVOCATION_NONCE) {
    process.stderr.write(`debug-evidence-action: ${subcommand}: recorded state does not carry this invocation's nonce (output-dir overwritten by a concurrent run, or never written by this run); refusing to trust it.\n`);
    return true;
  }
  return false;
};

const defaultSpawnShim = (args, { env }) => spawn(process.execPath, [BOOT_SHIM, ...args], {
  env,
  detached: true,
  windowsHide: true,
  stdio: ['ignore', 'pipe', 'pipe'],
});

// Hosted Windows: the detached collector must not spawn powershell.exe
// (Session 0 + DETACHED_PROCESS hangs EncodedCommand for the full 15s ACL
// budget, and POST /session then returns HTTP 500). `start` is a normal
// Actions step process with a console; apply the same current-user-only
// DACL from here after handshake/mint and before this process returns.
// `platform`/`protect` are seams: the failure path below is Windows-only and
// non-Windows CI has no PowerShell to fail with.
const protectWindowsPrivateFileIfPresent = (privateFile, {
  platform = process.platform, protect = protectWindowsPrivateFile,
} = {}) => {
  if (platform !== 'win32') return;
  try {
    lstatSync(privateFile);
  } catch (error) {
    if (error?.code === 'ENOENT') return;
    throw error;
  }
  try {
    protect(privateFile);
  } catch (error) {
    // Mirror the collector's in-process contract (readOrCreateProjectSalt in
    // scripts/debug_server.js): a salt whose owner-only DACL could not be
    // applied must never stay persisted with inherited NTFS read permissions.
    // Unlink exactly this file, then rethrow the ORIGINAL ACL error unmasked.
    try { unlinkSync(privateFile); } catch { /* best effort cleanup */ }
    throw error;
  }
};

// Read the shim's single startup line (private pipe). Resolves the parsed
// JSON object; rejects on timeout, spawn failure, child exit, or unparsable
// output.
const readShimStartLine = (child, timeoutMs) => new Promise((resolve, reject) => {
  let settled = false;
  let stdout = '';
  let stderr = '';
  const settle = (fn, value) => {
    if (settled) return;
    settled = true;
    clearTimeout(timer);
    fn(value);
  };
  const timer = setTimeout(() => {
    settle(reject, new Error(`collector shim did not report startup within ${timeoutMs}ms`));
  }, timeoutMs);
  child.stdout.on('data', (chunk) => {
    stdout += chunk;
    const newline = stdout.indexOf('\n');
    if (newline === -1) return;
    try {
      settle(resolve, JSON.parse(stdout.slice(0, newline)));
    } catch {
      settle(reject, new Error('collector shim printed an unparsable startup line'));
    }
  });
  child.stderr.on('data', (chunk) => { stderr += chunk; });
  // A spawn failure (ENOENT on the node binary, EACCES, fork limits) emits
  // 'error' and NO exit — without this listener it surfaces as an uncaught
  // exception on an EventEmitter instead of this promise's rejection
  // (Codex T3 #6).
  child.on('error', (error) => {
    settle(reject, new Error(`collector shim failed to spawn: ${error?.message ?? error}`));
  });
  // 'close', not 'exit': 'exit' fires as soon as the process is gone, which
  // can precede the final stderr chunk, so the shim's own structured reason
  // ({"status":"error","reason":"port_in_use"}) was routinely lost and
  // replaced by the generic message. 'close' waits for the stdio streams to
  // drain first (Codex T3 #6).
  child.on('close', () => {
    let reason = 'exited before startup';
    try { reason = JSON.parse(stderr.split('\n')[0]).reason ?? reason; } catch {}
    settle(reject, new Error(`collector shim did not report startup: ${reason}`));
  });
});

// start owns the LAUNCH TOKEN's entire lifecycle, and it ends here.
//
// The token is the collector's operator credential: it mints sessions and,
// crucially, it is the only thing that can POST a hypothesis line. Persisting
// it in action-state.json put that capability on disk for the rest of the
// job, where the wrapped command — same OS user, derivable path — could pick
// it up and forge a verdict the evidence contract then had to detect after
// the fact (Codex T5 r3). So the token is used and dropped inside this one
// process: handshake, mask, prove the port occupant holds it, mint the
// session, open the hypothesis, and write state carrying only the SESSION
// token. After start returns, no credential capable of writing a verdict
// exists anywhere in the job — the hypothesis-set contract stops being a
// detection and becomes a structural fact.
const startSubcommand = async ({
  inputs, outputDir, env = process.env, projectRoot = process.cwd(),
  spawnShim = defaultSpawnShim, probeReady = probeReadyCollector, kill = process.kill,
  request = httpRequestJson, probeToken = probeLaunchToken,
  writeStdout = defaultStdoutWrite,
  nonce = randomUUID(), readyTimeoutMs = Number(
    env.DEBUG_ACTION_READY_TIMEOUT_MS
    || process.env.DEBUG_ACTION_READY_TIMEOUT_MS
    || 15_000,
  ),
  // A SEAM, not a default value: evaluating `evaluateAdmission()` as a default
  // parameter would run it before this function's body, and therefore before
  // the identity outputs below — contradicting the "first act" invariant those
  // outputs are pinned by (Codex T6 r6, ordering).
  probeAdmission = evaluateAdmission,
}) => {
  // THE FIRST THING THIS PROCESS DOES, ahead of validation and ahead of any
  // filesystem work: publish this invocation's identity as a STEP OUTPUT.
  //
  // Two properties, and the order matters as much as the channel:
  //
  // 1. A step output is per-invocation by construction. The runner resolves
  //    `steps.start.outputs.*` from THIS action instance, so a second
  //    invocation in the same job reads its own `start`, never this one's.
  //    GITHUB_ENV — where this used to go — is job-global: its values persist
  //    into every later step of the job and DO appear in the expression `env`
  //    context (settled against the runner's own source; an earlier ruling in
  //    this project's plan claimed otherwise and was wrong). A nonce on that
  //    channel is inheritable, and inheritable identity is no identity at all.
  // 2. Emitting BEFORE the checks below means a `start` that fails still hands
  //    its own later steps an identity nothing else in the job can match.
  //    Emitting after them would leave a failed invocation's `report` with an
  //    EARLIER invocation's nonce, its state in a shared output-dir would then
  //    look owned, and the always() upload would publish that evidence under
  //    this run's artifact name (Codex T6 r1 #1).
  //
  // The staging directory goes out in the same act, and for a second reason
  // (Codex T6 r2 #1). The upload step has to be told where to look, and the
  // only safe moment to tell it is before the wrapped command exists: a value
  // published AFTER that command has run is not a boundary at all, because the
  // command can write into the runner's step-output file directly — stripping
  // GITHUB_OUTPUT from its environment hides the variable, not the file. So
  // `run` publishes nothing the upload step consults; the path set is fixed
  // here, in the same pre-command window that protects the verification key,
  // and it is derived from the nonce on the line above rather than duplicated.
  if (env.GITHUB_OUTPUT) {
    writeOutputs(env.GITHUB_OUTPUT, {
      'invocation-nonce': nonce,
      'evidence-dir': resolveEvidenceDir(outputDir, nonce),
    });
  }
  const workspace = env.GITHUB_WORKSPACE || '';
  const errors = validateActionInputs({ ...inputs, outputDir, workspace });
  if (errors.length > 0) throw new Error(`invalid inputs: ${errors.join('; ')}`);
  // Read here — after the identity outputs, before anything is spawned or
  // written — and carried in state from now on, so every later step answers
  // the same way. Read ONCE, and deliberately not re-read later: a re-read
  // would be defense in depth at best, never a fix, because a privileged actor
  // can change modes 0-2 at runtime, including after any check this code makes
  // (Codex T6 r6, ruling (c)). What the value is NOT is immutable.
  const admission = probeAdmission();
  // THE PRE-COMMAND ADMISSION RECORD (Codex T6 r9 #3), and it goes out HERE:
  // after the identity outputs, before the collector is spawned, and long
  // before the wrapped command exists. Every regime gets one — an admitted run
  // needs it as much as a refused one, because "which regime was in force" is
  // precisely what a reader cannot establish afterwards from anything the
  // wrapped command could have touched. This copy is the fixed point the
  // artifact's copy is compared against; it is streamed to the step log, where
  // it is immutable, and `run` and the report carry the identical text.
  for (const line of admissionCaveats(admission, inputs.evidenceTrust, nonce)) {
    process.stderr.write(`debug-evidence-action: start: ${line}\n`);
  }
  if (!admissionEstablished(admission)) {
    // THE REFUSAL, and it happens here because here is the last moment that is
    // still before the wrapped command exists (Codex T6 r6).
    //
    // Labeling alone cannot be a security control on this platform: the whole
    // hazard is a command able to rewrite `run`, and such a command can strip
    // the caveat that warns about it. Only a refusal that precedes the command
    // is out of its reach. `start` returning 3 fails this step, and the run
    // step is unconditional — so the runner skips it and the command never
    // executes at all.
    //
    // The diagnostic has to leave the caller somewhere to go, so it names what
    // was found, why that is not a boundary, and both ways forward.
    if (inputs.evidenceTrust !== 'best-effort') {
      process.stderr.write(`debug-evidence-action: start: refusing to run the wrapped command: this host does not establish the in-process boundary this action's evidence depends on (${describeAdmission(admission)}). Strict admission requires ALL of: Linux Yama ptrace_scope 3, a non-root effective uid, NO sudo binary at a conventional absolute path or anywhere on the inherited PATH (the inspection lstats /usr/bin/sudo, /bin/sudo, /usr/local/bin/sudo and every PATH candidate, and executes nothing), and none of CAP_SYS_ADMIN/CAP_BPF/CAP_SYS_PTRACE/CAP_SYS_MODULE in this process's own permitted or effective set. Mode 3 is necessary, not sufficient: it forbids classic same-UID ptrace attachment, but a command that can reach root rewrites another task's memory with a privileged BPF program (bpf_probe_write_user) or a kernel module without calling ptrace at all — and standard GitHub-hosted runners ship sudo with a passwordless rule, so hosted execution stays best-effort. Either run where the wrapped principal has no route to root, or set 'evidence-trust: best-effort' to accept clearly labeled best-effort evidence.\n`);
      return 3;
    }
    // Opted in. This copy of the qualification is the only one the wrapped
    // command cannot reach: it is streamed before that command exists, so
    // nothing it does afterwards can retract it. What that buys is precisely
    // one fact — that best-effort was consciously selected — and NOT that the
    // capture which follows is tamper-resistant. The other two copies (run's
    // pre-digest line and the report caveat) are written after the command has
    // run, by a process it may have been able to rewrite.
    process.stderr.write(`debug-evidence-action: start: BEST-EFFORT EVIDENCE: this host does not establish the in-process boundary this action's evidence depends on (${describeAdmission(admission)}), and 'evidence-trust: best-effort' was set. A same-user process may be able to attach to the collector or to the capturing step — or, where it can reach root, to rewrite their memory without ptrace at all — so the capture below cannot be treated as tamper-resistant. This line and the admission record above it are written before the wrapped command runs and cannot be retracted by it.\n`);
  }
  // Containment layer 2 (Codex T3 #3): the check above compares the paths as
  // WRITTEN, so an output-dir that merely RESOLVES into the workspace — a
  // symlink pointing back inside the checkout, or a workspace that is itself
  // a link — passes it. Create the directory (it has to exist to be
  // resolved), then compare real paths, before anything is spawned or
  // written. A workspace that does not resolve contains nothing.
  mkdirSync(outputDir, { recursive: true });
  if (workspace) {
    let realWorkspace = null;
    try {
      realWorkspace = realpathSync(workspace);
    } catch { /* no such workspace on disk — nothing to be contained by */ }
    if (realWorkspace !== null && isInsideDirectory(realWorkspace, realpathSync(outputDir))) {
      throw new Error('invalid inputs: output-dir: must be outside the repository workspace (it resolves inside it)');
    }
  }
  const shimEnv = { ...env, DEBUG_PORT: inputs.port };
  if (inputs.maxEvents) shimEnv.DEBUG_ACTION_MAX_EVENTS = inputs.maxEvents;
  if (inputs.maxBytes) shimEnv.DEBUG_ACTION_MAX_BYTES = inputs.maxBytes;
  // Input redact-names EXTENDS (never replaces) any job-level DEBUG_REDACT_NAMES.
  if (inputs.redactNames) {
    shimEnv.DEBUG_REDACT_NAMES = [env.DEBUG_REDACT_NAMES, inputs.redactNames].filter(Boolean).join(',');
  }
  const child = spawnShim([projectRoot], { env: shimEnv });
  let startLine;
  try {
    startLine = await readShimStartLine(child, readyTimeoutMs);
  } catch (error) {
    try { child.kill(); } catch {}
    throw error;
  }
  if (startLine.status !== 'started') {
    throw new Error(`collector failed to start: ${startLine.reason ?? 'unknown'}`);
  }
  // The FIRST thing done with a freshly minted launch token, ahead of the
  // readiness probe and the state write: from here on the runner scrubs it
  // out of anything this job logs, including output nobody here wrote.
  maskValue(env, startLine.launch_token, writeStdout);
  // From here on the collector is RUNNING and outlives this process, so every
  // failure has to take it down first: nothing has recorded its pid yet, and
  // a collector nothing can stop holds the port and writes session logs for
  // the rest of the runner's life.
  const abort = (message) => {
    try { kill(startLine.pid); } catch {}
    return new Error(message);
  };
  // The PUBLIC verification key. Deliberately not masked: it is public by
  // design, and masking it would only litter later logs with '***' where a
  // harmless value belongs. What matters is where it travels, not who sees
  // it — see the step-output write below.
  if (typeof startLine.verify_key !== 'string' || startLine.verify_key === '') {
    // Without it, `run` can never prove who served a log, and would fail
    // every capture. Better to stop here, while the collector can still be
    // killed cleanly, than to run a whole job that cannot produce evidence.
    throw abort('collector did not report a verification key; capture could never be verified');
  }
  const port = Number(inputs.port);
  const identity = await probeReady(port, startLine.project_hash, { deadlineMs: readyTimeoutMs });
  if (!identity || identity.project_hash !== startLine.project_hash || identity.ready !== true) {
    throw abort('collector did not become ready before the timeout');
  }
  // Prove the port occupant actually holds the token before handing it over.
  // The shim reported a pid and a token, but between that report and this
  // line the collector could have died and any local process could have taken
  // the port; the very next request puts the launch token in an Authorization
  // header (Codex T4 #4). probeLaunchToken settles it non-mutatingly — a
  // random challenge whose HMAC proof is verified locally, so a listener that
  // cannot compute it never receives the token.
  if (!(await probeToken(port, startLine.launch_token))) {
    throw abort(`collector identity could not be verified on port ${port}; refusing to send the launch token`);
  }
  const mint = await request({
    port,
    method: 'POST',
    path: '/session',
    headers: { Authorization: `Bearer ${startLine.launch_token}` },
    body: { name: inputs.sessionName },
  });
  if (mint.status !== 201 || !mint.json?.session_id || !mint.json?.session_token) {
    throw abort(`session mint failed (HTTP ${mint.status ?? 'no response'})`);
  }
  // Apply current-user-only Windows DACLs from this parent process, never
  // from the detached collector. powershell.exe EncodedCommand hangs until
  // timeout inside a DETACHED_PROCESS child on hosted windows-latest, which
  // blocked POST /session (HTTP 500, Validate 31973907121). Salt is fail-open
  // if absent (unpersisted); a minted session log is fail-closed.
  try {
    protectWindowsPrivateFileIfPresent(path.join(projectRoot, '.debug', 'project_salt'));
    const relativeLog = mint.json.log_file;
    if (typeof relativeLog === 'string' && relativeLog.length > 0) {
      protectWindowsPrivateFile(path.join(projectRoot, relativeLog));
    }
  } catch (error) {
    throw abort(`Windows private-file ACL failed: ${error?.message ?? error}`);
  }
  const sessionId = mint.json.session_id;
  const sessionToken = mint.json.session_token;
  const clientId = mint.json.client_id;
  if (typeof clientId !== 'string' || !/^[a-f0-9]{64}$/.test(clientId)) {
    throw abort('session mint returned no usable client_id');
  }
  // Masked before the token is used for anything else, and before it is
  // written anywhere.
  maskValue(env, sessionToken, writeStdout);
  if (inputs.hypothesisId) {
    // The ONLY hypothesis line this action will ever post, and the last thing
    // the launch token is used for. It records intent (OPEN) and never a
    // verdict — judgment stays with humans and agents (spec amendment,
    // planning round). Because the token dies with this process, this is also
    // the only hypothesis line that CAN exist in the session.
    const hypothesis = await request({
      port,
      method: 'POST',
      path: '/hypothesis',
      headers: { Authorization: `Bearer ${startLine.launch_token}` },
      body: {
        sessionId,
        hypothesisId: inputs.hypothesisId,
        status: 'OPEN',
        ...(inputs.hypothesisTitle ? { title: inputs.hypothesisTitle } : {}),
      },
    });
    if (hypothesis.status !== 202) {
      throw abort(`hypothesis post failed (HTTP ${hypothesis.status ?? 'no response'})`);
    }
  }
  // Persist BEFORE releasing the pipes, and kill the child if persisting
  // fails (Codex T3 #2). teardown stops the collector from the pid published
  // as a pre-command start output, not from this file: the wrapped command
  // can rewrite action-state.json. The pid is still recorded here as a
  // diagnostic, never as the kill target.
  //
  // Note what is NOT in here: the launch token. The session token that is
  // recorded can append events and read this session's own log back, and
  // nothing else — it cannot mint, and it cannot post a hypothesis line.
  try {
    await withStateLock(outputDir, () => writeState(outputDir, {
      nonce,
      pid: startLine.pid,
      port,
      projectRoot,
      sessionName: inputs.sessionName,
      sessionId,
      sessionToken,
      clientId,
      hypothesisId: inputs.hypothesisId,
      hypothesisTitle: inputs.hypothesisTitle,
      failOnCommandFailure: inputs.failOnCommandFailure,
      // The four readings, recorded here and consumed by `run` when it
      // qualifies and renders: only this step is in a position to have looked
      // before the wrapped command existed. Reaching this line with any
      // blocker at all means the caller opted in to best-effort — strict
      // returned 3 above. The persisted `blockers` list is a diagnostic
      // convenience; every consumer re-derives it from the four fields, so a
      // rewritten state file cannot launder a failing reading (Codex T6 r9 #2).
      admission,
      evidenceTrust: inputs.evidenceTrust,
    }));
  } catch (error) {
    // Covers a failed lock acquisition too, and must: a collector whose state
    // was never recorded is a collector nothing can stop.
    try { kill(startLine.pid); } catch {}
    throw error;
  }
  // The verification key travels as a STEP OUTPUT, never in state. That
  // routing is the whole security property, and it is about INTEGRITY rather
  // than secrecy: the runner parses this file when the start step ends —
  // before the wrapped command exists — and interpolates the value into later
  // steps' env from its own memory. A same-user process can rewrite
  // action-state.json at leisure, and could happily put ITS OWN public key
  // there and sign with the matching private one; it cannot reach into the
  // runner and change the value the runner already parsed out of this file.
  // State stays routing data; trust is anchored in memory (Codex T5 r4 #1 /
  // r5 #2, ruling iii). Scope, stated because it does not generalise: what is
  // out of reach is the RUNNER'S copy. A `shell: bash` step's env can still be
  // rewritten after the runner resolves it, by BASH_ENV — which is why the key
  // is consumed only inside `run`, whose process starts before this
  // invocation's command exists, and why an EARLIER invocation's command in
  // the same job is outside the guarantee (Codex T6 r3 #1).
  if (env.GITHUB_OUTPUT) {
    writeOutputs(env.GITHUB_OUTPUT, {
      'collector-verify-key': startLine.verify_key,
      'collector-pid': String(startLine.pid),
    });
  }
  // RELEASE the pipes, never destroy them (Codex T3 #1): destroying this end
  // leaves the collector writing into a closed pipe for the rest of the job,
  // which is the exact EPIPE the shim's no-op handlers are the backstop for.
  // Dropping the 'data' listeners and resuming leaves the pipe drained and
  // discarded; unref stops it from holding this process open.
  for (const stream of [child.stdout, child.stderr]) {
    stream.removeAllListeners('data');
    stream.resume();
    stream.unref();
  }
  child.unref();
  return 0;
};

const teardownSubcommand = ({ outputDir, env = process.env, kill = process.kill }) => {
  if (requireInvocationNonce(env, 'teardown')) return 3;
  const state = readState(outputDir);
  if (!state) return 0; // start never wrote state — nothing to tear down
  if (rejectForeignNonce(state, env, 'teardown')) return 3;
  // PID comes from start's pre-command step output, not from action-state.json.
  // The wrapped command can rewrite the state file; it cannot change the
  // value the runner already parsed out of start's GITHUB_OUTPUT.
  const rawPid = env.DEBUG_ACTION_COLLECTOR_PID;
  const pid = Number.parseInt(rawPid, 10);
  if (!Number.isInteger(pid) || pid < 1 || String(pid) !== String(rawPid).trim()) {
    process.stderr.write('debug-evidence-action: teardown: recorded state carries no usable pid.\n');
    return 3;
  }
  try {
    kill(pid);
  } catch (error) {
    if (error?.code === 'ESRCH') return 0; // already gone — success, not a leak
    process.stderr.write(`debug-evidence-action: teardown: failed to stop collector pid ${pid}: ${error?.code ?? error}\n`);
    return 3;
  }
  return 0;
};

// A collector answer is a status line and a small JSON object; a megabyte is
// already far past anything the contract produces, so treat more as hostile
// rather than buffering it into this process's heap.
const RESPONSE_BYTE_CAP = 1024 * 1024;
// Inactivity timeout: no bytes moved for this long.
// Must exceed protectWindowsPrivateFileAsync's 15s PowerShell budget: POST
// /session awaits that ACL on Windows before returning 201, and a 5s idle
// timeout made start fail with `collector request timed out` on hosted
// windows-latest (Validate logs, 2026-08-16).
const REQUEST_IDLE_TIMEOUT_MS = 20_000;
// Wall-clock ceiling for the WHOLE exchange. The idle timeout alone is not a
// bound: a peer that dribbles one byte every second resets it forever and the
// subcommand hangs for the life of the job (Codex T4 #2). Keep this above the
// Windows ACL budget so a legitimate mint is not killed by the wall clock.
const REQUEST_DEADLINE_MS = 25_000;

// Minimal JSON-over-loopback helper (node:http; fetch is avoided so tests can
// inject `request` and so no keep-alive agent outlives the subcommand).
//
// Every exit from this promise is guarded by settle(), because the failure
// this replaced was not a wrong answer but NO answer: a peer that declared
// Content-Length: 100, sent ten bytes and hung up produced a response stream
// that emitted neither 'end' nor 'error', so the promise was never settled
// and `run` waited forever holding the whole job (Codex T4 #2, reproduced).
const httpRequestJson = ({
  port, method, path: requestPath, headers = {}, body,
  idleTimeoutMs = REQUEST_IDLE_TIMEOUT_MS, deadlineMs = REQUEST_DEADLINE_MS,
}) => new Promise((resolve, reject) => {
  const payload = body === undefined ? null : JSON.stringify(body);
  let settled = false;
  let deadline;
  const settle = (fn, value) => {
    if (settled) return;
    settled = true;
    clearTimeout(deadline);
    fn(value);
  };
  const request = http.request({
    host: '127.0.0.1',
    port,
    method,
    path: requestPath,
    headers: payload === null ? headers : { ...headers, 'content-type': 'application/json' },
  }, (response) => {
    let text = '';
    let bytes = 0;
    let ended = false;
    // Decode through a StringDecoder rather than concatenating Buffers, so a
    // multi-byte character split across two chunks cannot be mangled.
    response.setEncoding('utf8');
    response.on('data', (chunk) => {
      bytes += Buffer.byteLength(chunk, 'utf8');
      if (bytes > RESPONSE_BYTE_CAP) {
        request.destroy();
        settle(reject, new Error(`collector response exceeded ${RESPONSE_BYTE_CAP} bytes`));
        return;
      }
      text += chunk;
    });
    response.on('end', () => {
      ended = true;
      let json = null;
      try { json = JSON.parse(text); } catch {}
      settle(resolve, { status: response.statusCode, json });
    });
    response.on('aborted', () => settle(reject, new Error('collector aborted the response')));
    response.on('error', (error) => settle(reject, error));
    // 'close' AFTER 'end' is the ordinary finish and settle() already ignores
    // it; 'close' WITHOUT 'end' is the peer hanging up mid-body — the lying
    // Content-Length shape above.
    response.on('close', () => {
      if (!ended) settle(reject, new Error('collector closed the response before it completed'));
    });
  });
  request.on('error', (error) => settle(reject, error));
  request.setTimeout(idleTimeoutMs, () => request.destroy(new Error('collector request timed out')));
  deadline = setTimeout(() => {
    request.destroy();
    settle(reject, new Error(`collector request exceeded ${deadlineMs}ms`));
  }, deadlineMs);
  if (payload !== null) request.write(payload);
  request.end();
});

// stdio: 'inherit' — the wrapped command's output belongs in the step log.
const defaultSpawnCommand = (command, { cwd, env }) => spawnSync('bash', ['-c', command], { cwd, env, stdio: 'inherit' });


// Render both surfaces from bytes ALREADY IN MEMORY.
//
// The renderer used to be a child process reading the staged session.log back
// off disk. That path is a race with teeth: a detached child of the wrapped
// command could swap the staged bytes between capture and render, and because
// the digests were also computed by re-reading the same path, report.md,
// report.json and all three hashes ended up consistently describing the
// forgery (Codex T5 r4 #2). A pathname is a shared, writable name; a buffer
// this process holds is not. So the captured bytes are rendered, hashed and
// written from one immutable in-memory value, and the staged files become
// write-only sinks — nothing downstream ever reads them back.
//
// In-process rather than piping to the CLI's stdin: debug_report.js already
// exports exactly the three functions its own main() composes, so importing
// them removes the serialization boundary entirely instead of narrowing it
// (precedent: collector_boot requires debug_server directly). It also lets
// the report carry the real session id, which the CLI could only derive from
// a filename — the staged copy is called session.log, so the CLI rendered
// every report as "(file)".
const defaultRenderReport = (sessionText, sessionId, { caveats = [], capturedAt = null } = {}) => {
  const report = buildReport(parseSessionText(sessionText), { sessionId, caveats, capturedAt });
  return { markdown: renderMarkdown(report), json: renderJson(report) };
};

// The staged files are WRITE-ONLY SINKS. Nothing downstream reads them back —
// not the renderer, not the digests — so this is the single point where the
// in-memory payload leaves the process, and injecting it is how a test can
// prove the digests describe the payload rather than whatever ended up on
// disk.
const defaultStageFile = (filePath, bytes) => {
  try { unlinkSync(filePath); } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
  }
  const flags = constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL
    | (constants.O_NOFOLLOW || 0);
  const fd = openSync(filePath, flags, 0o444);
  try {
    writeSync(fd, bytes);
  } finally {
    closeSync(fd);
  }
};

// Rebuild the collector's public verification key from the SPKI DER base64
// that travelled as a step output. Anything unparsable is treated as no key
// at all — a verifier that cannot verify must not proceed.
const responderVerifyKey = (encoded) => {
  if (typeof encoded !== 'string' || encoded === '') return null;
  try {
    return createPublicKey({ key: Buffer.from(encoded, 'base64'), format: 'der', type: 'spki' });
  } catch {
    return null;
  }
};

// Does this answer carry proof that it came from the collector `start`
// booted, AND that it answers the question this process actually asked?
//
// The record is rebuilt from INTENT, never from the response: the target is
// the unfiltered `/sessions/<id>/logs` this capture meant to fetch, the nonce
// is the one this capture generated, and the digest is over the bytes that
// came back. A relay that forwarded the challenge to the real collector with
// `?limit=1` gets back a perfectly valid signature — over a DIFFERENT target
// — and it will not verify against this reconstruction. No comparison logic
// is needed for that; the signature simply fails (Codex T5 r5 #1).
//
// The key is public, so this is verification, not a shared secret: nothing
// here could sign anything even if the whole environment leaked.
const verifyResponderProof = ({ verifyKey, sessionId, clientId, challenge, text, proof }) => {
  if (verifyKey === null || typeof proof !== 'string' || proof === '') return false;
  const signature = Buffer.from(proof, 'base64');
  // Ed25519 signatures are exactly 64 bytes; anything else is not one, and
  // base64 decoding never throws, so the length is the guard.
  if (signature.length !== 64) return false;
  const record = Buffer.from(canonicalResponderRecord({
    method: 'GET',
    target: `/sessions/${sessionId}/logs?client_id=${clientId}`,
    challenge,
    bodyDigest: createHash('sha256').update(text, 'utf8').digest('hex'),
  }), 'utf8');
  try {
    return verify(null, record, verifyKey, signature) === true;
  } catch {
    return false;
  }
};

// A renderer that exited 0 has not thereby produced a report. Its stdout is
// what report.json and the event-count output are made of, so it is parsed
// and shape-checked BEFORE either is committed: a status-0 child that printed
// truncated JSON, a report from some future schema, or a nonsense event count
// would otherwise be published as authoritative evidence, and the old
// `catch {}` around the count turned exactly that into a silently empty
// output (Codex T5 #2). Returns the validated report, or null.
const parseRenderedReport = (text) => {
  let report;
  try {
    report = JSON.parse(text);
  } catch {
    return null;
  }
  if (!report || typeof report !== 'object' || Array.isArray(report) || report.schema !== 1) return null;
  const events = report.session?.events;
  return Number.isInteger(events) && events >= 0 ? report : null;
};

// Exactly what the upload step enumerates, and therefore exactly what has to
// belong to THIS invocation.
const EVIDENCE_FILES = ['session.log', 'report.md', 'report.json'];

// Empty the staging slots this invocation does not own (or has not filled
// yet). Anything other than "it was not there" is left to throw: a staging
// slot that cannot be cleared cannot be scoped either. One implementation
// because all three callers must fail the same way — run clearing on entry,
// report clearing what it will not publish, and report refusing an invocation
// it cannot identify.
const dropSubstitutedStagedFiles = (evidenceDir) => {
  for (const name of EVIDENCE_FILES) {
    const staged = path.join(evidenceDir, name);
    let info;
    try {
      info = lstatSync(staged);
    } catch (error) {
      if (error?.code === 'ENOENT') continue;
      throw error;
    }
    if (info.isSymbolicLink() || !info.isFile()) {
      rmSync(staged, { recursive: true, force: true });
    }
  }
};

const clearStagedEvidence = (evidenceDir, names = EVIDENCE_FILES) => {
  mkdirSync(evidenceDir, { recursive: true });
  for (const name of names) {
    try {
      unlinkSync(path.join(evidenceDir, name));
    } catch (error) {
      if (error?.code !== 'ENOENT') throw error;
    }
  }
};

// The action is the ONLY legitimate holder of the launch token in the
// wrap-one-command model, and POST /hypothesis is a launch-token capability
// the wrapped command is never given. That makes a captured session's
// hypothesis lines DECIDABLE: there must be exactly the line this action
// posted — an OPEN for the configured hypothesis-id, carrying the title it
// sent — or none at all when no hypothesis-id was configured. Any other
// hypothesis line was forged, by definition.
//
// As of T5 r3 this is a BELT, not the braces. It was introduced when the
// launch token was persisted in action-state.json, where the wrapped command
// — same OS user, derivable path — could take it and post a CONFIRMED verdict
// through the real endpoint for authenticated capture to bless (Codex T5 r2
// #1). That token now lives and dies inside start's process, so no credential
// able to write a hypothesis line exists while the wrapped command runs and
// this check should never fire. It stays precisely because of that: if it
// ever does fire, the structural guarantee has been broken somewhere and the
// evidence must not be published on the strength of an assumption.
//
// EVENTS are deliberately not checked: they come from the instrumented
// process and are attacker-authored by design — recording what that process
// says is the entire point of the evidence.
//
// Returns null when the set is exactly right, or a short reason.
const describeHypothesisDeviation = (entries, state) => {
  const posted = [];
  for (const entry of entries) {
    const parsed = entry?.parsed;
    // Served entries are {raw, parsed} by contract. A line this check cannot
    // read is not evidence that there is nothing to find.
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      return 'the collector served an entry in a shape this check cannot inspect';
    }
    if (parsed.type === 'hypothesis') posted.push(parsed);
  }
  const expected = state.hypothesisId ? 1 : 0;
  if (posted.length !== expected) {
    return `expected exactly ${expected} hypothesis line${expected === 1 ? '' : 's'}, captured ${posted.length}`;
  }
  if (expected === 0) return null;
  const [line] = posted;
  // Values below are attacker-influenced; JSON.stringify neutralizes quotes
  // and newlines before they reach a log line.
  if (line.hypothesisId !== state.hypothesisId) {
    return `hypothesis id ${JSON.stringify(line.hypothesisId)} is not the ${JSON.stringify(state.hypothesisId)} this action opened`;
  }
  if (line.status !== 'OPEN') {
    return `status ${JSON.stringify(line.status)} — this action opens hypotheses and never records a verdict`;
  }
  if (state.hypothesisTitle && line.title !== state.hypothesisTitle) {
    return `title ${JSON.stringify(line.title)} is not the one this action posted`;
  }
  return null;
};

// Ceiling on the authoritative read. A collector that accepts the connection
// and then says nothing must not hold the capture step open for the rest of
// the job; timing out here is an evidence-integrity failure like any other.
const LIVE_READ_TIMEOUT_MS = 5_000;

// And the absolute one. The idle timeout above is reset by every byte, so a
// listener dripping a byte every four seconds satisfies it forever; only a
// wall-clock ceiling ends that. Thirty seconds is far longer than a loopback
// read of a capped session log has any business taking, and it bounds the
// capture step no matter what is on the other end.
const LIVE_READ_DEADLINE_MS = 30_000;

// Which live-read failures mean "there is no collector to ask" rather than
// "the collector answered and refused". Only the first class may fall back to
// the on-disk log, and only as labeled partial evidence: nothing answered
// (connect failure), nothing answered in time, or what answered does not hold
// this session's token — a foreign process that rebound the port. Every other
// failure came from a collector that authenticated us and then declined, and
// preferring the file on disk over its refusal would stage the exact bytes it
// refused to vouch for.
const UNREACHABLE_READ = /^live_read_(connect_failed|timeout|unauthorized)/;

// SHA-256 of every payload this invocation intends to stage, as one line,
// computed from the IN-MEMORY bytes.
//
// Prevention is not available here: staging and upload are separate steps of
// the same composite action running as the same user, so a detached child of
// the wrapped command can rewrite a staged file in the window between them.
// Detection is. The step log is streamed and immutable once emitted, so a
// digest printed at staging time is a record no later rewrite can revise —
// compare the uploaded artifact against this line and any swap is visible
// (Codex T5 r3, threat-model option taken with teeth).
//
// Hashing the FILES back off disk would have quietly destroyed that: a swap
// landing before the hash produced digests that described the forgery
// perfectly, and the step log would have blessed it (Codex T5 r4 #2). These
// digests describe what this process decided to write, so any later
// divergence is exactly what the comparison is meant to catch.
//
// Only payloads that exist appear; a run that staged nothing claims nothing.
const payloadDigestLine = (payloads, { capturedAt } = {}) => {
  const parts = [];
  for (const name of EVIDENCE_FILES) {
    const bytes = payloads[name];
    if (bytes === undefined) continue;
    parts.push(`${name}=${createHash('sha256').update(bytes, 'utf8').digest('hex')}`);
  }
  if (parts.length === 0) return null;
  if (typeof capturedAt === 'string' && capturedAt !== '') {
    parts.unshift(`capturedAt=${capturedAt}`);
  }
  return `evidence-sha256 ${parts.join(' ')}`;
};

// One diagnostic is one line. The values interpolated into run's capture
// diagnostics come from a state file and from OS/collector errors quoting it,
// so a raw
// newline in either would split one message into what reads as two — the same
// discipline debug_report.js applies to its own error line.
const oneLine = (value) => String(value).replace(/\r?\n|\r/g, ' ');

// The three capture decisions that moved here with it, unchanged:
// 1. Evidence is captured FROM THE COLLECTOR, never by pathname. The wrapped
//    command is handed DEBUG_SESSION_ID and shares the filesystem, so it can
//    overwrite .debug/debug-<id>.log with whatever NDJSON it likes — including
//    hypothesis lines carrying a CONFIRMED verdict it has no credential to
//    POST — and a copyFileSync would stage that forgery and render it as the
//    run's official evidence (Codex T5 #1, Critical). Reading back through
//    GET /sessions/:id/logs puts the collector's own checks in the path —
//    dev/ino/birthtime/size identity, and since r2 a SHA-256 of every byte it
//    appended — so a tampered log is a 409 rather than an answer, including
//    the same-length in-place rewrite metadata alone cannot see.
// 2. Aliveness is the authenticated read itself. An unauthenticated /health
//    answer only says SOMETHING is listening — exactly what a process that
//    rebound the port would also produce. A served log proves the occupant
//    holds the session this run minted; a foreign one answers 401.
// 3. Live read and renderer both run BEFORE the lock is taken. That
//    work can take seconds; the state lock's staleness threshold is 30s and
//    its retry budget ~450ms, so a holder doing it inside the critical
//    section would make every concurrent invocation fail to acquire — and, at
//    the tail, would itself risk being judged stale and reaped mid-flight
//    (recorded T4 r2 requirement: no holder approaches the threshold). The
//    commit is then a compare-and-set under that lock, exactly as run's is:
//    re-read, compare nonces, and spread the CURRENT state rather than the
//    snapshot this function opened with (Codex T4 #3/r2).

// Runner command-file variables. Stripped from the wrapped command's
// environment as DEFENCE IN DEPTH, and explicitly not as a boundary.
//
// GITHUB_ENV is the sharp one: it names a file whose contents the runner
// applies to every SUBSEQUENT step. A wrapped command that appends
// `BASH_ENV=/tmp/theirs.sh` to it gets that script sourced by the
// non-interactive bash of every later step — after the runner has already
// resolved those steps' `env:` — which is how a later step's view of any
// variable can be rewritten by an earlier step's child (Codex T5 r6).
//
// Removing the names raises the bar; it does not close the channel, because a
// determined child can still enumerate the runner's command files under
// RUNNER_TEMP. What actually closes it is that no security decision is left
// for a later step to make: capture happens in THIS process, whose
// environment was resolved before the wrapped command existed.
const RUNNER_COMMAND_FILE_VARS = [
  'GITHUB_ENV',
  'GITHUB_PATH',
  'GITHUB_OUTPUT',
  'GITHUB_STATE',
  'GITHUB_STEP_SUMMARY',
];

// run is the TRUSTED PROCESS on the strict path, and that is the whole
// architecture. What "trusted" is worth depends on how the invocation was
// admitted, so it is stated once, here, and every claim below inherits it:
//
//   - successful STRICT admission: the host positively establishes the
//     boundary, so this process's decisions are authenticated. The trust unit
//     is the pre-command admission record start streamed to its own step log,
//     plus the matching digest from this step's log, plus the artifact — all
//     three together (Codex T6 r9 #3). Not the artifact and digest alone: a
//     compromised run can produce both, and it is start's pre-command copy,
//     which no later process can retract, that says which regime was in force.
//   - BEST-EFFORT: the caller accepted a host where the wrapped command may
//     be able to rewrite this very process. Everything below still happens,
//     and none of it authenticates anything — the capture, the digest, the
//     report and the qualification are diagnostic claims. The only thing that
//     survives that threat is `start`'s pre-command line, and all IT
//     establishes is that best-effort was consciously selected.
//
// It is the only process in the job that spans the wrapped command's
// execution: its environment was resolved by the runner before the command
// existed, and an ordinary child has no interface for writing into its
// parent's address space. So every decision that must not be influenced by
// the command — which collector to believe, whether an answer is authentic,
// what gets staged — is made here, on either side of the command rather than
// in a later step the command can poison.
//
// The claim is about THIS PROCESS'S OWN VALUES, and only about them. The
// command influences plenty: it writes files, rewrites the state file, can
// kill the collector, and authors every event in the log. What it cannot
// reach is the copy this process read before the command started.
//
// And that much is CONDITIONAL on the platform (Codex T6 r5, corrected r6 and
// again r9). It holds only where the host refuses same-UID ptrace attachment
// AND the wrapped principal has no route to root — because a principal that
// reaches root rewrites this process's memory with a privileged BPF program or
// a kernel module and never calls ptrace at all. So the condition is all four
// readings: Yama ptrace_scope 3 (modes 1 and 2 are bypassable with
// CAP_SYS_PTRACE), a non-root effective uid, no sudo binary at a conventional
// absolute path OR anywhere on the inherited PATH, and no CAP_SYS_ADMIN /
// CAP_BPF / CAP_SYS_PTRACE / CAP_SYS_MODULE in this process's own set. Any sudo
// binary the inspection finds denies strict admission: sudoers rules are
// command-specific,
// so no probe of one command can establish the absence of a rule for another,
// and a PATH-planted fake could fabricate a denial that GRANTED admission.
// Where any of that is open, a hostile native command can reach this process,
// or the collector whose pid is in state, and read or inject memory; no
// in-process argument survives that. `start` refuses to run the wrapped
// command at all unless the prerequisite is positively established, and a
// caller who sets `evidence-trust: best-effort` gets evidence labeled as
// unverifiable-by-construction instead. The action classifies the platform; it
// does not create the boundary on it. These are the escalation routes it
// checks, not a proof that no route exists.
//
// This also means the verification key is read BEFORE the command runs. It is
// public, so a child reading /proc/<ppid>/environ learns nothing it can use;
// that is exactly what round 5's asymmetric switch bought, and it is what
// makes hosting the key in this long-lived process safe.
//
// And run FAILS CLOSED: any integrity failure returns 3 with nothing staged.
// A composite step that fails fails the action, and no later step can undo
// that — so even a completely poisoned report or finish cannot turn a failed
// verification green. Only the wrapped command's own exit code stays deferred
// to finish, which is not security-critical: a hostile command can always
// choose what to exit with.
const runSubcommand = async ({
  inputs, outputDir, env = process.env,
  spawnCommand = defaultSpawnCommand, writeStdout = defaultStdoutWrite,
  renderReport = defaultRenderReport, readLive = readSessionLive,
  stageFile = defaultStageFile,
}) => {
  // Invocation-scoped staging, cleared FIRST — before state is even read, and
  // long before the command runs. An output-dir can be reused — across steps,
  // across jobs on a self-hosted runner — and the upload step enumerates three
  // fixed filenames, so a previous invocation's report left sitting there
  // ships as this run's evidence under this run's artifact name. The refusals
  // just below are exactly the paths where stale evidence is most plausible,
  // which is why the clear precedes them (Codex T5 r2 #3, hoisted in r3, and
  // hoisted again with capture in r6). Clearing here also means a run that
  // dies mid-command leaves nothing behind to be mistaken for its own output.
  //
  // The identity comes first because the staging path is DERIVED from it: this
  // step cannot even name where its evidence goes without knowing which
  // invocation it belongs to (Codex T6 r1 #1/#3).
  if (requireInvocationNonce(env, 'run')) return 3;
  const evidenceDir = resolveEvidenceDir(outputDir, env.DEBUG_ACTION_INVOCATION_NONCE);
  clearStagedEvidence(evidenceDir);
  const state = readState(outputDir);
  if (!state) {
    process.stderr.write('debug-evidence-action: run: no recorded state; the start step never completed.\n');
    return 3;
  }
  if (rejectForeignNonce(state, env, 'run')) return 3;
  // The session was minted in start, while the launch token still existed.
  // Nothing here holds a credential that could mint a session or post a
  // hypothesis, because no such credential survives into this process
  // (Codex T5 r3).
  if (!state.sessionId || !state.sessionToken) {
    process.stderr.write('debug-evidence-action: run: recorded state carries no session; the start step never completed its mint.\n');
    return 3;
  }
  if (typeof state.clientId !== 'string' || !/^[a-f0-9]{64}$/.test(state.clientId)) {
    process.stderr.write('debug-evidence-action: run: recorded state carries no usable client_id; capture cannot bind the session to this tenant.\n');
    return 3;
  }
  // Read from THIS process's environment, before the wrapped command exists.
  // From the environment only, never from state: the key is public, so its
  // secrecy does not matter, but its INTEGRITY is everything — a same-user
  // process that could substitute its own public key would then sign answers
  // with the matching private one. This process's own memory, populated before
  // the wrapped command exists, is the one channel that command cannot reach
  // through any ordinary interface (and, where the host permits same-UID
  // ptrace attachment, not even that holds — see the platform prerequisite),
  // so state and every other file on disk are excluded as sources by
  // construction (Codex T5 r5 #2, r6 #1). It is THIS invocation's command that
  // cannot reach it: a command an earlier invocation ran in the same job can
  // rewrite this step's env through BASH_ENV before node starts, which is why
  // the guarantees are scoped to the first invocation in a job (Codex T6 r3 #1).
  const verifyKey = responderVerifyKey(env.DEBUG_ACTION_COLLECTOR_VERIFY_KEY);
  // Re-registering a value the runner already masks in start is a no-op for
  // Actions and cheap insurance for this step's own log, which is where the
  // token is about to be put into a child process's environment.
  maskValue(env, state.sessionToken, writeStdout);
  const commandEnv = {
    ...env,
    DEBUG_LOG_URL: `http://127.0.0.1:${state.port}/log`,
    DEBUG_SESSION_ID: state.sessionId,
    DEBUG_SESSION_TOKEN: state.sessionToken,
  };
  // The action's own wiring is not part of the contract the wrapped command
  // is promised, and DEBUG_ACTION_OUTPUT_DIR points straight at
  // action-state.json — which no longer carries a launch token, but does
  // carry the session token and this invocation's nonce. The wrapped command
  // runs as the same OS user, so the file's 0600 mode is no boundary against
  // it; handing over the path is (Codex T5 r2 #1). Stripping the whole prefix
  // rather than one name keeps the rule stable as more wiring vars appear.
  // The runner's own command files go with them (see above).
  for (const key of Object.keys(commandEnv)) {
    if (key.startsWith('DEBUG_ACTION_') || RUNNER_COMMAND_FILE_VARS.includes(key)) delete commandEnv[key];
  }
  if (state.hypothesisId) {
    commandEnv.DEBUG_HYPOTHESIS_ID = state.hypothesisId;
  } else {
    // The `...env` spread above would otherwise let a job-level
    // DEBUG_HYPOTHESIS_ID through, and every event the wrapped command logged
    // would be attributed to a hypothesis THIS action never opened — evidence
    // filed under a claim nobody made (Codex T4 #5). Delete rather than set to
    // '', because an empty string is still a present variable.
    delete commandEnv.DEBUG_HYPOTHESIS_ID;
  }
  // Awaited so a seam can be asynchronous; defaultSpawnCommand is spawnSync
  // and resolves immediately.
  const result = await spawnCommand(inputs.runCommand, { cwd: inputs.workingDirectory, env: commandEnv });
  const commandExitCode = result.error ? 127 : (result.status ?? 128);

  // ---- capture, in the same process, with the key it already held ----

  // Aliveness is a PROVEN read succeeding. An authenticated read alone is not
  // enough: Bearer proves this caller to the listener, and the port, session
  // id and token it used all came out of a file the wrapped command can
  // rewrite — so a counterfeit listener serving contract-shaped NDJSON would
  // have satisfied every check (Codex T5 r4 #1).
  let collectorAlive = false;
  // Did the staged bytes come from the collector, or off a filesystem the
  // wrapped command can write? Recorded either way, so the artifact's
  // provenance is a fact in the state file rather than an assumption.
  let evidenceAuthentic = false;
  let entries = null;
  let capturedText = null;
  let readFailure = null;
  if (verifyKey === null) {
    // Valid state, no usable key: the wiring that carries it from start's
    // step output into this step's env is broken or absent. That is an
    // integrity failure, not a missing collector — capture cannot prove
    // anything, so it must not fall back to the on-disk log and call the
    // result evidence.
    readFailure = 'responder_key_missing';
    process.stderr.write('debug-evidence-action: run: no usable collector verification key in this step\'s environment; capture cannot verify who it is talking to.\n');
  } else {
    // Fresh per capture. A nonce reused across captures would let a recorded
    // answer be replayed by anything that saw it.
    const challenge = randomBytes(32).toString('hex');
    try {
      const answer = await readLive({
        port: state.port,
        // The session's OWN token. GET /sessions/:id/logs accepts it for this
        // session and nothing else, which is why start could drop the launch
        // token and still leave capture possible.
        token: state.sessionToken,
        sessionId: state.sessionId,
        clientId: state.clientId,
        timeoutMs: LIVE_READ_TIMEOUT_MS,
        deadlineMs: LIVE_READ_DEADLINE_MS,
        challenge,
      });
      if (!verifyResponderProof({
        verifyKey, sessionId: state.sessionId, clientId: state.clientId, challenge, text: answer.text, proof: answer.proof,
      })) {
        readFailure = 'responder_proof_invalid';
        process.stderr.write(oneLine(`debug-evidence-action: run: whatever served this session on port ${state.port} could not prove it is this run's collector; refusing to treat its answer as evidence.`) + '\n');
      } else {
        entries = answer.entries;
        // The bytes the proof covers, and the only copy anything downstream
        // will read. Staging exactly these keeps the artifact byte-identical
        // to what was proven.
        capturedText = answer.text;
        collectorAlive = true;
      }
    } catch (error) {
      readFailure = String(error?.message ?? error);
    }
  }
  // Everything from here works on in-memory payloads; the staged files are
  // written once, at the end, and never read back.
  const payloads = {};
  if (entries !== null) {
    const deviation = describeHypothesisDeviation(entries, state);
    if (deviation !== null) {
      // Belt to the structural braces. No credential capable of posting a
      // hypothesis line survives start, so this should now be unreachable —
      // which is exactly why it stays: if it ever fires, something about that
      // invariant is wrong and the evidence must not be published.
      process.stderr.write(oneLine(`debug-evidence-action: run: the captured session's hypothesis lines are not the set this action posted (${deviation}); refusing to stage evidence carrying a verdict it never made.`) + '\n');
    } else {
      payloads['session.log'] = capturedText;
      evidenceAuthentic = true;
    }
  } else if (UNREACHABLE_READ.test(readFailure)) {
    // Nothing answered, or what answered is not our collector. There is no
    // authoritative source to prefer, so the on-disk log is read best-effort
    // and LABELED: whatever is readable is still worth a human's eyes, while
    // the step itself fails below, so unverifiable bytes can be inspected but
    // can never ride a green build. Read into memory like every other payload
    // — a copyFileSync would put the render back on a pathname.
    process.stderr.write(oneLine(`debug-evidence-action: run: no collector on port ${state.port} would serve this session (${readFailure}); staging the on-disk log as UNAUTHENTICATED partial evidence and failing this step.`) + '\n');
    try {
      payloads['session.log'] = readFileSync(path.join(state.projectRoot, '.debug', `debug-${state.sessionId}.log`), 'utf8');
    } catch (error) {
      process.stderr.write(`debug-evidence-action: run: session log unreadable (${error?.code ?? error}).\n`);
    }
  } else {
    // The collector answered us and refused — session_log_tampered or
    // session_log_replaced surfacing as live_read_log_replaced, an unknown
    // session, a torn line, an unprovable responder. Falling back to the file
    // on disk would stage precisely the bytes nothing will vouch for, so this
    // is an evidence-integrity failure and nothing else.
    process.stderr.write(oneLine(`debug-evidence-action: run: the collector refused to serve this session (${readFailure}); the on-disk log is not a substitute for it.`) + '\n');
  }
  const evidenceCopied = payloads['session.log'] !== undefined;
  const capturedAt = new Date().toISOString();
  let reportRendered = false;
  let eventCount = '';
  if (evidenceCopied) {
    let rendered = null;
    try {
      // The platform label is stamped ON the evidence, not merely logged
      // beside it (Codex T6 r5) — the same doctrine as the labeled
      // unreachable-collector fallback: whoever ends up holding report.md or
      // report.json, with no access to the job that produced them, still has
      // to know the in-process guarantees were not established. An absent
      // record labels as `unknown`, never as met.
      rendered = renderReport(payloads['session.log'], state.sessionId, {
        caveats: admissionCaveats(state.admission, state.evidenceTrust, state.nonce),
        capturedAt,
      });
    } catch (error) {
      process.stderr.write(oneLine(`debug-evidence-action: run: renderer failed (${error?.message ?? error}).`) + '\n');
    }
    if (rendered !== null) {
      const validated = parseRenderedReport(rendered.json);
      if (validated === null) {
        process.stderr.write('debug-evidence-action: run: the renderer returned no schema-1 report; refusing to publish it.\n');
      } else {
        payloads['report.md'] = rendered.markdown;
        payloads['report.json'] = rendered.json;
        reportRendered = true;
        eventCount = String(validated.session.events);
      }
    }
  }
  // Hash from memory, THEN write. The order is the guarantee: the digest
  // describes what this invocation decided to stage, so anything that reaches
  // the files afterwards is a mismatch rather than a blessing. Computing it
  // from the files instead would hand a swap the step log's endorsement.
  const digestLine = payloadDigestLine(payloads, { capturedAt });
  const stagedNames = EVIDENCE_FILES.filter((name) => payloads[name] !== undefined);
  for (const name of stagedNames) stageFile(path.join(evidenceDir, name), payloads[name]);
  // Printed as soon as the bytes exist and BEFORE the ownership commit: this
  // line is a forensic record of what this process wrote to disk, not a claim
  // about which invocation owns the output-dir. Emitting it late — or only on
  // the paths that go on to succeed — would leave exactly the failure windows
  // undocumented.
  // The qualification belongs BESIDE the digest, because the digest is the
  // record of what this process staged and the two are read together (Codex
  // T6 r6, ruling (b)) — and because a reader who sees the digest must not be
  // able to miss that, in this mode, the digest authenticates nothing.
  //
  // Printed even on the renderer-failure classes, where only session.log is
  // staged and there is no report.md to carry a caveat — those are exactly the
  // runs where the log copy is the only copy. `start` printed the copy the
  // command cannot reach, before that command existed, and all that copy
  // establishes is that best-effort was consciously selected. This one and the
  // report caveat are both written after the command ran, by a process it may
  // have been able to rewrite, so it could suppress either.
  for (const caveat of admissionCaveats(state.admission, state.evidenceTrust, state.nonce)) writeStdout(`evidence-qualification ${caveat}\n`);
  if (digestLine !== null) writeStdout(`${digestLine}\n`);
  // Ownership check and commit as ONE indivisible step. The snapshot in
  // `state` was read before a wrapped command that may have run for an hour,
  // and the write below is a blind whole-file overwrite: if another
  // invocation claimed this output-dir meanwhile, it would restore OUR stale
  // pid/port/session over theirs and strand their live collector. Re-reading
  // first was not enough on its own — between the compare and the rename a
  // second invocation could still commit, and this one would clobber it
  // anyway (Codex T4 #3, then r2). Under the lock the re-read and the write
  // cannot be split, so whoever the compare saw is still who is there.
  const committed = await withStateLock(outputDir, () => {
    const current = readState(outputDir);
    if (!current || current.nonce !== state.nonce) return false;
    writeState(outputDir, {
      ...current,
      commandExitCode,
      commandSignal: result.signal ?? null,
      commandError: result.error ? String(result.error.message) : null,
      collectorAlive,
      evidenceAuthentic,
      evidenceCopied,
      reportRendered,
    });
    return true;
  });
  // Refuse completely: no state write, and no outputs either, since a
  // session-id emitted from state we just declined to own would be a lie.
  if (!committed) {
    process.stderr.write('debug-evidence-action: run: recorded state changed while the wrapped command ran (another invocation now owns this output-dir); refusing to overwrite it.\n');
    return 3;
  }
  // Published only AFTER the commit succeeds: outputs announced from state
  // this invocation just declined to own would be advertising someone else's
  // run as its own.
  if (env.GITHUB_OUTPUT) {
    // NOTHING here controls the upload step, and nothing here may (Codex T6
    // r2 #1). These lines are written after the wrapped command has run, into
    // a file that command can append to itself: it can claim any key this step
    // does not, and for a key this step DOES write it can open a heredoc whose
    // delimiter is the exact line this step is about to append, swallowing it
    // as body. A post-command step output is therefore a convenience, never a
    // boundary — the upload step reads `start`'s pre-command outputs instead.
    // The digest below is the same kind of thing and is documented as such:
    // its better copy is the line printed to this step's log, which is
    // immutable once streamed. "Better", not "authoritative", is the whole of
    // it under best-effort: immutability defends the line against later
    // EDITING, never against a process that was able to choose what the line
    // said in the first place.
    const outputs = {
      'command-exit-code': commandExitCode,
      'session-id': state.sessionId,
    };
    if (reportRendered) {
      outputs['event-count'] = eventCount;
      outputs['report-path'] = path.join(evidenceDir, 'report.md');
      // Byte-identical to the stdout line, so a consumer can compare the
      // artifact against either surface.
      outputs['evidence-digest'] = digestLine ?? '';
    }
    writeOutputs(env.GITHUB_OUTPUT, outputs);
  }
  // Capture is the product, so its failure is this step's failure — and a
  // failed composite step is one no later step can un-fail. The wrapped
  // command's own exit code is deliberately NOT consulted here; that verdict
  // belongs to finish.
  //
  // Exit 0 requires evidence this process PROVED, not merely evidence it
  // found, which is why the gate is evidenceAuthentic rather than
  // evidenceCopied. The labeled on-disk fallback above is still staged and
  // still worth a human's eyes — that has not changed — but it can no longer
  // ride a 0. Returning 0 there would have left the verdict to finish, reading
  // collectorAlive out of a state file any co-resident process can rewrite
  // after this commit: kill the collector, forge the log, and have a detached
  // child flip the flags to green. That is the round-6 Critical in a different
  // suit, and the answer is the same one — the deciding process is the one
  // that spans the command (Codex T5 r7). The exit table's outcome is
  // unchanged; only the process that raises it moved.
  return evidenceAuthentic && reportRendered ? 0 : 3;
};

// report is now PUBLISH-ONLY, and holds no credential at all.
//
// It used to perform capture, which put a verification key in the environment
// of a step that runs AFTER the wrapped command — a step whose environment
// that command can poison through the runner's env-file channel (Codex T5
// r6). Moving capture into run left this step with nothing an attacker would
// want: it verifies nothing, decides nothing, and publishes only what run
// already committed to state and staged on disk.
//
// It still runs with `if: always()` so a human gets the summary even when the
// wrapped command failed.
const reportSubcommand = ({ outputDir, env = process.env }) => {
  // No identity, no publish — decided before state is read and before any
  // path is resolved. `start` emits this invocation's nonce as a step output
  // as its very first action, so an empty one means this invocation's `start`
  // never ran that far. Whatever is in the output-dir was then written by
  // somebody else, and "a state file exists" is not a substitute for
  // ownership: an output-dir is reusable across steps and across jobs on a
  // self-hosted runner. Degrading to that check would append a stranger's
  // report to this job's summary.
  //
  // Nothing is deleted on this path, and that is deliberate: staging is
  // invocation-scoped, so the only directories that could be cleared here
  // belong to OTHER invocations — possibly a live concurrent one. Their
  // evidence is not this step's to ship and not this step's to destroy, and
  // it cannot leak into this job's artifact either way, because the upload
  // step's guard and paths come from THIS invocation's `start` outputs, fixed
  // before the wrapped command existed (Codex T6 r2 #1).
  if (requireInvocationNonce(env, 'report')) return 3;
  const evidenceDir = resolveEvidenceDir(outputDir, env.DEBUG_ACTION_INVOCATION_NONCE);
  dropSubstitutedStagedFiles(evidenceDir);
  const state = readState(outputDir);
  // Is this invocation's own run what wrote these slots? Absent state and a
  // foreign nonce both mean no, and in both cases whatever is sitting in the
  // staging slots belongs to somebody else's run.
  const ours = state !== null && state.nonce === env.DEBUG_ACTION_INVOCATION_NONCE;
  const capturedHere = ours && state.reportRendered === true;
  if (!capturedHere) {
    // A renderer failure is NOT "nothing was captured". On those classes run
    // authenticated the collector's answer, staged it, and recorded
    // evidenceCopied — deliberately, because partial evidence a human can read
    // is worth uploading — and only the rendered surfaces are missing. This
    // step runs BEFORE the upload step, so clearing session.log here would
    // destroy authentic evidence on its way to the artifact, which is what
    // round 8 caught. Clear only the surfaces that do not exist, and only when
    // this invocation owns the slots (Codex T5 r8).
    const preserveLog = ours && state.evidenceCopied === true;
    clearStagedEvidence(
      evidenceDir,
      preserveLog ? EVIDENCE_FILES.filter((name) => name !== 'session.log') : EVIDENCE_FILES,
    );
    if (state === null) return 0; // start never completed; finish owns that failure
    if (rejectForeignNonce(state, env, 'report')) return 3;
    process.stderr.write(preserveLog
      ? 'debug-evidence-action: report: the run step staged a session log but no report; publishing nothing and keeping the log for the artifact.\n'
      : 'debug-evidence-action: report: the run step recorded no capture; there is nothing to publish.\n');
    return 0; // run already failed the action if this was an integrity failure
  }
  if (!env.GITHUB_STEP_SUMMARY) return 0;
  // Read back from the staged file rather than from state, because the
  // summary is the human surface and the staged bytes are what the artifact
  // will carry. That the file could have been swapped since run staged it is
  // the known, accepted staging window — and the digest run printed to the
  // step log is precisely how such a swap is detected.
  try {
    appendFileSync(env.GITHUB_STEP_SUMMARY, `${readFileSync(path.join(evidenceDir, 'report.md'), 'utf8')}\n`);
  } catch (error) {
    process.stderr.write(`debug-evidence-action: report: staged report is unreadable (${error?.code ?? error}).\n`);
    return 3;
  }
  return 0;
};

// The exit taxonomy. Read-only by construction, so it takes no lock (recorded
// decision: lock-free read paths). Every failure mode of the machinery is a
// 3; only a wrapped command's own non-zero exit is mirrored, so a consumer
// can always tell "your build failed" from "this action failed".
//
// It no longer DECIDES anything about the evidence. Every evidence verdict —
// integrity failure, unreachable collector, success — is made inside run, and
// a failed run is already a failed action (Codex T5 r7). The evidence checks
// below are kept as a belt over a job that is by then red anyway; they read a
// state file a co-resident process can rewrite after run commits, so they can
// be defeated, and defeating them buys nothing. What remains genuinely this
// step's is the command-failure mirror, which is not security-critical: a
// hostile wrapped command chooses its own exit code regardless.
const bindArtifactSubcommand = ({ env = process.env, writeStdout = (text) => process.stdout.write(text) }) => {
  if (requireInvocationNonce(env, 'bind-artifact')) return 3;
  const id = String(env.DEBUG_ACTION_ARTIFACT_ID || '');
  const digest = String(env.DEBUG_ACTION_ARTIFACT_DIGEST || '').replace(/^sha256:/i, '');
  if (id === '' && digest === '') return 0;
  if (!/^[0-9]+$/.test(id) || !/^[a-f0-9]{64}$/i.test(digest)) {
    process.stderr.write('debug-evidence-action: bind-artifact: upload reported an unusable artifact identity.\n');
    return 3;
  }
  writeStdout(`evidence-artifact id=${id} digest=sha256:${digest.toLowerCase()}\n`);
  return 0;
};

const finishSubcommand = ({ outputDir, env = process.env }) => {
  if (requireInvocationNonce(env, 'finish')) return 3;
  const state = readState(outputDir);
  if (!state) {
    process.stderr.write('debug-evidence-action: finish: no recorded state; the start step never completed.\n');
    return 3;
  }
  if (rejectForeignNonce(state, env, 'finish')) return 3;
  if (!Number.isInteger(state.commandExitCode)) {
    process.stderr.write('debug-evidence-action: finish: the run step never completed.\n');
    return 3;
  }
  if (state.collectorAlive !== true) {
    process.stderr.write('debug-evidence-action: finish: the collector was not alive and ready at capture time; evidence may be incomplete.\n');
    return 3;
  }
  if (state.evidenceCopied !== true || state.reportRendered !== true) {
    process.stderr.write('debug-evidence-action: finish: evidence capture or report rendering failed.\n');
    return 3;
  }
  // Validated on EVERY run, green ones included. The toggle is read out of a
  // state file, and a state file that carries a value validateActionInputs
  // could never have produced is corrupt or forged — which says nothing good
  // about the exit code sitting next to it. Deferring this check to the
  // failure branch would let exactly that state pass as a success (Codex T5
  // #3).
  if (state.failOnCommandFailure !== 'true' && state.failOnCommandFailure !== 'false') {
    process.stderr.write(`debug-evidence-action: finish: recorded fail-on-command-failure is neither 'true' nor 'false'; refusing to interpret this state.\n`);
    return 3;
  }
  if (state.commandExitCode !== 0) {
    if (state.failOnCommandFailure === 'false') {
      process.stderr.write(`debug-evidence-action: wrapped command exited ${state.commandExitCode}; fail-on-command-failure is false, so the action succeeds. Evidence is in the artifact.\n`);
      return 0;
    }
    // Anything but the literal 'false' mirrors — fail closed on unknowns.
    process.stderr.write(`debug-evidence-action: wrapped command exited ${state.commandExitCode}.\n`);
    // Out of range (a 128+signal sentinel above 255, or anything a shell
    // could not have produced) becomes a plain 1: process.exitCode is taken
    // modulo 256, so passing 300 through would surface as 44 — a code that
    // looks like a real, different failure.
    return state.commandExitCode >= 1 && state.commandExitCode <= 255 ? state.commandExitCode : 1;
  }
  return 0;
};

// The session token is the only credential a state file can carry now — the
// launch token never reaches disk (Codex T5 r3), so there is nothing else
// here to redact out of a terminal diagnostic.
const collectStateSecrets = (state) => [state?.sessionToken].filter(Boolean);

// The env -> inputs mapping, lifted out of main so a test can assert what an
// ABSENT input defaults to without asking this machine what its ptrace policy
// is (Codex T6 r8 #3). The old test inferred the default from a refusal, which
// made it a statement about the host as much as about the default — and would
// have failed on exactly the hardened runner strict mode exists for.
const actionInputsFromEnv = (env) => ({
  runCommand: env.DEBUG_ACTION_RUN || '',
  sessionName: env.DEBUG_ACTION_SESSION_NAME || 'ci-debug',
  workingDirectory: env.DEBUG_ACTION_WORKDIR || '.',
  failOnCommandFailure: env.DEBUG_ACTION_FAIL_ON_COMMAND_FAILURE || 'true',
  port: env.DEBUG_ACTION_PORT || '8787',
  redactNames: env.DEBUG_ACTION_REDACT_NAMES || '',
  maxEvents: env.DEBUG_ACTION_MAX_EVENTS_INPUT || '',
  maxBytes: env.DEBUG_ACTION_MAX_BYTES_INPUT || '',
  hypothesisId: env.DEBUG_ACTION_HYPOTHESIS_ID || '',
  hypothesisTitle: env.DEBUG_ACTION_HYPOTHESIS_TITLE || '',
  // Defaulted BY ABSENCE to the safe literal: an unset variable means the
  // caller has not opted out of anything. An explicitly EMPTY one is a
  // different thing entirely — a value the contract does not recognise — and
  // '??' lets it through to validateActionInputs, which says so. '||' rounded
  // it up to 'strict' and quietly broke that promise (Codex T6 r7 #3).
  evidenceTrust: env.DEBUG_ACTION_EVIDENCE_TRUST ?? 'strict',
});

const main = async () => {
  const [subcommand] = process.argv.slice(2);
  const env = process.env;
  const outputDir = env.DEBUG_ACTION_OUTPUT_DIR
    || path.join(env.RUNNER_TEMP || os.tmpdir(), 'debug-evidence');
  const inputs = actionInputsFromEnv(env);
  try {
    if (subcommand === 'start') {
      process.exitCode = await startSubcommand({ inputs, outputDir, env, projectRoot: env.GITHUB_WORKSPACE || process.cwd() });
    } else if (subcommand === 'run') {
      process.exitCode = await runSubcommand({ inputs, outputDir, env });
    } else if (subcommand === 'report') {
      process.exitCode = reportSubcommand({ outputDir, env });
    } else if (subcommand === 'bind-artifact') {
      process.exitCode = bindArtifactSubcommand({ env });
    } else if (subcommand === 'teardown') {
      process.exitCode = teardownSubcommand({ outputDir, env });
    } else if (subcommand === 'finish') {
      process.exitCode = finishSubcommand({ outputDir, env });
    } else {
      throw new Error(`Unknown subcommand: ${subcommand ?? '(none)'}. Use start, run, report, bind-artifact, teardown, or finish.`);
    }
  } catch (error) {
    const secrets = collectStateSecrets(readState(outputDir));
    process.stderr.write(`debug-evidence-action: ${redactKnownSecrets(error?.message ?? String(error), secrets)}\n`);
    process.exitCode = 1;
  }
};

if (require.main === module) void main();

module.exports = {
  actionInputsFromEnv,
  admissionBlockers,
  admissionCaveats,
  admissionEstablished,
  admissionField,
  defaultRenderReport,
  defaultSpawnCommand,
  defaultSpawnShim,
  finishSubcommand,
  bindArtifactSubcommand,
  httpRequestJson,
  detectSudoBinary,
  evaluateAdmission,
  maskValue,
  protectWindowsPrivateFileIfPresent,
  readEffectiveUid,
  readOwnCapabilities,
  readPtraceScope,
  readShimStartLine,
  readState,
  redactKnownSecrets,
  reportSubcommand,
  resolveEvidenceDir,
  runSubcommand,
  // Exported for the cross-module byte contract, not for reuse: demo/repro.js
  // keeps its own copy of this list so its exit 98 guard reads as the contract
  // it checks, and support.test.js asserts the two are deeply equal so the
  // copy cannot drift out from under the guard.
  RUNNER_COMMAND_FILE_VARS,
  startSubcommand,
  teardownSubcommand,
  validateActionInputs,
  withStateLock,
  writeOutputs,
  writeState,
};
