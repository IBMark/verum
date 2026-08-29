# Verum detector reference

Every finding Verum can report, what triggers it, why it matters, and when ignoring it is reasonable.

This file is generated from the detector table in `crates/verum-nucleus/src/reference.rs`. Do not edit it by hand - run `verum explain --all --format markdown > docs/detectors.md` instead. A test fails if the two drift apart.

67 detectors.

## Contents

**Dead code**

- [DeadFunction](#deadfunction) - A function or method nothing in the program ever calls
- [DeadClass](#deadclass) - A class or type nothing in the program ever instantiates or references
- [DeadFile](#deadfile) - A file whose every symbol is unreachable
- [UnreachableCode](#unreachablecode) - Statements after a return, throw, or infinite loop that can never execute

**Duplication**

- [ExactDuplicate](#exactduplicate) - Two symbols with byte-identical structure
- [RenamedDuplicate](#renamedduplicate) - Two symbols identical once identifiers are normalised
- [SemanticDuplicate](#semanticduplicate) - Two symbols with the same data flow written differently

**Security**

- [SqlInjection](#sqlinjection) - User-controlled input reaches a SQL query without parameter binding
- [XssVulnerability](#xssvulnerability) - User-controlled input reaches HTML output unescaped
- [WeakCrypto](#weakcrypto) - A broken hash or cipher used where security depends on it
- [HardcodedSecret](#hardcodedsecret) - A credential-shaped literal committed in source
- [EvalUsage](#evalusage) - Dynamic code execution, or user input reaching an execution sink
- [TlsVerificationDisabled](#tlsverificationdisabled) - TLS certificate verification switched off on an HTTPS client
- [UnsafeDeserialization](#unsafedeserialization) - Deserialization that can execute code during decoding
- [WeakRandom](#weakrandom) - A non-cryptographic random source used for a security value
- [OpenRedirect](#openredirect) - A redirect target taken from user input without an allowlist
- [PathTraversal](#pathtraversal) - User-controlled input reaches a filesystem path

**Access control**

- [MissingAuthMiddleware](#missingauthmiddleware) - A route with no authentication middleware in sight
- [MissingRoleCheck](#missingrolecheck) - An authenticated route with no authorization check
- [PotentialIdor](#potentialidor) - A record fetched by a caller-supplied identifier with no ownership check

**Complexity**

- [GodClass](#godclass) - A class with more methods than the configured maximum
- [CircularDependency](#circulardependency) - Modules that depend on each other in a cycle
- [HighComplexity](#highcomplexity) - A function with too many independent branches
- [LongFunction](#longfunction) - A function longer than the configured maximum
- [TooManyParams](#toomanyparams) - A function with more parameters than the configured maximum
- [DeepNesting](#deepnesting) - Control flow nested past the configured depth

**Performance**

- [NPlusOneQuery](#nplusonequery) - A transformer touching relationships with no eager loading in sight
- [StringConcatInLoop](#stringconcatinloop) - A string built by repeated concatenation inside a loop
- [ObjectInstantiationInLoop](#objectinstantiationinloop) - An expensive object constructed on every iteration
- [MissingHookDependencies](#missinghookdependencies) - A React hook called with no dependency array

**Naming**

- [NamingInconsistency](#naminginconsistency) - One concept named with several interchangeable verbs across the project
- [ConventionViolation](#conventionviolation) - An identifier or manifest line that breaks the project's stated convention

**Infrastructure**

- [OpenSecurityGroup](#opensecuritygroup) - A network rule that admits the entire internet
- [UnencryptedStorage](#unencryptedstorage) - Data at rest or in transit left unencrypted
- [PublicResource](#publicresource) - A storage or database resource exposed to the public internet
- [IamOverPermission](#iamoverpermission) - A policy or role that grants far more than it needs
- [RunningAsRoot](#runningasroot) - A container that runs as UID 0
- [PrivilegedContainer](#privilegedcontainer) - A container with the host namespaces or full kernel capabilities
- [MissingResourceLimits](#missingresourcelimits) - A container with no CPU/memory bounds or a writable root filesystem
- [MissingHealthProbes](#missinghealthprobes) - A workload the orchestrator cannot tell is healthy
- [UnpinnedImage](#unpinnedimage) - A dependency pulled by a moving reference instead of a fixed one
- [NoNetworkPolicy](#nonetworkpolicy) - Network isolation declared but not actually enforced
- [SecretInEnvVar](#secretinenvvar) - A secret written in plaintext into a manifest
- [HardcodedCredential](#hardcodedcredential) - A credential or unreplaced placeholder committed in a manifest

**Compliance**

- [PciViolation](#pciviolation) - A pattern that breaks a PCI-DSS requirement
- [GdprViolation](#gdprviolation) - A pattern that breaks a GDPR obligation
- [Soc2Violation](#soc2violation) - Missing audit, retention, or change-control evidence

**Chains**

- [DangerousChain](#dangerouschain) - A call path from an entry point to a dangerous sink

**Rust insights**

- [UnsafeUsage](#unsafeusage) - An `unsafe` block or function
- [PanicRisk](#panicrisk) - A panicking call such as `.unwrap()`, `.expect()`, or `panic!`
- [BlockingInAsync](#blockinginasync) - A blocking call inside an async function
- [UnboundedChannel](#unboundedchannel) - A queue with no backpressure
- [HotPathAllocation](#hotpathallocation) - An allocation or clone on a latency-sensitive path
- [LockOnHotPath](#lockonhotpath) - A blocking lock taken on a latency-sensitive path
- [LockAcrossAwait](#lockacrossawait) - A synchronous lock guard held across an `.await`
- [MissingSafetyComment](#missingsafetycomment) - An `unsafe` block with no `// SAFETY:` justification

**Transport**

- [SplitDatagramMessage](#splitdatagrammessage) - One logical message written as several datagrams
- [OversizedDatagram](#oversizeddatagram) - A datagram larger than the safe MTU payload
- [UnvalidatedLengthPrefix](#unvalidatedlengthprefix) - A length read from the wire used unchecked as an allocation or read size

**Dependencies**

- [VulnerableDependency](#vulnerabledependency) - A locked dependency version matching a known advisory
- [UnmaintainedDependency](#unmaintaineddependency) - A locked dependency flagged as abandoned
- [DuplicateDependency](#duplicatedependency) - One crate present at several incompatible versions
- [CrateApiMisuse](#crateapimisuse) - A call that contradicts a known crate's documented behaviour

**Cryptography**

- [NonConstantTimeComparison](#nonconstanttimecomparison) - A security-sensitive value compared with `==`
- [StaticAeadNonce](#staticaeadnonce) - A constant nonce or IV reaching an AEAD encrypt call

**Diagnostics**

- [ParseFailure](#parsefailure) - A file whose parse or analysis panicked and was isolated
- [StaleSuppression](#stalesuppression) - A verum:ignore comment that suppresses nothing

---

## DeadFunction

A function or method nothing in the program ever calls  
`dead-function` | category: Dead code

**Detects.** A function, method, or static method whose name appears at no call site and that no route, entry point, or test reaches through the call graph. Framework entry points, magic methods, constructors, `main`, Go interface methods, public items of a library root, test and fixture trees, and `vendor/` and `node_modules/` are all excluded, and the confidence drops when the symbol could plausibly be reached by dynamic dispatch.

**Why it matters.** Dead code is read, reviewed, refactored, and ported like live code, and it keeps its dependencies alive. It is also where stale security assumptions hide: a handler nobody calls today is one route registration away from being live again with years-old validation.

**Flagged**

```rust
pub fn parse_legacy_header(bytes: &[u8]) -> Header { /* ... */ }
// no caller anywhere in the tree
```

**Fixed**

```rust
// deleted - the v1 header format was removed in the 2.0 wire protocol
```

**Reasonable to suppress.** The symbol is reached in a way Verum cannot see - a dynamic dispatch table, a macro-generated registration, an FFI export, a plugin ABI - or it is a deliberately public API of a library whose callers live outside this tree.

---

## DeadClass

A class or type nothing in the program ever instantiates or references  
`dead-class` | category: Dead code

**Detects.** A class whose name appears at no construction site, type position, or call site anywhere the analysis can see. Reserved: no analysis pass currently emits this kind - class-level liveness is reported through its methods.

**Why it matters.** A dead class carries its whole transitive surface with it: its imports, its interface obligations, its migrations. Deleting one usually removes far more code than deleting a single function.

**Flagged**

```php
class LegacyInvoiceExporter
{
    public function export(Invoice $invoice): string { /* ... */ }
}
```

**Fixed**

```php
// deleted with the legacy export endpoint
```

**Reasonable to suppress.** The class is constructed reflectively (a DI container, a service-provider map, a deserializer building it by name) or it is a published API of this package.

---

## DeadFile

A file whose every symbol is unreachable  
`dead-file` | category: Dead code

**Detects.** A source file in which no symbol is reachable from any entry point, route, or test. Reserved: no analysis pass currently emits this kind - unreachable files surface as a cluster of per-symbol findings instead.

**Why it matters.** A file nobody reaches is still compiled, still linted, still shipped in the image, and still turns up in every grep. It is the cheapest deletion in the codebase.

**Flagged**

```text
src/legacy/xml_importer.rs   # nothing imports this module
```

**Fixed**

```text
# file deleted, and its `mod legacy;` declaration with it
```

**Reasonable to suppress.** The file is an example, a build script, a template consumed by tooling, or an entry point that is invoked from outside the tree.

---

## UnreachableCode

Statements after a return, throw, or infinite loop that can never execute  
`unreachable-code` | category: Dead code

**Detects.** Statements in a basic block that follows an unconditional transfer of control - a `return`, `throw`, `panic!`, `exit`, or diverging loop - within the same scope. Reserved: no analysis pass currently emits this kind.

**Why it matters.** Unreachable code is almost always a bug rather than tidy-up debt: the cleanup, the log line, or the rollback that was meant to run simply does not. Reviewers read it as if it executes.

**Flagged**

```js
function save(order) {
  return repo.persist(order);
  audit.log("saved", order.id);   // never runs
}
```

**Fixed**

```js
function save(order) {
  const saved = repo.persist(order);
  audit.log("saved", order.id);
  return saved;
}
```

**Reasonable to suppress.** The block is deliberately unreachable scaffolding - an exhaustiveness guard, a placeholder behind a feature flag - and is documented as such.

---

## ExactDuplicate

Two symbols with byte-identical structure  
`exact-duplicate` | category: Duplication

**Detects.** Two or more symbols whose structural hash is identical: the same code, including the same identifiers. Entry points and, unless the path mentions `fixtures`, tests, benches, and examples are excluded. The copy with the most call sites is nominated canonical (ties broken by source position).

**Why it matters.** Every copy is a place a fix can fail to land. Exact duplicates are where security patches go missing: the vulnerability is fixed in the copy the reviewer opened and left standing in the other two.

**Flagged**

```python
def normalize_email(value):
    return value.strip().lower()

# in another module, character for character:
def normalize_email(value):
    return value.strip().lower()
```

**Fixed**

```python
from .text import normalize_email
```

**Reasonable to suppress.** The copies are deliberately independent - vendored code, a generated file, or a boundary you are unwilling to couple across (two services that must be able to diverge).

---

## RenamedDuplicate

Two symbols identical once identifiers are normalised  
`renamed-duplicate` | category: Duplication

**Detects.** Two or more symbols spanning at least two lines whose hash matches after identifier names are normalised away - the same code with different variable, parameter, or function names. Same exclusions as `ExactDuplicate`.

**Why it matters.** The rename hides the duplication from grep, so the second copy survives every cleanup pass. Behaviourally it is the same code with the same bugs.

**Flagged**

```js
function centsToString(cents) { return (cents / 100).toFixed(2); }
function formatAmount(amount) { return (amount / 100).toFixed(2); }
```

**Fixed**

```js
function centsToString(cents) { return (cents / 100).toFixed(2); }
const formatAmount = centsToString;
```

**Reasonable to suppress.** The similarity is incidental - two short accessors that happen to have the same shape - or the two live on either side of a boundary you intend to keep decoupled.

---

## SemanticDuplicate

Two symbols with the same data flow written differently  
`semantic-duplicate` | category: Duplication

**Detects.** Two or more symbols spanning at least two lines whose control- and data-flow hash matches: the same operations in the same order, expressed with different syntax. Reported at lower confidence than the exact and renamed levels.

**Why it matters.** Two implementations of one behaviour drift. The one that is fixed and the one that is called are, eventually, not the same one.

**Flagged**

```python
def total(items):
    out = 0
    for i in items:
        out += i.price
    return out

def sum_prices(items):
    return sum(i.price for i in items)
```

**Fixed**

```python
def total(items):
    return sum(i.price for i in items)
```

**Reasonable to suppress.** The two are genuinely different concerns that currently compute the same thing, or one is a deliberately simple reference implementation kept for testing the optimised one.

---

## SqlInjection

User-controlled input reaches a SQL query without parameter binding  
`sql-injection` | category: Security

**Detects.** A taint path from a request source (`$_GET`/`$_POST`/`$_REQUEST`/`$_COOKIE`, `req.query`/`params`/`body`, a web-framework extractor, stdin) to a raw-SQL sink (`DB::raw`, `whereRaw`, `mysqli_query`, `->unprepared`, `sqlx::query`, `sql_query`) with no sanitizer in between, in PHP, JavaScript, TypeScript, or Rust; plus the string-concatenation form, where a SQL keyword and an interpolated variable share a line. Rust build scripts, tests, benches, and examples are excluded.

**Why it matters.** The most reliable full-database compromise there is. One crafted parameter reads every row the connection can see, and on many deployments writes them, or the filesystem, back.

**Flagged**

```php
$rows = DB::select("SELECT * FROM users WHERE email = '" . $_GET['email'] . "'");
```

**Fixed**

```php
$rows = DB::select('SELECT * FROM users WHERE email = ?', [$request->input('email')]);
```

**Reasonable to suppress.** The interpolated value is provably not user-controlled - a compile-time constant, an enum rendered to a literal, a column name checked against an allowlist immediately above. Escaping by hand is not a reason to suppress.

---

## XssVulnerability

User-controlled input reaches HTML output unescaped  
`xss-vulnerability` | category: Security

**Detects.** A taint path from a request source to an HTML output sink (`echo`, `print`) with no escaping call in between, in PHP, JavaScript, and TypeScript. Rust is excluded: its templating layers escape by default and the pattern produced only false positives.

**Why it matters.** Script injected into a page runs with the victim's session. That is account takeover for anyone who loads the page, including the administrator viewing a user-submitted value in an admin panel.

**Flagged**

```php
echo "Welcome back, " . $_GET['name'];
```

**Fixed**

```php
echo 'Welcome back, ' . htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');
```

**Reasonable to suppress.** The value is escaped by a helper Verum cannot see through, or the output is provably not HTML (a `text/plain` or JSON response with the content type set at the same layer).

---

## WeakCrypto

A broken hash or cipher used where security depends on it  
`weak-crypto` | category: Security

**Detects.** A call to `md5()` or `sha1()` in PHP, JavaScript, TypeScript, or Python (including `hashlib.md5`), classified by the words on the same line: password, token, secret, auth, signature, or HMAC context raises it to critical; cache-key, ETag, checksum, gravatar, and fingerprint context suppresses it entirely. `crypto.createHash('md5'|'sha1')` in JavaScript/TypeScript is flagged only when such a sensitive word appears on the line. Algorithms listed in `code.security.forbid_weak_crypto` in `verum.standard.json` are always flagged, and that file can also allowlist specific contexts.

**Why it matters.** MD5 and SHA-1 are collision-broken and, for passwords, so fast that an offline attacker tries billions of candidates a second on commodity hardware. A stolen hash column is a stolen password column.

**Flagged**

```php
$user->password = md5($request->input('password'));
```

**Fixed**

```php
$user->password = password_hash($request->input('password'), PASSWORD_ARGON2ID);
```

**Reasonable to suppress.** The digest is a non-security identifier - a cache key, an ETag, a shard selector, a content fingerprint that is not a trust boundary. Add the context to the allowlist in `verum.standard.json` rather than ignoring the finding by hand.

---

## HardcodedSecret

A credential-shaped literal committed in source  
`hardcoded-secret` | category: Security

**Detects.** An assignment whose name mentions password, passphrase, secret, API key, token, access key, or private key and whose value is a quoted literal of at least eight characters; and, independent of the name, a provider-shaped token literal in Python/JavaScript/TypeScript (`sk_live_`, `AKIA`, `ghp_`, `github_pat_`, `xoxb-`/`xoxp-`, `glpat-`, or a PEM private-key block with key material). Placeholders, template expressions containing `{`, `$`, `%` or `<`, identifier-like values, status words such as `configured` or `redacted`, env-var reads, and comment lines are all filtered out - except when the value carries a known credential prefix (`sk-`, `ghp_`, `xoxb-`, `AKIA`, `glpat-`, ...), which overrides the filters.

**Why it matters.** A secret in git is a secret in every clone, every fork, every CI cache, and every backup of the repository - permanently. Rotating it is the only remediation, and the clock starts at the commit, not at the discovery.

**Flagged**

```python
STRIPE_API_KEY = "sk_live_51H8sample"
```

**Fixed**

```python
STRIPE_API_KEY = os.environ["STRIPE_API_KEY"]
```

**Reasonable to suppress.** The value is a test fixture, a documented public sandbox key, or an example in a template. Keep such values in fixture directories so the filters catch them for everyone.

---

## EvalUsage

Dynamic code execution, or user input reaching an execution sink  
`eval-usage` | category: Security

**Detects.** Three shapes: a literal `eval(` call in PHP, JavaScript, TypeScript, or Python; a taint path from a request source to an execution sink (`eval`, `exec`, `shell_exec`, `system`, `passthru`, `popen`, `proc_open`, `Command::new`); and, in Dockerfiles, piping a downloaded script straight into a shell or `ADD`-ing a remote URL.

**Why it matters.** An execution sink turns any input-handling bug into remote code execution on the host. It also defeats every static tool downstream, including this one: nothing can reason about what the string will be.

**Flagged**

```php
eval('$result = ' . $_POST['expr'] . ';');
```

**Fixed**

```php
$result = (new ExpressionEvaluator($allowedOperations))->evaluate($_POST['expr']);
```

**Reasonable to suppress.** Practically never for the taint form. The literal form is defensible in a build or codegen script that runs on trusted input only, never on a request path.

---

## TlsVerificationDisabled

TLS certificate verification switched off on an HTTPS client  
`tls-verification-disabled` | category: Security

**Detects.** `rejectUnauthorized: false` or `NODE_TLS_REJECT_UNAUTHORIZED=0` in JavaScript/TypeScript; `verify=False` on a `requests`/`httpx` call, `ssl._create_unverified_context()`, or `verify_mode = ssl.CERT_NONE` in Python. Comment lines and test/vendored paths are excluded.

**Why it matters.** With verification off the client encrypts to whoever answered the connection. Any on-path attacker - a hostile network, a compromised router, a rogue proxy - can present any certificate and silently read or rewrite the traffic, including the credentials the connection was supposed to protect.

**Flagged**

```python
resp = requests.post(WEBHOOK_URL, json=payload, verify=False)
```

**Fixed**

```python
resp = requests.post(WEBHOOK_URL, json=payload)  # verification stays on
```

**Reasonable to suppress.** A local development script talking to a self-signed endpoint that never handles production data - and even then, pinning the self-signed certificate (`verify=path/to/ca.pem`, `ca` option) is the fix that keeps working in production.

---

## UnsafeDeserialization

Deserialization that can execute code during decoding  
`unsafe-deserialization` | category: Security

**Detects.** `pickle.load(`/`pickle.loads(` on a non-literal argument, `yaml.load(` without `SafeLoader`/`FullLoader`, and `yaml.unsafe_load(` in Python; `new Function(` built from non-literal text in JavaScript/TypeScript. Literal arguments and comment lines are excluded.

**Why it matters.** These decoders run code as a feature: a pickle byte-stream can invoke any callable while loading, a full YAML loader instantiates arbitrary Python objects, and `new Function` compiles its argument as JavaScript. Feeding any of them attacker-influenced data is remote code execution, not a parsing bug.

**Flagged**

```python
config = yaml.load(request.data)
session = pickle.loads(cookie_bytes)
```

**Fixed**

```python
config = yaml.safe_load(request.data)
session = json.loads(cookie_text)
```

**Reasonable to suppress.** The bytes provably never leave trusted storage the application itself wrote (a local cache file with restrictive permissions), or a codegen step that runs at build time on checked-in input only.

---

## MissingAuthMiddleware

A route with no authentication middleware in sight  
`missing-auth-middleware` | category: Access control

**Detects.** A PHP/Laravel route with no auth middleware on the route itself and none on an enclosing group in the same file. Routes in `auth.php` and `admin.php` and paths containing `health`, `status`, or `ping` are excluded. Other languages are not checked: middleware attachment is too implicit to read reliably.

**Why it matters.** An unauthenticated route is not a missing feature, it is an open door. These are found by scanners in hours and are the standard first step of a breach chain.

**Flagged**

```php
Route::post('/invoices/{invoice}/refund', [RefundController::class, 'store']);
```

**Fixed**

```php
Route::post('/invoices/{invoice}/refund', [RefundController::class, 'store'])
    ->middleware(['auth:api', 'can:refund,invoice']);
```

**Reasonable to suppress.** The route is genuinely public (a webhook with signature verification inside the controller, a health probe, a public marketing page), or the middleware is applied in a file the route declaration does not name.

---

## MissingRoleCheck

An authenticated route with no authorization check  
`missing-role-check` | category: Access control

**Detects.** A route that authenticates the caller but never checks what that caller is permitted to do. Reserved: no analysis pass currently emits this kind; the gate-less paths that would produce it surface as `DangerousChain`.

**Why it matters.** Authentication answers who; authorization answers whether. Without the second check, every logged-in user is an administrator of every record they can name.

**Flagged**

```php
public function destroy(Invoice $invoice)
{
    $invoice->delete();          // any authenticated user
}
```

**Fixed**

```php
public function destroy(Invoice $invoice)
{
    $this->authorize('delete', $invoice);
    $invoice->delete();
}
```

**Reasonable to suppress.** The action is intentionally available to every authenticated user, or the check happens in a policy the framework applies automatically.

---

## PotentialIdor

A record fetched by a caller-supplied identifier with no ownership check  
`potential-idor` | category: Access control

**Detects.** A lookup keyed on an identifier that came from the request, with no comparison against the current user's scope. Reserved: no analysis pass currently emits this kind.

**Why it matters.** Insecure direct object reference is the single most common real-world API vulnerability: incrementing an id in a URL walks the whole table, one other customer's record at a time, and every request looks legitimate in the logs.

**Flagged**

```js
const invoice = await Invoice.findById(req.params.id);
res.json(invoice);
```

**Fixed**

```js
const invoice = await Invoice.findOne({ _id: req.params.id, ownerId: req.user.id });
if (!invoice) return res.sendStatus(404);
res.json(invoice);
```

**Reasonable to suppress.** The identifier is unguessable and the resource is intentionally shared by link, or the scoping happens in a repository layer that always applies the tenant filter.

---

## WeakRandom

A non-cryptographic random source used for a security value  
`weak-random` | category: Security

**Detects.** A predictable generator (`Math.random()` in JavaScript/TypeScript; `random.random()`, `random.randint()`, `random.getrandbits()` in Python) on a line whose identifiers name a security value - password, secret, token, OTP, nonce, salt, or CSRF. Lines without a security-named identifier are never flagged, so simulations, sampling, jitter, and games stay quiet.

**Why it matters.** These generators are seeded from low-entropy state and are designed to be fast, not unpredictable. Given a few outputs an attacker can reproduce the sequence and mint the next password-reset token before the user reads their email.

**Flagged**

```php
$token = md5(mt_rand());
```

**Fixed**

```php
$token = bin2hex(random_bytes(32));
```

**Reasonable to suppress.** The value is not a security token - a jitter interval, a sampling decision, a shuffled demo dataset.

---

## OpenRedirect

A redirect target taken from user input without an allowlist  
`open-redirect` | category: Security

**Detects.** A redirect whose destination derives from request data with no host allowlist or relative-path enforcement. Reserved: no analysis pass currently emits this kind.

**Why it matters.** A link on your domain that lands on the attacker's is the credibility half of a phishing campaign, and it defeats OAuth and SSO flows that trust the redirect parameter to stay in-origin.

**Flagged**

```php
return redirect($request->input('next'));
```

**Fixed**

```php
$next = $request->input('next', '/');
abort_unless(str_starts_with($next, '/'), 400);
return redirect($next);
```

**Reasonable to suppress.** The destination is validated against an allowlist a few lines away, or the parameter is a route name rather than a URL.

---

## GodClass

A class with more methods than the configured maximum  
`god-class` | category: Complexity

**Detects.** A class whose method count exceeds `code.architecture.max_class_methods` in `verum.standard.json` (20 by default). Counts methods and static methods declared on the class itself.

**Why it matters.** A class that does twenty things has twenty reasons to change, and every change risks the other nineteen. It is also the shape that makes tests slow and mocking painful, which is how a module stops being tested at all.

**Flagged**

```php
class OrderService
{
    public function create() {}
    public function refund() {}
    public function exportCsv() {}
    public function sendReceiptEmail() {}
    // ... 20 more
}
```

**Fixed**

```php
class OrderService { public function create() {} public function refund() {} }
class OrderExporter { public function exportCsv() {} }
class OrderMailer { public function sendReceiptEmail() {} }
```

**Reasonable to suppress.** The type is a deliberate facade over a wide external API, or generated code. Raise `max_class_methods` in `verum.standard.json` if the whole project has agreed on a different number.

---

## CircularDependency

Modules that depend on each other in a cycle  
`circular-dependency` | category: Complexity

**Detects.** A cycle in the module dependency graph: A imports B, which imports A, directly or through intermediates. Reserved: no analysis pass currently emits this kind as a finding - `verum map` reports the cycles it finds.

**Why it matters.** A cycle means neither module can be understood, tested, built, or extracted without the other. It is the concrete reason a 'we will split this later' refactor never happens.

**Flagged**

```text
billing/invoice.rs  ->  billing/customer.rs  ->  billing/invoice.rs
```

**Fixed**

```text
billing/invoice.rs  ->  billing/ids.rs  <-  billing/customer.rs
```

**Reasonable to suppress.** The cycle is between files of one cohesive module in a language where that is free (a Rust module tree, a Go package), rather than across a boundary you intend to keep.

---

## HighComplexity

A function with too many independent branches  
`high-complexity` | category: Complexity

**Detects.** A function whose cyclomatic complexity - the number of independent paths through it - exceeds the configured maximum. Reserved: no analysis pass currently emits this kind; length, nesting, and parameter count carry the complexity dimension today.

**Why it matters.** Paths multiply: each branch doubles what a test suite must cover, and the ones that go untested are exactly the error paths that matter under load.

**Flagged**

```rust
fn route(req: &Request) -> Response {
    if a { if b { if c { /* ... */ } else if d { /* ... */ } } }
    // fifteen more branches
}
```

**Fixed**

```rust
fn route(req: &Request) -> Response {
    match classify(req) {
        Kind::Upload => handle_upload(req),
        Kind::Fetch => handle_fetch(req),
    }
}
```

**Reasonable to suppress.** The function is a generated or hand-written dispatch table where the branches are data, not logic.

---

## LongFunction

A function longer than the configured maximum  
`long-function` | category: Complexity

**Detects.** A function whose inclusive line span exceeds `code.architecture.max_function_lines` in `verum.standard.json` (50 by default). Applies to every supported language.

**Why it matters.** A function that does not fit on a screen cannot be held in one reader's head, so reviews of it degrade to skimming. Long functions also hide their own local state, which is where the off-by-one and the missing early return live.

**Flagged**

```python
def process_order(order):
    # 140 lines: validation, pricing, tax, persistence, email, metrics
    ...
```

**Fixed**

```python
def process_order(order):
    validate(order)
    priced = price(order)
    persist(priced)
    notify(priced)
```

**Reasonable to suppress.** The body is one flat, irreducible sequence - a long match over a wire protocol, a generated builder - where splitting it would only add indirection.

---

## TooManyParams

A function with more parameters than the configured maximum  
`too-many-params` | category: Complexity

**Detects.** A function whose parameter count exceeds `code.architecture.max_parameters` in `verum.standard.json` (5 by default).

**Why it matters.** Long parameter lists are call-site bugs waiting to happen: two adjacent arguments of the same type will eventually be passed the wrong way round, and the compiler will not say a word.

**Flagged**

```rust
fn send(host: &str, port: u16, user: &str, pass: &str, tls: bool, timeout: u64) {}
```

**Fixed**

```rust
struct SmtpConfig { host: String, port: u16, user: String, pass: String,
                    tls: bool, timeout: Duration }
fn send(config: &SmtpConfig) {}
```

**Reasonable to suppress.** The signature is fixed by an external interface (an FFI boundary, a trait you implement) or the parameters are distinctly typed enough that a transposition cannot compile.

---

## DeepNesting

Control flow nested past the configured depth  
`deep-nesting` | category: Complexity

**Detects.** A block nested deeper than the configured maximum - loops inside conditions inside loops. Reserved: no analysis pass currently emits this kind.

**Why it matters.** Each level of nesting is another invariant the reader must carry to understand the innermost line. Deeply nested error handling is where the early return that should have happened does not.

**Flagged**

```js
for (const o of orders) {
  if (o.paid) {
    for (const l of o.lines) {
      if (l.taxable) { if (l.qty > 0) { total += tax(l); } }
    }
  }
}
```

**Fixed**

```js
const taxable = orders.filter(o => o.paid).flatMap(o => o.lines)
  .filter(l => l.taxable && l.qty > 0);
const total = taxable.reduce((sum, l) => sum + tax(l), 0);
```

**Reasonable to suppress.** The nesting mirrors an inherently nested data structure and flattening it would obscure that structure.

---

## NPlusOneQuery

A transformer touching relationships with no eager loading in sight  
`n-plus-one-query` | category: Performance

**Detects.** A PHP transformer, resource, or presenter class (its path names one of those, and the file mentions `TransformerAbstract`, `JsonResource`, or `Fractal`) whose `transform`, `toArray`, or `toResponse` body dereferences relationship properties while the file contains no `->with([...])` eager load. `vendor/` and `node_modules/` are excluded.

**Why it matters.** One query becomes one query per row. A list endpoint that is instant with the ten rows in development issues ten thousand round trips in production, and the database, not the application, is what falls over.

**Flagged**

```php
public function transform(Order $order)
{
    return ['customer' => $order->customer->name];   // one query per order
}
```

**Fixed**

```php
$orders = Order::with(['customer'])->paginate();     // one query for all of them
```

**Reasonable to suppress.** The relationship is eager-loaded by the caller in a way this file cannot show, or the transformer only ever runs on a single record.

---

## StringConcatInLoop

A string built by repeated concatenation inside a loop  
`string-concat-in-loop` | category: Performance

**Detects.** Repeated `+=`-style string building inside a loop body, where each iteration reallocates and copies the accumulated string. Reserved: no analysis pass currently emits this kind.

**Why it matters.** Quadratic time and quadratic garbage. It is invisible on a hundred iterations and is the whole request budget at a hundred thousand.

**Flagged**

```python
out = ""
for row in rows:
    out += row.render()
```

**Fixed**

```python
out = "".join(row.render() for row in rows)
```

**Reasonable to suppress.** The loop is bounded to a handful of iterations, or the language's runtime optimises the pattern (some do, for local single-reference strings).

---

## ObjectInstantiationInLoop

An expensive object constructed on every iteration  
`object-instantiation-in-loop` | category: Performance

**Detects.** Construction of a heavyweight object - a client, a parser, a compiled pattern - inside a loop body when it is loop-invariant. Reserved: no analysis pass currently emits this kind.

**Why it matters.** Constructors of this sort do real work: they compile patterns, open sockets, read configuration. Doing it per iteration multiplies a fixed cost by the collection size, and can exhaust connection pools outright.

**Flagged**

```js
for (const line of lines) {
  const re = new RegExp(pattern);   // recompiled every line
  if (re.test(line)) hits.push(line);
}
```

**Fixed**

```js
const re = new RegExp(pattern);
for (const line of lines) if (re.test(line)) hits.push(line);
```

**Reasonable to suppress.** The object carries per-iteration state and genuinely cannot be hoisted, or construction is trivially cheap.

---

## MissingHookDependencies

A React hook called with no dependency array  
`missing-hook-dependencies` | category: Performance

**Detects.** A `useEffect`, `useCallback`, or `useMemo` call in a `.js`, `.jsx`, `.ts`, or `.tsx` file whose argument list has no array after the first argument. The scan is string- and comment-aware, so hook names inside literals or comments are not counted.

**Why it matters.** Without the array the effect re-runs after every render. If it sets state or fetches, that is an infinite render loop or a request storm - a class of bug that shows up as an inexplicably hot browser tab and a hammered API.

**Flagged**

```js
useEffect(() => { fetchUser(id).then(setUser); });
```

**Fixed**

```js
useEffect(() => { fetchUser(id).then(setUser); }, [id]);
```

**Reasonable to suppress.** The effect is deliberately per-render and does no work that can loop - a pure measurement or a ref sync - and says so in a comment.

---

## NamingInconsistency

One concept named with several interchangeable verbs across the project  
`naming-inconsistency` | category: Naming

**Detects.** More than one prefix from a synonym group used as a word across the project's functions and methods: get/fetch/load/retrieve/find, delete/remove/destroy, create/make/build/generate, update/modify/change/edit. `vendor/`, `node_modules/`, and `/target/` are excluded. One finding per group.

**Why it matters.** Inconsistent verbs defeat search. A developer looking for how records are removed greps `delete`, finds three call sites, and misses the four that use `destroy` - including the one without the authorization check.

**Flagged**

```text
getUser()      fetchOrder()      loadInvoice()      retrieveCustomer()
```

**Fixed**

```text
getUser()      getOrder()        getInvoice()       getCustomer()
```

**Reasonable to suppress.** The verbs are genuinely distinct in your domain - `fetch` crosses the network, `load` reads a cache, `get` is a pure accessor - and that distinction is documented.

---

## ConventionViolation

An identifier or manifest line that breaks the project's stated convention  
`convention-violation` | category: Naming

**Detects.** In code: a class, interface, trait, enum, component, method, function, constant, or variable whose case does not match the convention for its language in `code.naming` in `verum.standard.json` (PascalCase types, language-default callables and constants). Go is skipped entirely, as are `vendor/`, `node_modules/`, dunder methods, and names of two characters or fewer. In infrastructure: TODO/FIXME/HACK/XXX comments, commented-out configuration blocks, `ADD` where `COPY` belongs, `COPY . .` with no `.dockerignore`, multiple `CMD` or `ENTRYPOINT` directives, missing image labels, `force_destroy = true`, and untagged taggable Terraform resources.

**Why it matters.** Conventions are how a reader knows what a name is without looking it up. In manifests the same checks catch operational foot-guns: a second `CMD` silently overrides the first, and `force_destroy = true` turns a plan mistake into deleted production data.

**Flagged**

```hcl
resource "aws_s3_bucket" "exports" {
  bucket        = "acme-exports"
  force_destroy = true
}
```

**Fixed**

```hcl
resource "aws_s3_bucket" "exports" {
  bucket = "acme-exports"
  tags   = { owner = "platform", environment = "prod" }
}
```

**Reasonable to suppress.** The name is imposed by an external interface (a serialized field, a database column, a framework hook), or the manifest pattern is deliberate for an ephemeral environment. Configure the convention in `verum.standard.json` rather than suppressing case-by-case.

---

## OpenSecurityGroup

A network rule that admits the entire internet  
`open-security-group` | category: Infrastructure

**Detects.** Terraform: an ingress rule with `cidr_blocks` of `0.0.0.0/0` or `::/0`, a port range of 0-65535, `protocol = "-1"`, or a security group with no egress restrictions at all. Kubernetes: a pod using the host network namespace, or a NetworkPolicy peer with an all-addresses `ipBlock`. Dockerfiles: `EXPOSE 22`.

**Why it matters.** An open ingress rule is the difference between an internal service and an internet-facing one. Managed databases and admin ports opened this way are found by internet-wide scanners within minutes of the apply.

**Flagged**

```hcl
ingress {
  from_port   = 5432
  to_port     = 5432
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
}
```

**Fixed**

```hcl
ingress {
  from_port       = 5432
  to_port         = 5432
  protocol        = "tcp"
  security_groups = [aws_security_group.app.id]
}
```

**Reasonable to suppress.** The service is deliberately public and the port is a public one (443 on a load balancer). An open management or database port is never that.

---

## UnencryptedStorage

Data at rest or in transit left unencrypted  
`unencrypted-storage` | category: Infrastructure

**Detects.** Terraform: an S3 bucket with no server-side encryption or no versioning, an RDS instance or cluster without `storage_encrypted`, an unencrypted EBS volume, a state backend without `encrypt = true`. Kubernetes: an Ingress with no TLS block, or an environment variable that switches TLS/SSL verification off.

**Why it matters.** Unencrypted storage turns every lower-level failure - a snapshot shared by mistake, a decommissioned disk, a misconfigured bucket policy - into a data breach with notification obligations. Disabled TLS verification makes every network hop a trusted one.

**Flagged**

```hcl
resource "aws_db_instance" "main" {
  engine             = "postgres"
  storage_encrypted  = false
}
```

**Fixed**

```hcl
resource "aws_db_instance" "main" {
  engine            = "postgres"
  storage_encrypted = true
  kms_key_id        = aws_kms_key.rds.arn
}
```

**Reasonable to suppress.** The data is public by design and provably contains nothing personal or confidential - a static asset bucket serving a marketing site.

---

## PublicResource

A storage or database resource exposed to the public internet  
`public-resource` | category: Infrastructure

**Detects.** Terraform: an S3 bucket with a `public-read` or `public-read-write` ACL, or an RDS instance or cluster with `publicly_accessible = true`.

**Why it matters.** Public buckets and publicly addressable databases are the two most common causes of large-scale data exposure. Neither requires an exploit - only a URL or a hostname and a weak password.

**Flagged**

```hcl
resource "aws_s3_bucket" "uploads" {
  bucket = "acme-uploads"
  acl    = "public-read"
}
```

**Fixed**

```hcl
resource "aws_s3_bucket" "uploads" {
  bucket = "acme-uploads"
  acl    = "private"
}
```

**Reasonable to suppress.** The bucket is a deliberate public asset host and the objects in it are published content. A database is never a defensible exception.

---

## IamOverPermission

A policy or role that grants far more than it needs  
`iam-over-permission` | category: Infrastructure

**Detects.** Terraform: an IAM policy with a wildcard `Action` or `Resource`, or an IAM user with an inline policy. Kubernetes: a Role or ClusterRole with wildcard API groups, resources, and verbs, or a service account that mounts its token automatically.

**Why it matters.** Wildcard permissions collapse every other control: the blast radius of one leaked credential becomes the whole account. They also make the audit question 'what could this identity do?' unanswerable.

**Flagged**

```hcl
statement {
  actions   = ["*"]
  resources = ["*"]
}
```

**Fixed**

```hcl
statement {
  actions   = ["s3:GetObject", "s3:PutObject"]
  resources = ["${aws_s3_bucket.uploads.arn}/*"]
}
```

**Reasonable to suppress.** The role is a break-glass administrator identity that is audited and short-lived, or a bootstrap role used once by a pipeline that nothing else can assume.

---

## RunningAsRoot

A container that runs as UID 0  
`running-as-root` | category: Infrastructure

**Detects.** Kubernetes: a container with `runAsUser: 0`, or without `runAsNonRoot: true`. Dockerfiles: no `USER` directive anywhere in the file, a final `USER` of `root` or `0`, or a `RUN` line invoking `sudo`.

**Why it matters.** Root in the container is one kernel or runtime bug away from root on the node. It also means any write the process is tricked into performing can overwrite anything in the image, including the binary it will run next.

**Flagged**

```dockerfile
FROM node:20.11-alpine
COPY . /app
CMD ["node", "/app/server.js"]
```

**Fixed**

```dockerfile
FROM node:20.11-alpine
COPY --chown=node:node . /app
USER node
CMD ["node", "/app/server.js"]
```

**Reasonable to suppress.** The container genuinely needs privileged host access - a CNI plugin, a node agent, a log shipper reading host paths - and is deployed with a matching restricted scope.

---

## PrivilegedContainer

A container with the host namespaces or full kernel capabilities  
`privileged-container` | category: Infrastructure

**Detects.** Kubernetes: `securityContext.privileged: true`, `hostPID: true`, `hostIPC: true`, `allowPrivilegeEscalation` set to true or left unset, or capabilities that do not drop `ALL`.

**Why it matters.** A privileged container is not isolated in any meaningful sense: it can see other processes, access every device, and load kernel modules. A compromise inside it is a compromise of the node and everything scheduled on it.

**Flagged**

```yaml
securityContext:
  privileged: true
```

**Fixed**

```yaml
securityContext:
  privileged: false
  allowPrivilegeEscalation: false
  capabilities:
    drop: ["ALL"]
```

**Reasonable to suppress.** The workload is a node-level agent whose function requires it (storage drivers, eBPF tooling), and it is confined to nodes that run nothing else sensitive.

---

## MissingResourceLimits

A container with no CPU/memory bounds or a writable root filesystem  
`missing-resource-limits` | category: Infrastructure

**Detects.** Kubernetes: a container with no `resources.limits`, no `resources.requests`, or without `readOnlyRootFilesystem: true`.

**Why it matters.** Without limits, one leaking pod consumes the node and evicts its neighbours - a single-service bug becomes a cluster-wide outage. Without requests, the scheduler cannot place the pod sensibly in the first place.

**Flagged**

```yaml
containers:
  - name: api
    image: acme/api:1.4.2
```

**Fixed**

```yaml
containers:
  - name: api
    image: acme/api:1.4.2
    resources:
      requests: { cpu: 100m, memory: 128Mi }
      limits:   { cpu: "1",  memory: 512Mi }
```

**Reasonable to suppress.** The pod is a batch job on a dedicated node pool sized for it, or limits are injected by a LimitRange the manifest does not show.

---

## MissingHealthProbes

A workload the orchestrator cannot tell is healthy  
`missing-health-probes` | category: Infrastructure

**Detects.** Kubernetes: a container with no `livenessProbe` or no `readinessProbe`. Dockerfiles: no `HEALTHCHECK` directive. Terraform: an autoscaling group with no health check configuration.

**Why it matters.** Without a readiness probe traffic is routed to a process that has not finished starting, so every deploy drops requests. Without a liveness probe a wedged process stays in the rotation indefinitely, failing silently.

**Flagged**

```yaml
containers:
  - name: api
    image: acme/api:1.4.2
```

**Fixed**

```yaml
containers:
  - name: api
    image: acme/api:1.4.2
    readinessProbe: { httpGet: { path: /ready, port: 8080 } }
    livenessProbe:  { httpGet: { path: /live,  port: 8080 } }
```

**Reasonable to suppress.** The workload is a one-shot Job or CronJob, where liveness and readiness have no meaning.

---

## UnpinnedImage

A dependency pulled by a moving reference instead of a fixed one  
`unpinned-image` | category: Infrastructure

**Detects.** Kubernetes and Dockerfiles: an image tagged `:latest`, an image with no tag, a tagged image with no `@sha256:` digest, a pre-release version tag, or `apt-get install` without version pins. Terraform: a `terraform` block with no `required_version` or no provider version constraints. Build stages and `scratch` are excluded.

**Why it matters.** An unpinned reference means the artifact you tested and the artifact you deploy are different artifacts, and a rollback does not roll back. It is also the supply-chain attack path: whoever can push that tag ships code to your cluster.

**Flagged**

```dockerfile
FROM node:latest
```

**Fixed**

```dockerfile
FROM node:20.11-alpine@sha256:2b3d9b2b4b6e5f0a1c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b
```

**Reasonable to suppress.** The image is built and consumed inside one pipeline run, where the tag cannot move between build and deploy.

---

## NoNetworkPolicy

Network isolation declared but not actually enforced  
`no-network-policy` | category: Infrastructure

**Detects.** Kubernetes: a NetworkPolicy with an empty pod selector and no `policyTypes`, which selects everything and enforces nothing. Terraform: a Lambda function with no VPC configuration, or a VPC with no flow logs.

**Why it matters.** A no-op policy is worse than no policy: it appears in the audit, satisfies the checklist, and permits every east-west connection in the namespace. Lateral movement after one compromised pod is then unimpeded and unlogged.

**Flagged**

```yaml
spec:
  podSelector: {}
```

**Fixed**

```yaml
spec:
  podSelector:
    matchLabels: { app: api }
  policyTypes: ["Ingress", "Egress"]
  ingress:
    - from: [{ podSelector: { matchLabels: { app: gateway } } }]
```

**Reasonable to suppress.** The empty selector is a deliberate default-deny baseline that does declare `policyTypes` - in which case this does not fire - or isolation is enforced by a service mesh instead.

---

## SecretInEnvVar

A secret written in plaintext into a manifest  
`secret-in-env-var` | category: Infrastructure

**Detects.** Kubernetes: an environment variable whose name mentions password, secret, API key, token, credential, or private key and that carries an inline `value` rather than a `valueFrom` reference; also non-empty `stringData` or `data` on a Secret object.

**Why it matters.** Manifests are committed, templated, copied between environments, and rendered into CI logs. Base64 in a Secret is encoding, not encryption - anyone with read access to the object, or to the repository, has the credential.

**Flagged**

```yaml
env:
  - name: DATABASE_PASSWORD
    value: "hunter2-prod-primary"
```

**Fixed**

```yaml
env:
  - name: DATABASE_PASSWORD
    valueFrom:
      secretKeyRef: { name: db-credentials, key: password }
```

**Reasonable to suppress.** The value is a placeholder for a local development overlay that never reaches a shared cluster.

---

## HardcodedCredential

A credential or unreplaced placeholder committed in a manifest  
`hardcoded-credential` | category: Infrastructure

**Detects.** Dockerfiles: an `ENV` or `ARG` whose name mentions a credential and that has a value, a `COPY` of `.env`, `credentials`, `.pem`, `.key`, `id_rsa`, or a PKCS#12 file, or a build-arg secret in a comment. Terraform: an AWS access key or secret key literal, a credential-named variable with a default, or any credential-named assignment of eight or more characters. Kubernetes: an unreplaced placeholder such as `CHANGEME` or `REPLACE_WITH_...`.

**Why it matters.** A credential in a manifest is a credential in the image layer and in git history: `docker history` and `git log` both retrieve it long after the line is deleted. An unreplaced placeholder is worse than a leak - it means the real secret was never installed and something is running with a known value.

**Flagged**

```dockerfile
ENV AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIsampleKEYbPxRfiCYEXAMPLEKEY
```

**Fixed**

```dockerfile
# injected at runtime from the orchestrator's secret store
ENV AWS_SECRET_ACCESS_KEY=""
```

**Reasonable to suppress.** The value belongs to a throwaway local fixture (a docker-compose test database) and provably grants nothing beyond that sandbox.

---

## PciViolation

A pattern that breaks a PCI-DSS requirement  
`pci-violation` | category: Compliance

**Detects.** Handling of cardholder data in a way PCI-DSS forbids - storing a primary account number unencrypted, logging a CVV, transmitting card data over an unencrypted channel. Reserved: no analysis pass currently emits this kind.

**Why it matters.** PCI findings are not advisory. They gate the ability to take card payments at all, and a breach involving stored card data carries per-record fines on top of the incident itself.

**Flagged**

```php
Log::info('charge attempt', ['pan' => $card->number, 'cvv' => $card->cvv]);
```

**Fixed**

```php
Log::info('charge attempt', ['last4' => $card->last4, 'brand' => $card->brand]);
```

**Reasonable to suppress.** The system is provably out of PCI scope - it never touches cardholder data, only a tokenized reference from the payment provider.

---

## GdprViolation

A pattern that breaks a GDPR obligation  
`gdpr-violation` | category: Compliance

**Detects.** Processing of personal data without the controls GDPR requires - no deletion path for a subject's records, personal data in logs, transfers with no documented basis. Reserved: no analysis pass currently emits this kind.

**Why it matters.** Data-subject rights are implemented in code or not at all. An erasure request that cannot be honoured because the data was copied into a log or a warehouse is a reportable failure, with a fine ceiling measured against global turnover.

**Flagged**

```python
logger.info("signup", extra={"email": user.email, "ip": request.remote_addr})
```

**Fixed**

```python
logger.info("signup", extra={"user_id": user.id})
```

**Reasonable to suppress.** The data is anonymised rather than pseudonymised - it cannot be re-linked to a person even with the other data you hold.

---

## Soc2Violation

Missing audit, retention, or change-control evidence  
`soc2-violation` | category: Compliance

**Detects.** Kubernetes: a Namespace with no pod-security enforce label, a `privileged` enforce level, an audit level stricter than the enforce level, or a Kyverno policy left in `Audit` rather than `Enforce`. Terraform: no remote state backend, a backend with no state locking, an S3 bucket with no access logging, or an EC2 instance that does not require IMDSv2.

**Why it matters.** These are the controls an auditor samples: who changed what, and can it be proven. A policy in audit-only mode passes the review and blocks nothing; state without locking lets two applies corrupt an environment with no record of which one won.

**Flagged**

```yaml
spec:
  validationFailureAction: Audit
```

**Fixed**

```yaml
spec:
  validationFailureAction: Enforce
```

**Reasonable to suppress.** The control is enforced by a platform layer outside this repository, and that ownership is documented where the auditor will look.

---

## DangerousChain

A call path from an entry point to a dangerous sink  
`dangerous-chain` | category: Chains

**Detects.** A breadth-first walk of up to six hops from a route controller or entry point to a deletion, execution, SQL, filesystem, or SSRF sink, and every unsanitized taint path the mapper recorded. Severity rises when no authorization or validation gate was seen on the path and when the path crosses a privilege boundary; a gated path is reported at low severity as a thing to confirm rather than a defect. Tests, migrations, and file pseudo-symbols are not entry points, and chains never fail the deploy gate on their own.

**Why it matters.** Individually safe-looking functions compose into a reachable path. This is the view an attacker takes and the one code review does not: nobody reads six frames of call stack across four files while reviewing a two-line diff.

**Flagged**

```text
POST /export -> ExportController::store -> Exporter::run -> shell_exec()
(no auth or validation gate on the path)
```

**Fixed**

```text
POST /export -> [authorize('export')] -> ExportController::store
             -> Exporter::run(allowlisted_format) -> Process::fromShellCommandline()
```

**Reasonable to suppress.** The gate exists in a form Verum cannot recognise (middleware registered elsewhere, an authorization attribute), or the sink is not reachable with attacker-controlled arguments. Confirm the gate covers the path before dismissing it.

---

## UnsafeUsage

An `unsafe` block or function  
`unsafe-usage` | category: Rust insights

**Detects.** The `unsafe` keyword on a Rust code line, excluding `unsafe impl` and `unsafe trait` declarations, in non-test files. Informational: it is a map of where the compiler's guarantees stop, not an accusation.

**Why it matters.** Every `unsafe` block is a proof obligation that the compiler has handed to a human. Knowing where they are is what makes an audit of memory safety finite - and most of them exist for a performance reason worth re-checking.

**Flagged**

```rust
let value = unsafe { *ptr.add(index) };
```

**Fixed**

```rust
// SAFETY: `index < len` was checked above and `ptr` is valid for `len` reads.
let value = unsafe { *ptr.add(index) };
```

**Reasonable to suppress.** It is informational and carries no score penalty. Ignore it when the block is reviewed and documented - which is exactly what the fixed example shows.

---

## PanicRisk

A panicking call such as `.unwrap()`, `.expect()`, or `panic!`  
`panic-risk` | category: Rust insights

**Detects.** `.unwrap(`, `.expect(`, `panic!(`, `todo!(`, `unimplemented!(`, or `unreachable!(` in a non-test Rust file. Infallible idioms are filtered out (a `write!` into a `String`, a `Regex::new` on a literal), as are lock and borrow guard unwraps and `.expect(` outside a latency-sensitive function. Severity rises when the enclosing function name suggests a hot path (`recv`, `poll`, `handle`, `decode`, `dispatch`, ...); beyond five cold panics one aggregate finding stands in for the rest of the file.

**Why it matters.** A panic in a request handler or packet loop takes the process down and every connection with it. Degrading gracefully - dropping the message, not the link - is the difference between a bad packet and an outage.

**Flagged**

```rust
let header = Header::parse(&buf).unwrap();
```

**Fixed**

```rust
let Ok(header) = Header::parse(&buf) else {
    metrics::bad_header();
    return;                       // drop the datagram, keep the socket
};
```

**Reasonable to suppress.** The invariant is genuinely local and checked immediately above, or the code is startup configuration where failing fast is the correct behaviour.

---

## BlockingInAsync

A blocking call inside an async function  
`blocking-in-async` | category: Rust insights

**Detects.** A line inside an `async fn` containing `std::fs::`, `std::net::`, `thread::sleep`, `std::io::stdin`, `reqwest::blocking`, or a `.blocking_` method. Tokio's async mutexes are not blocking calls and are not flagged.

**Why it matters.** The executor thread cannot be preempted. One blocking read stalls every other task scheduled on that thread, so a single slow disk or DNS lookup shows up as tail latency across unrelated requests.

**Flagged**

```rust
async fn load(path: &Path) -> Vec<u8> {
    std::fs::read(path).unwrap_or_default()
}
```

**Fixed**

```rust
async fn load(path: &Path) -> Vec<u8> {
    tokio::fs::read(path).await.unwrap_or_default()
}
```

**Reasonable to suppress.** The call runs once at startup before the runtime is under load, or it is already inside `spawn_blocking` in a way the line does not show.

---

## UnboundedChannel

A queue with no backpressure  
`unbounded-channel` | category: Rust insights

**Detects.** `mpsc::channel()` with no capacity argument, `unbounded_channel(`, `unbounded::<`, or `crossbeam_channel::unbounded(`. Tokio's `mpsc::channel(N)` is bounded and is not flagged.

**Why it matters.** Without a bound, a producer that outruns its consumer converts memory into latency: the queue grows, messages age, and by the time the consumer reaches them they are stale. The failure mode is an OOM kill, and it arrives during the traffic spike.

**Flagged**

```rust
let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
```

**Fixed**

```rust
let (tx, rx) = tokio::sync::mpsc::channel(1024);
// and decide explicitly what a full queue means: block, or drop the oldest
```

**Reasonable to suppress.** The producer is provably bounded (a fixed number of startup messages, a one-shot completion signal) so the queue cannot grow.

---

## HotPathAllocation

An allocation or clone on a latency-sensitive path  
`hot-path-allocation` | category: Rust insights

**Detects.** `Vec::new`, `vec![`, `Box::new`, `.to_vec()`, `.to_string()`, `String::from`, `format!`, `.collect::<Vec`, `.clone()`, or `Vec::with_capacity` inside a Rust function whose name suggests a hot path (`recv`, `send`, `poll`, `encode`, `decode`, `handle`, `tick`, ...), in non-test files. Informational.

**Why it matters.** A per-message allocation is a per-message trip to the allocator, and the tail of that distribution is what users feel. In media and packet paths it is also the main source of jitter.

**Flagged**

```rust
fn handle_packet(&mut self, data: &[u8]) {
    let owned = data.to_vec();          // one allocation per packet
    self.queue.push(owned);
}
```

**Fixed**

```rust
fn handle_packet(&mut self, data: Bytes) {
    self.queue.push(data);              // sliced from the recv buffer, no copy
}
```

**Reasonable to suppress.** The function name only looks hot, the allocation is amortised (one `with_capacity` before a loop), or the measured profile says it does not matter.

---

## LockOnHotPath

A blocking lock taken on a latency-sensitive path  
`lock-on-hot-path` | category: Rust insights

**Detects.** A `.lock(`, `.read(`, or `.write(` call on a line that also mentions `Mutex`, `RwLock`, or a guard, inside a Rust function whose name suggests a hot path. Informational, and the lowest-confidence signal in the pass.

**Why it matters.** A lock on the hot path serialises it. Throughput stops scaling with cores at the point of contention, and the latency distribution grows a long tail that only appears under the load you cannot reproduce locally.

**Flagged**

```rust
fn on_frame(&self, frame: &Frame) {
    let mut stats = self.stats.lock().unwrap();
    stats.frames += 1;
}
```

**Fixed**

```rust
fn on_frame(&self, frame: &Frame) {
    self.frames.fetch_add(1, Ordering::Relaxed);
}
```

**Reasonable to suppress.** The critical section is a few instructions and uncontended in practice, or the profile shows the lock is not the bottleneck.

---

## LockAcrossAwait

A synchronous lock guard held across an `.await`  
`lock-across-await` | category: Rust insights

**Detects.** A guard from `.lock()` (std or parking_lot) or `RefCell::borrow[_mut]()` that is still live at an `.await` point in the same async function, tracked by brace depth and cleared by an explicit `drop`. Tokio's async guards, which are designed to be held across awaits, are excluded.

**Why it matters.** The task can suspend at the await and resume on another thread while still holding a guard that was never meant to cross threads. That is a deadlock waiting for the right interleaving, and it makes the future `!Send`, which usually surfaces as a compile error somewhere far from the cause.

**Flagged**

```rust
let mut state = self.state.lock().unwrap();
let value = fetch(state.key).await;      // guard still held
state.value = value;
```

**Fixed**

```rust
let key = { self.state.lock().unwrap().key };   // guard dropped here
let value = fetch(key).await;
self.state.lock().unwrap().value = value;
```

**Reasonable to suppress.** Essentially never for a synchronous guard. If the lock must span the await, use an async-aware mutex, which is not flagged.

---

## SplitDatagramMessage

One logical message written as several datagrams  
`split-datagram-message` | category: Transport

**Detects.** In a file that uses a datagram socket (`UdpSocket`, `SOCK_DGRAM`, `node:dgram`, `ListenUDP`, ...), a function containing two or more write calls of which at least one writes a header or a `to_be_bytes`/`to_le_bytes` length prefix.

**Why it matters.** A datagram transport has no byte-stream continuity. Writing a length prefix and its payload separately means losing either one shears the message, and every subsequent read is misaligned - a permanent desynchronisation from a single lost packet.

**Flagged**

```rust
socket.send(&(payload.len() as u32).to_be_bytes()).await?;
socket.send(payload).await?;
```

**Fixed**

```rust
let mut frame = Vec::with_capacity(4 + payload.len());
frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
frame.extend_from_slice(payload);
socket.send(&frame).await?;          // exactly one datagram
```

**Reasonable to suppress.** The socket is connected to a stream transport despite the surrounding file's UDP code, or the protocol defines each write as an independent message with its own framing.

---

## OversizedDatagram

A datagram larger than the safe MTU payload  
`oversized-datagram` | category: Transport

**Detects.** A `.chunks(N)` call in a datagram file whose size - a literal or a file-local `const` - exceeds 1472 bytes, the payload that fits a 1500-byte Ethernet MTU after the IPv4 and UDP headers.

**Why it matters.** An oversized datagram travels as several IP fragments, and losing any one fragment loses the entire datagram. At 5% packet loss, a multi-fragment datagram is damaged roughly half the time: the effective loss rate multiplies.

**Flagged**

```rust
for chunk in payload.chunks(8192) {
    socket.send(chunk).await?;
}
```

**Fixed**

```rust
const MAX_PAYLOAD: usize = 1200;     // safe below every common MTU
for chunk in payload.chunks(MAX_PAYLOAD) {
    socket.send(chunk).await?;
}
```

**Reasonable to suppress.** The path MTU is known and larger (a controlled datacentre fabric with jumbo frames end to end), and that assumption is documented next to the constant.

---

## UnvalidatedLengthPrefix

A length read from the wire used unchecked as an allocation or read size  
`unvalidated-length-prefix` | category: Transport

**Detects.** A variable parsed from wire bytes (`from_be_bytes`, `from_le_bytes`, `read_u32`, `getUint32`, `readUInt32`, ...) and then used at a sizing sink (`with_capacity`, `read_exact`, `vec![0`, `.take(`, `Buffer.alloc`, `new Uint8Array`, `split_to`), with no bound check on any line that mentions it. Narrow reads capped at 65535 by their own type are not flagged, and `.min`, `clamp`, `assert`, `ensure`, `bail!`, and comparison guards all count as bound checks.

**Why it matters.** The peer controls this number. A corrupted or hostile 4-byte field asks for a four-gigabyte allocation or a read that never completes - a one-packet denial of service that needs no authentication.

**Flagged**

```rust
let len = u32::from_be_bytes(header[0..4].try_into()?) as usize;
let mut body = vec![0u8; len];
stream.read_exact(&mut body).await?;
```

**Fixed**

```rust
const MAX_BODY: usize = 1 << 20;
let len = u32::from_be_bytes(header[0..4].try_into()?) as usize;
if len > MAX_BODY { return Err(Error::FrameTooLarge(len)); }
let mut body = vec![0u8; len];
stream.read_exact(&mut body).await?;
```

**Reasonable to suppress.** The value is bounded by its own type against a protocol maximum, or a codec layer below this one already caps the frame size.

---

## PathTraversal

User-controlled input reaches a filesystem path  
`path-traversal` | category: Security

**Detects.** A taint path from a request source to a filesystem sink (`fs::read`, `fs::write`, `File::open`, `file_get_contents`, `unlink`, `fs.readFile`, ...) with no sanitizer in between. Environment variables and process arguments are deliberately not treated as taint sources, which keeps CLI tools quiet.

**Why it matters.** `../../../etc/passwd` in a filename parameter reads any file the process can read; on a write sink it overwrites any file the process can write, which includes the application's own code. Both are full compromises of the service.

**Flagged**

```js
const data = fs.readFileSync(path.join(UPLOAD_DIR, req.query.name));
```

**Fixed**

```js
const target = path.resolve(UPLOAD_DIR, req.query.name);
if (!target.startsWith(path.resolve(UPLOAD_DIR) + path.sep)) return res.sendStatus(400);
const data = fs.readFileSync(target);
```

**Reasonable to suppress.** The component is validated against an allowlist or a strict pattern (a UUID, an integer id) before it reaches the join.

---

## VulnerableDependency

A locked dependency version matching a known advisory  
`vulnerable-dependency` | category: Dependencies

**Detects.** A package in `Cargo.lock`, or pinned exactly in `requirements.txt`, `poetry.lock` or `uv.lock`, whose name and version fall within an entry of the offline advisory table Verum ships. The match is purely local - no network request is made - so the table is a seed set, not a substitute for a full advisory database. Unpinned Python ranges are never guessed at.

**Why it matters.** A known vulnerability with a published advisory is a vulnerability with a published exploit path and an automated scanner looking for it. These are compromised by opportunists, not by targeted attackers.

**Flagged**

```text
[[package]]
name = "time"
version = "0.2.10"
```

**Fixed**

```text
[[package]]
name = "time"
version = "0.3.36"
```

**Reasonable to suppress.** The vulnerable code path is provably not reachable from your build (a feature you do not enable), and the exemption is recorded where the next upgrade will see it.

---

## UnmaintainedDependency

A locked dependency flagged as abandoned  
`unmaintained-dependency` | category: Dependencies

**Detects.** A package in `Cargo.lock` that the shipped advisory table marks unmaintained, at any version.

**Why it matters.** An unmaintained crate has no one to fix the next vulnerability in it. The cost of migrating is fixed and known today; the cost of migrating during an incident is neither.

**Flagged**

```text
[[package]]
name = "net2"
version = "0.2.39"
```

**Fixed**

```text
[[package]]
name = "socket2"
version = "0.5.7"
```

**Reasonable to suppress.** The dependency is small, vendored, or pinned deliberately, and someone owns it locally.

---

## DuplicateDependency

One crate present at several incompatible versions  
`duplicate-dependency` | category: Dependencies

**Detects.** A crate name in `Cargo.lock` resolving to more than one compatibility version - different majors, or different minors below 1.0, which Cargo treats as incompatible.

**Why it matters.** Both copies are compiled and both are linked, so build time and binary size pay twice. Worse, their types are distinct to the compiler: a value from one cannot be passed to the other, which produces error messages that name the same type twice and explain nothing.

**Flagged**

```text
rand 0.7.3
rand 0.8.5
```

**Fixed**

```text
rand 0.8.5
```

**Reasonable to suppress.** The duplication comes from a transitive dependency you do not control and the size cost is acceptable until it updates.

---

## MissingSafetyComment

An `unsafe` block with no `// SAFETY:` justification  
`missing-safety-comment` | category: Rust insights

**Detects.** An `unsafe` usage with no case-insensitive `SAFETY:` comment on its line or the three lines above it.

**Why it matters.** The invariant that makes an unsafe block sound lives only in the author's head until it is written down. The next person to change the surrounding code cannot preserve a guarantee nobody stated, and that is how a sound block becomes unsound without anyone touching it.

**Flagged**

```rust
let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
```

**Fixed**

```rust
// SAFETY: `ptr` comes from `Vec::as_ptr` above and is valid for `len` elements,
// and the vector outlives `slice`.
let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
```

**Reasonable to suppress.** The comment exists but is worded in a way the check does not recognise - in which case rewording it to start `// SAFETY:` is cheaper than the suppression.

---

## CrateApiMisuse

A call that contradicts a known crate's documented behaviour  
`crate-api-misuse` | category: Dependencies

**Detects.** A small table of behaviours that surprise people, checked only when the crate is an actual dependency of the tree: tokio's `interval` first tick firing immediately, its default `Burst` missed-tick behaviour, udp-stream's buffer constant not being an MTU, and `mem::forget` leaking a RAII guard. A guard string anywhere in the file suppresses its rule for that file.

**Why it matters.** These are not bugs in the crate, they are documented behaviours that read as something else. The tokio interval one silently doubles the first iteration's rate; the missed-tick default turns a stalled loop into a burst of catch-up ticks exactly when the system is already behind.

**Flagged**

```rust
let mut ticker = tokio::time::interval(Duration::from_secs(60));
loop {
    ticker.tick().await;      // fires immediately the first time
    run_job().await;
}
```

**Fixed**

```rust
let mut ticker = tokio::time::interval_at(
    Instant::now() + Duration::from_secs(60), Duration::from_secs(60));
ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
```

**Reasonable to suppress.** The behaviour is the one you want - an immediate first tick is often correct - and the code says so.

---

## NonConstantTimeComparison

A security-sensitive value compared with `==`  
`non-constant-time-comparison` | category: Cryptography

**Detects.** An `==`/`!=` (Rust, Python) or `==`/`===`/`!=`/`!==` (JavaScript/TypeScript) where one operand names a MAC, CMAC, signature, secret, digest, or verifier, or a compound such as `auth_tag`, `expected_mac`, `csrf_token`, `bearer_token`, or a password-derived hash. Lines mentioning a constant-time comparison (`ct_eq`, `ConstantTimeEq`, `subtle::`, `constant_time_eq`, `hmac.compare_digest`, `crypto.timingSafeEqual`, `hash_equals`) are excluded, as are comparisons against string literals, booleans, numbers, `None`/`null`/`undefined`, enum variants, and length/size/count metadata fields.

**Why it matters.** A byte-wise comparison returns as soon as it finds a mismatch, so how long it took reveals how many leading bytes were right. An attacker who can time the endpoint recovers the tag one byte at a time - a few hundred requests per byte - and forges a valid MAC without ever knowing the key.

**Flagged**

```rust
if computed_mac == provided_mac {
    accept(request);
}
```

**Fixed**

```rust
use subtle::ConstantTimeEq;
if computed_mac.ct_eq(&provided_mac).into() {
    accept(request);
}
```

**Reasonable to suppress.** The comparison is not on an attacker-observable path (an offline test, a log line) or neither operand is secret despite its name - a public key identifier, a non-secret content digest.

---

## StaticAeadNonce

A constant nonce or IV reaching an AEAD encrypt call  
`static-aead-nonce` | category: Cryptography

**Detects.** A 12-, 16-, or 24-byte literal array reaching `.encrypt(`, `.seal(`, or `Nonce::from_slice(`, either directly or through a `let`/`const`/`static` binding traced back to a literal. Any randomness marker on the line or on the binding's path (`OsRng`, `fill_bytes`, `getrandom`, `rand::`, ...) suppresses it.

**Why it matters.** Reusing a nonce under one key breaks the cipher outright. For counter-mode AEADs the keystream repeats, so XOR-ing two ciphertexts recovers the plaintexts, and for GCM and Poly1305 nonce reuse leaks the authentication key itself - after which an attacker forges valid ciphertexts at will.

**Flagged**

```rust
let nonce = Nonce::from_slice(&[0u8; 12]);
let ct = cipher.encrypt(nonce, plaintext)?;
```

**Fixed**

```rust
let mut bytes = [0u8; 12];
OsRng.fill_bytes(&mut bytes);           // or a strictly increasing counter
let ct = cipher.encrypt(Nonce::from_slice(&bytes), plaintext)?;
```

**Reasonable to suppress.** The key is single-use, so the nonce cannot repeat under it - a fresh key derived per message. Say so in a comment: this is the assumption that quietly stops holding.

---

## ParseFailure

A file whose parse or analysis panicked and was isolated  
`parse-failure` | category: Diagnostics

**Detects.** A file on which per-file work panicked. The panic is caught, the file is skipped, and the rest of the run completes. The message is a fixed phrase plus the path and never the panic payload - payloads embed source locations that change between compiler versions, and identical inputs must produce identical findings.

**Why it matters.** It is not a defect in your code: it means Verum did not analyse that file, so anything in it is unreported. Treat it as a gap in coverage of the run, and as a parser bug worth reporting.

**Flagged**

```text
parser panicked on this file: src/generated/huge_table.rs
```

**Fixed**

```text
# no output - the file parsed, and its findings are in the report
```

**Reasonable to suppress.** It is diagnostic only: no score penalty, and it never gates a deploy. Inspect the file by hand and report the panic.

---

## StaleSuppression

A verum:ignore comment that suppresses nothing  
`stale-suppression` | category: Diagnostics

**Detects.** A `verum:ignore` (or `verum:ignore[Kind,...]`) comment with no matching finding on its own line or the line directly below - either nothing is flagged there any more, or the bracket filter names kinds that do not occur there. Detected only in files that currently have findings.

**Why it matters.** A suppression that matches nothing is either a note about an issue that was fixed (delete it) or a trap: it sits in the code ready to silently swallow the next real finding introduced at that spot. Low severity, unscored, and never gating - but visible, so suppressions cannot rot.

**Flagged**

```python
# verum:ignore[SqlInjection] the query below was parameterized long ago
rows = db.execute(PREPARED_QUERY, (user_id,))
```

**Fixed**

```python
rows = db.execute(PREPARED_QUERY, (user_id,))
```

**Reasonable to suppress.** It cannot itself be suppressed or baselined - that would defeat its purpose. Delete the stale comment, or fix its kind list so it matches what is actually flagged.
