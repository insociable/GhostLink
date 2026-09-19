# Dependency security policy

GhostLink uses automated dependency scanning as a blocking defense-in-depth control.
These checks reduce known-vulnerability exposure; they do not establish that a
dependency, build artifact, protocol, or release is secure.

## Blocking controls

Python dependencies are installed from `poetry.lock`. The development toolchain
pins `pip-audit==2.10.1`, and CI runs `poetry run pip-audit` against the installed
environment. A reported known vulnerability fails the quality job by default.

The ratchet engine continues to run `npm audit --audit-level=high`. High and
critical npm advisories are therefore blocking.

Pull requests run `actions/dependency-review-action@v5` with
`fail-on-severity: high`. A dependency change that introduces a known high or
critical advisory is blocking before merge.

Dependabot checks the Python, npm, Docker and GitHub Actions dependency surfaces
weekly. Dependabot availability does not replace the blocking CI controls above.

## Exception policy

There are no standing advisory ignores. A temporary exception requires a dedicated
reviewed pull request that records:

- the exact advisory identifier and affected package/version;
- why no fixed compatible version can currently be used;
- the GhostLink exposure and any compensating controls;
- the person/review responsible for accepting the temporary risk;
- a concrete expiry date or removal condition.

Any scanner ignore must be visible in repository configuration and linked to that
exception record. Broad package-level or permanent ignores are not acceptable.

## Update policy

Security fixes should prefer the smallest compatible dependency update that removes
the advisory. Cryptographic dependency changes remain subject to the stricter
review requirements in `SECURITY.md`.

After a security-related dependency update, run the Python audit, lint, type checks,
full Python test suite, ratchet-engine audit/tests, and relevant container checks
before merge.

## Limits

A clean automated scan means only that the configured advisory sources did not
report a blocking known vulnerability for the inspected dependency graph at scan
time. It does not detect or exclude:

- zero-day vulnerabilities or advisories not yet present in the scanner databases;
- malicious or compromised packages merely because they have no vulnerability ID;
- application or protocol flaws in GhostLink source code;
- unsafe use of an otherwise non-vulnerable dependency;
- every native/shared-library vulnerability reachable below a Python or npm package;
- supply-chain compromise of build infrastructure or publishing credentials.

Automated dependency scanning therefore complements, but never replaces, source
review, threat modeling, protocol review, reproducible-build work, signed-artifact
work, or independent security review.
