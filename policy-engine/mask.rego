package pgdam.masking

import future.keywords.if
import future.keywords.in

# ── Masking policy ────────────────────────────────────────────────────────────

default mask_field := false

# Regex for common Credit Card numbers
# Supports Visa, Mastercard, Amex, Discover
cc_regex := `\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b`

# Rule to mask based on value pattern (PII detection)
mask_field if {
    re_match(cc_regex, input.value)
}

# Rule to mask based on common sensitive column names (Fallback/Layering)
sensitive_columns := {"email", "ssn", "credit_card", "password", "secret"}
mask_field if {
    input.column_name in sensitive_columns
}

# ── Kill policy ───────────────────────────────────────────────────────────────
# Evaluated per query event. Returns true when the session should be terminated.
# Input shape:
#   input.sql       — raw SQL string
#   input.user      — postgres username
#   input.db        — database name
#   input.src_ip    — client IP address
#   input.pid       — postgres backend PID

package pgdam.kill

import future.keywords.if
import future.keywords.in

default should_kill := false

# ── SQLi detection ────────────────────────────────────────────────────────────
# Detects classic SQL injection patterns via keyword fingerprinting.
# These match tokenized patterns rather than raw strings to reduce false positives.

sqli_patterns := [
    # UNION-based injection
    `(?i)\bUNION\b.{0,100}\bSELECT\b`,
    # Comment-based injection (-- or /**/)
    `(?i)(--|\/\*).{0,50}\b(OR|AND)\b.{0,50}(=|LIKE)`,
    # Tautology injection (1=1, 'a'='a')
    `(?i)\b(OR|AND)\b\s+[\w'"]+=[\w'"]+\s*--`,
    # Stacked queries
    `(?i);\s*(DROP|DELETE|INSERT|UPDATE|CREATE|ALTER|TRUNCATE)\b`,
    # Boolean-based blind injection
    `(?i)\b(OR|AND)\b\s+\d+\s*=\s*\d+`,
]

should_kill if {
    some pattern in sqli_patterns
    re_match(pattern, input.sql)
}

# ── Privilege escalation detection ───────────────────────────────────────────

should_kill if {
    re_match(`(?i)\bALTER\s+ROLE\b.{0,100}\bSUPERUSER\b`, input.sql)
}

should_kill if {
    re_match(`(?i)\bCREATE\s+ROLE\b.{0,100}\bSUPERUSER\b`, input.sql)
}

# ── Dangerous operations ──────────────────────────────────────────────────────
# Only trigger for non-superuser accounts to avoid false positives on DBAs.

should_kill if {
    re_match(`(?i)\bDROP\s+(DATABASE|SCHEMA|TABLE)\b`, input.sql)
    not input.user in {"postgres", "admin", "dba"}
}

# ── Access pattern anomalies ──────────────────────────────────────────────────
# Suspicious: reading pg_shadow (password hashes) as a non-superuser.

should_kill if {
    re_match(`(?i)\bpg_shadow\b`, input.sql)
    not input.user in {"postgres", "admin", "dba"}
}

# ── Trusted sources whitelist ─────────────────────────────────────────────────
# Never kill connections from localhost or known internal CIDRs.
# Add your application service IPs here.

trusted_sources := {"[local]", "127.0.0.1", "::1"}

# Override: never kill if source is trusted, regardless of other rules.
should_kill := false if {
    input.src_ip in trusted_sources
}
