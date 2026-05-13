package pgdam.kill

import future.keywords.if
import future.keywords.in

default should_kill := false

# 1. Define Whitelists
trusted_users := {"postgres", "admin", "dba"}
trusted_sources := {"127.0.0.1", "::1"}
# Adding [local] to trusted_sources is too braod for production
# trusted_sources := {"[local]", "127.0.0.1", "::1"}

# 2. Define the "Kill" logic as a sub-rule (is_malicious)
is_malicious if {
    regex.match(`(?i)\bUNION\b.{0,100}\bSELECT\b`, input.sql)
}

is_malicious if {
    regex.match(`(?i)(--|\/\*).{0,50}\b(OR|AND)\b.{0,50}(=|LIKE)`, input.sql)
}

is_malicious if {
    regex.match(`(?i)\b(OR|AND)\b\s+[\w'"]+=[\w'"]+\s*--`, input.sql)
}

is_malicious if {
    regex.match(`(?i);\s*(DROP|DELETE|INSERT|UPDATE|CREATE|ALTER|TRUNCATE)\b`, input.sql)
}

is_malicious if {
    regex.match(`(?i)\b(OR|AND)\b\s+\d+\s*=\s*\d+`, input.sql)
}

is_malicious if {
    regex.match(`(?i)\bALTER\s+ROLE\b.{0,100}\bSUPERUSER\b`, input.sql)
}

is_malicious if {
    regex.match(`(?i)\bCREATE\s+ROLE\b.{0,100}\bSUPERUSER\b`, input.sql)
}

is_malicious if {
    regex.match(`(?i)\bDROP\s+(DATABASE|SCHEMA|TABLE)\b`, input.sql)
    not input.user in trusted_users
}

is_malicious if {
    regex.match(`(?i)\bpg_shadow\b`, input.sql)
    not input.user in trusted_users
}

# 3. Final Decision Logic
# This rule only returns true if it's malicious AND NOT from a trusted source.
should_kill if {
    is_malicious
    not input.src_ip in trusted_sources
}
