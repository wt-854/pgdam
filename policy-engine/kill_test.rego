package pgdam.kill_test

import data.pgdam.kill
import future.keywords.if

# ── Helpers ───────────────────────────────────────────────────────────────────

external_user := {
    "user":   "app_user",
    "db":      "mydb",
    "src_ip": "10.0.1.50",
    "pid":    1234,
}

trusted_local := {
    "user":   "app_user",
    "db":      "mydb",
    "src_ip": "127.0.0.1",
    "pid":    1234,
}

# ── SQLi detection ────────────────────────────────────────────────────────────

test_union_select_detected if {
    kill.should_kill with input as object.union(
        external_user,
        {"sql": "SELECT * FROM users UNION SELECT password, username FROM admin--"}
    )
}

test_boolean_injection_detected if {
    kill.should_kill with input as object.union(
        external_user,
        {"sql": "SELECT * FROM users WHERE id=1 OR 1=1"}
    )
}

test_stacked_query_detected if {
    kill.should_kill with input as object.union(
        external_user,
        {"sql": "SELECT * FROM users; DROP TABLE users--"}
    )
}

test_comment_injection_detected if {
    kill.should_kill with input as object.union(
        external_user,
        {"sql": "SELECT * FROM users WHERE id=1 -- OR 1=1 LIKE 1"}
    )
}

# ── Privilege escalation ──────────────────────────────────────────────────────

test_alter_role_superuser_detected if {
    kill.should_kill with input as object.union(
        external_user,
        {"sql": "ALTER ROLE app_user WITH SUPERUSER"}
    )
}

test_create_role_superuser_detected if {
    kill.should_kill with input as object.union(
        external_user,
        {"sql": "CREATE ROLE evil WITH SUPERUSER LOGIN"}
    )
}

# ── Dangerous operations ──────────────────────────────────────────────────────

test_drop_table_non_dba_detected if {
    kill.should_kill with input as object.union(
        external_user,
        {"sql": "DROP TABLE users"}
    )
}

test_drop_table_dba_not_killed if {
    not kill.should_kill with input as {
        "sql":    "DROP TABLE staging_temp",
        "user":   "postgres",
        "db":     "mydb",
        "src_ip": "10.0.1.50",
        "pid":    1234,
    }
}

test_pg_shadow_non_dba_detected if {
    kill.should_kill with input as object.union(
        external_user,
        {"sql": "SELECT * FROM pg_shadow"}
    )
}

test_pg_shadow_dba_not_killed if {
    not kill.should_kill with input as {
        "sql":    "SELECT * FROM pg_shadow",
        "user":   "postgres",
        "db":     "mydb",
        "src_ip": "10.0.1.50",
        "pid":    1234,
    }
}

# ── Trusted source whitelist ──────────────────────────────────────────────────

test_union_injection_trusted_source_not_killed if {
    not kill.should_kill with input as object.union(
        trusted_local,
        {"sql": "SELECT * FROM users UNION SELECT password FROM admin--"}
    )
}

test_localhost_v6_not_killed if {
    not kill.should_kill with input as {
        "sql":    "SELECT * FROM users UNION SELECT password FROM admin",
        "user":   "app_user",
        "db":     "mydb",
        "src_ip": "::1",
        "pid":    1234,
    }
}

# ── Safe queries not killed ───────────────────────────────────────────────────

test_normal_select_not_killed if {
    not kill.should_kill with input as object.union(
        external_user,
        {"sql": "SELECT id, name FROM users WHERE id = 42"}
    )
}

test_normal_insert_not_killed if {
    not kill.should_kill with input as object.union(
        external_user,
        {"sql": "INSERT INTO orders (user_id, amount) VALUES (1, 100)"}
    )
}

test_normal_update_not_killed if {
    not kill.should_kill with input as object.union(
        external_user,
        {"sql": "UPDATE users SET name = 'John' WHERE id = 5"}
    )
}

test_begin_not_killed if {
    not kill.should_kill with input as object.union(
        external_user,
        {"sql": "BEGIN"}
    )
}

test_commit_not_killed if {
    not kill.should_kill with input as object.union(
        external_user,
        {"sql": "COMMIT"}
    )
}
