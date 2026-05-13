package pgdam.mask

import future.keywords.if

default mask_field := false

# Regex for common Credit Card numbers
cc_regex = `\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b`

# Rule to mask based on value pattern (PII detection)
mask_field if {
    regex.match(cc_regex, input.value)
}

# Rule to mask based on common sensitive column names
sensitive_columns := {"email", "ssn", "credit_card", "password", "secret"}
mask_field if {
    input.column_name != null
    sensitive_columns[input.column_name]
}
