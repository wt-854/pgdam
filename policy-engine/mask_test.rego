package pgdam.mask_test

import data.pgdam.mask as mask
import future.keywords.if

test_mask_by_column_name if {
    mask.mask_field with input as {"column_name": "email", "value": "test@example.com"}
}

test_mask_by_value_regex if {
    # Visa test
    mask.mask_field with input as {"column_name": "unknown", "value": "4111111111111111"}
}

test_no_mask_for_safe_data if {
    not mask.mask_field with input as {"column_name": "public_id", "value": "12345"}
}
