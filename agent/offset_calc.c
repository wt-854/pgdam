#include <stdio.h>
#include <stddef.h>
#include "postgres.h"
#include "libpq/libpq-be.h"

int main() {
    printf("OFFSET_REMOTE_HOST=%zu\n", offsetof(Port, remote_host));
    printf("OFFSET_USER_NAME=%zu\n", offsetof(Port, user_name));
    return 0;
}
