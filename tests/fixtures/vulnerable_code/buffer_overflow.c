/*
 * tests/fixtures/vulnerable_code/buffer_overflow.c
 * --------------------------------------------------
 * Intentionally vulnerable C code for testing purposes.
 * DO NOT use any of these patterns in production.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* VULNERABLE: CWE-120 — gets() has no length limit */
void read_username(void) {
    char buffer[64];
    printf("Enter username: ");
    gets(buffer);           /* ❌ CWE-120: classic gets() overflow */
    printf("Hello, %s\n", buffer);
}

/* VULNERABLE: CWE-120 — strcpy without size check */
void copy_input(const char *input) {
    char dest[32];
    strcpy(dest, input);    /* ❌ CWE-120: no bounds check on dest */
    printf("Copied: %s\n", dest);
}

/* VULNERABLE: CWE-120 — sprintf can overflow the destination */
void format_message(const char *user_data) {
    char msg[128];
    sprintf(msg, "Hello %s, welcome to the system!", user_data);  /* ❌ CWE-120 */
    puts(msg);
}

/* VULNERABLE: CWE-120 — scanf %s with no field width */
void read_input(void) {
    char name[16];
    scanf("%s", name);      /* ❌ CWE-120: no length limit */
    printf("Name: %s\n", name);
}

/* VULNERABLE: CWE-190 — integer overflow in malloc argument */
void allocate_buffer(int count) {
    /* If count is large, count * sizeof(int) overflows before malloc */
    int *arr = malloc(count * sizeof(int));  /* ❌ CWE-190 */
    if (arr) {
        arr[0] = 42;
        free(arr);
    }
}

int main(void) {
    read_username();
    copy_input("very_long_string_that_may_exceed_the_destination_buffer_capacity");
    format_message("attacker_controlled_input");
    return 0;
}
