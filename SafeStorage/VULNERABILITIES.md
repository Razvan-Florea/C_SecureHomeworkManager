# Vulnerabilities in SafeStorage(main.c)

### 1. Buffer overflow
**Line 54**

> **Vulnerability:** The command buffer is declared with a fixed size of 10 bytes. `scanf` with the `%s` format specifier does not verify user input length. If a user enters a string longer than 9 chars, it will overwrite adjacent stack memory, leading to a crash or potential code execution.

**Fix:** Use `scanf_s` or `fgets` to limit the input size.

---

### 2. Use of uninitialized memory
**Lines 56, 64, 72, 77, 85, 93**

> **Vulnerability:** The command buffer is not init with 0. `memcmp` compares a fixed number of bytes regardless of the actual length of the string in command. If the user gives a short input command, `memcmp` will continue reading past the null terminator of the users input into uninitialized stack garbage to complete the 9-byte comparison. This can lead to unpredictable behavior.

**Fix:** Use `strcmp` which correctly stops comparing at the null terminator.

---

### 3. Buffer overflow
**Lines 58, 59, 66, 67, 79, 80, 87, 88**

> **Vulnerability:** `arg1` and `arg2` are fixed-size buffers. Unbounded use of `scanf` allows an attacker to input a very long string, overflowing the stack.

**Fix:** Use `scanf_s` with a width limit.

---

### 4. Denial of service
**Lines 51/102**

> **Vulnerability:** If standard input closes (EOF) or errors, `scanf` returns failure immediately without blocking. The loop spins infinitely, consuming CPU resources (DoS).

**Fix:** Check return value of `scanf`.

---

### 5. Integer truncation
**Lines 62, 70, 83, 91**

> **Vulnerability:** Explicit cast truncates lengths > 65535 to smaller values (e.g. 65536 becomes 0). This can cause library functions to under-allocate memory while processing large data.

**Fix:** Validate length < `UINT16_MAX` before casting.

---

### 6. Stale data usage
**Lines 39-41**

> **Vulnerability:** `arg1` and `arg2` retain values from previous commands. If a `scanf` fails or is bypassed in a later iteration, the previous command's arguments are reused unintentionally.

**Fix:** Zero out buffers (`memset`) at the start of the do-while loop.
