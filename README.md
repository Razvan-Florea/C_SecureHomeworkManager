# SafeStorage - Secure Assignment Management System

## 📌 Project Overview
SafeStorage is a Windows-based console application designed as a secure platform for students to upload and retrieve assignments. The project focuses on a **defensive coding style**, emphasizing memory safety, access control, and protection against common exploit vectors like brute-force attacks and symlink races.

## 🛠 Core Features
* **Secure User Authentication**: Implements salted SHA-256 hashing for password storage to ensure credentials are never kept in plain text.
* **Multi-threaded File Transfer**: Utilizes a Windows Thread Pool with 4 threads to handle files up to 8GB, processing data in fixed 64KB chunks for optimal performance.
* **Granular Access Control**: Employs Windows Security Descriptors (ACLs) to ensure users can only access their own subdirectory and submissions.
* **Input Sanitization**: Strict validation for usernames, passwords, and file paths to prevent injection and directory traversal.

## 🛡 Security Architecture & Defensive Measures

### 1. Cryptographic Protection
Passwords are secured using the Windows CNG (Cryptography Next Generation) API. For every registration, a **16-byte cryptographically secure salt** is generated via `CryptGenRandom`. The password and salt are then hashed using **SHA-256** before being stored in the `users.txt` database.

### 2. Anti-Brute Force Mechanism
To mitigate automated login attempts, the application tracks failed logins within a rolling time window. If more than **5 attempts** occur within **1000ms**, the account is temporarily locked out.

### 3. Filesystem Security (Symlink/Junction Protection)
The application is designed to run with administrator privileges, making it a target for "Symlink Races." To prevent this, `Commands.c` includes:
* **Reparse Point Validation**: Before interacting with the database or user directories, the code verifies the `FILE_ATTRIBUTE_REPARSE_POINT` flag to ensure it hasn't been redirected to sensitive system files.
* **Path Sanitization**: All paths are resolved via `GetFullPathNameA` and checked against allowed environments (e.g., ensuring system drive access is restricted to the `%USERPROFILE%` directory).

### 4. Thread Safety and Synchronization
File operations (Store/Retrieve) are offloaded to a private thread pool. Atomic operations (`Interlocked` functions) are used to manage shared state across threads, preventing race conditions during concurrent chunk processing.

### 5. Memory & Resource Management
* **Secure Cleanup**: Sensitive data, such as the current logged-in username and file buffers, are wiped from RAM using `SecureZeroMemory` during logout or deinitialization.
* **Resource Management**: All Windows handles and heap allocations are rigorously tracked to ensure zero memory leaks, even in error-handling paths.

## ⚠️ Identified Vulnerability: Pre-initialization Attack
A specific edge case was identified regarding the initialization of the application's environment:
* **The Issue**: If the `users.txt` database or the `\users` directory is created by a low-privileged attacker *before* the application is run for the first time, the attacker could potentially pre-insert malicious data or set weak permissions on the database.
* **Current Mitigation**: The application attempts to apply **Secure ACLs** (System, Built-in Admins, and Creator Owner only) during creation. However, administrators should ensure the `%AppDir%` is protected to prevent unauthorized pre-creation of these resources.

## 📂 Project Structure
* **SafeStorageLib**: Static library containing the core security logic and command implementations.
* **SafeStorage**: Console application serving as the command-line parser.
* **SafeStorageUnitTests**: Unit-test project for verifying registration, login, and file integrity.

## 🚀 Requirements
* **OS**: Windows 10/11
* **Compiler**: Visual Studio 2022 (Warning Level 4, Treat Warnings as Errors).
* **Privileges**: Must be run as **Administrator** to manage secure directories and ACLs.
