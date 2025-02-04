Overview

This program is a C-based tool for:
-Scanning directories recursively.
-Identifying and isolating dangerous files (e.g., files with no permissions).
-Managing directory snapshots to track changes.
-Comparing snapshots and updating them when differences are detected.
-It uses system calls (lstat, fork, exec, pipe) for efficient process management and file handling.

Usage

Compilation
gcc -o dir_scanner main.c

Execution

./dir_scanner [DIRECTORIES] -o [OUTPUT_DIRECTORY] -x [ISOLATION_DIRECTORY]

Arguments:
DIRECTORIES: List of directories to scan.
-o: Output directory for snapshots.
-x: Directory where dangerous files are isolated.

Features
-Snapshot Management: Tracks changes in directory structures.
-Dangerous File Isolation: Moves files with no permissions to a quarantine directory.
-Parallel Processing: Processes multiple directories concurrently.
-Multi-Inode Handling: Avoids redundant processing of the same directory.

Limitations
-Processes a maximum of 15 directories simultaneously.
-Skips symbolic links.
-Requires the path to the script.
