# Githunter #

## Introduction ##
Githunter is a tool designed to research .git folder disclosure vulnerabilities.
It identifies, downloads and reconstructs leaked Git repositories by systematically enumerating object directories. Downloading Git objects and pack files. Also reconstructs the repository locally.

## Features ##

- Enumerates Git Object Directories: Automatically identifies Git object directories exposed by misconfigurations.
- Download Git Objects and Pack Files: Downloads individual Git objects and pack files. Handles large repositories with ease.
- SHA-1 Verification: Ensures the integrity od downloaded objects by verifying ther hashes.
- Pack File Verification: Optionally verifies the integrity of pack files using Git's native verify-pack command.
- Resume Capability: Supports resuming interrupted downloads.
- Auto-Repair Git Structure: Automaticaly creates Git files (Head, config, refs/heads/master) if missing.
- Concurrency Control: Allows specification of numbers od concurrent download workers to balance speed and server load.

## Prerequisites ##

Ensure that your system meets the following requirements:
- **Go:** Version 1.16 or higher.
- **Git**

## Installation ##

**Step 1**

**go mod init githunter**

This will setup the module path and creates a go.mod file.

**Step 2**

**go get golang.org/x/net/html**

This downloads the necessary package and updates your go.mod and go.sum files.

**Step3**

**go build githunter.go -o githunter**

This will produce executable named githunter or githunter.exe on windows in current directory.

## Usage ##

Githunter is a commandline tool that needs a target URL pointing to an exposed .git directory.

**Basic Usage**

./githunter [options] <target_url>

- <target_url>: The URL of the target website hosting the .git directory (e.g hxxps://example.com/.git)

**Examples**
1. Basic Enumeration and Download
./bithunter hxxps://example.com/.git

2. Enable Verbose Output and Specify Worker Count
./githunter -v -workers 5 hxxps://example.com/.git

3. Use a Wordlist for Reference Brute Forsing with Throttling
./githunter -worlist wordlist.txt -throttle 100 hxxps://example.com/.git

4. Resume Interrupted Downloads and Verify Pack Files
./githunter -resume -verifyPack -v hxxps://example.com/.git

## Commandline Flags

In Githunter there is various flags to customize its behavior. Below is a list of available options:

| **Flag**           | **Description**                                                                                                                                                     | **Default**          |
|--------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------------------|
| `-workers <n>`     | Number of concurrent download workers for objects and pack files. Balances speed with server load and detection risks.                                               | `10`                 |
| `-o <dir>`         | Output directory for the reconstructed repository.                                                                                                                   | `reconstructed_repo` |
| `-v`               | Enable verbose (debug) output. Provides detailed logs for monitoring and troubleshooting.                                                                           | `false`              |
| `-wordlist <file>` | Path to a file containing potential reference (branch) names. If provided, the tool performs a global-throttled brute force on `.git/refs/heads/<branch>`.           | `""` (disabled)      |
| `-throttle <ms>`   | Global throttle in milliseconds between reference brute force requests. Helps avoid rate limiting or detection. e.g., `0` = no delay, `100` = one request per 100ms. | `0`                  |
| `-resume`          | Skip re-downloading objects and packs if local files are already valid. Useful for resuming interrupted sessions.                                                     | `false`              |
| `-verifyPack`      | Run `git verify-pack` on downloaded pack files for deeper integrity checks. Ensures that `.pack` files are not corrupted or tampered with.                              | `false`              |


## How It Works

Githunter operates in systematic phases to enumerate, download, verify and reconstruct Git repositories.

**1. Enumerate Object Directories**
- Process: Scans the /objects directory to identify all Git object directories (e.g objects/ab/, objects/cd).

**2. Enumerate Pack Files**
- Process: Scans the /object/pack/ directory to identify all pack files (.pack and .idx).

**3. Brute Force (Optional)**
- Process: Uses a provided wordlist to brute force branch names in .git/refs/heads/.

**4. Download Git Objects and Pack Files**
- Process: Concurrently downloads identified Git objects and pack files
- Features:
    - Resume Capability: Skips downloading if local files are already validated.
    - SHA1 Verification: Conforms the integrity of each Git object by verifying it's hash.
    -Pack File Verification: Optionally verifies pack files using git verify-pack for enhanced integrity checks.

**5. Auto-Repair Git Structure**
- Process: Ensures that essential Git files (Head, config, refs/heads/master) are present. If missing it will create minimal versions to facilitate repository reconstruction.

**6. Reconstuct Repository**
- Process: Initialices a new repository, replaces its .git directory with the downloaded data and performs checks using gi fsck. Lastly it checks out all files to make the repository usable.


## Ethical and Legal Considerations
**Githunter** is a tool intended for ethical use in penetration testing, security research, and educational purposes. Unauthorized access or scanning of systems without explicit permission is illegal and unethical. By using this tool, you agree to adhere to the following guidelines:

1. **Authorization**: Ensure you have explicit permission to scan, test, or assess the target repository. Unauthorized access can lead to legal consequences.

2. **Responsibility**: You are solely responsible for any actions taken using this tool. Misuse can result in damage to systems, loss of data, or legal repercussions.

3. **No Warranty**: The tool is provided "as-is" without any warranties. The developers are not liable for any misuse or damages resulting from its use.

4. **Respect Privacy**: Do not use the tool to access or disclose private or sensitive information without consent.

5. **Compliance**: Adhere to all applicable local, national, and international laws and regulations regarding cybersecurity and data protection.

**Disclaimer**: The creators of Githunter do not endorse or encourage any form of malicious activity. Use this tool responsibly and ethically.

## License

This project is licensed under the Apache-2.0 License
