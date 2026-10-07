# Original User Request

## 2026-10-06T18:52:37Z

A resilient Windows background service that tracks cumulative daily gameplay across all games, warns the user at 5 and 1 minute thresholds, terminates active game processes upon reaching 2 cumulative hours (120 minutes), and locks out all game launches until midnight (00:00) with parental-control tamper resistance.

Working directory: c:/Users/Breeze/Documents/antigravity/blissful-mendel
Integrity mode: development

## Requirements

### R1. Cumulative Daily Time Tracking & Reset
- Monitor execution time across all detected game processes.
- Accumulate active gameplay time into a single shared daily counter.
- Hard limit is strictly 120 minutes (2 hours) per calendar day.
- Reset the counter automatically at 00:00 (midnight) local system time.

### R2. Hybrid Game Detection
- Automatically detect game executables located in standard library paths of major launchers: Steam, Epic Games Launcher, GOG Galaxy, and Xbox / Microsoft Store games.
- Provide a configuration file (`config.json` or `config.yaml`) allowing custom process names (e.g., standalone/emulated `.exe`) and paths to be blacklisted or whitelisted.

### R3. Notifications and Process Termination
- Display desktop toast notifications warning when 5 minutes and 1 minute remain before the 2-hour daily limit.
- Upon hitting 120 minutes of cumulative gameplay, immediately terminate all running game processes.
- While lockout is active (between reaching 120 minutes and midnight reset), continually detect and immediately terminate any game executables that attempt to launch.

### R4. Windows Service Architecture & Anti-Tamper Protection
- Implement the core daemon as a Windows Service running under `NT AUTHORITY\SYSTEM` with automatic startup on boot.
- Protect against clock-tampering bypasses (e.g., rolling back the system clock) by cross-referencing system uptime/tick counters (`GetTickCount64` / monotonic clock) and storing monotonic timestamps.
- Provide a CLI or management utility requiring password authentication (cryptographically hashed) to view status, alter configuration, or manually override the lock.
- Persist counter state and lockout status reliably to disk so that restarts/reboots do not wipe accrued game time.

### R5. Automated Mock Test Suite
- Provide an automated test suite verifying process detection, cumulative timing, toast notification triggering, process killing, midnight reset, and resistance to clock manipulation without requiring actual 2-hour real-time waiting or physical game installations.

## Acceptance Criteria

### Detection & Tracking
- [ ] Process monitor detects simulated executables inside mock launcher directories and custom config lists.
- [ ] Multiple game sessions sequentially or concurrently sum up to a single monotonic counter without double-counting identical time intervals.

### Warnings & Lockout
- [ ] Warning triggers execute reliably at the configured thresholds (5 min and 1 min before limit).
- [ ] Target processes are terminated within 2 seconds of the counter hitting 120 minutes.
- [ ] Any blacklisted/game process launched during an active lockout is terminated within 2 seconds.

### Persistence & Security
- [ ] Service restarts preserve accrued time and lockout state from persistent storage.
- [ ] Shifting system clock backward does not decrement elapsed time or bypass the active lockout.
- [ ] Service stop / config modification commands without the correct password fail with an unauthorized error.

### Verification
- [ ] End-to-end automated test runner executes and passes all test assertions in under 60 seconds using time compression/mocking.
