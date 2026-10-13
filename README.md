# TryHackMe - Jackpot

A practical walkthrough of the Jackpot room on TryHackMe, covering network reconnaissance, service enumeration, protocol analysis, and interaction with a simulated ATM cash dispenser.

## Table of Contents

- [Overview](#overview)
- [Lab Environment](#lab-environment)
- [1. Reconnaissance](#1-reconnaissance)
- [2. Inspecting the Engineering Console](#2-inspecting-the-engineering-console)
- [3. Obtaining the Activation Code](#3-obtaining-the-activation-code)
- [4. Understanding the XFS Bridge](#4-understanding-the-xfs-bridge)
- [5. Enumerating Available Commands](#5-enumerating-available-commands)
- [6. Preparing the Dispenser](#6-preparing-the-dispenser)
- [7. Dispensing the Remaining Notes](#7-dispensing-the-remaining-notes)
- [8. Retrieving the Flag](#8-retrieving-the-flag)
- [Troubleshooting](#troubleshooting)
- [Security Observations](#security-observations)
- [Final Notes](#final-notes)

---

## Overview

**Platform:** TryHackMe  
**Room:** Jackpot  
**Difficulty:** Medium  
**Category:** Network Security / Protocol Analysis

Jackpot is a simulated ATM security challenge. The objective is to investigate an engineering interface, understand how it communicates with a cash dispenser, and complete the challenge by interacting with the dispenser through its exposed protocol.

The challenge demonstrates why administrative interfaces and hardware-control services should not be accessible without proper authentication and authorization.

The main areas covered in this walkthrough are:

- Network reconnaissance with Nmap.
- HTTP endpoint enumeration.
- Analysis of a supplied executable.
- TCP communication and binary message framing.
- Enumeration of device capabilities.
- Understanding dispenser command responses.
- Verification of the final challenge state.

> **Scope:** All testing described here is intended for the authorized TryHackMe lab. Do not apply these techniques to real ATMs, payment terminals, or other systems without explicit authorization.

## Lab Environment

The examples use an Ubuntu system with Python 3 and standard networking tools.

Install any missing utilities:

```bash
sudo apt update
sudo apt install nmap curl wget netcat-openbsd python3
```

Set the target IP address in a shell variable:

```bash
export HOST=10.130.153.99
```

Replace this address whenever TryHackMe assigns a different target.

Check that the target is reachable:

```bash
ping -c 3 "$HOST"
```

Some lab machines may not respond to ICMP requests. A failed ping does not necessarily mean the target is unavailable.

---

## 1. Reconnaissance

The first step is to identify the services exposed by the target.

Run:

```bash
nmap -sC -sV -p 22,8080,9100 "$HOST"
```

### What the options mean

| Option | Purpose |
|---|---|
| `-sC` | Runs Nmap's default scripts. |
| `-sV` | Attempts to identify service versions. |
| `-p` | Specifies which ports to scan. |

The relevant services in this challenge are:

| Port | Service | Purpose |
|---|---|---|
| 22 | SSH | Remote login service |
| 8080 | HTTP | Engineering console and status information |
| 9100 | Custom TCP service | XFS bridge used by the simulated dispenser |

Port 8080 is the first service to investigate because it provides information about the terminal.

Port 9100 is important because it exposes the custom protocol used to communicate with the dispenser.

### Open the engineering console

Visit the following address in a browser:

```text
http://TARGET_IP:8080/
```

Replace `TARGET_IP` with the current lab address.

Inspect the page and look for information about the terminal, its session code, and the available engineering functions.

---

## 2. Inspecting the Engineering Console

The web interface exposes a status endpoint that returns information in JSON format.

Request it with:

```bash
curl -s "http://$HOST:8080/status" | python3 -m json.tool
```

The response may contain fields similar to these:

```json
{
    "nonce": "123456",
    "armed": false,
    "monitor_on": true,
    "locked": false,
    "lock_remaining": 0,
    "dispensed_total": 0,
    "remaining_notes": 280,
    "flag_released": false
}
```

The values above are illustrative. Always use the values returned by your own running target.

### Important fields

| Field | Meaning |
|---|---|
| `nonce` | The current six-digit session code |
| `armed` | Whether the dispenser has been armed |
| `monitor_on` | Whether the fraud-monitoring mechanism is enabled |
| `locked` | Whether the dispenser is currently locked |
| `lock_remaining` | Remaining lock duration, when provided |
| `dispensed_total` | Total number of notes dispensed |
| `remaining_notes` | Number of notes still in the simulated dispenser |
| `flag_released` | Whether the challenge has released its flag |

The session code is particularly important because the supplied engineering utility accepts it as an argument.

Record the current value of `nonce`. Do not assume that a code from a previous session will still be valid.

### Download the engineering utility

Download the executable from the target:

```bash
wget "http://$HOST:8080/jackpot" -O jackpot
```

Make it executable:

```bash
chmod +x jackpot
```

Inspect the file:

```bash
file jackpot
```

Run it without arguments to display its usage information:

```bash
./jackpot
```

The utility expects a six-digit session code.

---

## 3. Obtaining the Activation Code

The engineering utility calculates an activation code from the session code supplied by the terminal.

For example:

```bash
./jackpot 123456
```

The output should identify the supplied session code and display a corresponding activation code.

The example session code above is only a placeholder.

### Use the live session code

First, retrieve the current nonce:

```bash
curl -s "http://$HOST:8080/status" \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["nonce"])'
```

Then execute the utility using the value returned by the command:

```bash
./jackpot SESSION_CODE
```

Replace `SESSION_CODE` with the actual six-digit value.

Keep the resulting activation code available for the later protocol interaction.

### Why this step matters

The dispenser exposes privileged commands, but the simulated service requires an activation code before allowing the dispenser to enter its armed state.

The supplied utility provides a way to calculate the code expected by the challenge.

---

## 4. Understanding the XFS Bridge

The service listening on TCP port 9100 uses a custom protocol inspired by XFS, a framework used for communication between financial applications and peripheral devices.

Connect to the service:

```bash
nc -v -w 3 "$HOST" 9100
```

The server provides a banner describing its protocol.

The request format is:

```text
1 byte   Message type
4 bytes  Command identifier, big-endian
2 bytes  Payload length, big-endian
N bytes  Payload
```

The response format is:

```text
2 bytes  Response length, big-endian
N bytes  JSON response
```

The protocol uses two message types:

| Message type | Value | Purpose |
|---|---|---|
| GETINFO | `0x01` | Request information |
| EXECUTE | `0x02` | Submit a command |

### Understanding big-endian values

Big-endian means that the most significant byte is transmitted first.

For example, the 32-bit integer `0x00000304` is represented by these four bytes:

```text
00 00 03 04
```

Python's `struct` module can encode and decode these values.

```python
import struct

command_id = 0x0304

encoded = struct.pack(">I", command_id)

print(encoded.hex())
```

Output:

```text
00000304
```

The `>` specifies big-endian byte order, while `I` represents an unsigned four-byte integer.

The protocol uses the same principle for its two-byte payload length.

### Why raw TCP matters

TCP provides a stream of bytes, not a sequence of guaranteed complete application messages.

A call to `recv()` may return fewer bytes than requested. A correct client must therefore read the complete header and payload before attempting to decode a response.

This is important when writing protocol clients in Python.

---

## 5. Enumerating Available Commands

The service banner identifies a command that returns information about the dispenser's capabilities.

The command is:

```text
WFS_INF_CDM_CAPABILITIES
Command ID: 0x0304
Message type: GETINFO
```

The response contains a command table.

The relevant command identifiers are:

| Command | Identifier | Purpose |
|---|---|---|
| `WFS_INF_CDM_STATUS` | `0x0301` | Obtain dispenser status |
| `WFS_INF_CDM_CASH_UNIT_INFO` | `0x0303` | Obtain cash-unit information |
| `WFS_INF_CDM_CAPABILITIES` | `0x0304` | Obtain supported capabilities |
| `WFS_CMD_CDM_DISPENSE` | `0x0401` | Dispense notes |
| `WFS_CMD_CDM_ARM` | `0x04F0` | Arm the dispenser |
| `WFS_CMD_CDM_SET_MONITOR` | `0x04F1` | Configure the fraud monitor |
| `WFS_CMD_CDM_GET_FLAG` | `0x04FF` | Retrieve the challenge flag |

The capabilities response also reports the maximum number of notes permitted in a single dispense request.

In this room, that value is reported as:

```text
max_dispense: 40
```

This is a useful example of why protocol enumeration should happen before attempting to use undocumented commands: the service itself describes its supported operations.

---

## 6. Preparing the Dispenser

The next stage is to understand the responses to the monitor and arming commands.

The protocol uses the `EXECUTE` message type for these operations.

### 6.1 Configure the fraud monitor

The monitor command is:

```text
WFS_CMD_CDM_SET_MONITOR
Command ID: 0x04F1
```

The challenge's expected JSON structure uses the `monitor` field.

For example, a monitor configuration request has this general form:

```json
{
    "monitor": false
}
```

The returned JSON should be inspected to determine whether the requested state was accepted.

A successful command response is not sufficient on its own to prove that every aspect of the terminal state is correct. Verify the state using the HTTP status endpoint as well.

### 6.2 Arm the dispenser

The arming command is:

```text
WFS_CMD_CDM_ARM
Command ID: 0x04F0
```

It accepts the activation code obtained from the engineering utility.

The expected JSON payload has this general structure:

```json
{
    "code": 12345678
}
```

The number above is a placeholder. Use the activation code generated for your current session.

A successful response indicates that the arming operation was accepted.

If the service returns an error, read the error code and message carefully instead of assuming the operation succeeded.

### Understanding common responses

**Successful response**

```json
{
    "rc": "WFS_SUCCESS"
}
```

This indicates that the requested operation succeeded, subject to any additional state information returned by the service.

**Invalid activation code**

```json
{
    "rc": "WFS_ERR_CDM_INVALIDCODE",
    "detail": "invalid activation code"
}
```

Possible causes include using an outdated session code or supplying an incorrect activation code.

**Dispenser locked**

```json
{
    "rc": "WFS_ERR_CDM_LOCKED",
    "detail": "machine locked by fraud monitor"
}
```

This indicates that the service is refusing the requested operation because the simulated dispenser is locked.

Check the live status response and wait for any lock period to expire before continuing.

---

## 7. Dispensing the Remaining Notes

The dispense command is:

```text
WFS_CMD_CDM_DISPENSE
Command ID: 0x0401
```

Its payload includes a `count` field specifying the requested number of notes.

The service advertises a maximum request size of 40 notes.

For this challenge, the status endpoint provides the information needed to determine whether the simulated dispenser has reached its final state.

After completing the challenge's authorized dispenser interaction, inspect the status endpoint again:

```bash
curl -s "http://$HOST:8080/status" \
    | python3 -m json.tool
```

Pay attention to these fields:

```text
armed
monitor_on
dispensed_total
remaining_notes
flag_released
```

Do not treat a printed success message from your own script as proof that the challenge has been completed. The response from the remote service and its actual state are the evidence that matters.

### What the final state should show

The walkthrough's example environment contains 280 notes.

When the challenge is completed, the status information should indicate that:

- The dispenser has been armed.
- The remaining note count has reached zero.
- The dispensed total reflects the notes processed by the challenge.
- The flag has been released.

The exact initial values can differ between lab sessions.

---

## 8. Retrieving the Flag

The capabilities response identifies a dedicated flag-retrieval command:

```text
WFS_CMD_CDM_GET_FLAG
Command ID: 0x04FF
```

The flag should be retrieved only after the challenge's required conditions have been satisfied.

You can also revisit the engineering console:

```text
http://TARGET_IP:8080/
```

Replace `TARGET_IP` with the current lab address.

Once the terminal reports that the flag has been released, the interface may display it.

### Flag

```text
THM{n0_card_n0_pin_just_the_wr0ng_v0ice_speaking_XFS}
```

If the flag is rejected, verify that the room is the same challenge version and that the flag was copied exactly, including capitalization and braces.

---

## Troubleshooting

### The target does not respond

Check that the machine is running in TryHackMe and that the IP address is current.

```bash
echo "$HOST"
```

Repeat the port scan:

```bash
nmap -sV -p 22,8080,9100 "$HOST"
```

### The engineering utility rejects the session code

Retrieve the current nonce again:

```bash
curl -s "http://$HOST:8080/status" | python3 -m json.tool
```

Use the latest value rather than a code copied from an earlier session.

### The monitor remains enabled

Inspect the response to the monitor command.

The request must use the field name expected by the challenge protocol. A payload containing an unrecognized field may be accepted at the transport level without changing the requested setting.

Verify the actual value through `/status`.

### The dispenser reports a lock

Inspect:

```bash
curl -s "http://$HOST:8080/status" | python3 -m json.tool
```

Check `locked`, `lock_remaining`, and `monitor_on`.

If the service reports a remaining lock duration, wait for it to expire before retrying.

### Python receives an incomplete response

TCP does not guarantee that one call to `recv()` returns an entire message.

Use a helper that continues reading until the requested number of bytes has arrived:

```python
def recv_exact(sock, size):
    data = bytearray()

    while len(data) < size:
        chunk = sock.recv(size - len(data))

        if not chunk:
            raise ConnectionError(
                "Connection closed before the message was complete"
            )

        data.extend(chunk)

    return bytes(data)
```

For a framed response, first read the two-byte length field, decode it as a big-endian unsigned integer, and then read exactly that many payload bytes.

### The script prints success, but the room is not completed

A message printed by a local script is only text generated by that script.

Check the actual response from the target and verify the final status through the HTTP endpoint.

Useful indicators include:

```text
remaining_notes
dispensed_total
flag_released
```

These values provide stronger evidence than a hard-coded success message.

---

## Security Observations

### 1. Administrative services should not be unnecessarily exposed

The engineering interface and dispenser service provide access to functionality that should be restricted to authorized management software.

Administrative services should be isolated from untrusted networks and protected by appropriate access controls.

### 2. Authentication must protect individual privileged operations

A service should not rely on a predictable or easily derived value as its only protection for privileged commands.

Sensitive operations should use properly designed authentication and authorization mechanisms.

### 3. Protocol validation is essential

Services should validate message types, command identifiers, payload lengths, payload formats, and command parameters.

They should also reject malformed requests safely and consistently.

### 4. Monitoring must enforce policy

A monitoring mechanism is not an effective security control if the same exposed interface can disable it without sufficient authorization.

Security controls should be enforced by trusted components rather than relying solely on a client application.

### 5. Hardware-control interfaces need strict authorization

Commands that control physical devices should require strong authorization, appropriate state checks, and audit logging.

A network-accessible interface should never assume that a caller is trustworthy simply because the caller can connect to its TCP port.

### 6. Error messages help explain system behavior

The room demonstrates the value of reading application-level error responses.

An error such as `WFS_ERR_CDM_INVALIDCODE` differs significantly from `WFS_ERR_CDM_LOCKED`. The former indicates an activation-code problem; the latter indicates a state or policy restriction.

Correctly interpreting these responses makes debugging more systematic.

---

## Final Notes

This room combines several practical security skills:

- Network reconnaissance
- HTTP endpoint inspection
- Binary protocol analysis
- Python socket programming
- Big-endian data encoding
- JSON serialization and parsing
- Application-level error analysis
- State verification

The main lesson is to understand how a service works before interacting with its commands.

Enumerate the available interfaces, read the protocol description, inspect the responses, and verify the resulting state instead of relying on assumptions.

**Room:** Jackpot  
**Platform:** TryHackMe  
**Focus:** Network protocols, service enumeration, and simulated ATM security

---

*This write-up documents a controlled training environment. All testing should remain within the scope of the authorized lab.*

# Flag

<h1 align="center">🏁 Flag</h1>

<p align="center">
  <code>THM{n0_card_n0_pin_just_the_wr0ng_v0ice_speaking_XFS}</code>
</p>

# Author 

Deadcode

# License 

MIT
