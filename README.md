# 🛡️ Threat Hunt Report: Unauthorized TOR Usage  

<img width="1536" height="1024" alt="image" src="https://github.com/user-attachments/assets/60eb938f-0874-426c-bf7a-85973948d2ab" />


![KQL](https://img.shields.io/badge/Language-KQL-blue)  
![Microsoft Defender for Endpoint](https://img.shields.io/badge/Tool-Microsoft%20Defender%20for%20Endpoint-purple)  
![Threat Hunting](https://img.shields.io/badge/Skill-Threat%20Hunting-orange)  
![Incident Response](https://img.shields.io/badge/Skill-Incident%20Response-red)  
![Security Operations](https://img.shields.io/badge/Domain-Security%20Operations-green)  

**Case:** Detection of Unauthorized TOR Browser Installation and Use  
**Endpoint:** `shawn-mde-test`  
**Date:** August 23, 2025  
**Account Involved:** `bigbyc0ffee`  

---

## 📌 Example Scenario

Management suspected employees may be using TOR browsers to bypass network security controls. This suspicion arose due to:

- Unusual encrypted traffic patterns in recent network logs.  
- Connections to known TOR entry nodes.  
- Anonymous reports of employees discussing ways to access restricted sites during work hours.  

**Objective:**  
Detect TOR usage, analyze related incidents, and report findings to management. If confirmed, take response actions.

---

## 🔍 High-Level TOR-related IoC Discovery Plan

1. **File Events** – Search for `tor(.exe)` or `firefox(.exe)` installation and execution files.  
2. **Process Events** – Identify installation commands and TOR-related process launches.  
3. **Network Events** – Detect outbound connections on known TOR ports (`9001, 9030, 9040, 9050, 9051, 9150`).  

---

## 📝 Steps Taken & Findings

### 1. File Discovery

Searched `DeviceFileEvents` for any file containing `tor`.  

**Findings:**  
- User `bigbyc0ffee` downloaded a TOR installer.  
- TOR-related files appeared on the desktop.  
- File `tor-shopping-list.txt` was created at **2025-08-23T18:32:59.92838Z**.  
- Events began at **2025-08-23T18:18:52.4869352Z**.  

**Query Used:**
```kusto
DeviceFileEvents
| where DeviceName == "shawn-mde-test"
| where InitiatingProcessAccountName == "bigbyc0ffee"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-08-23T18:18:52.4869352Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName

```
**Result:**

<img width="1235" height="1047" alt="image" src="https://github.com/user-attachments/assets/fee5f07c-31e2-4876-9691-6be5f0862d06" />

---

### 2. Process Execution

- On **2025-08-23 14:22 (UTC)**, user `bigbyc0ffee` executed
 `tor-browser-windows-x86_64-portable-14.5.6.exe ` from the Downloads folder.
- Evidence shows a **silent installation** was performed.

**Query Used:**

```kusto
DeviceProcessEvents
| where DeviceName == "shawn-mde-test"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.6.exe"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA256, ProcessCommandLine

```
**Result:**

<img width="1310" height="717" alt="image" src="https://github.com/user-attachments/assets/6b901994-7c3a-4df5-938e-d98de7bfc08a" />

---

### 3. TOR Browser Execution

- At **2025-08-23T18:23:07.4073042Z**, TOR browser was opened.
- Multiple subsequent instances of `firefox.exe (tor)` and `tor.exe` were executed.

**Query Used:**

```kusto
DeviceProcessEvents
| where DeviceName == "shawn-mde-test"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```

**Result:**

<img width="1456" height="911" alt="image" src="https://github.com/user-attachments/assets/20a1061a-e196-4e46-bcd1-99a1a5040390" />

---

### 4. Network Connections

- At **2025-08-23T18:23:22.6137069Z**, `tor.exe` successfully connected to remote IP **159.69.71.228** over **port 9001**.

**Query Used:**

```kusto
DeviceNetworkEvents
| where DeviceName == "shawn-mde-test"
| where InitiatingProcessAccountName == "bigbyc0ffee"
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName
```

**Result:**

<img width="1431" height="756" alt="image" src="https://github.com/user-attachments/assets/25ade4f3-ba3e-45d9-84af-f690b16f61e0" />

---

## 📅 Chronological Events Timeline

**2025-08-23T18:18:52Z** – TOR installer downloaded.

**2025-08-23T18:22:00Z** – Silent installation executed.

**2025-08-23T18:23:07Z** – TOR browser launched.

**2025-08-23T18:23:22Z** – Outbound connection to TOR network (IP: 159.69.71.228:9001).

**2025-08-23T18:32:59Z** – Creation of tor-shopping-list.txt on desktop.

---

## ✅ Summary

TOR usage was confirmed on the endpoint `shawn-mde-test` under user account `bigbyc0ffee`.

The investigation revealed installation, execution, and active network usage of TOR.

---

## 🚨 Response Taken

- **Confirmed TOR usage** on endpoint `shawn-mde-test`.

- **Device isolated** from the network.

- **Management notified** of user activity and security policy violation.

---

## 📖 Key Takeaways & Lessons Learned

- **Proactive Detection**: Regularly monitor endpoints for installation of high-risk applications (TOR, VPNs, P2P tools).

- **User Awareness**: Security awareness training should emphasize the risks of unauthorized anonymization tools.

- **Policy Enforcement**: Endpoint restrictions and application control policies should block unauthorized software installations.

- **Improved Visibility**: Continuous monitoring of network egress traffic on known TOR ports is critical.

- **Incident Response Readiness**: This case highlights the importance of swift containment (device isolation) and clear communication with management.




