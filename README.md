
<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/jm218/Threat-Hunting-Scenario-TOR/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 11 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

A search for filenames containing "tor" revealed that the user labuser downloaded the Tor Browser installer, which began creating Tor-related files on the desktop starting at 2025-11-26T18:06:29.192329Z. During the session, a file named tor-shopping-list.txt was also created on the desktop at 2025-11-26T18:32:49.3714225Z, indicating interactive user activity.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "threat-huntlab-"
| where InitiatingProcessAccountName == "labuser"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-11-26T18:06:29.192329Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName,FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1793" height="710" alt="Screenshot 2025-11-26 165230" src="https://github.com/user-attachments/assets/60264f4f-7748-486b-976b-c31dbc469306" />

>

---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any ProcessCommandLine containing the Tor installer filename confirmed that at 2025-11-26T18:07:08.7182914Z, user labuser executed: C:\Users\labuser\Downloads\tor-browser-windows-x86_64-portable-15.0.2.exe /S
The /S flag indicates a silent installation, meaning the Tor Browser was installed without user prompts or GUI interaction.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "threat-huntlab-"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.2.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1746" height="85" alt="Screenshot 2025-11-26 165926" src="https://github.com/user-attachments/assets/82290ec3-d549-466c-8a9c-ab253478dc92" />




---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Further review confirmed that the user launched the Tor Browser at 2025-11-26T18:11:53.1350306Z, when firefox.exe (Tor’s bundled browser) was executed from: C:\Users\labuser\Desktop\Tor Browser\Browser\ Additional Tor-related processes such as tor.exe and start-tor-browser.exe were spawned shortly after, confirming full browser startup activity.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "threat-huntlab-"
| where FileName has_any ("tor.exe", "firefox.exe", "browser.exe", "start-tor-browser.exe", "tor-broswer.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```
<img width="1712" height="697" alt="Screenshot 2025-11-26 170035" src="https://github.com/user-attachments/assets/ba7b40af-4c66-47fe-8e4f-ea0d4fb83b3d" />


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

A search for connections over known TOR ports revealed that at 2025-11-26T18:12:59.4051488Z, the device successfully established a connection to a Tor relay at 94.16.115.121 on port 9001, initiated by: c:\users\labuser\desktop\tor browser\browser\torbrowser\tor\tor.exe There were also several Tor SOCKS listener connections to 127.0.0.1:9150 and 127.0.0.1:9151, along with encrypted outbound traffic over port 443, confirming active Tor browsing.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "threat-huntlab-"
| where InitiatingProcessAccountName != "system"
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "9151")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl,InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc
```
<img width="1733" height="227" alt="Screenshot 2025-11-26 170126" src="https://github.com/user-attachments/assets/f2bda739-de31-4b3b-b22c-010171bc3c5c" />


---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- Timestamp: 2025-11-26T18:06:29.192329Z
- Event: The user "labuser" downloaded a file named tor-browser-windows-x86_64-portable-15.0.2.exe to the Downloads folder.
- Action: File download detected.
- File Path: C:\Users\labuser\Downloads\tor-browser-windows-x86_64-portable-15.0.2.exe
  
### 2. Process Execution - TOR Browser Installation

- Timestamp: 2025-11-26T18:07:08.7182914Z
- Event: The user "labuser" executed the file tor-browser-windows-x86_64-portable-15.0.2.exe in silent mode, initiating a background  installation of the TOR Browser.
- Action: Process creation detected.
- Command: tor-browser-windows-x86_64-portable-15.0.2.exe /S
- File Path: C:\Users\labuser\Downloads\tor-browser-windows-x86_64-portable-15.0.2.exe

### 3. Process Execution - TOR Browser Launch

- Timestamp: 2025-11-26T18:11:53.1350306Z
- Event: User "labuser" opened the TOR browser. Subsequent processes associated with TOR browser, such as firefox.exe and tor.exe, -  were also created, indicating that the browser launched successfully.
- Action: Process creation of TOR browser-related executables detected.
- File Path: C:\Users\labuser\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe

### 4. Network Connection - TOR Network

- Event: A network connection to IP 94.16.115.121 on port 9001 by user "labuser" was established using tor.exe, confirming TOR  browser network activity.
- Action: Connection success.
- Process: tor.exe 
- File Path: c:\users\labuser\desktop\tor browser\browser\torbrowser\tor\tor.exe

### 5. Additional Network Connections - TOR Browser Activity

- Timestamps:
- 2025-11-26T18:13:08Z - Local connection to 127.0.0.1 on port 9150.
- 2025-11-26T18:14:45Z - Connected to 94.16.115.121 on port 9001.
- 2025-11-26T18:14:46Z - Additional TOR relay connection on port 9001.
- 2025-11-26T18:15:07Z - Firefox connected to 127.0.0.1:9150, indicating active TOR routing.
- Event: Additional TOR network connections were established, indicating ongoing activity by user "labuser" through the TOR browser.
- Action: Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- Timestamp: 2025-11-26T18:32:49.3714225Z
- Event: The user "labuser" created a file named tor-shopping-list.txt on the desktop, potentially indicating notes or content  created during their TOR browsing session.
- Action: File creation detected.
- File Path: C:\Users\labuser\Desktop\tor-shopping-list.txt
---

## Summary

The user "labuser" on the "threat-huntlab-" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named tor-shopping-list.txt. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint threat-huntlab- by the user labuser. The device was isolated, and the user's direct manager was notified.

---
