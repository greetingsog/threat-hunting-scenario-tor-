<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/greetingsog/threat-hunting-scenario-tor-/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
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

Searched the DeviceFileEvents table for any file that had the string “tor” in it and discovered what looks to be the user “azurelinko” downloaded a TOR installer and did something that resulted in many TOR-related files being copied to the desktop and the creation of a file called “tor-shopping-list.txt” on the desktop at `2025-10-23T19:21:13.3960656Z`. These events began at: 2025-10-23T18:41:40.0019389Z

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "og-vm-mde9"
| where InitiatingProcessAccountName == "azurelinko"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-10-23T18:41:40.0019389Z)
| order by Timestamp desc 
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
![Screenshot 2025-11-04 at 4 58 40 PM](https://github.com/user-attachments/assets/bb853740-d727-420e-a61a-5817e69592b3)

---

### 2. Searched the `DeviceProcessEvents` Table

Searched the DeviceProcessEvents table for any ProcessCommandLine that contained the string “tor-browser-windows-x86_64-portable-14.5.8.exe”. Based on the log returned at 2025-10-23T18:52:18.6823948Z, A user named azurelinko executed the installer for the Tor Browser on the virtual machine “og-vm-mde9”, launching the installation silently from their Downloads folder.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "og-vm-mde9"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.8.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
![Screenshot 2025-11-04 at 5 10 18 PM](https://github.com/user-attachments/assets/fa7c2e22-c6f0-41a2-ab5f-0c30eae046aa)

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the DeviceProcessEvents table for any indication that the user “azurelinko” opened the tor browser. There was evidence that they did open at 2025-10-23T18:53:25.9192101Z

There were several other instances of Firefox.exe (Tor) as well as tor.exe spawned afterwards. 

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "og-vm-mde9"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser-windows-*.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc 
```
![Screenshot 2025-11-04 at 5 12 42 PM](https://github.com/user-attachments/assets/993e6525-7a1b-4065-ae3c-b734766c1a13)



---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched DeviceNetworkEvents table for any indication that the Tor Browser was used to establish an outgoing connection over commonly known and used Tor ports ("9150", "9151", "9050", "9001", “9030”). 

At 2025-10-23T18:54:25.0505537Z, the employee account azurelinko on the device og-vm-mde9 initiated the Tor Browser's custom version of Firefox (firefox.exe). This program successfully established a connection to the local machine (127.0.0.1) on the dedicated Tor control port 9151. This action confirms that the Firefox component was connecting to and preparing to manage the local Tor service, which is a signature step in starting the Tor Browser Bundle.

At 2025-10-23T18:55:23.1560397Z, the user account azurelinko on the device og-vm-mde9 ran the Tor anonymity program (tor.exe) directly from their desktop. The program successfully established a connection to a public Tor relay node located at the IP address 88.99.27.141 using the dedicated Tor communication port 9001. This log confirms the intentional and successful use of the Tor network by the user. There were a couple other connections to sites over port 443.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "og-vm-mde9"
| where InitiatingProcessAccountName == "azurelinko"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| where RemotePort in ("9150", "9151", "9050", "9001", "9030", "80", "443")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc 
```
![Screenshot 2025-11-04 at 5 14 55 PM](https://github.com/user-attachments/assets/f0a4fe24-11d9-4ac7-9d5b-44a2204800f3)

---

## Detailed Chronological Events Timeline

- **2025-10-23 18:41:40.000Z:** Tor Browser installer file created (Downloaded). File: tor-browser-windows-x86_64-portable-14.5.8.exe - Path: C:\Users\azurelinko\Downloads\tor-browser-windows-x86_64-portable-14.5.8.exe, SHA256: 42175e455f814e5a691195c92df92695f68bca451af53ae405d7a5129898ad89
- **2025-10-23 18:52:18.000Z:** Tor Browser installer executed silently. File: tor-browser-windows-x86_64-portable-14.5.8.exe - Command Line: tor-browser-windows-x86_64-portable-14.5.8.exe /S, Path: C:\Users\azurelinko\Downloads\tor-browser-windows-x86_64-portable-14.5.8.exe
- **2025-10-23 18:53:25.000Z:** Tor Browser (firefox.exe) initial process created/launched by user azurelinko. - Path: C:\Users\azurelinko\Desktop\Tor Browser\Browser\firefox.exe, Command Line: firefox.exe
- **2025-10-23 18:54:22.000Z:** Tor service process created. File: tor.exe - Path: C:\Users\azurelinko\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe
- **2025-10-23 18:54:25.000Z:** Tor Browser (firefox.exe) established connection to local Tor control port 9151. - IP: 127.0.0.1:9151
- **2025-10-23 18:54:46.000Z:** Tor Browser (firefox.exe) established connection to local Tor SOCKS port 9150. - IP: 127.0.0.1:9150
- **2025-10-23 18:55:14.000Z:** Tor anonymity program (tor.exe) successfully connected to a public Tor relay node. - IP: 177.100.214.111:9001
- **2025-10-23 18:55:15.000Z:** Tor Browser or service established a secure connection (HTTPS). - IP: 192.184.93.11:443
- **2025-10-23 18:55:15.000Z:** Tor Browser or service established a secure connection (HTTPS) to an Onion Domain. - IP: 192.184.93.11:443, URL: https://www.j3bffc44.com
- **2025-10-23 18:55:18.000Z:** Tor Browser or service established a secure connection (HTTPS). - IP: 131.188.40.189:443
- **2025-10-23 18:55:19.000Z:** Tor Browser or service established a secure connection (HTTPS) to an Onion Domain. - IP: 131.188.40.189:443, URL: https://www.nwdnnh34xcrrczd7.com
- **2025-10-23 18:55:23.000Z:** Tor anonymity program (tor.exe) successfully connected to a public Tor relay node. - IP: 88.99.27.141:9001
- **2025-10-23 18:55:23.000Z:** Tor Browser or service established a secure connection (HTTPS). - IP: 212.227.197.40:443
- **2025-10-23 18:55:23.000Z:** Tor Browser or service established a secure connection (HTTPS) to an Onion Domain. - IP: 212.227.197.40:443, URL: https://www.skza3ntbbi7zra5exgl5.com
- **2025-10-23 18:55:35.000Z:** Tor Browser (firefox.exe) established connection to local Tor SOCKS port 9150. - IP: 127.0.0.1:9150
- **2025-10-23 18:57:29.000Z:** Tor Browser (firefox.exe) established connection to local Tor SOCKS port 9150. - IP: 127.0.0.1:9150
- **2025-10-23 19:21:13.396Z:** File 'tor-shopping-list.txt' created on the desktop (based on threat hunter's finding). - This file creation marks the end of the initial file activity.
- **2025-10-23 19:24:37.000Z:** Tor service process created. File: tor.exe (Possible relaunch/new session) - Path: C:\Users\azurelinko\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe, Command Line includes +__ControlPort 127.0.0.1:9151
- **2025-10-23 19:24:40.000Z:** Tor Browser (firefox.exe) established connection to local Tor control port 9151. - IP: 127.0.0.1:9151

---

## Summary of Events
The threat hunt successfully documented the full lifecycle of Tor Browser usage by the user azurelinko on the device og-vm-mde9 on October 23, 2025.

- **Installation/File Activity** (18:41Z - 18:52Z): The process began with the download of the portable Tor Browser installer at 18:41:40.000Z. This installer was executed silently (/S flag) at 18:52:18.000Z, leading to the creation of the Tor Browser files on the Desktop.
- **Execution and Session Start** (18:53Z - 18:55Z): The Tor Browser application (firefox.exe) was launched at 18:53:25Z, followed almost immediately by the Tor service (tor.exe) at 18:54:22Z. The browser component then connected to the local Tor service over the standard control port 9151 and SOCKS port 9150, confirming the application was successfully initiating the Tor connection.
- **External Tor Network Connection** (18:55Z): The tor.exe process successfully established outgoing connections to public Tor relay nodes on the dedicated Tor communication port 9001 (IPs 177.100.214.111 and 88.99.27.141). This event confirms the user was actively connected to and routing traffic through the Tor network.
- **Web Activity** (18:55Z): Immediately after connecting to a Tor relay, the user visited at least three different websites over HTTPS (port 443). The URLs, such as https://www.nwdnnh34xcrrczd7.com, are typical of onion-based or Tor-proxied traffic, suggesting the user was accessing sites through the anonymity network.
- **Anomalous File Creation** (19:21Z): At 19:21:13Z, well into the session, a file named tor-shopping-list.txt was created on the desktop, which is a file of interest identified by the threat hunter.
- **Second Session** (19:24Z): A second, distinct launch of the Tor service (tor.exe) and subsequent connection by the browser component to the local ports 9151 and 9150 occurred at 19:24:37Z and 19:24:40Z, respectively, indicating a possible relaunch or new browsing session.

---

## Summary

On October 23, 2025, user azurelinko successfully downloaded, silently installed, and intentionally used the Tor Browser on the corporate device og-vm-mde9. The activity, beginning at 18:41 UTC, quickly escalated to external connections with Tor relays on port 9001 and included encrypted web traffic (port 443) to sites consistent with Tor network usage. The user created a file named tor-shopping-list.txt on the desktop at 19:21 UTC, confirming active engagement within the anonymous network environment. This event confirms a violation of policy involving the use of anonymity software.

---

## Response Taken

TOR usage was confirmed on endpoint og-vm-mde9 by the user azurelinko. The device was isolated and the user's direct manager was notified.

---
