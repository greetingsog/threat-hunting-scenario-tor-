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

Searched the DeviceFileEvents table for any file that had the string “tor” in it and discovered what looks to be the user “azurelinko” downloaded a TOR installer and did something that resulted in many TOR-related files being copied to the desktop and the creation of a file called “tor-shopping-list.txt” on the desktop at 2025-10-23T19:21:13.3960656Z. These events began at: 2025-10-23T18:41:40.0019389Z

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

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2024-11-08T22:14:48.6065231Z`
- **Event:** The user "employee" downloaded a file named `tor-browser-windows-x86_64-portable-14.0.1.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2024-11-08T22:16:47.4484567Z`
- **Event:** The user "employee" executed the file `tor-browser-windows-x86_64-portable-14.0.1.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.1.exe /S`
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2024-11-08T22:17:21.6357935Z`
- **Event:** User "employee" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\employee\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2024-11-08T22:18:01.1246358Z`
- **Event:** A network connection to IP `176.198.159.33` on port `9001` by user "employee" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2024-11-08T22:18:08Z` - Connected to `194.164.169.85` on port `443`.
  - `2024-11-08T22:18:16Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2024-11-08T22:27:19.7259964Z`
- **Event:** The user "employee" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\employee\Desktop\tor-shopping-list.txt`

---

## Summary

The user "employee" on the "threat-hunt-lab" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `threat-hunt-lab` by the user `employee`. The device was isolated, and the user's direct manager was notified.

---
