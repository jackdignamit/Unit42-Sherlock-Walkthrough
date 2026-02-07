
# Unit42 Sherlock | HackTheBox Walkthrough
> ## Using Windows Event Viewer and Sysmon Logs to Analyze Malware
*Completed 10/19/2025*

*Jack Dignam*

- - - 
<p align="center"> <img width="320" height="320" alt="1_0TYv2CLsBWzhS5aBzyHBIw" src="https://github.com/user-attachments/assets/e7da59ae-f4d4-4164-9f31-f78ad51c962e" />
<p align="center"> https://app.hackthebox.com/sherlocks/632

# Introduction
My first [Hack The Box](https://app.hackthebox.com/home) Sherlock walkthrough is [Unit42](https://app.hackthebox.com/sherlocks/632)! This lab is the third challenge from the **Intro to Blue Team** track that focuses on **Windows Event Viewer** and **Sysmon logs**.

This lab is inspired by Palo Alto's Unit42 research about UltraVNC in which attackers used a backdoor version of it to maintain access to systems. It showcases how attackers can deliver trojans using cloud-based delivery methods.

If you're new to *Sysmon*, understanding common Event IDs will greatly assist with this challenge. Here is a quick overview of the most important events for this particular lab:

```
- Event ID 1: Process Creation / Execution
- Event ID 2: File Creation Time Changed
- Event ID 3: Network Connection
- Event ID 5: Process Termination
- Event ID 11: File Created
- Event ID 22: DNS Query

```

If you find this walkthrough helpful, please feel free to drop a follow. Thank you for your consideration, now let's do this investigation!

--- 

# Challenge Scenario
> In this Sherlock, you will familiarize yourself with Sysmon logs and various useful EventIDs for identifying and analyzing malicious activities on a Windows system.
> Palo Alto's Unit42 recently conducted research on an UltraVNC campaign, wherein attackers utilized a backdoored version of UltraVNC to maintain access to systems.
> This lab is inspired by that campaign and guides participants through the initial access stage of the campaign.

## Setup the Lab Environment:
As a good rule of thumb before any simulated investigation, it is a wise idea to use a **virtual machine**. This ensures the environment is completely isolated and safe. Hack the Box does not distribute live, malicious malware but it does often contain some for the purpose of hands-on, ethical training. In this case, it does not contain any malware but its important to keep that in mind.

If you need instructions on installing a virtual machine of your own, you can follow this tutorial: 

[![](https://github.com/user-attachments/assets/e9091b5f-0e05-4b4c-9272-0e1e7e0ab851)](https://youtu.be/CMGa6DsGIpc?si=Dif9kTTge-xOandS)

https://youtu.be/CMGa6DsGIpc?si=Dif9kTTge-xOandS

From your virtual machine, download the Hack the Box file and unzip it onto your desktop. You can then double click on the **Microsoft-Windows-Sysmon-Operational** file to open it up in *Windows Event Viewer*.

---

# Walkthrough
## Task 1: How many Event logs are there with Event ID 11?
We're looking for Event ID 11, which is dedicated to file creation. On the right side of *Windows Event Viewer*, there is a panel with a list of organization and set options. Click on `Filter Current Log…` and enter *11* in the Event ID box.

<img width="543" height="554" alt="1_PILuZZv80E_HS4wm-48WUA" src="https://github.com/user-attachments/assets/02002641-a3ef-4aa7-a61b-333df5a11048" />

Once we have applied the filter, the number of events is visible at the very top of the screen. There is a total of 56 file creation events captured by Sysmon.

<img width="801" height="66" alt="1_WZAVYzoVUhsqA-ZxIUsI6Q" src="https://github.com/user-attachments/assets/12973660-5010-41ab-aed7-c7607b480ab8" />
<img width="1000" height="146" alt="1_xGVFNtQuz2P7SBrPlQgikA" src="https://github.com/user-attachments/assets/ef1f363d-6b69-4c35-be91-a9cb5e22ad0c" />

--- 

## Task 2: Whenever a process is created in memory, an event with Event ID 1 is recorded with details such as command line, hashes, process path, parent process path, etc. This information is very useful for an analyst because it allows us to see all programs executed on a system, which means we can spot any malicious processes being executed. What is the malicious process that infected the victim's system?
This tasks asks of us to discover the malicious process which infected the compromised host. To do this, filter the logs this time for **Event ID 1** (process creation).

<img width="1000" height="147" alt="1_Bpqq0lWeGX7YiQwSZlK6Kg" src="https://github.com/user-attachments/assets/139de196-263f-4d5c-87f6-8741572472fa" />

The result lists 6 events, of which, the second entry contains suspicious process information. It has an executable that is formatted with **.exe** located in the victim's `Downloads` folder.

<img width="1000" height="561" alt="1_mQQTUOJyjLaR_CuzhRei_A" src="https://github.com/user-attachments/assets/2fc02bc3-62b5-4d7b-ae49-103833ae1dac" />

But what if, on the off chance, it is a legitimate process? In that case, you can utilize **[Virustotal](https://www.virustotal.com/gui/home/upload)** to enter the file's hash values to check if the exact file has been flagged before as malicious. This ensures we make a more informed decision.

<img width="1000" height="685" alt="1_Tfkf-wzAshNVhwpVyHy-1A" src="https://github.com/user-attachments/assets/4c98f450-b82f-42bb-bb84-75449ff2adf4" />

Upon immediate inspection, its clear that this exact file hash is detected as malicious by 47 antivirus softwares. Therefore, the answer for task 2 is: `C:\Users\CyberJunkie\Downloads\Preventivo24.02.14.exe.exe`

<img width="1000" height="190" alt="1_8mUHPDPokxY7XMsjlTee4A" src="https://github.com/user-attachments/assets/36ae70a4-0fa7-4560-8c9c-2898a62d2172" />

--- 
## Task 3: Which Cloud drive was used to distribute the malware?
**Event ID 22** is used to view DNS queries made by the system. Filtering for it outputs 3 events, which the one occurring at `03:41:26` reveals the utilization of **Dropbox**, a cloud-based storage site.

<img width="1000" height="146" alt="1_B3D2OSmfYDpqvKQTdiZDNg" src="https://github.com/user-attachments/assets/0811e641-15b2-4e5a-a5ba-eb9bf55405b4" />

--- 
## Task 4: For many of the files it wrote to disk, the initial malicious file used a defense evasion technique called Time Stomping, where the file creation date is changed to make it appear older and blend in with other files. What was the timestamp changed to for the PDF file?
Time Stomping is a common technique performed by threat actors to conceal the original timestamps for an event relating to a file in a computer system. 
By changing these details, tracking the original order of events relating to the file is made harder. 
Investigators or security software would not be able to reliably determine the true sequence of events.

**Event ID 2** records when a process changed a file's creation time. Sysmon deliberately made this event to counteract this common attack method.

On *Windows Event Viewer*, on the right side, is a built-in *Find* function which can keyword search for `pdf`. In the output, there is an event with two unique timestamps showcasing usage of timestomping. The first timestamp is the original before external manipulation.

<img width="687" height="402" alt="1_eNHEozyyWu5z9SSXo21HCQ" src="https://github.com/user-attachments/assets/be9e1b70-141c-44eb-920c-7113e1c9e093" />

The answer for task 4 is **2024–01–14 08:10:06**.

<img width="1000" height="168" alt="1_SsEA2HJvOi4hDEP8XL9w7A" src="https://github.com/user-attachments/assets/50ed6b54-9b4c-4394-a025-7a467ae71ae6" />

--- 
## Task 5: The malicious file dropped a few files on disk. Where was "once.cmd" created on disk? Please answer with the full path along with the filename.
The task specifies that a few files were created on the disk, therefore we need to filter for **Event ID 11** (*FileCreate*). Then, use the Find function to search for `once.cmd`.

<img width="875" height="468" alt="0_JuDgCgFgLjcwSnWv" src="https://github.com/user-attachments/assets/9ad88b6c-8ca4-46cf-a71c-bdca6091b7aa" />

From here, we discover the full file path of the dropped file: 
`C:\Users\CyberJunkie\AppData\Roaming\Photo and Fax Vn\Photo and vn 1.1.2\install\F97891C\WindowsVolume\Games\once.cmd`

<img width="1000" height="143" alt="1_vmuKtPBmKiCKPyucfJT56w" src="https://github.com/user-attachments/assets/ac6f1343-6ea4-4937-af47-f05c3f812d67" />

--- 
## Task 6: The malicious file attempted to reach a dummy domain, most likely to check the internet connection status. What domain name did it try to connect to?
**Event ID 22** contains DNS queries from processes which identify DNS lookups to external domains. Searching for this event ID and looking through the results reveals only one valid answer:

<img width="491" height="350" alt="1_dKcntyrAVr6gkxB0uaThfg" src="https://github.com/user-attachments/assets/ccaa7ae4-fa8a-4a9c-8d26-8fab86c09d7d" />

```www.example.com``` is the only website that makes sense in the resulting events because it was most likely used to check if the victim's internet was functioning. If the process managed to get a response back from the website, then the internet works.

<img width="1000" height="147" alt="1_m9iSzR98xPwYO0WZ2C3_zg" src="https://github.com/user-attachments/assets/68df46ea-aaaa-4a6f-ac30-245c9eeaf14e" />

--- 
## Task 7: Which IP address did the malicious process try to reach out to?
After the malicious process confirms it can access the internet, it attempts to reach out to an IP address. To find which, we can filter for **Event ID 3**.

- **Event ID 3** records IP addresses and TCP/UDP connections made by processes on the machine.

Once the filter is applied, only one log appears. If there were more, it is best to use the **Find** function to discover more specific logs such as any containing `Preventivo`.

<img width="360" height="261" alt="1_6GNRjot4lOKdTB-BqzY_kA" src="https://github.com/user-attachments/assets/50b6773d-aa55-4792-b743-b7501d4b51bf" />

From here, the destination IP reveals the malicious process is communicating with `93.184.216.34`.

<img width="1000" height="141" alt="1_OykzWkK5NFLj8jEHO-AQIg" src="https://github.com/user-attachments/assets/cc836107-49cd-47bf-be11-3ee42e19565c" />

--- 
## Task 8: The malicious process terminated itself after infecting the PC with a backdoored variant of UltraVNC. When did the process terminate itself?
We can discover when the process terminated itself by filtering for **Event ID 5**, which logs process terminations. It provides `UtcTime`, `ProcessId`, and `ProcessGuid` of the process.

This returns only one event, which contains the timestamp of the event termination.

<img width="557" height="422" alt="1_eoACGC0iZMPLlbwT8rZhsQ" src="https://github.com/user-attachments/assets/79d1b4cb-76e3-4fd0-a9c5-57d6bb5ad42c" />
<img width="1000" height="142" alt="1_CGEr94gW58AMqD-3aKbFvQ" src="https://github.com/user-attachments/assets/39fc0cf6-a862-48f8-8550-6d7e28edf2bb" />
<img width="747" height="732" alt="1_7OlVC_x31KSieNxjHEQ0Jw" src="https://github.com/user-attachments/assets/ae1eee11-65b9-40e0-812d-4447266d365c" />

---
# Conclusion 
The [Unit42](https://app.hackthebox.com/sherlocks/632) challenge from [Hack The Box](https://app.hackthebox.com/home) offers a realistic forensics scenario inspired a real backdoor campaign. 
It tasks you with filtering through Sysmon logs to track how a malware attack was conducted, from the initial installation to the cleanup process.

We learnt many key Event IDs thanks to this exercise such as **process creation (ID 1)**, **file creation (ID 11)**, **DNS queries (ID 22)**, **network connections (ID 3)**, **timestamp modifications (ID 2)**, and **process terminations (ID 5)**.

Thanks to this challenge, we gained practical **log analysis, event correlation, timeline reconstruction**, and **threat detection forensic skills.** 
This knowledge will come in handy especially considering that this challenge mirrored a **real-world incident response workflow**. If you found this walkthrough helpful, please **drop a follow**. 

Thank you for reading!

## References
Challenge: https://app.hackthebox.com/sherlocks/632

Microsoft Sysmon: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon

VirusTotal: https://www.virustotal.com/gui/file/0cb44c4f8273750fa40497fca81e850f73927e70b13c8f80cdcfee9d1478e6f3

---
