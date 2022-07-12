# MITIG&TE

**Machine Interrogation To Identify Gaps & Techniques for Execution**

MITIG&TE is a Windows binary that automatically enumerates Windows settings in order to identify MITRE ATT&CK™ techniques mitigated due to configuration hardening and existing endpoint controls. It relies heavily on the amazing work of the MITRE ATT&CK™ team and the [mitigations](https://attack.mitre.org/mitigations/enterprise/) defined for each of the techniques. It is written in C# and it's dependent on .NET Framework v4.5.

## Goals
The tool aims to allow security teams to easily account and track the impact endpoint configuration hardening and controls have against their threat profile. Additionally it can be used to identify configuration hardening settings that can further improve security posture. Use MITIG&TE to:
 - Identify techniques that are currently mitigated/less likely to be executed successfully, posing less risk to your environment
 - Surface non-applied endpoint controls that can improve endpoint hardening
 - Combine with threat intelligence and your existing detection capabilities to get a holistic view of your security posture mapped against ATT&CK

## Status
MITIG&TE is currently under development. Current coverage [here](https://mitre-attack.github.io/attack-navigator/enterprise/#layerURL=https://raw.githubusercontent.com/moullos/Mitigate/master/examples/Coverage.json). 

## Quick Start and Example
If you would like to try MITIG&TE you can either compile it yourself or use the [precompiled executable](https://nightly.link/moullos/Mitigate/workflows/dotnet/master/mitigate.exe.zip) provided as part of the CI.  For maximum effectiveness, consider running MITIG&TE as an administrator and specifying a user for the least privilege checks. Ideally, that user should have the same privileges as a typical end-user in your environment. By default, MITIG&TE performs the checks for the last logged-in user. When executed, MITIG&TE will pull the latest ATT&CK information and iterate over all the Windows techniques, pulling information on the mitigations defined for each one. 
```
Mitigate.exe -OutFile=results.json                 # Outputs findings into results.json
Mitigate.exe -OutFile=results.json -UserName=user1 # Outputs findings into results.json and performs least privilege checks for user1
Mitigate.exe -OutFile=results.csv -UserName=user1  # Outputs findings into results.csv and performs least privilege checks for user1
``` 
![](https://github.com/moullos/Mitigate/blob/master/examples/Screenshot.png?raw=true)

## Output

### Att&ck Navigator
In addition to the console output, MITIG&TE outputs a json file that can be ingested by the [ATT&CK™ Navigator](https://mitre-attack.github.io/attack-navigator/enterprise/) for easy visualisation.  Colour scheme used:
- ![](https://via.placeholder.com/15/f4a261/000000?text=+) `No mitigations were detected`
- ![](https://via.placeholder.com/15/e9c46a/000000?text=+) `Some mitigation were detected`
- ![](https://via.placeholder.com/15/2a9d8f/000000?text=+) `All mitigations were detected`
- ![](https://via.placeholder.com/15/009ACD/000000?text=+) `Technique cannot be mitigated`

![](https://github.com/moullos/Mitigate/blob/master/examples/Navigator.png?raw=true)

Hovering over a specific technique in the navigator will provide more context on the checks performed. For an interactive example, take a look [here](https://mitre-attack.github.io/attack-navigator/enterprise/#layerURL=https://raw.githubusercontent.com/moullos/Mitigate/master/examples/results.json).

### CSV Output
A CSV output can also be generated if a CSV is specified as the output file. This is suitable for users looking to get the results in a structured format apart from JSON.

## Contributing
Mitig&te is fully modular and enumerations can be added by dropping the relevant file into the logical file location, include in the Visual Studio Solution Explorer and compile. An enumeration template is provided at ./Mitigate/EnumerationTemplate.cs.

If you are considering contributing and have further questions don't hesitate to open an issue.

## Issues and Feature Requests
MITIG&TE has been tested on Windows 10 64bit in a simple AD lab based on [Detection Lab](https://github.com/clong/DetectionLab). However, for any bug reports and features request please raise an issue. For now, bugs will carry higher priority than new feature requests.

## Inspirations
- [MITRE ATT&CK™](https://attack.mitre.org)
- [WinPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)
- [SeatBelt](https://github.com/GhostPack/Seatbelt)
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
- [DeTTECT](https://github.com/rabobank-cdc/DeTTECT)

## Acknowlegments
MITIG&TE makes use of a number of slightly adapted code snippets found through research for its checks. I have marked those code snippets and added a link to the source in each case but please don't hesitate to [contact me](https://t.me/mitigate) if you find anything not listed.

## Disclaimer
MITIG&TE is to be used only when authorized and/or for educational purposes only and comes with no guarantee. Its findings should not be actioned before testing and consideration on user impact.

## Full list of enumerations
### Account Use Policies
No enumerations defined for the mitigation yet
### Active Directory Configuration
No enumerations defined for the mitigation yet
### Antivirus/Antimalware
|Mitigation Description | Enumeration Details | Enumeration Class | Techniques Covered |
|---|---|---|---|
|Consider utilizing the Antimalware Scan Interface (AMSI) on Windows 10 to analyze commands after being processed/interpreted.|Checks if any providers has been registered for AMSI|AMSI.cs|T1027|
|Anti-virus can be used to automatically quarantine suspicious files.|Checks if any antivirus is registered (WMI-based)|Antivirus.cs|T1059, T1059.001, T1059.005, T1059.006, T1027.002, T1566, T1566.001, T1566.003, T1221|
### Application Developer Guidance
No enumerations defined for the mitigation yet
### Application Isolation and Sandboxing
|Mitigation Description | Enumeration Details | Enumeration Class | Techniques Covered |
|---|---|---|---|
|Browser sandboxes can be used to mitigate some of the impact of exploitation, but sandbox escapes may still exist.|List installed browsers and checks their sandboxing status|BrowserSandboxes.cs|T1189, T1203|
|Ensure Office Protected View is enabled.|Protected view status|ProtectedView.cs|T1559, T1559.001, T1559.002, T1559.002, T1021.003|
### Audit
No enumerations defined for the mitigation yet
### Behavior Prevention on Endpoint
|Mitigation Description | Enumeration Details | Enumeration Class | Techniques Covered |
|---|---|---|---|
|On Windows 10, enable Attack Surface Reduction (ASR) rules to prevent Visual Basic and JavaScript scripts from executing potentially malicious downloaded conten|VBA/JS ASR rules status|ASRVbaJS.cs|T1059, T1059.005, T1059.007|
|On Windows 10, enable Attack Surface Reduction (ASR) rules to prevent execution of potentially obfuscated scripts. |Obfuscated ASR rules status|ASRObfuscated.cs|T1027|
|On Windows 10, enable Attack Surface Reduction (ASR) rules to block unsigned/untrusted executable files (such as .exe, .dll, or .scr) from running from USB removable drives.|USB ASR rules status|ASRUsb.cs|T1091|
|On Windows 10, enable Attack Surface Reduction (ASR) rules to block processes created by WMI commands from running. Note: many legitimate tools and applications utilize WMI for command execution.|WMI and PSexec ASR rules status|ASRWmi.cs|T1047, T1569, T1569.002, T1546.003|
|On Windows 10, enable Attack Surface Reduction (ASR) rules to secure LSASS and prevent credential stealing.|LSASS ASR rules status|ASRLsass.cs|T1003, T1003.001|
|On Windows 10, enable cloud-delivered protection and Attack Surface Reduction (ASR) rules to block the execution of files that resemble ransomware. (Citation: win10_asr)|Ransomware ASR rules status|ASRRansomware.cs|T1486|
|On Windows 10, enable Attack Surface Reduction (ASR) rules to prevent executable files from running unless they meet a prevalence, age, or trusted list criteria|Prevelance ASR rules status|ASR.cs|T1055, T1559, T1559.002, T1204, T1204.002|
|On Windows 10, enable Attack Surface Reduction (ASR) rules to prevent DDE attacks and spawning of child processes from Office programs.|Office ASR rules status|ASROffice.cs|T1055, T1559, T1559.002, T1204, T1204.002, T1106, T1137, T1137.001, T1137.002, T1137.003, T1137.004, T1137.005, T1137.006|
|Some endpoint security solutions can be configured to block some types of process injection based on common sequences of behavior that occur during the injection process.|TODO|EndpointSecuritySolutions.cs|T1189, T1203|
### Boot Integrity
No enumerations defined for the mitigation yet
### Code Signing
|Mitigation Description | Enumeration Details | Enumeration Class | Techniques Covered |
|---|---|---|---|
|Set PowerShell execution policy to execute only signed scripts.|Checks if the default powershell execution policy only allows for the execution of signed scripts|PowershellExecutionPolicy.cs|T1059.001, T1546.013|
|Require signed binaries|Checks if and Software Restriction Policies enforce signed binaries|SoftwareRestrictionPolicies.cs|T1036.001, T1036.005|
### Credential Access Protection
No enumerations defined for the mitigation yet
### Data Backup
No enumerations defined for the mitigation yet
### Data Loss Prevention
No enumerations defined for the mitigation yet
### Disable or Remove Feature or Program
|Mitigation Description | Enumeration Details | Enumeration Class | Techniques Covered |
|---|---|---|---|
|InstallUtil may not be necessary within a given environment.|Checks if InstallUtil is removed|InstallUtil.cs|T1218.004|
|Regsvcs and Regasm may not be necessary within a given environment.|Checks if odbcconf is removed|Odbcconf.cs|T1218.008|
|Use Group Policy to disable screensavers if they are unnecessary.|Checks if ScreenSavers are disabled|ScreenSavers.cs|T1546.002|
|Disable the SSH service if it is unnecessary.|Checks if SSH is disabled|SSH.cs|T1563|
|Disable Autorun if it is unnecessary.|Check if Autorun is disabled|Autorun.cs|T1092, T1052, T1052.001, T1091|
|Disable Bluetooth in local computer security settings or by group policy if it is not needed within an environment.|TODO|Bluetooth.cs|T1011.001|
|CMSTP.exe may not be necessary within a given environment (unless using it for VPN connection installation).|Checks if CMSTP is removed|CMSTP.cs|T1218.003|
|Consider disabling DCOM through Dcomcnfg.exe.|Checks if DCOM is disabled|DCOM.cs|T1021.003|
|Registry keys specific to Microsoft Office feature control security can be set to disable automatic DDE/OLE execution. Microsoft also created, and enabled by default, Registry keys to completely disable DDE execution in Word and Excel.|Checks DDE/OLE automatic execution is disabled|DDEExecution.cs|T1559, T1559.002, T1137, T1221|
|Disable Hyper-V if not necessary within a given environment.|Checks if Hyper-V is disabled|HyperV.cs|T1564.006|
|Disable LLMNR and NetBIOS in local computer security settings or by group policy if they are not needed within an environment.|Checks LLMNR and NetBIOS are disabled|LLMNRandNetBios.cs|T1557.001|
|MSBuild.exe may not be necessary within an environment and should be removed if not being used.|Checks if MSBuild exists|MSbuild.cs|T1127.001|
|Mshta.exe may not be necessary within a given environment since its functionality is tied to older versions of Internet Explorer that have reached end of life.|Checks if Mshta is removed|MSHTA.cs|T1218.005|
|Disable Office add-ins. If they are required, follow best practices for securing them by requiring them to be signed and disabling user notification for allowing add-ins. For some add-ins types (WLL, VBA) additional mitigation is likely required as disabling add-ins in the Office Trust Center does not disable WLL nor does it prevent VBA code from executing.|Checks if Office add-ins are disabled|OfficeAddins.cs|T1137.001, T1137, T1221|
|It may be possible to remove PowerShell from systems when not needed, but a review should be performed to assess the impact to an environment, since it could be in use for many legitimate purposes and administrative functions.|Checks for SRP policies on Powershell|PowerShell.cs|T1059.001|
|Disable the RDP service if it is unnecessary.|Checks if RDP is disabled|RDP.cs|T1563, T1563.002, T1021.001|
|Regsvcs and Regasm may not be necessary within a given environment.|Checks if Regsvcs and Regasm are removed|RegsvcsRegasm.cs|T1218.009|
|Turn off or restrict access to unneeded VB components.|Checks if VBA is disabled for office|VisualBasic.cs|T1059.005, T1564.007|
|Disable the WinRM service.|Checks if WinRM is disabled|WinRM.cs|T1021.006|
|Consider disabling the AlwaysInstallElevated policy to prevent elevated execution of Windows Installer packages.|Checks if the AlwaysInstallElevated registry key is disabled|AlwaysInstallElevatedDisabled.cs|T1218.007|
|Anti-virus can be used to automatically quarantine suspicious files.|Checks if any antivirus is registered (WMI-based)|WakeUpOnLanDisabled.cs|T1059|
|Consider enabling the “Network access: Do not allow storage of passwords and credentials for network authentication” setting that will prevent network credentials from being stored by the Credential Manager.|Checks if the storage of password and credentials for network authentication is disable|VisualBasic.cs|T1555.004|
### Do Not Mitigate
No enumerations defined for the mitigation yet
### Encrypt Sensitive Information
No enumerations defined for the mitigation yet
### Environment Variable Permissions
No enumerations defined for the mitigation yet
### Execution Prevention
|Mitigation Description | Enumeration Details | Enumeration Class | Techniques Covered |
|---|---|---|---|
|Set a browser extension allow or deny list as appropriate for your security policy.|Checks if a Chrome Extension Whitelist is enforced|BrowserExtensions.cs|T1176|
|Consider using application control configured to block execution of CMSTP.exe if it is not required for a given system or network to prevent potential misuse by adversaries.|Checks for SRP or AppLocker restrictions on CMSTP|CSMTP.cs|T1218.003|
|Consider using application control to prevent execution of hh.exe if it is not required for a given system or network to prevent potential misuse by adversaries.|Checks for SRP or AppLocker restrictions on hh.exe|CompiledHTMLFiles.cs|T1218.001|
|Use application control configured to block execution of InstallUtil.exe if it is not required for a given system or network to prevent potential misuse by adversaries.|Checks for SRP or AppLocker restrictions on InstallUtil.exe|InstallUtil.cs|T1218.004|
|Use application control configured to block execution of mshta.exe if it is not required for a given system or network to prevent potential misuse by adversaries.|Checks for SRP or AppLocker restrictions on mshta.exe|Mshta.cs|T1218.005|
|Block execution of Odbcconf.exe if they are not required for a given system or network to prevent potential misuse by adversaries.|Checks for SRP or AppLocker restrictions on odbcconf.exe|Odbcconf.cs|T1218.008|
|Certain signed scripts that can be used to execute other programs may not be necessary within a given environment. Use application control configured to block execution of these scripts if they are not required for a given system or network to prevent potential misuse by adversaries.|Checks for SRP or AppLocker restrictions on PubPrn.vbs|PubPrn.cs|T1216.001|
|Block execution of Regsvcs.exe and Regasm.exe if they are not required for a given system or network to prevent potential misuse by adversaries.|Checks for SRP or AppLocker restrictions on Regasm.exe and/or REgsvcs.exe|RegasmRegsvcs.cs|T1218.009|
|Block .scr files from being executed from non-standard locations.|Checks for SRP or AppLocker restrictions on .scr files|ScreenSaver.cs|T1546.002|
| Identify and block potentially malicious software executed through accessibility features functionality by using application control tools, like Windows Defender Application Control, AppLocker, or Software Restriction Policies where appropriate.|Checks for SRP or AppLocker restrictions on unknown binaries|UnknownBinaries.cs|T1548, T1546.006, T1546.008, T1574.007, T1574.008, T1574.009, T1106, T1219, T1218, T1080, T1204, T1204.002|
|Identify and block potentially malicious software by using application control tools like Windows Defender Application Control, AppLocker, or Software Restriction Policies [6 that are capable of auditing and/or blocking unknown DLLs.|Checks if SRPs or Applocker is enabled for DLLs|UnknownDLLs.cs|T1547.004, T1546.009, T1546.010, T1574, T1574.001, T1574.006, T1574.012, T1129, T1553.003|
|Block execution of Verclsid if they are not required for a given system or network to prevent potential misuse by adversaries.|Checks for SRP or AppLocker restrictions on Verclsid.exe|Verclsid.cs|T1218.012|
### Exploit Protection
|Mitigation Description | Enumeration Details | Enumeration Class | Techniques Covered |
|---|---|---|---|
|Microsoft's Enhanced Mitigation Experience Toolkit (EMET) Attack Surface Reduction (ASR) feature can be used to block methods of using rundll32.exe to bypass application control.|Enumerates the status of all ASR rules|AttackSurfaceReduction.cs|T1189, T1203, T1068, T1211, T1212, T1210, T1080, T1218.011, T1218.010|
|Security applications that look for behavior used during exploitation such as Windows Defender Exploit Guard (WDEG) and the Enhanced Mitigation Experience Toolkit (EMET) can be used to mitigate some exploitation behavior. Control flow integrity checking is another way to potentially identify and stop a software exploit from occurring. Many of these protections depend on the architecture and target application binary for compatibility.|Checks for the status of Exploit Protection, Network Protection and ASR rules|WindowsExploitGuard.cs|T1189, T1203, T1068, T1211, T1212, T1210, T1080|
### Filter Network Traffic
No enumerations defined for the mitigation yet
### Limit Access to Resource Over Network
No enumerations defined for the mitigation yet
### Limit Hardware Installation
No enumerations defined for the mitigation yet
### Limit Software Installation
No enumerations defined for the mitigation yet
### Multi-factor Authentication
No enumerations defined for the mitigation yet
### Network Intrusion Prevention
No enumerations defined for the mitigation yet
### Network Segmentation
No enumerations defined for the mitigation yet
### Operating System Configuration
|Mitigation Description | Enumeration Details | Enumeration Class | Techniques Covered |
|---|---|---|---|
|Prevent administrator accounts from being enumerated when an application is elevating through UAC since it can lead to the disclosure of account names. The Registry key is located HKLM\ SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI\EnumerateAdministrators. It can be disabled through GPO: Computer Configuration > [Policies] > Administrative Templates > Windows Components > Credential User Interface: E numerate administrator accounts on elevation|Checks if account enumeration on UAC is disabled|AdminEnumerationPrevention.cs|T1087.001, T1087.002|
|Consider reducing the default BITS job lifetime in Group Policy or by editing the JobInactivityTimeout and MaxDownloadTime Registry values in HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\BITS.|Checks if the BITS job configuration is in line with the CIS benchmarks|BITSJobsLifetimeLimit.cs|T1197|
|Consider limiting the number of cached credentials (HKLM\SOFTWARE\Microsoft\Windows NT\Current Version\Winlogon\cachedlogonscountvalue)|Checks if the cached credentials limit is less than 10|CachedDomainCredsLimit.cs|T1003.005|
|Consider disabling or restricting NTLM.|Checks if both inbound and outbound NTLM is disabled|DisableNTLM.cs|T1003.001, T1003.002|
|Consider disabling or restricting WDigest.|Checks if WDigest is disabled|DisableWDigest.cs|T1003.001, T1003.002|
|Ensure that Network Level Authentication is enabled to force the remote desktop session to authenticate before the session is created and the login screen displayed. It is enabled by default on Windows Vista and later.|Checks if Network Level Authentication of RDP is disabled|NetworkLevelAuthenticationRDP.cs|T1546.008|
|Enable Windows Group Policy 'Do Not Allow Anonymous Enumeration of SAM Accounts and Shares' security setting to limit users who can enumerate network shares.|Checks if the anonymous enumeration of SAM accounts is restricted|NetworkShareDiscoveryPrevention.cs|T1135|
|Change GPOs to define shorter timeouts sessions and maximum amount of time any single session can be active. Change GPOs to specify the maximum amount of time that a disconnected session stays active on the RD session host server.|Checks if RDP sessions timeout limits are set|RDPSessionTimeout.cs|T1021.001|
|Disallow or restrict removable media at an organizational policy level if they are not required for business operations.|Checks if removable storage use is disabled|RemovableMediaRestrictrion.cs|T1092, T1052.001|
|Windows Group Policy can be used to manage root certificates and the Flags value of HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\Root\ProtectedRoots can be set to 1 to prevent non-administrator users from making further root installations into their own HKCU certificate store.|Checks if the addition of new root certificates requires elevated privileges|RootCertAdmin.cs|T1553.004|
|Configure settings for scheduled tasks to force tasks to run under the context of the authenticated account instead of allowing them to run as SYSTEM. The associated Registry key is located at HKLM\SYSTEM\CurrentControlSet\Control\Lsa\SubmitControl. The setting can be configured through GPO: Computer Configuration > [Policies] > Windows Settings > Security Settings > Local Policies > Security Options: Domain Controller: Allow server operators to schedule tasks, set to disabled.|Checks if schedules tasks are not set to run as SYSTEM|ScheduleTasksRunAs.cs|T1053.002, T1053.005|
### Password Policies
|Mitigation Description | Enumeration Details | Enumeration Class | Techniques Covered |
|---|---|---|---|
|Organizations may consider weighing the risk of storing credentials in web browsers. If web browser credential disclosure is a significant concern, technical controls, policy, and user training may be used to prevent storage of credentials in web browsers.|Checks if the Chrome Password Manager is disabled|ChromePasswordManager.cs|T1555.003|
|Refer to NIST guidelines when creating password policies.|Checks if the Windows password policies are in line with the NIST guidelines|NISTGuidelines.cs|T1110.001, T1110.002, T1110.003, T1110.004, T1187, T1003.006, T1003.002, T1003.003, T1003.004, T1003.005, T1021.002, T1550.003, T1078.003|
### Pre-compromise
No enumerations defined for the mitigation yet
### Privileged Account Management
No enumerations defined for the mitigation yet
### Privileged Process Integrity
No enumerations defined for the mitigation yet
### Remote Data Storage
No enumerations defined for the mitigation yet
### Restrict File and Directory Permissions
No enumerations defined for the mitigation yet

### Restrict Library Loading
No enumerations defined for the mitigation yet
### Restrict Registry Permissions
No enumerations defined for the mitigation yet
### Restrict Web-Based Content
No enumerations defined for the mitigation yet
### SSL/TLS Inspection
No enumerations defined for the mitigation yet
### Software Configuration
No enumerations defined for the mitigation yet
### Threat Intelligence Program
No enumerations defined for the mitigation yet
### Update Software
No enumerations defined for the mitigation yet
### User Account Control
No enumerations defined for the mitigation yet
### User Account Management
No enumerations defined for the mitigation yet
### User Training
No enumerations defined for the mitigation yet
### Vulnerability Scanning
No enumerations defined for the mitigation yet



## License: MIT
[MITIG&TE's license](https://github.com/moullos/Mitigate/blob/master/LICENSE)