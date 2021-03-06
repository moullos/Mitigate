# MITIG&TE

**Machine Interrogation To Identify Gaps & Techniques for Execution**

MITIG&TE is a Windows binary that automatically enumerates Windows settings in order to identify MITRE ATT&CK™ techniques mitigated due to configuration hardening and existing endpoint controls. It relies heavily on the amazing work of the MITRE ATT&CK™ team and the [mitigations](https://attack.mitre.org/mitigations/enterprise/) defined for each of the techniques. It is written in C# and it's dependent on .NET Framework v4.

## Goals
The tool aims to allow security teams to easily account and track the impact endpoint configuration hardening and controls have against their threat profile. Additionally it can be used to identify configuration hardening settings that can further improve security posture. Use MITIG&TE to:
 - Identify techniques that are currently mitigated/less likely to be executed successfully, posing less risk to your environment
 - Surface non-applied endpoint controls that can improve endpoint hardening
 - Combine with threat intelligence and your existing detection capabilities to get a holistic view of your security posture mapped against ATT&CK

## Status
MITIG&TE is currently under development. Current coverage [here](https://mitre-attack.github.io/attack-navigator/enterprise/#layerURL=https://raw.githubusercontent.com/moullos/Mitigate/master/examples/Coverage.json). 

## Quick Start and Example
If you would like to try MITIG&TE you can either compile it yourself (recommended) or use the latest released version. For maximum effectiveness, consider running MITIG&TE as an administrator and specifying a user for the least privilege checks. Ideally, that user should have the same privileges as a typical end-user in your environment. By default, MITIG&TE performs the checks for the last logged-in user. When executed, MITIG&TE will pull the latest ATT&CK information and iterate over all the Windows techniques, pulling information on the mitigations defined for each one. 
```
Mitigate.exe -OutFile=results.json                 # Outputs findings into results.json
Mitigate.exe -OutFile=results.json -UserName=user1 # Outputs findings into results.json and performs least privileges checks for user1
``` 
![](https://github.com/moullos/Mitigate/blob/master/examples/Screenshot.png?raw=true)

## Output
In addition to the console output, MITIG&TE outputs a json file that can be ingested by the [ATT&CK™ Navigator](https://mitre-attack.github.io/attack-navigator/enterprise/) for easy visualisation.  Colour scheme used:
- ![](https://via.placeholder.com/15/f4a261/000000?text=+) `No mitigations were detected`
- ![](https://via.placeholder.com/15/e9c46a/000000?text=+) `Some mitigation were detected`
- ![](https://via.placeholder.com/15/2a9d8f/000000?text=+) `All mitigations were detected`
- ![](https://via.placeholder.com/15/009ACD/000000?text=+) `Technique cannot be mitigated`

![](https://github.com/moullos/Mitigate/blob/master/examples/Navigator.PNG?raw=true)

Hovering over a specific technique in the navigator will provide more context on the checks performed. For an interactive example, take a look [here](https://mitre-attack.github.io/attack-navigator/enterprise/#layerURL=https://raw.githubusercontent.com/moullos/Mitigate/master/examples/result.json).

## Contributing
I will be gradually expanding coverage and adding more features as availability allows. All the enumeration logic resides within the [Tests.cs](./Tests.cs) file and a template for contributing additional enumeration modules is given there. If you are considering contributing and have further questions don't hesitate to [contact me](https://t.me/mitigate).

## Issues and Feature Requests
MITIG&TE has been tested on Windows 10 64bit in a simple AD lab. However, for any bug reports and features request please raise an issue. For now, bugs will carry higher priority than new feature requests.

## Inspirations
- [MITRE ATT&CK™](https://attack.mitre.org)
- [WinPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)
- [SeatBelt](https://github.com/GhostPack/Seatbelt)
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
- [DeTTECT](https://github.com/rabobank-cdc/DeTTECT)

## Acknowlegments
MITIG&TE makes use of a number of slightly adapted code snippets found through research for its checks. I have marked those code snippets and added a link to the source in each case but please don't hesitate to [contact me](https://t.me/mitigate) if you find anything not listed.

## Disclaimer
MITIG&TE is to be used only when authorized and/or for educational purposes only. Its findings should not be actioned before testing and consideration on user impact.

## To Do
- [ ] Expand technique coverage (duh!)
- [ ] Improve app whitelisting checks
  - [x] Add support for Applocker rules
  - [ ] Add support for Software Restriction Policies
  - [ ] Add support for Windows Defender Application Control
- [ ] Improve Windows Defender Application Guard enumeration
- [ ] Add support for Windows Defender Exploit Guard
  - [x] ASR rules enumeration
  - [ ] Exploit Protection settings
  - [ ] Control Folder Access settings
  - [ ] Network Protection settings
- [ ] Web File Restriction check functionality (based on the artifacts in the Atomic Red Team project)
- [ ] Automate testing and add CI
- [ ] Add scoring/weight functionality
  - [ ] Define Scoring Framework (The score should indicate the mitigating impact of a control/configuration against a technique)
  - [ ] Assign mitigating scores to enumerations

## License: MIT
[MITIG&TE's license](https://github.com/moullos/Mitigate/blob/master/LICENSE)