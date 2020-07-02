# MITIG&TE

**Machine Interrogation To Identify Gaps & Techniques for Execution**

MITIG&TE is a Windows binary that automatically enumerates Windows settings in order to identify MITRE ATT&CK™ techniques mitigated due to configuration hardening and existing endpoint controls. It relies heavily on the amazing work of the MITRE ATT&CK™ team and the mitigations defined for each of the techniques. It is written in C# and it's dependent on .Net Framework v4.

## Goals
The tool aims to allow security teams to easily account and track the impact of endpoint configuration hardening and controls have against their threat profile. Additionally it can be used to identify  configuration hardening settings that can further improve security posture. Use MITIG&TE to:
 - Identify techniques that are currently mitigated/less likely to be executed successfully, posing less risk to your environment.
 - Surface non-applied endpoint controls that can improve endpoint hardening.
 - Combine with threat intelligence and your existing detection capabilities to get a holistic view of your security posture mapped against ATT&CK.

## Status
MITIG&TE is currently under development. Current coverage [here](https://mitre-attack.github.io/attack-navigator/beta/enterprise/#layerURL=https://raw.githubusercontent.com/moullos/Mitigate/master/examples/Coverage.json). 

## Quick Start and Example
If you would like to try MITIG&TE you can either compile it yourself (recommended) or use the precompiled files in [bin](./bin). For maximum effectiveness run MITIG&TE as an administrator and specify a user for the least privilege checks. Ideally, that user should have the same privileges as a typical end-user in your environment. By default, mitigates performs the checks for the last logged-in user.

```
Mitigate.exe -OutFile=results.json                 # Outputs findings into results.json
Mitigate.exe -OutFile=results.json -UserName=user1 # Outputs findings into results.json and performs least privileges checks for user1
``` 
![](https://github.com/moullos/Mitigate/blob/master/examples/Screenshot.png?raw=true)

## Output
In addition to the console output, MITIG&TE outputs a json file that can be ingested by the [ATT&CK™ Navigator](https://mitre-attack.github.io/attack-navigator/beta/enterprise/) for easy visualisation. Take a look at the example [here](https://mitre-attack.github.io/attack-navigator/beta/enterprise/#layerURL=https://raw.githubusercontent.com/moullos/Mitigate/master/examples/result.json). Colour scheme used:
- ![](https://via.placeholder.com/15/f4a261/000000?text=+) `No mitigations were detected`
- ![](https://via.placeholder.com/15/e9c46a/000000?text=+) `Some mitigation were detected`
- ![](https://via.placeholder.com/15/2a9d8f/000000?text=+) `All mitigations were detected`
- ![](https://via.placeholder.com/15/009ACD/000000?text=+) `Technique cannot be mitigated`

Hovering over a specific technique in the navigator will provide more context on the enumeration performed. Please note that this feature does not work correctly in the current version of the navigator. The bug has been [fixed](https://github.com/mitre-attack/attack-navigator/issues/153) and is part of the new version of the navigator(v3.1) published very soon. 

## Let's make MITIG&TE a reality 
I will be gradually expanding coverage and testing as availability allows. All the enumeration logic resides within the [Tests.cs](./Tests.cs) file and a template for contributing additional enumeration modules is given there. 

## Issues and Feature Requests
MITIG&TE has been tested on Windows 10 in a simple AD lab. For any bug reports and features request please raise an issue. For now, bugs will carry higher priority than new feature requests.

## Inspirations
- [MITRE ATT&CK™](https://attack.mitre.org)
- [WinPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)
- [SeatBelt](https://github.com/GhostPack/Seatbelt)
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
- [DeTTECT](https://github.com/rabobank-cdc/DeTTECT)

## Acknowlegments
MITIG&TE makes use of a number of slightly adapted code snippets found through research for its checks. I have marked those code snippets and added a link to the source in the code but please don't hesitate to contact me if you find anything not listed.

## To Do
- [ ] Expand technique coverage
- [ ] Improve app whitelisting check
- [ ] Web File Restriction check functionality (based on the artifacts in Atomic Red Team)
- [ ] Automate testing
- [ ] Flag for recursive WMI checks

## License: MIT
[MITIG&TE's license](https://github.com/moullos/Mitigate/blob/master/LICENSE)