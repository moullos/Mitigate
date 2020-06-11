# MITIG&TE

**Machine Interrogation To Identify Gaps & Techniques for Execution**

MITIG&TE automatically enumerates Windows settings in order to identify MITRE ATT&CK™ techniques mitigated due to configuration hardening and existing endpoint controls. It heavily relies on the amazing work of the MITRE ATT&CK™ team and the mitigations defined for each of the techniques. 

## Goals

This tool aims to allow security teams to easily account and track the impact of endpoint configuration hardening and controls have against their threat profile. Use MITIG&TE to:
 - Identify techniques that are currently mitigated/less likely to be executed successfully.
 - Highlight techniques that can be easily mitigated.
 - Combine with threat intelligence and your existing blue teaming capabilities to get a holistic view of you security posture mapped against ATT&CK

## Quick Start and Example
If you would like to try MITIG&TE you can either compile it yourself or use the precompiled files in [bin](./bin). 

```
./Mitigate.exe results.json # Outputs findings into results.json

=====( initial-access )=======================================================================================
[i] T1566     Phishing........................................................................................
[*] T1566.001 Spearphishing Attachment........................................................................
              AV detected?...................................................................................√
[*] T1566.002 Spearphishing Link..............................................................................
[*] T1566.003 Spearphishing via Service.......................................................................
              AV detected?...................................................................................√
[i] T1078     Valid Accounts..................................................................................
[*] T1078.001 Default Accounts................................................................................
[*] T1078.002 Domain Accounts.................................................................................
              Are domain users local admins?.................................................................X
[*] T1078.003 Local Accounts..................................................................................
              LAPS enabled?..................................................................................X

=====( execution )============================================================================================
...
```
MITIG&TE outputs a json file that can be ingested by the [ATT&CK™ Navigator](https://mitre-attack.github.io/attack-navigator/beta/enterprise/) for easy visualisation. Take a look at the example [here](https://mitre-attack.github.io/attack-navigator/beta/enterprise/#layerURL=https://raw.githubusercontent.com/moullos/Mitigate/master/examples/result.json). 

## Status
Current coverage [here](https://mitre-attack.github.io/attack-navigator/beta/enterprise/#layerURL=https://raw.githubusercontent.com/moullos/Mitigate/master/examples/Coverage.json).


## Let's make MITIG&TE a reality 
Currently MITIG&TE is under development and only covers a small number of ATT&CK techniques. I will be gradually expanding coverage (as availability allows). If you would like to contribute please [contact me](https://t.me/moullos). 

## Disclaimer
I am not a software development so I apologise in advance for the state of the code. Hopefully, I will be able to focus a bit more on my code cleanliness and add more comments in the future.

## Acknowledgements/Inspirations
- [MITRE ATT&CK™](https://attack.mitre.org)
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
- [Privilege Escalation Awesome Scripts Suite(PEASS)](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)
- [DeTTECT](https://github.com/rabobank-cdc/DeTTECT)

## License: MIT
[MITIG&TE's license](https://github.com/moullos/Mitigate/blob/master/LICENSE)