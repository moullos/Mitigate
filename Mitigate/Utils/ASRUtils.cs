using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Mitigate.Utils
{
    class ASRUtils
    {
        internal static bool IsASREnabled()
        {
            string RegPath = @"SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR";
            string RegKey = "ExploitGuard_ASR_Rules";

            return Helper.GetRegValue("HKLM", RegPath, RegKey) == "1" ? true : false;
        }

        internal static bool IsRuleEnabled(string RuleGuid)
        {
            if (!IsASREnabled()) return false;
            string RegPath = @"SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules";
            return Helper.GetRegValue("HKLM", RegPath, RuleGuid) == "1";
        }


        internal static Dictionary<string, bool> GetASRRulesStatus(List<string> RuleGUIDs = null)
        {
            // Well-known ASR rules
            Dictionary<string, string> Guid2Description = new Dictionary<string, string>()
            {
                {"BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550","Block executable content from email client and webmail"},
                {"D4F940AB-401B-4EFC-AADC-AD5F3C50688A","Block all Office applications from creating child processes"},
                {"3B576869-A4EC-4529-8536-B80A7769E899","Block Office applications from creating executable content"},
                {"75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84","Block Office applications from injecting code into other processes"},
                {"D3E037E1-3EB8-44C8-A917-57927947596D","Block JavaScript or VBScript from launching downloaded executable content"},
                {"5BEB7EFE-FD9A-4556-801D-275E5FFC04CC","Block execution of potentially obfuscated scripts"},
                {"92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B","Block Win32 API calls from Office macros"},
                {"01443614-cd74-433a-b99e-2ecdc07bfc25","Block executable files from running unless they meet a prevalence, age, or trusted list criterion(Requires cloud delivered protection)"},
                {"c1db55ab-c21a-4637-bb3f-a12568109d35","Use advanced protection against ransomware"},
                {"9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2","Block credential stealing from the windows local security authority subsystem (lsass.exe)"},
                {"d1e49aac-8f56-4280-b9ba-993a6d77406c","Block process creations originating from psexec and wmi commands"},
                {"b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4","Block untrusted and unsigned processes that run from usb"},
                {"26190899-1602-49e8-8b27-eb1d0a1ce869","Block office communication application from creating child processes"},
                {"7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c","Block adobe reader from creating child processes"},
                {"e6db77e5-3df2-4cf1-b95a-636979351e5b","Block persistence through WMI event subscription"}
            };
            if (RuleGUIDs == null)
            {
                RuleGUIDs = Guid2Description.Keys.ToList();
            }
            Dictionary<string, bool> ASRRulesStatus = new Dictionary<string, bool>();
            string RegPath = @"SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules";
            foreach (string ruleGUID in RuleGUIDs)
            {
                string RuleDescription;
                if (Guid2Description.ContainsKey(ruleGUID))
                {
                    // It's a known rule
                    RuleDescription = Guid2Description[ruleGUID];
                }
                else
                {
                    RuleDescription = String.Format("Unknown Rule({0})", ruleGUID);
                }
                // ruleGUID key needs to be set to 1 for blocking
                ASRRulesStatus[RuleDescription] = Helper.GetRegValue("HKLM", RegPath, ruleGUID) == "1" ? true : false;
            }
            return ASRRulesStatus;
        }
    }
}
