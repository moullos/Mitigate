using System;
using System.Collections.Generic;
using System.Xml.Linq;

namespace Mitigate.Utils
{
    class AppLockerUtils
    {
        public static bool IsAppLockerRunning()
        {
            return Helper.IsServiceRunning("AppIDSvc");
        }

        public static bool IsAppLockerEnabled(string type)
        {
            Dictionary<string, string> ValidRuleTypes = new Dictionary<string, string>()
            {
                {"Executable Rules", "Exe" },
                {"Windows Installer Rules", "Msi"},
                {"Script Rules", "Script" },
                {"Packaged App Rules", "Appx"},
                {"DLL", "Dll" }
            };
            if (!ValidRuleTypes.ContainsKey(type))
            {
                throw new Exception("IsAppLockerEnabled: Unknown AppLocker Rule Type");
            }
            var RegPath = String.Format(@"Software\Policies\Microsoft\Windows\SrpV2\{0}", ValidRuleTypes[type]);
            if (Helper.RegExists("HKLM", RegPath))
            {
                return Helper.GetRegValue("HKLM", RegPath, "EnforcementMode") != "0";
            }
            return false;
        }
        public static bool IsAppLockerEnabled()
        {
            Dictionary<string, string> ValidRuleTypes = new Dictionary<string, string>()
            {
                {"Executable Rules", "Exe" },
                {"Windows Installer Rules", "Msi" },
                {"Script Rules", "Script" },
                {"Packaged App Rules", "Appx"},
                {"DLL", "Dll" }
            };
            foreach (var RuleType in ValidRuleTypes.Keys)
            {
                if (IsAppLockerEnabled(RuleType))
                    return true;
            }
            return false;
        }

        public static IEnumerable<ASRRule> GetAppLockerRules(string type)
        {
            Dictionary<string, string> ValidRuleTypes = new Dictionary<string, string>()
            {
                {"Executable Rules", "Exe" },
                {"Windows Installer Rules", "Msi" },
                {"Script Rules", "Script" },
                {"Packaged App Rules", "Appx"},
                {"DLL", "Dll" }
            };
            if (!ValidRuleTypes.ContainsKey(type))
            {
                throw new Exception("Unknown AppLocker Rule Type");
            }
            Dictionary<string, bool> RulesInfo = new Dictionary<string, bool>();
            var RegPath = String.Format(@"Software\Policies\Microsoft\Windows\SrpV2\{0}", ValidRuleTypes[type]);
            var RuleIDs = Helper.GetRegSubkeys("HKML", RegPath);
            foreach (var RuleID in RuleIDs)
            {
                RegPath = String.Format(@"Software\Policies\Microsoft\Windows\SrpV2\{0}\{1}", ValidRuleTypes[type], RuleID);
                XElement Rule = XElement.Parse(Helper.GetRegValue("HKML", RegPath, "Value"));
                var RuleName = Rule.Attribute("Name").Value;
                var RuleDescription = Rule.Attribute("Description").Value;
                var RuleAction = Rule.Attribute("Action").Value;
                yield return new ASRRule(RuleName, RuleDescription, RuleAction);
            }
        }
        public static bool CheckApplockerPolicyforDenied(string ExecPath, string UserName)
        {
            // Will possibly trigger AV. 
            string CommandMask = @"Get-AppLockerPolicy -Effective | Test-AppLockerPolicy -Path '{0}' -User '{1}' -Filter Denied,DeniedByDefault";
            string Command = String.Format(CommandMask, ExecPath, UserName);
            var CommandResult = Helper.Base64EncodedCommand(Command);
            var output = CommandResult.Item1;
            var err = CommandResult.Item2;
            var ExitCode = CommandResult.Item3;
            if (ExitCode != 0)
            {
                throw new Exception($"CheckApplockerPolicyforDenied: Path={ExecPath} Username={UserName}");
            }
            return !string.IsNullOrEmpty(output);
        }
    }
    public class ASRRule 
    {
        public string Name;
        public string Description;
        public string Action;

        public ASRRule(string RuleName,string  RuleDescription, string RuleAction)
        {
            this.Name = RuleName;
            this.Description = RuleDescription;
            this.Action = RuleAction;
        }
    }
}
