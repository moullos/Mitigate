using Mitigate.Utils;
using System.Collections.Generic;


namespace Mitigate.Enumerations.BehaviourPreventionOnEndpoint
{
    class ASROffice : Enumeration
    {
        public override string Name => "ASR Office";
        public override string MitigationType => "Behavior Prevention on Endpoint";
        public override string MitigationDescription => "On Windows 10, enable Attack Surface Reduction (ASR) rules to prevent DDE attacks and spawning of child processes from Office programs.";
        public override string EnumerationDescription => "Office ASR rules status";

        public override string[] Techniques => new string[] {
            "T1055",
            "T1559",
            "T1559.002",
            "T1204",
            "T1204.002",
            "T1106",
            "T1137",
            "T1137.001",
            "T1137.002",
            "T1137.003",
            "T1137.004",
            "T1137.005",
            "T1137.006"
            

        };

        public override IEnumerable<EnumerationResults> Enumerate(Context context)
        {
            var RelevantRules = new Dictionary<string, string>()
            {
                { "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550","Block executable content from email client and webmail rule"},
                { "D4F940AB-401B-4EFC-AADC-AD5F3C50688A","Block all Office applications from creating child processes rule"},
                { "3B576869-A4EC-4529-8536-B80A7769E899","Block Office applications from creating executable content rule"},
                { "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84","Block Office applications from injecting code into other processes rule"},
                { "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B","Block Win32 API calls from Office macros rule"},
                {"7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c","Block adobe reader from creating child processes"},
                { "26190899-1602-49e8-8b27-eb1d0a1ce869","Block office communication application from creating child processes rule"},
            };
            foreach(var rule in RelevantRules)
            {
                    yield return new BooleanConfig(rule.Value, ASRUtils.IsRuleEnabled(rule.Key));
            }
        }




    }
}
