using Mitigate.Utils;
using System.Collections.Generic;


namespace Mitigate.Enumerations
{
    class ASRUsb : Enumeration
    {
        public override string Name => "ASR USB";
        public override string MitigationType => MitigationTypes.BehaviorPreventionOnEndpoint;
        public override string MitigationDescription => "On Windows 10, enable Attack Surface Reduction (ASR) rules to block unsigned/untrusted executable files (such as .exe, .dll, or .scr) from running from USB removable drives.";
        public override string EnumerationDescription => "USB ASR rules status";

        public override string[] Techniques => new string[] {
            "T1091",
        };

        public override IEnumerable<EnumerationResults> Enumerate(Context context)
        {
            var RelevantRules = new Dictionary<string, string>()
            {
                {"b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4","Block untrusted and unsigned processes that run from usb"},
            };
            foreach(var rule in RelevantRules)
            {
                    yield return new BooleanConfig(rule.Value, ASRUtils.IsRuleEnabled(rule.Key));
            }
        }




    }
}
