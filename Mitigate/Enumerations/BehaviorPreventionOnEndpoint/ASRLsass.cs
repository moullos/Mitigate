using Mitigate.Utils;
using System.Collections.Generic;


namespace Mitigate.Enumerations
{
    class ASRLsass : Enumeration
    {
        public override string Name => "ASR LSASS";
        public override string MitigationType => MitigationTypes.BehaviorPreventionOnEndpoint;
        public override string MitigationDescription => "On Windows 10, enable Attack Surface Reduction (ASR) rules to secure LSASS and prevent credential stealing.";
        public override string EnumerationDescription => "LSASS ASR rules status";

        public override string[] Techniques => new string[] {
            "T1003",
            "T1003.001"
        };

        public override IEnumerable<EnumerationResults> Enumerate(Context context)
        {
            var RelevantRules = new Dictionary<string, string>()
            {
                {"9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2","Block credential stealing from the windows local security authority subsystem (lsass.exe)"},
            };
            foreach(var rule in RelevantRules)
            {
                    yield return new BooleanConfig(rule.Value, ASRUtils.IsRuleEnabled(rule.Key));
            }
        }




    }
}
