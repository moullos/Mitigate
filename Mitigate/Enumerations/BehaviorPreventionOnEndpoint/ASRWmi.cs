using Mitigate.Utils;
using System.Collections.Generic;


namespace Mitigate.Enumerations
{ 
    class ASRWmi : Enumeration
    {
        public override string Name => "ASR/PSexec WMI";
        public override string MitigationType => MitigationTypes.BehaviorPreventionOnEndpoint;
        public override string MitigationDescription => "On Windows 10, enable Attack Surface Reduction (ASR) rules to block processes created by WMI commands from running. Note: many legitimate tools and applications utilize WMI for command execution.";
        public override string EnumerationDescription => "WMI and PSexec ASR rules status";

        public override string[] Techniques => new string[] {
            "T1047",
            "T1569",
            "T1569.002",
            "T1546.003",
            
        };

        public override IEnumerable<EnumerationResults> Enumerate(Context context)
        {
            var RelevantRules = new Dictionary<string, string>()
            {
                {"d1e49aac-8f56-4280-b9ba-993a6d77406c","Block process creations originating from psexec and wmi commands"},
                {"e6db77e5-3df2-4cf1-b95a-636979351e5b","Block persistence through WMI event subscription"}
            };
            foreach(var rule in RelevantRules)
            {
                    yield return new BooleanConfig(rule.Value, ASRUtils.IsRuleEnabled(rule.Key));
            }
        }




    }
}
