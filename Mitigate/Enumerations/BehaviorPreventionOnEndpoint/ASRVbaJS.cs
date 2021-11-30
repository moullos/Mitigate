using Mitigate.Utils;
using System.Collections.Generic;


namespace Mitigate.Enumerations.BehaviourPreventionOnEndpoint
{
    class ASRVbaJS : Enumeration
    {
        public override string Name => "ASR VBA/JS";
        public override string MitigationType => "Behavior Prevention on Endpoint";
        public override string MitigationDescription => "On Windows 10, enable Attack Surface Reduction (ASR) rules to prevent Visual Basic and JavaScript scripts from executing potentially malicious downloaded conten";
        public override string EnumerationDescription => "VBA/JS ASR rules status";

        public override string[] Techniques => new string[] {
            "T1059",
            "T1059.005",
            "T1059.007"
        };

        public override IEnumerable<EnumerationResults> Enumerate(Context context)
        {
            var RelevantRules = new Dictionary<string, string>()
            {
                {"D3E037E1-3EB8-44C8-A917-57927947596D","Block JavaScript or VBScript from launching downloaded executable content"},
            };
            foreach(var rule in RelevantRules)
            {
                    yield return new BooleanConfig(rule.Value, ASRUtils.IsRuleEnabled(rule.Key));
            }
        }




    }
}
