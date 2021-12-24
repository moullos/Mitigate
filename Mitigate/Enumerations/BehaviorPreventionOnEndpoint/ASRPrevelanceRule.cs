using Mitigate.Utils;
using System.Collections.Generic;


namespace Mitigate.Enumerations
{
    class ASR : Enumeration
    {
        public override string Name => "ASR Prevelance Rule";
        public override string MitigationType => MitigationTypes.BehaviorPreventionOnEndpoint;
        public override string MitigationDescription => "On Windows 10, enable Attack Surface Reduction (ASR) rules to prevent executable files from running unless they meet a prevalence, age, or trusted list criteria";
        public override string EnumerationDescription => "Prevelance ASR rules status";

        public override string[] Techniques => new string[] {
            "T1055",
            "T1559",
            "T1559.002",
            "T1204",
            "T1204.002"
        };

        public override IEnumerable<EnumerationResults> Enumerate(Context context)
        {
            Dictionary<string, string> RelevantRules = new Dictionary<string, string>()
            {
                {"01443614-cd74-433a-b99e-2ecdc07bfc25","Block executable files from running unless they meet a prevalence, age, or trusted list criterion(Requires cloud delivered protection)"},
            };
            foreach (var rule in RelevantRules)
            {
                    yield return new BooleanConfig(rule.Value, ASRUtils.IsRuleEnabled(rule.Key));
            }
        }




    }
}
