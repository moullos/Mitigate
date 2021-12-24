using Mitigate.Utils;
using System.Collections.Generic;


namespace Mitigate.Enumerations
{ 
    class ASRObfuscated : Enumeration
    {
        public override string Name => "ASR Obfuscated";
        public override string MitigationType => MitigationTypes.BehaviorPreventionOnEndpoint;
        public override string MitigationDescription => "On Windows 10, enable Attack Surface Reduction (ASR) rules to prevent execution of potentially obfuscated scripts. ";
        public override string EnumerationDescription => "Obfuscated ASR rules status";

        public override string[] Techniques => new string[] {
            "T1027"
        };

        public override IEnumerable<EnumerationResults> Enumerate(Context context)
        {
            var RelevantRules = new Dictionary<string, string>()
            {
                {"5BEB7EFE-FD9A-4556-801D-275E5FFC04CC","Block execution of potentially obfuscated scripts"},
            };
            foreach(var rule in RelevantRules)
            {
                    yield return new BooleanConfig(rule.Value, ASRUtils.IsRuleEnabled(rule.Key));
            }
        }




    }
}
