using Mitigate.Utils;
using System.Collections.Generic;


namespace Mitigate.Enumerations
{
    class ASRRansomware : Enumeration
    {
        public override string Name => "ASR ransomware Rule";
        public override string MitigationType => MitigationTypes.BehaviorPreventionOnEndpoint;
        public override string MitigationDescription => "On Windows 10, enable cloud-delivered protection and Attack Surface Reduction (ASR) rules to block the execution of files that resemble ransomware. (Citation: win10_asr)";
        public override string EnumerationDescription => "Ransomware ASR rules status";

        public override string[] Techniques => new string[] {
            "T1486",
        };

        public override IEnumerable<EnumerationResults> Enumerate(Context context)
        {
            Dictionary<string, string> RelevantRules = new Dictionary<string, string>()
            {
                {"c1db55ab-c21a-4637-bb3f-a12568109d35","Use advanced protection against ransomware"},
            };
            foreach (var rule in RelevantRules)
            {
                    yield return new BooleanConfig(rule.Value, ASRUtils.IsRuleEnabled(rule.Key));
            }
        }




    }
}
