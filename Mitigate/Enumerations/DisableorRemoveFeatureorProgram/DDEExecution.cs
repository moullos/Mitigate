using Mitigate.Utils;
using System.Collections.Generic;

namespace Mitigate.Enumerations
{
  
    class DDEExecution : Enumeration
    {
        public override string Name => "DDE/OLE disabled";
        public override string MitigationType => MitigationTypes.DisableOrRemoveFeatureOrProgram;
        public override string MitigationDescription => "Registry keys specific to Microsoft Office feature control security can be set to disable automatic DDE/OLE execution. Microsoft also created, and enabled by default, Registry keys to completely disable DDE execution in Word and Excel.";
        public override string EnumerationDescription => "Checks DDE/OLE automatic execution is disabled";
        public override string[] Techniques => new string[] {
            "T1559",
            "T1559.002",
            "T1137",
            "T1221",
        };

        public override IEnumerable<EnumerationResults> Enumerate(Context context)
        {
            foreach (var config in OfficeUtils.GetAutomaticDDEExecutionConf())
            {
                yield return new BooleanConfig("DDE/OLE " + config.Key, config.Value);

            }
        }
    }
}
