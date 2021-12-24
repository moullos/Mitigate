using System.Collections.Generic;


namespace Mitigate.Enumerations
{
  
    class Bluetooth : Enumeration
    {
        public override string Name => "Bluetooth Disabled";
        public override string MitigationType => MitigationTypes.DisableOrRemoveFeatureOrProgram;
        public override string MitigationDescription => "Disable Bluetooth in local computer security settings or by group policy if it is not needed within an environment.";
        public override string EnumerationDescription => "TODO";

        public override string[] Techniques => new string[] {
            "T1011.001",
        };

        public override IEnumerable<EnumerationResults> Enumerate(Context context)
        {
            // TODO:
            // Check bluetooth status
            yield return new NotImplemented();
        }
    }
}
