using System;
using System.Collections.Generic;

namespace Mitigate.Enumerations
{ 
    class ScreenSaver : Enumeration
    {
        public override string Name => "ScreenSaver";
        public override string MitigationType => MitigationTypes.ExecutionPrevention;
        public override string MitigationDescription => "Block .scr files from being executed from non-standard locations.";
        public override string EnumerationDescription => "Checks for SRP or AppLocker restrictions on .scr files";

        public override string[] Techniques => new string[] {
            "T1546.002",
        };

        public override IEnumerable<EnumerationResults> Enumerate(Context context)
        {
            // TODO : Check scr file restrictions
            yield return new NotImplemented() ;
        }

    }
}
