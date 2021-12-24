using System;

namespace Mitigate.Enumerations
{
    [Flags]
    public enum ResultType
    {
        TestNotImplemented,    // Mitigation enumaration is not implemented (yet)
        NA,                    // Mitigation enumeration is implemented, but it does not apply to this machine
        False,                 // Mitigation is not applied
        True,                  // Mitigation is applied
        Partial,               // Mitigation is partially applied
        TestFailed,            // Mitigation enumeration failed
        CannotBeMeasured,      // Mitigation is not quantifiable using machine interrogation e.g. User Training, Network Segmentation etc
        NoMitigationAvailable  // Technique cannot be mitigated
    }
}
