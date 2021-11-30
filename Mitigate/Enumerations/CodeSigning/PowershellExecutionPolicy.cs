using Mitigate.Utils;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;

namespace Mitigate.Enumerations.CodeSigning
{
    class PowershellExecutionPolicy : Enumeration
    {
        public override string Name => "Powershell Execution Policy";
        public override string MitigationType => "Code Signing";
        public override string MitigationDescription => "Set PowerShell execution policy to execute only signed scripts.";
        public override string EnumerationDescription => "Checks if the default powershell execution policy only allows for the execution of signed scripts";

        public override string[] Techniques => new string[] {
            "T1059.001",
            "T1546.013"
        };

        public override IEnumerable<EnumerationResults> Enumerate(Context context)
        {
            var policy = GetPSExecutionPolicy();
            string[] SatisfyingPolicies = { "AllSigned", "RemoteSigned", "Restricted" };
            yield return new BooleanConfig("Only signed scripts execution policy", SatisfyingPolicies.Contains(policy));
        }

        private string GetPSExecutionPolicy()
        {
            // Priority is: Machine Group Policy, Current User Group Policy, Current Session, Current User, Local Machine
            // Machine Group Policy
            var ExecutionPolicy = Helper.GetRegValue("HKLM", @"Software\Policies\Microsoft\Windows\PowerShell", "ExecutionPolicy");
            if (ExecutionPolicy != "")
            {
                return ExecutionPolicy;
            }
            // Current User Group Policy
            ExecutionPolicy = Helper.GetRegValue("HKCU", @"Software\Policies\Microsoft\Windows\PowerShell", "ExecutionPolicy");
            if (ExecutionPolicy != "")
            {
                return ExecutionPolicy;
            }
            // Execution Policy is not set by Group Policy. Policy restrictions can be bypassed.
            return "Unrestricted";
        }
    }
}
