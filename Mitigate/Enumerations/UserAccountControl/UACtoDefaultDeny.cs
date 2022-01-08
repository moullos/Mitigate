using Mitigate.Utils;
using System.Collections.Generic;
using System.Linq;

namespace Mitigate.Enumerations
{
    class UACtoDefaultDeny : Enumeration
    {
        public override string Name => "Disable UAC's privilege elevation for standard users";
        public override string MitigationType => MitigationTypes.UserAccountControl;
        public override string MitigationDescription => @"Turn off UAC's privilege elevation for standard users [HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System] to automatically deny elevation requests, add: ConsentPromptBehaviorUser=dword:00000000. Consider enabling installer detection for all users by adding: EnableInstallerDetection=dword:00000001. This will prompt for a password for installation and also log the attempt. To disable installer detection, instead add: EnableInstallerDetection=dword:00000000. This may prevent potential elevation of privileges through exploitation during the process of UAC detecting the installer, but will allow the installation process to continue without being logged.";
        public override string EnumerationDescription => "Checks if UAC's privilege elevation is set to default deny";

        public override string[] Techniques => new string[] {
            "T1574",
            "T1574.005",
            "T1574.010"
        };

        public override IEnumerable<EnumerationResults> Enumerate(Context context)
        {
            // Consent Behaviour Settings
            var RegPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
            var RegName = @"ConsentPromptBehaviorUser";
            var ConsentPromtpBehaviorUserValue = Helper.GetRegValue("HKLM", RegPath, RegName);
            yield return new BooleanConfig("UAC's privilege escalation default deny", ConsentPromtpBehaviorUserValue == "0");

            // Enable Installer Detection for all users
            RegName = @"EnableInstallerDetection";
            var EnableInstallerDetectionValue = Helper.GetRegValue("HKLM", RegPath, RegName);
            yield return new BooleanConfig("Installed Detection", EnableInstallerDetectionValue == "1");
        }
    }
}
