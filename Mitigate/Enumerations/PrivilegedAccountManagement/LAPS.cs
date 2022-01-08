using Mitigate.Utils;
using System.Collections.Generic;
using System.Linq;

namespace Mitigate.Enumerations
{
    class LAPS : Enumeration
    {
        public override string Name => "LAPS";
        public override string MitigationType => MitigationTypes.PrivilegedAccountManagement;
        public override string MitigationDescription => "Audit local accounts permission levels routinely to look for situations that could allow an adversary to gain wide access by obtaining credentials of a privileged account. These audits should check if new local accounts are created that have not be authorized. Implementing LAPS may help prevent reuse of local administrator credentials across a domain.";
        public override string EnumerationDescription => "Checks the LAPs status";

        public override string[] Techniques => new string[] {
            "T1078",
            "T1078.003"
        };

        public override IEnumerable<EnumerationResults> Enumerate(Context context)
        {
            var LAPsConfig = GetLapsSettings();
            yield return new BooleanConfig("LAPS", LAPsConfig["LAPS Enabled"] == "1");
        }

        private static Dictionary<string, string> GetLapsSettings()
        {
            // From WinPEAS: https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/winPEAS/winPEASexe/winPEAS/SystemInfo.cs
            // https://getadmx.com/?Category=LAPS&Policy=FullArmor.Policies.C9E1D975_EA58_48C3_958E_3BC214D89A2E::POL_AdmPwd
            Dictionary<string, string> results = new Dictionary<string, string>();
            string AdmPwdEnabled = Helper.GetRegValue("HKLM", "Software\\Policies\\Microsoft Services\\AdmPwd", "AdmPwdEnabled");

            if (AdmPwdEnabled != "")
            {
                results["LAPS Enabled"] = AdmPwdEnabled;
                results["LAPS Admin Account Name"] = Helper.GetRegValue("HKLM", "Software\\Policies\\Microsoft Services\\AdmPwd", "AdminAccountName");
                results["LAPS Password Complexity"] = Helper.GetRegValue("HKLM", "Software\\Policies\\Microsoft Services\\AdmPwd", "PasswordComplexity");
                results["LAPS Password Length"] = Helper.GetRegValue("HKLM", "Software\\Policies\\Microsoft Services\\AdmPwd", "PasswordLength");
                results["LAPS Expiration Protection Enabled"] = Helper.GetRegValue("HKLM", "Software\\Policies\\Microsoft Services\\AdmPwd", "PwdExpirationProtectionEnabled");
            }
            else
            {
                results["LAPS Enabled"] = "LAPS not installed";
            }
            return results;
        }
    }
}
