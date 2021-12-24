using Mitigate.Utils;
using System.Collections.Generic;

namespace Mitigate.Enumerations
{
    class ChromePasswordManager : Enumeration
    {
        public override string Name => "Chrome Password Manager";
        public override string MitigationType => MitigationTypes.PasswordPolicies;
        public override string MitigationDescription => "Organizations may consider weighing the risk of storing credentials in web browsers. If web browser credential disclosure is a significant concern, technical controls, policy, and user training may be used to prevent storage of credentials in web browsers.";
        public override string EnumerationDescription => "Checks if the Chrome Password Manager is disabled";

        public override string[] Techniques => new string[] {
            "T1555.003",

        
        };

        public override IEnumerable<EnumerationResults> Enumerate(Context context)
        {
            // https://cloud.google.com/docs/chrome-enterprise/policies/?policy=PasswordManagerEnabled
            var RegValue = Helper.GetRegValue("HKLM", @"Software\Policies\Google\Chrome", "PasswordManagerEnabled");
            yield return new DisabledFeature("Chrome Password Manager", RegValue == "1");
        }   
    }
}
