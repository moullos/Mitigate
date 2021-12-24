using Mitigate.Utils;
using System.Collections.Generic;

namespace Mitigate.Enumerations
{ 
    class BrowserExtensions : Enumeration
    {
        public override string Name => "Browser Extensions";
        public override string MitigationType => MitigationTypes.ExecutionPrevention;
        public override string MitigationDescription => "Set a browser extension allow or deny list as appropriate for your security policy.";
        public override string EnumerationDescription => "Checks if a Chrome Extension Whitelist is enforced";

        public override string[] Techniques => new string[] {
            "T1176",
        };

        public override IEnumerable<EnumerationResults> Enumerate(Context context)
        {
            yield return new BooleanConfig("Chrome Whitelist", IsChromeExtensionWhitelistEnabled());

        }


        private static bool IsChromeExtensionWhitelistEnabled()
        {
            // https://cloud.google.com/docs/chrome-enterprise/policies/?policy=ExtensionInstallWhitelist
            // Looking for whitelisted extensions
            string[] WhitelistedExtensions = Helper.GetRegSubkeys("HKLM", @"Software\Policies\Google\Chrome\ExtensionInstallWhitelist");
            if (WhitelistedExtensions.Length > 0)
            {
                //  Whitelist only applies if all extensions have been blacklisted 
                // https://cloud.google.com/docs/chrome-enterprise/policies/?policy=ExtensionInstallBlacklist
                string[] BlacklistedExtensions = Helper.GetRegSubkeys("HKLM", @"Software\Policies\Google\Chrome\ExtensionInstallBlacklist");
                foreach (string id in BlacklistedExtensions)
                {
                    if (Helper.GetRegValue("HKLM", @"Software\Policies\Google\Chrome\ExtensionInstallBlacklist", id) == "*")
                        return true;

                }
            }
            return false;
        }
    }
}
