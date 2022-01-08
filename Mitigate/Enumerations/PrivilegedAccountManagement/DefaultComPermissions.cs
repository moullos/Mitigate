using Mitigate.Utils;
using System;
using System.Collections.Generic;
using System.Linq;

namespace Mitigate.Enumerations
{
    class COM : Enumeration
    {
        public override string Name => "Default system-wide COM permissions";
        public override string MitigationType => MitigationTypes.PrivilegedAccountManagement;
        public override string MitigationDescription => "Modify Registry settings (directly or using Dcomcnfg.exe) in HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Ole associated with system-wide security defaults for all COM applications that do no set their own process-wide security.";
        public override string EnumerationDescription => "Checks if the machine system-wide COM permissions are hardened";

        public override string[] Techniques => new string[] {
            "T1159",
            "T1159.001",
            "T1021.003"
        };

        public override IEnumerable<EnumerationResults> Enumerate(Context context)
        {
            string[] ComKeys = Helper.GetRegSubkeys("HKLM", @"SOFTWARE\Microsoft\Ole");
            if (Helper.RegExists("HKLM", @"SOFTWARE\Microsoft\Ole", "DefaultLaunchPermission"))
            {
                // Checking if the permissions are the default
                var RawLaunchPermission = Helper.GetRegValueBytes("HKLM", @"SOFTWARE\Microsoft\Ole", "DefaultLaunchPermission");
                yield return new BooleanConfig("Default COM Launch Permissions", Helper.EqualsDefaultLaunchPermissions(RawLaunchPermission));
            }
            else
            {
                // If the key does not exist the default system-wide permissions are enforced
                yield return new BooleanConfig("Default COM Launch Permissions", true);

            }
            if (Helper.RegExists("HKLM", @"SOFTWARE\Microsoft\Ole", "DefaultAccessPermission"))
            {
                // Checking if the permissions are the default
                var RawAccessPermission = Helper.GetRegValueBytes("HKLM", @"SOFTWARE\Microsoft\Ole", "DefaultAccessPermission");
                yield return new BooleanConfig("Default COM Access Permissions", Helper.EqualsDefaultAccessPermissions(RawAccessPermission));
            }
            else
            {
                // If the key does not exist the default system-wide permissions are enforced
                yield return new BooleanConfig("Default COM Access Permissions", true);

            }

            if (context.Arguments.Full)
            {
                // If Full checks is defined, then the individual app permissions are parse and are checked for loose(non-default) permissions
                var AllAppGUIDs = Helper.GetRegSubkeys("HKLM", @"SOFTWARE\Classes\AppID\").Where(o => o.StartsWith("{"));
                foreach (var AppGUID in AllAppGUIDs)
                {
                    var RegPath = String.Format(@"SOFTWARE\Classes\AppID\{0}", AppGUID);
                    // Check for app Access Permission
                    if (Helper.RegExists("HKLM", RegPath, "AccessPermission"))
                    {
                        var RawAccessPermission = Helper.GetRegValueBytes("HKLM", RegPath, "AccessPermission");
                        var DefaultPermissions = Helper.EqualsDefaultAccessPermissions(RawAccessPermission);
                        yield return new BooleanConfig($"{AppGUID} default COM Access Permissions", DefaultPermissions);
                    }
                    else yield return new BooleanConfig($"{AppGUID} default COM Access Permissions", true);

                    // Check for app launch Permission
                    if (Helper.RegExists("HKLM", RegPath, "LaunchPermission"))
                    {
                        var RawLaunchPermission = Helper.GetRegValueBytes("HKLM", RegPath, "LaunchPermission");
                        var DefaultPermissions = Helper.EqualsDefaultLaunchPermissions(RawLaunchPermission);
                        yield return new BooleanConfig($"{AppGUID} default COM Launch Permissions", DefaultPermissions);

                    }
                    else yield return new BooleanConfig($"{AppGUID} default COM Launch Permissions", true);
                }
            }
        }
    }
}
