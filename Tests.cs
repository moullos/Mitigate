using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Dynamic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Permissions;
using System.Text;

namespace Mitigate
{

    public enum Mitigation
    {
        TestNotImplemented = -2,
        NA = -1,
        False = 0,
        True = 2,
        partial = 1,
        Failed = 3,
        CannotBeMeasured = 4,
        NoMitigationAvailable = 5
    }
    static class Tests
    {
        //////////////////////
        // Helper functions //
        //////////////////////
        /// <summary>
        /// Executes tests for a technique that has subtechniques
        /// </summary>
        /// <param name="technique">The root technique Technique object</param>
        /// <param name="subtechniques">A list of Technique objects for the subtechniques</param>
        /// <param name="navigator">The navigator object instance handling the test results</param>
        public static void Execute(Technique technique, IEnumerable<Technique> subtechniques, Navigator navigator)
        {
            bool testsDefined = false; // variable tracking whether any tests have been defined
            List<string> SubTechniqueIDs = new List<string>();
            List<Dictionary<string, Mitigation>> TestResults = new List<Dictionary<string, Mitigation>>();
            foreach (Technique subtechnique in subtechniques)
            {
                string MethodName = subtechnique.GetID().Replace(".", "_");
                // Check if a test for the subtechnique is defined
                MethodInfo test = typeof(Tests).GetMethod(MethodName);
                if (test != null)
                {
                    //test detected :)
                    if (!testsDefined)
                    {
                        PrintUtils.PrintTechniqueStart(technique.GetName(), technique.GetID());
                        testsDefined = true;
                    }
                    PrintUtils.PrintSubTechniqueStart(subtechnique.GetName(), subtechnique.GetID());
                    SubTechniqueIDs.Add(subtechnique.GetID());
                    TestResults.Add((Dictionary<string, Mitigation>)test.Invoke(null, null));
                }
            }
            // Only add the root technique if at least one test for a sub technique is defined
            if (testsDefined)
                navigator.AddResults(technique.GetID(), SubTechniqueIDs, TestResults);
        }
        /// <summary>
        /// Executes tests for a techniques with not subtechniques
        /// </summary>
        /// <param name="technique">The technique object</param>
        /// <param name="navigator">The navigator object instance handling the test results</param>
        public static void Execute(Technique technique, Navigator navigator)
        {
            // Check if a test for the technique is defined
            MethodInfo test = typeof(Tests).GetMethod(technique.GetID());
            if (test != null)
            {
                PrintUtils.PrintTechniqueStart(technique.GetName(), technique.GetID());
                var result = (Dictionary<string, Mitigation>)test.Invoke(null, null);
                navigator.AddResults(technique.GetID(), result);
            }
        }

        private static Dictionary<string, Mitigation> InitiateMitigation(params string[] mitigations)
        {
            Dictionary<string, Mitigation> results = new Dictionary<string, Mitigation>();
            foreach (string mitigation in mitigations)
            {
                results[mitigation] = Mitigation.TestNotImplemented;
            }
            return results;
        }
        private static Mitigation TestNotPossible()
        {
            return Mitigation.NA;
        }
        private static Dictionary<string, Mitigation> NoMitigationAvailable()
        {
            Dictionary<string, Mitigation> result = new Dictionary<string, Mitigation>();
            PrintUtils.PrintInfo("No effective mitigation availabled");
            result["No effective mitigation available"] = Mitigation.NoMitigationAvailable;
            PrintUtils.PrintResult(Mitigation.NoMitigationAvailable);
            return result;
        }
        private static Mitigation Bool2TestResult(bool result)
        {
            return result ? Mitigation.True : Mitigation.False;
        }
        private static void AddMitigationResult(Dictionary<String, Mitigation> results, string test, bool result)
        {
            results[test] = Bool2TestResult(result);
            PrintUtils.PrintResult(results[test]);
        }
        private static void AddMitigationResult(Dictionary<String, Mitigation> results, string test, Mitigation result)
        {
            results[test] = result;
            PrintUtils.PrintResult(results[test]);
        }
        private static void AddMitigationResult(Dictionary<string, Mitigation> results, string test, Dictionary<string, bool> info)
        {
            results[test] = CollateResults(info);
            PrintUtils.PrintResult(results[test]);
        }
        private static Mitigation CollateResults(Dictionary<string, bool> info)
        {
            List<bool> configurationFlags = info.Values.ToList();
            // If all the configurations are enabled the technique is fully mitigated
            if (!configurationFlags.Contains(false))
            {
                return Mitigation.True;
            }
            if (!configurationFlags.Contains(true))
            {
                return Mitigation.False;
            }
            return Mitigation.partial;
        }
        public static Dictionary<string, Mitigation> NotApplicableSubTechnique()
        {
            Dictionary<string, Mitigation> results = InitiateMitigation("Not a Windows Subtechnique");
            results["Not a Windows Subtechnique"] = Mitigation.NA;
            return results;
        }
        ////////////////////////////////////////
        // Spearphishing Attachment:T1566.001 //
        ////////////////////////////////////////
        public static Dictionary<string, Mitigation> T1566_001()
        {
            Dictionary<string, Mitigation> results = InitiateMitigation(
                "Antivirus/Antimalware",
                "Malicious Attachment Detection",
                "Web Content Restriction",
                "User Training"
                );

            // Check 1: Does it have AV? //
            PrintUtils.PrintInfo("AV detected?");
            AddMitigationResult(results, "Antivirus/Antimalware", SystemUtils.DoesAVExist());

            // Cannot automatically measure User Training 
            AddMitigationResult(results, "User Training", TestNotPossible());

            // Rest of the checks not implemented yet
            return results;
        }
        //////////////////////////////////
        // Spearphishing Link:T1566.002 //
        //////////////////////////////////
        public static Dictionary<string, Mitigation> T1566_002()
        {
            Dictionary<string, Mitigation> results = InitiateMitigation(
                "Restrict Websites",
                "User Training"
                );

            // Cannot automatically measure User Training 
            AddMitigationResult(results, "User Training", TestNotPossible()); ;
            return results;
        }
        /////////////////////////////////////////
        // Spearphishing via Service:T1566.003 //
        /////////////////////////////////////////
        public static Dictionary<string, Mitigation> T1566_003()
        {
            Dictionary<string, Mitigation> results = InitiateMitigation(
                "Antivirus/Antimalware",
                "Restrict Websites",
                "User Training"
                );

            // Check 1: Does it have AV? //
            PrintUtils.PrintInfo("AV detected?");
            AddMitigationResult(results, "Antivirus/Antimalware", SystemUtils.DoesAVExist());

            // Cannot automatically measure User Training 
            AddMitigationResult(results, "User Training", TestNotPossible());
            return results;

        }
        ///////////////////////////////////////
        // Component Object Model: T1559.001 //
        ///////////////////////////////////////
        public static Dictionary<string, Mitigation> T1559_001()
        {
            Dictionary<string, Mitigation> results = InitiateMitigation(
                "Protected View Enabled",
                "Hardened system-wide permissions on COM"
                );

            // Check 1: Is protected view enabled? //
            PrintUtils.PrintInfo("Is protected view enabled?");
            Dictionary<string, bool> ProtectedViewInfo = null;
            try
            {
                ProtectedViewInfo = SystemUtils.GetProtectedViewInfo();
                AddMitigationResult(results, "Protected View Enabled", ProtectedViewInfo);
            }
            catch (Exception ex)
            {
                AddMitigationResult(results, "Protected View Enabled", Mitigation.Failed);
                PrintUtils.ErrorPrint(ex.Message);
            }

            // Check 2: Hardened system-wide permissions // 
            PrintUtils.PrintInfo("Are Default Com Permissions hardened?");
            AddMitigationResult(results, "Hardened system-wide COM permissions", SystemUtils.GetDefaultComPermissions());

            return results;
        }
        ///////////////////////////////////////
        // Dynamic Data Exchange: T1559.002 //
        //////////////////////////////////////
        public static Dictionary<string, Mitigation> T1559_002()
        {
            Dictionary<string, Mitigation> results = InitiateMitigation(
                "Protected View Enabled",
                "Attack Surface Reduction Rules",
                "Disable automatic DDE/OLE execution",
                "Disable embedded files in OneNote"
                );
            // Check 1: Is protected view enabled? //
            PrintUtils.PrintInfo("Is protected view enabled");
            Dictionary<string, bool> ProtectedViewInfo = null;
            try
            {
                ProtectedViewInfo = SystemUtils.GetProtectedViewInfo();
                AddMitigationResult(results, "Protected View Enabled", ProtectedViewInfo);
            }
            catch (Exception ex)
            {
                AddMitigationResult(results, "Protected View Enabled", Mitigation.Failed);
                PrintUtils.ErrorPrint(ex.Message);
            }

            // Check 2: Check for Attack Surface Reduction Rules //
            results["Attack Surface Reduction Rules"] = Mitigation.TestNotImplemented;

            // Check 3: Disabled automatic DDE/OLE execution //
            //https://gist.github.com/wdormann/732bb88d9b5dd5a66c9f1e1498f31a1b
            PrintUtils.PrintInfo("Is DDE Automatic execution disabled?");
            Dictionary<string, bool> AutomaticDDEExecutionConf = SystemUtils.GetAutomaticDDEExecutionConf();
            //if null office is not installed. Test in NA
            if (AutomaticDDEExecutionConf == null)
            {
                PrintUtils.ErrorPrint("Office is not installed");
                AddMitigationResult(results, "Disabled automatic DDE/OLE execution", Mitigation.NA);
            }
            else
            {
                AddMitigationResult(results, "Disabled automatic DDE/OLE execution", AutomaticDDEExecutionConf);
            }

            // Check 4: Disable embedded files in OneNote //
            PrintUtils.PrintInfo("Are embedded files in OneNote disabled");
            Dictionary<string, bool> OneNoteExecutionConf = SystemUtils.GetEmbeddedFilesOneNoteConf();
            if (OneNoteExecutionConf == null)
            {
                PrintUtils.ErrorPrint("Office is not installed");
                AddMitigationResult(results, "Disabled embedded files in OneNote", Mitigation.NA);
            }
            else
            {
                AddMitigationResult(results, "Disabled embedded files in OneNote", OneNoteExecutionConf);
            }

            // Checks done
            return results;
        }
        ////////////////////////////////
        // Default Accounts:T1078.001 //
        ////////////////////////////////
        public static Dictionary<string, Mitigation> T1078_001()

        {
            Dictionary<string, Mitigation> results = InitiateMitigation("Check for default credentials");
            return results;

        }
        ///////////////////////////////
        // Domain Accounts:T1078.002 //
        ///////////////////////////////
        public static Dictionary<string, Mitigation> T1078_002()
        {
            Dictionary<string, Mitigation> results = InitiateMitigation("MFA", "No domain accounts in local admin group");
            // Check 1: Are any domain users part of the local admin group?
            PrintUtils.PrintInfo("Are domain users local admins?");
            AddMitigationResult(results, "No domain accounts in local admin group", UserUtils.IsADomainUserMemberofLocalAdmins());
            return results;
        }
        //////////////////////////////
        // Local Accounts:T1078.003 //
        //////////////////////////////
        public static Dictionary<string, Mitigation> T1078_003()
        {
            Dictionary<string, Mitigation> results = InitiateMitigation("LAPS Enabled");


            // Check 1: Is LAPS enabled?
            PrintUtils.PrintInfo("LAPS enabled?");
            AddMitigationResult(results, "LAPS enabled?", SystemUtils.IsLapsEnabled());
            return results;
        }
        ///////////////////////////
        // PowerShell: T1059.001 //
        ///////////////////////////
        public static Dictionary<string, Mitigation> T1059_001()
        {
            Dictionary<string, Mitigation> results = InitiateMitigation(
                "Execute only signed scripts",
                "Disable or remove from systems that don't need it",
                "Restrict Execution policy to administrators"
                );
            // Check 1: Executeo only signed scripts
            PrintUtils.PrintInfo("Checking if only signed scripts are executed by PS");
            string[] SatisfyingPolicies = { "AllSigned", "RemoteSigned", "Restricted" };
            string ExecutionPolicy = SystemUtils.GetPowershellExecutionPolicy();
            AddMitigationResult(results, "Execute only signed scripts", SatisfyingPolicies.Contains(ExecutionPolicy));

            // Check 2: Check if PS is accessble
            PrintUtils.PrintInfo("Checking whether powershell is accessible from this user account");
            AddMitigationResult(results, "Disable or remove from systems that don't need it", Utils.CommandFileExists("powershell.exe"));

            return results;
        }
        //////////////////////////////////////
        // Windows Command Shell: T1059.003 //
        //////////////////////////////////////
        public static Dictionary<string, Mitigation> T1059_003()
        {
            Dictionary<string, Mitigation> results = InitiateMitigation("AppLocker Enabled", "WDAC Enabled");

            //Check 1: Applocker
            PrintUtils.PrintInfo("Is AppLocker Enabled?");
            AddMitigationResult(results, "App Locker Enabled", SystemUtils.IsAppLockerEnabled());

            //Check 2: Windows Defender Application Control
            PrintUtils.PrintInfo("Is WD Application Control on?");
            AddMitigationResult(results, "WDAC Enabled", SystemUtils.IsWDACEnabled());

            return results;
        }
        /////////////////////////
        // VBScript: T1059.005 //
        /////////////////////////
        public static Dictionary<string, Mitigation> T1059_005()
        {
            Dictionary<string, Mitigation> results = InitiateMitigation("AppLocker Enabled", "WDAC Enabled", "Restrict Access");

            //Check 1: Applocker
            PrintUtils.PrintInfo("Is AppLocker Enabled?");
            AddMitigationResult(results, "AppLocker Enabled", SystemUtils.IsAppLockerEnabled());

            //Check 2: Windows Defender Application Control
            PrintUtils.PrintInfo("Is WD Application Control on?");
            AddMitigationResult(results, "WDAC Enabled", SystemUtils.IsWDACEnabled());

            //Check 3: Are the scripts accessibled?
            PrintUtils.PrintInfo("Are VBScript utils accessible?");
            AddMitigationResult(results, "Restrict Access", Utils.CommandFileExists("Cscript.exe") || Utils.CommandFileExists("Wscript.exe"));

            return results;
        }
        ///////////////////////
        // Python: T1059.006 //
        ///////////////////////
        public static Dictionary<string, Mitigation> T1059_006()
        {
            Dictionary<string, Mitigation> results = InitiateMitigation("System Inventory Audit", "Blacklist", "Prevent users from installing");
            return results;
        }
        //////////////////////////////////////////////
        // Exploitation for Client Execution: T1203 //
        //////////////////////////////////////////////
        public static Dictionary<string, Mitigation> T1203()
        {
            Dictionary<string, Mitigation> results = InitiateMitigation(
                "WDAG Enabled",
                "WDEG Enabled"
                );
            //Check 1: Checking for application guard
            PrintUtils.PrintInfo("Checking for Windows Defender Application Guard");
            var WDAGStatus = SystemUtils.IsWDApplicationGuardEnabled();
            AddMitigationResult(results, "WDAG Enabled", WDAGStatus);

            //Check 2: Checking for exploit guard
            PrintUtils.PrintInfo("Checking for Windows Defender Exploit Guard");
            AddMitigationResult(results, "WDEG Enabled", SystemUtils.IsWDExploitGuardEnabled());

            return results;
        }
        ///////////////////////
        // Native API: T1106 //
        ///////////////////////
        public static Dictionary<string, Mitigation> T1106()
        {
            Dictionary<string, Mitigation> results = InitiateMitigation("WDAG Enabled", "AppLocker Enabled", "Software Restriction Policies");

            //Check 1: Checking for application guard
            PrintUtils.PrintInfo("Checking for Windows Defender Application Guard");
            var WDAGStatus = SystemUtils.IsWDApplicationGuardEnabled();
            AddMitigationResult(results, "WDAG Enabled", WDAGStatus);

            //Check 2: Applocker
            PrintUtils.PrintInfo("Is AppLocker Enabled?");
            AddMitigationResult(results, "AppLocker Enabled", SystemUtils.IsAppLockerEnabled());

            return results;
        }
        /////////////////////////////
        // At (Windows): T1053.002 //
        /////////////////////////////
        public static Dictionary<string, Mitigation> T1053_002()
        {
            Dictionary<string, Mitigation> results = InitiateMitigation(
                "Audit for weak permissions",
                "Do not run as SYSTEM",
                "Only allow administrators to schedule a priority process",
                "at deprecated");

            // Check 1: at runs in user context?
            PrintUtils.PrintInfo("Run at.exe in user context");
            AddMitigationResult(results, "Do not run as SYSTEM", SystemUtils.RunAtInUserContext());

            // Check 2: at deprecated
            PrintUtils.PrintInfo("Checking whether at is deprecated");
            AddMitigationResult(results, "at deprecated", !Utils.CommandFileExists("at.exe"));

            return results;
        }
        ///////////////////////////////
        // Scheduled Task: T1053.005 //
        ///////////////////////////////
        public static Dictionary<string, Mitigation> T1053_005()
        {
            Dictionary<string, Mitigation> results = InitiateMitigation(
                "Audit for weak permissions",
                "Do not run as SYSTEM",
                "Schedule task restricted");

            results["Audit for weak permissions"] = Mitigation.NA;

            // Check 1: at runs in user context?
            PrintUtils.PrintInfo("Run at.exe in user context");
            AddMitigationResult(results, "Do not run as SYSTEM", SystemUtils.RunAtInUserContext());

            return results;
        }
        //////////////////////
        // BITS Jobs: T1197 //
        //////////////////////
        public static Dictionary<string, Mitigation> T1197()
        {
            Dictionary<string, Mitigation> results = InitiateMitigation(
                "Firewall rules",
                "Reduce BITS job lifetime",
                "Limit User Access");

            PrintUtils.PrintInfo("Reduced BITS job lifetime?");
            AddMitigationResult(results, "Reduce BITS job lifetime", SystemUtils.GetBITSJobInfo());

            // Check 2: Firewall rules
            // need to fix this
            PrintUtils.PrintInfo("BITS host firewall rules?");
            var FirewallRules = SystemUtils.GetFirewallRules();
            if (FirewallRules != null)
            {
                results["Firewall rules"] = Mitigation.TestNotImplemented;
            }
            return results;
        }
        ///////////////////////////////////////////////
        // Windows Management Instrumentation: T1047 //
        ///////////////////////////////////////////////
        public static Dictionary<string, Mitigation> T1047()
        {
            Dictionary<string, Mitigation> results = InitiateMitigation("LAPS Enabled", "WMI Access Limited to Administrators");

            // Check 1: Is LAPS enabled?
            PrintUtils.PrintInfo("Is LAPS enabled?");
            AddMitigationResult(results, "Is LAPS enabled?", SystemUtils.IsLapsEnabled());

            return results;
        }
        ///////////////////////////////////////////////////
        // Registry Run Keys / Startup Folder: T1547.001 //
        ///////////////////////////////////////////////////
        public static Dictionary<string, Mitigation> T1547_001()
        {
            return NoMitigationAvailable();
        }
        ///////////////////////////////////////
        // Authentication Package: T1547.002 //
        ///////////////////////////////////////
        public static Dictionary<string, Mitigation> T1547_002()
        {
            PrintUtils.PrintInfo("Checking if LSA is run as a PPL");
            Dictionary<string, Mitigation> results = InitiateMitigation("Make LSA run as Protected Process Light");
            AddMitigationResult(results, "Make LSA run as Protected Process Light", SystemUtils.IsLsaRunAsPPL());
            return results;
        }
        ///////////////////////////////
        // Time Providers: T1547.003 //
        ///////////////////////////////
        public static Dictionary<string, Mitigation> T1547_003()
        {
            Dictionary<string, Mitigation> results = InitiateMitigation(
                "Block additions/modification to W32Time DLLs",
                "Block modification to W32Time parameters in registry"
                );
            // Check 1: W32Time dll permissions
            //string W32TimeDLLPath = @"%windir%\System32\W32Time.dll";
            string W32TimeDLLPath = @"C:\ExploitConfigfile.xml"; // for testing
            PrintUtils.PrintInfo("W32Time DLL permissions hardened?");
            var permissions = Utils.GetFileWritePermissions(W32TimeDLLPath, Program.InterestingUsers);
            if (!File.Exists(W32TimeDLLPath))
            {
                AddMitigationResult(results, "Block additions/modification to W32Time DLLs", Mitigation.NA);
            }
            else if (permissions != null)
            {
                AddMitigationResult(results, "Block additions/modification to W32Time DLLs", false);
            }
            else
            {
                AddMitigationResult(results, "Block additions/modification to W32Time DLLs", true);
            }
            // Check 2: Reg Permissions
            PrintUtils.PrintInfo("W32Time Reg permissions hardened?");
            bool RegPermissionsHardened = false;
            string[] RegPaths = {
                @"SYSTEM\CurrentControlSet\Services\W32Time\Config",
                @"SYSTEM\CurrentControlSet\Services\W32Time\Parameters",
                @"SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpClient",
                @"SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpServer"
            };
            foreach (string RegPath in RegPaths)
            {
                var RegPermissions = Utils.GetRegPermissions("HKLM", RegPath, Program.InterestingUsers);
                if (RegPermissions != null)
                {
                    RegPermissionsHardened = false;
                    break;
                }
            }
            AddMitigationResult(results, "Block modification to W32Time parameters in registry", RegPermissionsHardened);
            return results;
        }
        ////////////////////////////////////
        // Winlogon Helper DLL: T1547.004 //
        ////////////////////////////////////
        public static Dictionary<string, Mitigation> T1547_004()
        {
            Dictionary<string, Mitigation> results = InitiateMitigation(
                "DLL Whitelisting(Applocker)",
                "Registry Key Permissions");

            //Check 1: Applocker
            PrintUtils.PrintInfo("Is AppLocker Enabled?");
            AddMitigationResult(results, "DLL Whitelisting(Applocker)", SystemUtils.IsAppLockerEnabled());

            //Check 2: Winlogon permissions
            PrintUtils.PrintInfo("Winlogon permissions hardened?");
            AddMitigationResult(results, "Registry Key Permissions", SystemUtils.GetWinlogonRegPermissions());

            return results;
        }
        //////////////////////////////////////////
        // Security Support Provider: T1547.005 //
        //////////////////////////////////////////
        public static Dictionary<string, Mitigation> T1547_005()
        {
            Dictionary<string, Mitigation> results = InitiateMitigation("Make LSA run as Protected Process Light");

            PrintUtils.PrintInfo("Checking if LSA is run as a PPL");
            AddMitigationResult(results, "Make LSA run as Protected Process Light", SystemUtils.IsLsaRunAsPPL());

            return results;
        }
        /////////////////////////////
        // LSASS Driver: T1547.008 //
        /////////////////////////////
        public static Dictionary<string, Mitigation> T1547_008()
        {
            Dictionary<string, Mitigation> results = InitiateMitigation(
                "Make LSA run as Protected Process Light",
                "WDCG Enabled",
                "Safe DLL search mode enabled");
            // Check 1: LSA
            PrintUtils.PrintInfo("Checking if LSA is run as a PPL");
            AddMitigationResult(results, "Make LSA run as Protected Process Light", SystemUtils.IsLsaRunAsPPL());

            // Check 2: Windows Defender Credential Guard
            PrintUtils.PrintInfo("Checking for WD Credential Guard");
            AddMitigationResult(results, "WDCG Enabled", SystemUtils.IsCredentialGuardEnabled());

            // Check 3: Is DLL search mode enabled?
            //https://docs.microsoft.com/en-gb/windows/win32/dlls/dynamic-link-library-search-order
            PrintUtils.PrintInfo("Is DLL search mode enabled?");
            AddMitigationResult(results, "Safe DLL search mode enabled", SystemUtils.IsSafeDllSafeSearchModeOn());
            return results;
        }
        ///////////////////////////////////////
        // Shortcut Modification : T1547.009 //
        ///////////////////////////////////////
        public static Dictionary<string, Mitigation> T1547_009()
        {
            // https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/create-symbolic-links
            // https://www.stigviewer.com/stig/windows_server_2008_r2_member_server/2015-06-25/finding/V-26482
            Dictionary<string, Mitigation> results = InitiateMitigation("Only administrators are allowed to create symbolic links");
            // TODO: Check
            return results;
        }
        //////////////////////////////
        // Port Monitors: T1547.010 //
        //////////////////////////////
        public static Dictionary<string, Mitigation> T1547_010()
        {
            return NoMitigationAvailable();
        }
        ///////////////////////////////////////
        // Logon Script (Windows): T1037.001 //
        ///////////////////////////////////////
        public static Dictionary<string, Mitigation> T1037_001()
        {
            Dictionary<string, Mitigation> results = InitiateMitigation("Hardened registry Permissions");

            //Check 1: Hardened registry permissions
            PrintUtils.PrintInfo("Hardened registry permissions?");
            AddMitigationResult(results,
                "Hardened registry permissions",
                Utils.GetRegPermissions("HKCU", @"Environment", Program.InterestingUsers) != null
                );

            return results;
        }
        /////////////////////////////////////
        // Network Logon Script: T1037.003 //
        /////////////////////////////////////
        public static Dictionary<string, Mitigation> T1037_003()
        {
            Dictionary<string, Mitigation> results = InitiateMitigation("Restring logon script acccess");
            // TODO
            return results;
        }
        ///////////////////////////////
        // Browser Extensions: T1176 //
        ///////////////////////////////
        public static Dictionary<string, Mitigation> T1176()
        {
            Dictionary<string, Mitigation> results = InitiateMitigation(
                "Audit",
                "Browser extensions whitelist",
                "Only trusted browser extensions",
                "User training");
            results["Audit"] = Mitigation.NA;
            results["User training"] = Mitigation.NA;

            // Check 1: Extension whitelist
            // Checking only chrome for now
            PrintUtils.PrintInfo("Checking for chrome extension whitelist");
            AddMitigationResult(results, "Browser extensions whitelist", SystemUtils.IsChromeExtensionWhitelistEnabled());

            // Check 2: Only trusted extensions
            PrintUtils.PrintInfo("Checking for only trusted extensions");
            AddMitigationResult(results, "Only trusted browser extensions", SystemUtils.IsChromeExternalExtectionsBlocked());

            return results;
        }
        ////////////////////////////////////////////////
        // Change Default File Association: T1546.001 //
        ////////////////////////////////////////////////
        public static Dictionary<string, Mitigation> T1546_001()
        {
            return NoMitigationAvailable();
        }
        ////////////////////////////
        // Screensaver: T1546.002 //
        ////////////////////////////
        public static Dictionary<string, Mitigation> T1546_002()
        {
            Dictionary<string, Mitigation> results = InitiateMitigation("Screen Saver Disabled");
            //https://getadmx.com/?Category=Windows_10_2016&Policy=Microsoft.Policies.ControlPanelDisplay::CPL_Personalization_EnableScreenSaver

            PrintUtils.PrintInfo("Screen Saver Disabled?");
            AddMitigationResult(results, "Screen Saver Disabled", SystemUtils.IsScreenSaverDisabled());

            return results;
        }
        ///////////////////////////////////
        // PowerShell Profile: T1546.013 //
        ///////////////////////////////////
        /* PROFILE LOCATIONS
        a. AllUsersAllHosts - %windir%\System32\WindowsPowerShell\v1.0\profile.ps1
        b. AllUsersAllHosts (WoW64) - %windir%\SysWOW64\WindowsPowerShell\v1.0\profile.ps1
        c. AllUsersCurrentHost - %windir%\System32\WindowsPowerShell\v1.0\Microsoft.PowerShell_profile.ps1
        d. AllUsersCurrentHost (ISE) - %windir%\System32\WindowsPowerShell\v1.0\Microsoft.PowerShellISE_profile.ps1
        e. AllUsersCurrentHost (WoW64) – %windir%\SysWOW64\WindowsPowerShell\v1.0\Microsoft.PowerShell_profile.ps1
        f. AllUsersCurrentHost (ISE - WoW64) - %windir%\SysWOW64\WindowsPowerShell\v1.0\Microsoft.PowerShellISE_profile.ps1
        g. CurrentUserAllHosts - %homedrive%%homepath%\[My ]Documents\profile.ps1
        h. CurrentUserCurrentHost - %homedrive%%homepath%\[My ]Documents\Microsoft.PowerShell_profile.ps1
        i. CurrentUserCurrentHost (ISE) - %homedrive%%homepath%\[My ]Documents\Microsoft.PowerShellISE_profile.ps1
         */
        public static Dictionary<string, Mitigation> T1546_013()
        {
            Dictionary<string, Mitigation> results = InitiateMitigation(
                "Enforce execution of only signed PowerShell scripts",
                "Make Profile Files immutable. Allow only certain admins to changes them",
                "Avoid PowerShell profiles"
                );
            // Check 1: Powershell execution policy
            PrintUtils.PrintInfo("Powershell only signed scripts?");
            string[] SatisfyingPolicies = { "AllSigned", "RemoteSigned", "Restricted" };
            string ExecutionPolicy = SystemUtils.GetPowershellExecutionPolicy();
            AddMitigationResult(results, "Enforce execution of only signed PowerShell scripts", SatisfyingPolicies.Contains(ExecutionPolicy));

            // Check 2: Are profile files immutable by non privileged users?
            // TODO

            // Avoiding PowerShell profiles is not measurable
            AddMitigationResult(results, "Avoid PowerShell profiles", Mitigation.NA);

            return results;
        }
        /////////////////////////////////
        // T1547.007: Netsh Helper DLL //
        /////////////////////////////////
        public static Dictionary<string, Mitigation> T1546_007()
        {
            return NoMitigationAvailable();
        }
        //////////////////////////////////////
        // T1546.008: Accessbility Features //
        //////////////////////////////////////
        public static Dictionary<string, Mitigation> T1546_008()
        {
            Dictionary<string, Mitigation> results = InitiateMitigation(
                "Execution Prevention",
                "Remote Desktop Gateway",
                "Enable Network Level Authentication for RDP"
            );
            // Check 1: Application Whitelisting
            // TODO: Check for Software Restriction policies
            PrintUtils.PrintInfo("Checking for AppLocker or WDAG");
            bool ExecutionPrevention = SystemUtils.IsAppLockerEnabled() || SystemUtils.IsWDACEnabled();
            AddMitigationResult(results, "Execution Prevention", ExecutionPrevention);

            // Check 2: Remote Desktop Gateway
            // TODO

            //Check 3: NLA for RDP
            PrintUtils.PrintInfo("RDP Network Level Authentication Enabled?");
            AddMitigationResult(results, "Enabled Network Level Authentication for RDP", SystemUtils.IsRdpNLAEnabled());

            return results;
        }
        /////////////////////////////
        // T1546.009: AppCert DLLs //
        /////////////////////////////
        public static Dictionary<string, Mitigation> T1546_009()
        {
            Dictionary<string, Mitigation> results = InitiateMitigation("Execution Prevention");
            // Check 1: Application Whitelisting
            // TODO: Check for Software Restriction policies
            PrintUtils.PrintInfo("Checking for AppLocker or WDAG");
            bool ExecutionPrevention = SystemUtils.IsAppLockerEnabled() || SystemUtils.IsWDACEnabled();
            AddMitigationResult(results, "Execution Prevention", ExecutionPrevention);

            return results;
        }
        /////////////////////////////
        // T1546.010: AppInit DLLs //
        /////////////////////////////
        public static Dictionary<string, Mitigation> T1546_010()
        {
            Dictionary<string, Mitigation> results = InitiateMitigation("Execution Prevention", "Secure Boot");
            // Check 1: Application Whitelisting
            // TODO: Check for Software Restriction policies
            PrintUtils.PrintInfo("Checking for AppLocker or WDAG");
            bool ExecutionPrevention = SystemUtils.IsAppLockerEnabled() || SystemUtils.IsWDACEnabled();
            AddMitigationResult(results, "Execution Prevention", ExecutionPrevention);

            // Check 2: Secure Boot
            PrintUtils.PrintInfo("Is secure boot enabled");
            AddMitigationResult(results, "Secure Boot", SystemUtils.IsSecureBootEnabled());

            return results;
        }
        ///////////////////////////////////////////////////////
        // T1546.012: Image File Execution Options Injection //
        ///////////////////////////////////////////////////////
        public static Dictionary<string, Mitigation> T1546_012()
        {
            return NoMitigationAvailable();
        }
        /////////////////////////////////////////////////
        // T1546.015: Component Object Model Hijacking //
        /////////////////////////////////////////////////
        public static Dictionary<string, Mitigation> T1546_015()
        {
            return NoMitigationAvailable();
        }
        ///////////////////////////////////////
        // T1137.001: Office Template Macros //
        ///////////////////////////////////////
        public static Dictionary<string, Mitigation> T1137_001()
        {
            Dictionary<string, Mitigation> results = InitiateMitigation("Disabled/Signed Macros", "Disabled/Signed Addins");
            try
            {
                // Check 1: Disabled/Signed Macros
                PrintUtils.PrintInfo("Are macros disabled or signed only?");
                // Disabled holistically?
                if (OfficeUtils.IsVBADisabled())
                {
                    AddMitigationResult(results, "Disabled/Signed Macros", true);
                }
                else
                {
                    // Disabled on the application level?
                    AddMitigationResult(results, "Disabled/Signed Macros", OfficeUtils.GetMacroConf());
                }
                // Maybe I will add a check for disabled macros downloaded from the internet or ASR rule checks (https://www.ncsc.gov.uk/guidance/macro-security-for-microsoft-office)

                // Check 2: Disabled/Signed Addins
                PrintUtils.PrintInfo("Are addins disabled or signed only?");
                AddMitigationResult(results, "Disabled/Singed Addins", OfficeUtils.GetAddinsConf());
            }
            catch (OfficeUtils.OfficeNotInstallException ex)
            {
                AddMitigationResult(results, "Disabled/Signed Macros", Mitigation.Failed);
                AddMitigationResult(results, "Disabled/Singed Addins", Mitigation.Failed);
                PrintUtils.ErrorPrint(ex.Message);
            }
            return results;
        }
        ////////////////////////////
        // T1137.002: Office Test //
        ////////////////////////////
        public static Dictionary<string, Mitigation> T1137_002()
        {
            Dictionary<string, Mitigation> results = InitiateMitigation("Create and Harden Registry Key");

            // Check if the key exists
            string RegPath = @"Software\Microsoft\Office test\Special\Perf";
            Utils.GetRegPermissions("HKLM", RegPath, Program.InterestingUsers);
            return results;
        }
    }
}
