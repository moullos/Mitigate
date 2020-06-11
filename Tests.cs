using NetFwTypeLib;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Dynamic;
using System.IO;
using System.Linq;
using System.Management;
using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Permissions;
using System.Security.Principal;
using System.Text;

namespace Mitigate
{

    public enum Mitigation : int
    {
        TestNotImplemented = -2,    // Mitigation enumaration is not implemented (yet)
        NA = -1,                    // Mitigation enumeration is implemented, but it does not apply to this machine
        False = 0,                  // Mitigation is not applied
        True = 2,                   // Mitigation is applied
        Partial = 1,                // Mitigation is partially applied
        Failed = 3,                 // Mitigation enumeration failed
        CannotBeMeasured = 4,       // Mitigation is not quantifiable using machine interrogation e.g. User Training, Network Segmentation etc
        NoMitigationAvailable = 5   // Technique cannot be mitigated
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
        /// <param name="ATTCK">The object carrying all the ATT&CK info</param>
        public static void Execute(Technique technique, IEnumerable<Technique> subtechniques, Navigator navigator, AttackCTI ATTCK)
        {
            bool TechniquTestDetected = false; // variable tracking whether any mitigation tests has been defined for the technique
            bool SubTechniqueWithNoMitigation = false;
            List<string> SubTechniqueIDs = new List<string>();
            List<Dictionary<string, Mitigation>> SubTechniquesMitigationInfo = new List<Dictionary<string, Mitigation>>();
            foreach (Technique subtechnique in subtechniques)
            {
                SubTechniqueIDs.Add(subtechnique.GetID());
                // Check if mitigations for the subtechnique are defined within ATT&CK
                if (!ATTCK.DoesItHaveMitigations(subtechnique))
                {
                    SubTechniqueWithNoMitigation = true;
                    SubTechniquesMitigationInfo.Add(NoMitigationAvailable());
                    continue;
                }
                string MethodName = subtechnique.GetID().Replace(".", "_");
                // Check if a test for the subtechnique is defined
                MethodInfo test = typeof(Tests).GetMethod(MethodName);
                if (test != null)
                {
                    //test detected
                    if (!TechniquTestDetected)
                    {
                        PrintUtils.PrintTechniqueStart(technique.GetName(), technique.GetID());
                        TechniquTestDetected = true;
                    }
                    PrintUtils.PrintSubTechniqueStart(subtechnique.GetName(), subtechnique.GetID());
                    SubTechniquesMitigationInfo.Add((Dictionary<string, Mitigation>)test.Invoke(null, null));
                }
                else
                {
                    SubTechniquesMitigationInfo.Add(NoTestsImplemented());
                }
            }
            // Only add the root technique if at least one test for a sub technique is defined
            if (TechniquTestDetected || SubTechniqueWithNoMitigation) 
                navigator.AddMitigationInfo(technique, SubTechniqueIDs, SubTechniquesMitigationInfo);
        }
        /// <summary>
        /// Executes tests for a techniques with no subtechniques
        /// </summary>
        /// <param name="technique">The technique object</param>
        /// <param name="navigator">The navigator object instance handling the test results</param>
        public static void Execute(Technique technique, Navigator navigator, AttackCTI ATTCK)
        {
            // Check if mitigations for the technique exist in ATT&CK
            if (!ATTCK.DoesItHaveMitigations(technique))
            {
                // If it doesn't have mitigations just add to the navigator with no mitigation available results
                navigator.AddMitigationInfo(technique, NoMitigationAvailable());

            }
            // Check if a test for the technique is defined
            MethodInfo test = typeof(Tests).GetMethod(technique.GetID());
            if (test != null)
            {
                PrintUtils.PrintTechniqueStart(technique.GetName(), technique.GetID());
                var result = (Dictionary<string, Mitigation>)test.Invoke(null, null);
                navigator.AddMitigationInfo(technique, result);
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
            return Mitigation.CannotBeMeasured;
        }
        private static Dictionary<string, Mitigation> NoMitigationAvailable()
        {
            Dictionary<string, Mitigation> result = new Dictionary<string, Mitigation>();
            result["No effective mitigation available"] = Mitigation.NoMitigationAvailable;
            return result;
        }
        private static Dictionary<string, Mitigation> NoTestsImplemented()
        {
            Dictionary<string, Mitigation> result = new Dictionary<string, Mitigation>();
            result["No test implemented"] = Mitigation.TestNotImplemented;
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
            return Mitigation.Partial;
        }
        ////////////////////////
        /// Tests begin here ///
        ////////////////////////

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
                "Hardened system-wide COM permissions"
                );

            // Check 1: Is protected view enabled? //
            PrintUtils.PrintInfo("Is protected view enabled?");
            try
            {
                var ProtectedViewInfo = OfficeUtils.GetProtectedViewInfo();
                AddMitigationResult(results, "Protected View Enabled", ProtectedViewInfo);
            }
            catch (OfficeUtils.OfficeNotInstallException ex)
            {
                AddMitigationResult(results, "Protected View Enabled", Mitigation.NA);
                PrintUtils.ErrorPrint(ex.Message);
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
            try
            {
                var ProtectedViewInfo = OfficeUtils.GetProtectedViewInfo();
                AddMitigationResult(results, "Protected View Enabled", ProtectedViewInfo);
            }
            catch (OfficeUtils.OfficeNotInstallException ex)
            {
                AddMitigationResult(results, "Protected View Enabled", Mitigation.NA);
                PrintUtils.ErrorPrint(ex.Message);
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
            try
            {
                Dictionary<string, bool> AutomaticDDEExecutionConf = OfficeUtils.GetAutomaticDDEExecutionConf();
                AddMitigationResult(results, "Disabled automatic DDE/OLE execution", AutomaticDDEExecutionConf);

            }
            catch (OfficeUtils.OfficeNotInstallException ex)
            {
                AddMitigationResult(results, "Disabled automatic DDE/OLE execution", Mitigation.NA);
                PrintUtils.ErrorPrint(ex.Message);
            }
            catch (Exception ex)
            {
                AddMitigationResult(results, "Disabled automatic DDE/OLE execution", Mitigation.Failed);
                PrintUtils.ErrorPrint(ex.Message);
            }
            // Check 4: Disable embedded files in OneNote //
            PrintUtils.PrintInfo("Are embedded files in OneNote disabled");
            try
            {
                Dictionary<string, bool> OneNoteExecutionConf = OfficeUtils.GetEmbeddedFilesOneNoteConf();
                AddMitigationResult(results, "Disabled embedded files in OneNote", OneNoteExecutionConf);
            }
            catch (OfficeUtils.OfficeNotInstallException ex)
            {
                AddMitigationResult(results, "Disabled embedded files in OneNote", Mitigation.NA);
                PrintUtils.ErrorPrint(ex.Message);
            }
            catch (Exception ex)
            {
                AddMitigationResult(results, "Disabled embedded files in OneNote", Mitigation.Failed);
                PrintUtils.ErrorPrint(ex.Message);
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
            PrintUtils.PrintInfo("Are domain accounts excluded from local administrators?");
            AddMitigationResult(results, "No domain accounts in local admin group", !UserUtils.IsADomainUserMemberofLocalAdmins());
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
            // Check 1: Executed only signed scripts
            PrintUtils.PrintInfo("Checking if only signed scripts are executed by PS");
            string[] SatisfyingPolicies = { "AllSigned", "RemoteSigned", "Restricted" };
            string ExecutionPolicy = SystemUtils.GetPowershellExecutionPolicy();
            AddMitigationResult(results, "Execute only signed scripts", SatisfyingPolicies.Contains(ExecutionPolicy));

            // Check 2: Check if PS is accessble
            PrintUtils.PrintInfo("Checking whether powershell is accessible from this user account");
            AddMitigationResult(results, "Disable or remove from systems that don't need it", !Utils.CommandFileExists("powershell.exe"));

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
                "Host firewall rules",
                "Reduce BITS job lifetime",
                "Limit User Access");

            PrintUtils.PrintInfo("Reduced BITS job lifetime?");
            AddMitigationResult(results, "Reduce BITS job lifetime", SystemUtils.GetBITSJobInfo());

            // Check 2: Firewall rules
            PrintUtils.PrintInfo("BITS host firewall rules?");
            var MitigationResult = Mitigation.TestNotImplemented;
            try
            {
                List<INetFwRule> FirewallRules = SystemUtils.GetEnabledFirewallRules();
                var BITsRules = FirewallRules.Where(o => o.serviceName.ToString() == "BITS");
                MitigationResult = BITsRules.Count() > 0 ? Mitigation.True : Mitigation.False;
                AddMitigationResult(results, "BITS host firewall rules?", MitigationResult);
            }
            catch (Exception ex)
            {
                AddMitigationResult(results, "BITS host firewall rules", Mitigation.Failed);
                PrintUtils.ErrorPrint(ex.Message);
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
            AddMitigationResult(results, "LAPS Enabled", SystemUtils.IsLapsEnabled());

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
            string W32TimeDLLPath = @"%windir%\System32\W32Time.dll";
            //string W32TimeDLLPath = @"C:\ExploitConfigfile.xml"; // for testing
            PrintUtils.PrintInfo("W32Time DLL permissions hardened?");
            var permissions = Utils.GetFileWritePermissions(W32TimeDLLPath, Program.InterestingSIDs);
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
                var RegPermissions = Utils.GetRegPermissions("HKLM", RegPath, Program.InterestingSIDs);
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
                Utils.GetRegPermissions("HKCU", @"Environment", Program.InterestingSIDs) != null
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
        /* TODO: Check for profile lo
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
            AddMitigationResult(results, "Avoid PowerShell profiles", Mitigation.CannotBeMeasured);

            return results;
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
            }
            catch (OfficeUtils.OfficeNotInstallException ex)
            {
                AddMitigationResult(results, "Disabled/Signed Addins", Mitigation.Failed);
                PrintUtils.ErrorPrint(ex.Message);
            }

            // Check 2: Disabled/Signed Addins
            try
            {
                PrintUtils.PrintInfo("Are addins disabled or signed only?");
                AddMitigationResult(results, "Disabled/Signed Addins", OfficeUtils.GetAddinsConf());
            }
            catch (OfficeUtils.OfficeNotInstallException ex)
            {
                AddMitigationResult(results, "Disabled/Signed Addins", Mitigation.Failed);
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
            PrintUtils.PrintInfo("Is office test registry key hardened?");
            // Check if the key exists
            string RegPath = @"Software\Microsoft\Office test\Special\Perf";
            if (!Utils.RegExists("HKCU", RegPath, "Default"))
            {
                AddMitigationResult(results, "Create and Harden Registry Key", false);
            }
            else
            {
                var HavePermissionsToAlter = Utils.GetRegPermissions("HKCU", RegPath, Program.InterestingSIDs) is null ? false : true;
                AddMitigationResult(results, "Create and Harden Registry Key", HavePermissionsToAlter);
            }
            return results;
        }
        // TODO:
        //https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/detect-and-remediate-outlook-rules-forms-attack?view=o365-worldwide

        ////////////////////////////////
        // T1542.001: System Firmware //
        ////////////////////////////////
        public static Dictionary<string, Mitigation> T1542_001()
        {
            Dictionary<string, Mitigation> results = InitiateMitigation("Secure Boot", "PAM", "Patch BIOS and EFI");

            // Check 1: Checking for Secure Boot
            PrintUtils.PrintInfo("Secure Boot Enabled?");
            AddMitigationResult(results, "Secure Boot", SystemUtils.IsSecureBootEnabled());

            return results;
        }

        ////////////////////////
        // T1542.003: Bootkit //
        ////////////////////////
        public static Dictionary<string, Mitigation> T1542_003()
        {
            Dictionary<string, Mitigation> results = InitiateMitigation("Secure Boot", "PAM");

            // Check 1: Checking for Secure Boot
            PrintUtils.PrintInfo("Secure Boot Enabled?");
            AddMitigationResult(results, "Secure Boot", SystemUtils.IsSecureBootEnabled());

            return results;
        }

        /////////////////////////////////////////////////
        // T1595.003: Compromise Hardware Supply Chain //
        /////////////////////////////////////////////////
        public static Dictionary<string, Mitigation> T1195_003()
        {
            Dictionary<string, Mitigation> results = InitiateMitigation("Secure Boot", "PAM");

            // Check 1: Checking for Secure Boot
            PrintUtils.PrintInfo("Secure Boot Enabled?");
            AddMitigationResult(results, "Secure Boot", SystemUtils.IsSecureBootEnabled());

            return results;
        }

        //////////////////////////////////
        // T1110.001: Password Guessing //
        //////////////////////////////////
        public static Dictionary<string, Mitigation> T1110_001()
        {
            Dictionary<string, Mitigation> results = InitiateMitigation("Windows Lockout Policy", "MFA", "Hardened Password Policy");

            // Check 1: Windows Lockout Policy
            PrintUtils.PrintInfo("Is an AD lockout policy set?");
            AddMitigationResult(results, "Windows Lockout Policy", true);

            return results;
        }

        //////////////////////////////////
        // T1110.003: Password Spraying //
        //////////////////////////////////
        public static Dictionary<string, Mitigation> T1110_003()
        {
            //same mitigations as T1110.001
            return T1110_001();
        }

        ////////////////////////////////////
        // T1110.004: Credential Stuffing //
        ////////////////////////////////////
        public static Dictionary<string, Mitigation> T1110_004()
        {
            //same mitigations as T1110.001
            return T1110_001();
        }

        //////////////////////////////////////////////
        // T1555.003: Credentials from Web Browsers //
        //////////////////////////////////////////////
        public static Dictionary<string, Mitigation> T1555_003()
        {
            Dictionary<string, Mitigation> results = InitiateMitigation("Chrome Password Manager Disabled?");

            // Check 1: Is Chrome PW manager disabled?
            PrintUtils.PrintInfo("Is Chrome Password Manager Disabled?");
            AddMitigationResult(results, "Chrome Password Manager Disabled?", SystemUtils.IsChromePasswordManagerDisabled());

            return results;
        }

        //////////////////////////////////////////
        // T1134.001: Token Impersonation/Theft //
        //////////////////////////////////////////
        public static Dictionary<string, Mitigation> T1134_001()
        {
            Dictionary<string, Mitigation> results = InitiateMitigation(
                "Hardened create token object rights",
                "Hardened replace token object rights",
                "LAPS Enabled");

            // Check 1: Which users/groups can create token objects?
            // https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/user-rights-assignment
            PrintUtils.PrintInfo("Checking for harden permissions on user groups that can create tokens");
            try
            {
                List<string> AccountSIDs = UserUtils.GetUsersWithPrivilege("SeCreateTokenPrivilege");
                if (AccountSIDs.Count() == 0)
                {
                    // Only Local Admins have the permission
                    AddMitigationResult(results, "Hardened create token object rights", Mitigation.True);
                }
                else
                {
                    bool AccountsInInterestingSIDs = !AccountSIDs.Intersect(Program.InterestingSIDs).Any();
                    AddMitigationResult(results, "Hardened create token object rights", AccountsInInterestingSIDs);
                }
            }
            catch (UnauthorizedAccessException)
            {
                AddMitigationResult(results, "Hardened create token object rights", Mitigation.Failed);
                PrintUtils.ErrorPrint("Insufficient rights for this check");
            }
            catch (Exception ex)
            {
                AddMitigationResult(results, "Hardened create token object rights", Mitigation.Failed);
                PrintUtils.ErrorPrint(ex.Message);
            }
            // Check 2: Which users/groups can replace token object rights
            PrintUtils.PrintInfo("Checking for harden permissions on user groups that can replace process tokens");
            try
            {
                List<string> AccountSIDs = UserUtils.GetUsersWithPrivilege("SeAssignPrimaryTokenPrivilege");
                if (AccountSIDs.Count() == 0)
                {
                    // Only Local Admins have the permission
                    AddMitigationResult(results, "Hardened replace token object rights", Mitigation.True);
                }
                else
                {
                    bool AccountsInInterestingSIDs = !AccountSIDs.Intersect(Program.InterestingSIDs).Any();
                    AddMitigationResult(results, "Hardened replace token object rights", AccountsInInterestingSIDs);
                }
            }
            catch (UnauthorizedAccessException)
            {
                AddMitigationResult(results, "Hardened replace token object rights", Mitigation.Failed);
                PrintUtils.ErrorPrint("Insufficient rights for this check");
            }
            catch (Exception ex)
            {
                AddMitigationResult(results, "Hardened replace token object rights", Mitigation.Failed);
                PrintUtils.ErrorPrint(ex.Message);
            }
            // Check 3: Is LAPS enabled?
            PrintUtils.PrintInfo("LAPS enabled?");
            AddMitigationResult(results, "LAPS Enabled", SystemUtils.IsLapsEnabled());
            return results;

        }

        //////////////////////////////////////////
        // T1134.002: Create Process with Token //
        //////////////////////////////////////////
        public static Dictionary<string, Mitigation> T1134_002()
        {
            return T1134_001();
        }

        ///////////////////////////////////////////
        // T1134.003: Make and Impersonate Token //
        ///////////////////////////////////////////
        public static Dictionary<string, Mitigation> T1134_003()
        {
            return T1134_001();
        }
        /////////////////////////////////////////////////
        // T1087.001: Account Discovery: Local Account //
        /////////////////////////////////////////////////
        public static Dictionary<string, Mitigation> T1087_001()
        {
            Dictionary<string, Mitigation> results = InitiateMitigation(
                "Prevent Administrator Accounts from being enumerated when a user attempts to elevate a running application");
            PrintUtils.PrintInfo("Is UAC Admin acccount enumeration disabled?");
            var RegPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI";
            var RegKey = "EnumerateAdministrators";
            var RegValue = Utils.GetRegValue("HKLM", RegPath, RegKey);
            if (RegValue == "" || RegValue == "0")
                AddMitigationResult(
                    results,
                    "Prevent Administrator Accounts from being enumerated when a user attempts to elevate a running application",
                    Mitigation.True);
            else
                AddMitigationResult(
                  results,
                  "Prevent Administrator Accounts from being enumerated when a user attempts to elevate a running application",
                  Mitigation.False);
            return results;
        }
        //////////////////////////////////////////////////
        // T1087.002: Account Discovery: Domain Account //
        //////////////////////////////////////////////////
        public static Dictionary<string, Mitigation> T1087_002()
        {
            return T1087_001();
        }
        //////////////////////////////
        // T1550.002: Pass the Hash //
        //////////////////////////////
        public static Dictionary<string, Mitigation> T1550_002()
        {
            // Mitigations can be based on https://www.microsoft.com/en-us/download/details.aspx?id=36036 instead of ATT&CK
            Dictionary<string, Mitigation> results = InitiateMitigation(
                "Credential Overlap",  // no test defined yet
                "Update Software(KB2871997)",
                "PtH to apply UAC restring to local account on network logon",
                "No domain users as local admins");

            // Check 1: Checking for KB2871997
            PrintUtils.PrintInfo("Is KB2871997 installed and configured?");
            try
            {
                string OSVersion = SystemUtils.GetOSVersion();
                // Hotfix only applies to Windows Versions <= Windows 7 or Windows Server Version <= Windows 2012 R2 i.e. version < 6.3
                var tokens = OSVersion.Split('.');
                var DoubleVersion = double.Parse(String.Format("{0}.{1}", tokens[0], tokens[1]));

                // Is the HotFix needed?
                if (DoubleVersion >= 6.3)
                {
                    // No need for the hotfix
                    AddMitigationResult(results, "Update Software(KB2871997)", Mitigation.True);
                }
                else
                {
                    var Status = Mitigation.True;

                    // Check if the hotfix is installed + configured
                    bool IsHotFixInstalled = SystemUtils.IsHotFixInstalled("KB2871997");
                    if (!IsHotFixInstalled)
                        Status = Mitigation.False;

                    // Is the TokenLeakDetectDelaySecs reg set?
                    var TokenLeakDetectDelaySecs =
                        Utils.GetRegValue("HKLM", @"SYSTEM\CurrentControlSet\Control\Lsa", "TokenLeakDetectDelaySecs");
                    if (TokenLeakDetectDelaySecs == "" || int.Parse(TokenLeakDetectDelaySecs) > 30)
                        Status = Mitigation.False;

                    // Is WDigest's UseLogonCredential disabled? This prevents WDigest from storing creds in Memory
                    var UseLogonCredential =
                        Utils.GetRegValue("HKLM", @"System\CurrentControlSet\Control\SecurityProviders\WDigest", "UseLogonCredential");
                    if (UseLogonCredential != "0")
                        Status = Mitigation.False;
                    AddMitigationResult(results, "Update Software(KB2871997)", Status);
                }
            }
            catch (Exception ex)
            {
                AddMitigationResult(results, "Update Software(KB2871997)", Mitigation.Failed);
                PrintUtils.ErrorPrint(ex.Message);
            }

            // Check 2: PtH to apply UAC restring to local account on network logon
            PrintUtils.PrintInfo("Are UAC restrictions applied on network logon?");
            try
            {
                // Is the LocalAccountTokenFilterPolicy enabled?
                var RegValue =
                    Utils.GetRegValue("HKLM", @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "LocalAccountTokenFilterPolicy");
                if (RegValue != "1")
                {
                    AddMitigationResult(results, "PtH to apply UAC restring to local account on network logon", Mitigation.True);
                }
                else
                {
                    AddMitigationResult(results, "PtH to apply UAC restring to local account on network logon", Mitigation.False);
                }
            }
            catch (Exception ex)
            {
                AddMitigationResult(results, "PtH to apply UAC restring to local account on network logon", Mitigation.Failed);
                PrintUtils.ErrorPrint(ex.Message);
            }

            // Check 3: No domain accounts as local admins
            PrintUtils.PrintInfo("Are domain accounts excluded from local administrators?");
            try
            {
                AddMitigationResult(results, "No domain users as local admins", !UserUtils.IsADomainUserMemberofLocalAdmins());
            }
            catch (Exception ex)
            {
                AddMitigationResult(results, "No domain users as local admins", Mitigation.Failed);
                PrintUtils.ErrorPrint(ex.Message);
            }

            return results;
        }
        ////////////////////////////////
        // T1550.003: Pass the Ticket //
        ////////////////////////////////
        public static Dictionary<string, Mitigation> T1550_003()
        {
            Dictionary<string, Mitigation> results = InitiateMitigation("LAPS enabled", "No domain users as local admins");

            // Check 1: Is LAPS enabled?
            PrintUtils.PrintInfo("LAPS enabled?");
            AddMitigationResult(results, "LAPS enabled", SystemUtils.IsLapsEnabled());

            // Check 2: No domain accounts as local admins
            PrintUtils.PrintInfo("Are domain accounts excluded from local administrators?");
            try
            {
                AddMitigationResult(results, "No domain users as local admins", !UserUtils.IsADomainUserMemberofLocalAdmins());
            }
            catch (Exception ex)
            {
                AddMitigationResult(results, "No domain users as local admins", Mitigation.Failed);
                PrintUtils.ErrorPrint(ex.Message);
            }
            return results;

        }
        ///////////////////////////////////////////
        // T1574.001: DLL Search Order Hijacking //
        ///////////////////////////////////////////
        public static Dictionary<string, Mitigation> T1574_001()
        {
            Dictionary<string, Mitigation> results = InitiateMitigation(
                "Audit", "Application Whitelisting", "Safe DLL Search Mode");

            AddMitigationResult(results, "Audit", Mitigation.CannotBeMeasured);

            // Check 1: Application/DLL Whitelisting - TODO

            // Check 2: Safe DLL Search Mode
            // https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order?redirectedfrom=MSDN
            PrintUtils.PrintInfo("Ensuring Safe DLL Search mode is on");
            AddMitigationResult(results, "Safe DLL Search Mode", SystemUtils.IsSafeDllSafeSearchModeOn());

            return results;
        }
        ///////////////////////////////////////////////////////////////
        // T1574.005: Executable Installer File Permissions Weakness //
        ///////////////////////////////////////////////////////////////
        public static Dictionary<string, Mitigation> T1574_005()
        {
            Dictionary<string, Mitigation> results = InitiateMitigation(
                "Audit", "UAC privilege elevation default deny", "Limit user privileges on services");

            AddMitigationResult(results, "Audit", Mitigation.CannotBeMeasured);

            // Check 1: Checking for UAC privilege elevation consent behaviour
            PrintUtils.PrintInfo("Looking for UAC default deny behaviour");
            AddMitigationResult(results, "UAC privilege elevation default deny", SystemUtils.IsUACSetToDefaultDeny());

            return results;
        }

        ////////////////////////////////////////////////////
        // T1003.001: OS Credential Dumping: LSASS Memory //
        ////////////////////////////////////////////////////
        public static Dictionary<string, Mitigation> T1003_001()
        {
            Dictionary<string, Mitigation> results = InitiateMitigation(
                "Windows Credential Guard",
                "Disabling/Restricting Outbound NTLM",
                "LAPS enabled",
                "No domain users as local admins",
                "Run LSASS as PPL"
                );

            // Check 1: Credential Guard
            PrintUtils.PrintInfo("Checking for Credential Guard");
            AddMitigationResult(results, "Windows Credential Guard", SystemUtils.IsCredentialGuardEnabled());

            // Check 2: Disabling Outbound NTLM
            PrintUtils.PrintInfo("Is Outbound NTML disabled?");
            AddMitigationResult(results, "UAC privilege elevation default deny", SystemUtils.IsOutboundNTLMDisabled());

            // Check 3: LAPS
            PrintUtils.PrintInfo("LAPS enabled?");
            AddMitigationResult(results, "LAPS enabled", SystemUtils.IsLapsEnabled());

            // Check 4: Domain Users in local admin group
            PrintUtils.PrintInfo("Are domain accounts excluded from local administrators?");
            try
            {
                AddMitigationResult(results, "No domain users as local admins", !UserUtils.IsADomainUserMemberofLocalAdmins());
            }
            catch (Exception ex)
            {
                AddMitigationResult(results, "No domain users as local admins", Mitigation.Failed);
                PrintUtils.ErrorPrint(ex.Message);
            }

            // Check 5: LSASS as PPL
            PrintUtils.PrintInfo("Is LSA running as PPL?");
            AddMitigationResult(results, "Run LSASS as PPL", SystemUtils.IsLsaRunAsPPL());

            return results;
        }
        ////////////////////////////////////////////////////////////////
        // T1003.002: OS Credential Dumping: Security Account Manager //
        ////////////////////////////////////////////////////////////////
        public static Dictionary<string, Mitigation> T1003_002()
        {
            Dictionary<string, Mitigation> results = InitiateMitigation(
                "Disabling/Restricting Outbound NTLM",
                "LAPS enabled",
                "No domain users as local admins"
                );


            // Check 1: Disabling Outbound NTLM
            PrintUtils.PrintInfo("Is Outbound NTML disabled?");
            AddMitigationResult(results, "UAC privilege elevation default deny", SystemUtils.IsOutboundNTLMDisabled());

            // Check 2: LAPS
            PrintUtils.PrintInfo("LAPS enabled?");
            AddMitigationResult(results, "LAPS enabled", SystemUtils.IsLapsEnabled());

            // Check 3: Domain Users in local admin group
            PrintUtils.PrintInfo("Are domain accounts excluded from local administrators?");
            try
            {
                AddMitigationResult(results, "No domain users as local admins", !UserUtils.IsADomainUserMemberofLocalAdmins());
            }
            catch (Exception ex)
            {
                AddMitigationResult(results, "No domain users as local admins", Mitigation.Failed);
                PrintUtils.ErrorPrint(ex.Message);
            }

            return results;
        }
        ////////////////////////////////
        // T1021.003: Distributed COM //
        ////////////////////////////////
        public static Dictionary<string, Mitigation> T1021_003()
        {
            Dictionary<string, Mitigation> results = InitiateMitigation(
                "Protected View",
                "Disable DCOM",
                "Windows Firewall rule",
                "Default COM permissions"
                );

            // Check 1: Is protected view enabled? //
            PrintUtils.PrintInfo("Is protected view enabled");
            try
            {
                var ProtectedViewInfo = OfficeUtils.GetProtectedViewInfo();
                AddMitigationResult(results, "Protected View Enabled", ProtectedViewInfo);
            }
            catch (OfficeUtils.OfficeNotInstallException ex)
            {
                AddMitigationResult(results, "Protected View Enabled", Mitigation.NA);
                PrintUtils.ErrorPrint(ex.Message);
            }
            catch (Exception ex)
            {
                AddMitigationResult(results, "Protected View Enabled", Mitigation.Failed);
                PrintUtils.ErrorPrint(ex.Message);
            }
            // Check 2: Is DCOM disabled?
            PrintUtils.PrintInfo("Is DCOM fully disabled?");
            AddMitigationResult(results, "Disable DCOM", SystemUtils.IsDCOMDisabled());

            // Check 3: Windows Firewall rules //TODO

            // Check 4: Default DCOM permissions hardened
            PrintUtils.PrintInfo("Are COM permissions default permissions only to admins");
            AddMitigationResult(results, "Default COM permissions", SystemUtils.GetDefaultComPermissions());

            return results;
        }
        ////////////////////////////////////////
        // T1021.001: Remote Desktop Protocol //
        ////////////////////////////////////////
        public static Dictionary<string, Mitigation> T1021_001()
        {
            Dictionary<string, Mitigation> results = InitiateMitigation(
                "Audit",
                "RDP Disabled",
                "Use remote desktop gateways",
                "Use MFA",
                "Restrict RDP traffic between network segments",
                "Shorter session timeout and session max time",
                "Remove Local Admins from RDP groups",
                "Least Privelege on RDP Users"
                );

            AddMitigationResult(results, "Audit", Mitigation.CannotBeMeasured);
            AddMitigationResult(results, "Use remote desktop gateways", Mitigation.CannotBeMeasured);
            AddMitigationResult(results, "Use MFA", Mitigation.CannotBeMeasured);
            AddMitigationResult(results, "Least Privelege on RDP Users", Mitigation.CannotBeMeasured);

            // Check 1: Is RDP disabled on the machine //
            PrintUtils.PrintInfo("Is RDP disabled");
            AddMitigationResult(results, "RDP Disabled", SystemUtils.IsRDPDisabled());


            // Check 2: Shorter session timeout and session max time
            PrintUtils.PrintInfo("Sessions timing limits");
            AddMitigationResult(results, "Shorter session timeout and session max time", SystemUtils.GetRDPSessionConfig());

            // Check 3: Local Admin Groups in RDP
            PrintUtils.PrintInfo("Are local admins excluded from RDP?");
            try
            {
                List<string> AllowedSIDs = UserUtils.GetUsersWithPrivilege("SeRemoteInteractiveLogonRight");
                List<string> BlockedSIDs = UserUtils.GetUsersWithPrivilege("SeDenyRemoteInteractiveLogonRight");
                AddMitigationResult(results, "Remove Local Admins from RDP groups", !UserUtils.IsAdmin(AllowedSIDs) || UserUtils.IsAdmin(BlockedSIDs));
            }
            catch (UnauthorizedAccessException)
            {
                AddMitigationResult(results, "Remove Local Admins from RDP groups", Mitigation.Failed);
                PrintUtils.ErrorPrint("Insufficient rights for this check");
            }
            catch (Exception ex)
            {
                AddMitigationResult(results, "Remove Local Admins from RDP groups", Mitigation.Failed);
                PrintUtils.ErrorPrint(ex.Message);
            }

            return results;
        }
        /////////////////////////////////////////
        // T1021.002: SMB/Windows Admin Shares //
        /////////////////////////////////////////
        public static Dictionary<string, Mitigation> T1021_002()
        {
            Dictionary<string, Mitigation> results = InitiateMitigation(
                "LAPS enabled",
                "Deny remote use of local admin credentials to log into the system",
                "No domain users as local admins"
                );

            // Check 1: LAPS
            PrintUtils.PrintInfo("LAPS enabled?");
            AddMitigationResult(results, "LAPS enabled", SystemUtils.IsLapsEnabled());

            // Check 2: Remote local admin login
            PrintUtils.PrintInfo("Are local admins denied remote logon?");
            try
            {
                List<string> BlockedSIDs = UserUtils.GetUsersWithPrivilege("SeDenyRemoteInteractiveLogonRight");
                AddMitigationResult(results,
                    "Deny remote use of local admin credentials to log into the system",
                    UserUtils.IsAdmin(BlockedSIDs)
                    );
            }
            catch (UnauthorizedAccessException)
            {
                AddMitigationResult(results, "Deny remote use of local admin credentials to log into the system", Mitigation.Failed);
                PrintUtils.ErrorPrint("Insufficient rights for this check");
            }
            catch (Exception ex)
            {
                AddMitigationResult(results, "Deny remote use of local admin credentials to log into the system", Mitigation.Failed);
                PrintUtils.ErrorPrint(ex.Message);
            }

            // Check 3: No domain users as local admins
            PrintUtils.PrintInfo("No domain users as local admins");
            try
            {
                AddMitigationResult(results, "No domain users as local admins", !UserUtils.IsADomainUserMemberofLocalAdmins());
            }
            catch (Exception ex)
            {
                AddMitigationResult(results, "No domain users as local admins", Mitigation.Failed);
                PrintUtils.ErrorPrint(ex.Message);
            }
            return results;
        }
        //////////////////////////////////////////
        // T1021.006: Windows Remote Management //
        //////////////////////////////////////////
        public static Dictionary<string, Mitigation> T1021_006()
        {
            Dictionary<string, Mitigation> results = InitiateMitigation(
                "Disable WinRM",
                "Only allow WinRM from specific devices",
                "No domain users as local admins"
                );

            // Check 1: Disable WinRM
            PrintUtils.PrintInfo("WinRM Disabled?");
            var ServiceConfig = Utils.GetServiceConfig("WinRM");
            if (ServiceConfig["StartUpType"] != "AUTOMATIC")
            {
                AddMitigationResult(results, "Disable WinRM", true);
            }
            else
            {
                AddMitigationResult(results, "Disable WinRM", false);
            }

            // Check 2: Check if WinRM is configured to only allow traffic from specific devices
            PrintUtils.PrintInfo("WinRM inbound traffic filtering");
            try
            {
                // Is traffic restricted on host firewall?
                var AllRules = SystemUtils.GetEnabledFirewallRules();
                var WinRmRules = AllRules.Where(o => o.LocalPorts.Contains("5985") || o.LocalPorts.Contains("5986"));
                if (!WinRmRules.Any(o => o.RemoteAddresses == "Any"))
                {
                    // No rules exist that allow for unrestricted traffic
                    AddMitigationResult(results, "Only allow WinRM from specific devices", true);
                }
                else if (SystemUtils.IsWinRMFilteredByGPO())
                {
                    // Traffic is restricted on the application level by GPO
                    AddMitigationResult(results, "Only allow WinRM from specific devices", true);
                }
                else
                {
                    // Traffic does not seem restricted
                    AddMitigationResult(results, "Only allow WinRM from specific devices", false);
                }
            } catch (Exception ex)
            {
                AddMitigationResult(results, "Only allow WinRM from specific devices", Mitigation.Failed);
                PrintUtils.ErrorPrint(ex.Message);
            }

            // Check 3: No domain users as local admins
            PrintUtils.PrintInfo("No domain users as local admins");
            try
            {
                AddMitigationResult(results, "No domain users as local admins", !UserUtils.IsADomainUserMemberofLocalAdmins());
            }
            catch (Exception ex)
            {
                AddMitigationResult(results, "No domain users as local admins", Mitigation.Failed);
                PrintUtils.ErrorPrint(ex.Message);
            }
            return results;
        }
    }
}