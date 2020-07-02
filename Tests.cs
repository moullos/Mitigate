using NetFwTypeLib;
using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Reflection;

namespace Mitigate
{

    public enum Mitigation : int
    {
        TestNotImplemented = -2,    // Mitigation enumaration is not implemented (yet)
        NA = -1,                    // Mitigation enumeration is implemented, but it does not apply to this machine
        False = 0,                  // Mitigation is not applied
        True = 2,                   // Mitigation is applied
        Partial = 1,                // Mitigation is partially applied
        TestFailed = 3,             // Mitigation enumeration failed
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
        private static void AddMitigationResult(Dictionary<String, Mitigation> results, string Description, bool result)
        {
            results[Description] = Bool2TestResult(result);
            PrintUtils.PrintMitigationInfo(Description);
            PrintUtils.PrintMitigationResult(results[Description]);
        }

        private static void AddMitigationResult(Dictionary<String, Mitigation> results, string Description, Mitigation result)
        {
            results[Description] = result;
            PrintUtils.PrintMitigationInfo(Description);
            PrintUtils.PrintMitigationResult(results[Description]);
        }
        private static void AddMitigationResult(Dictionary<string, Mitigation> results, string Description, Dictionary<string, bool> info, bool Verbose = true)
        {
            results[Description] = CollateResults(info);
            PrintUtils.PrintMitigationInfo(Description);
            PrintUtils.PrintMitigationResult(results[Description]);
            if (Verbose)
            {
                foreach (var SubResult in info)
                {
                    var InfoTopic = SubResult.Key;
                    var InfoResult = SubResult.Value;
                    PrintUtils.PrintSubInfo(InfoTopic);
                    PrintUtils.PrintMitigationResult(Bool2TestResult(InfoResult));
                }
            }
            else PrintUtils.PrintMitigationMessage("Detailed results were omitted. Execute with -Verbose for full results");

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

        /////////////////////////////////
        // Enumeration Method Template //
        /////////////////////////////////

        /// <summary>
        /// This a template method for anyone looking to contribute.
        /// All enumeration methods must return a Dictionary with the results of the enumeration.
        /// Result dictionaries are initiated with the InitiateMitigation Method
        /// Results are added to the dictionary with the AddMitigationResult Method
        /// Mitig&te dynamically locates enumeration methods based on the method name which needs to follow a specific naming  
        /// ID of the technique being simulated
        /// XXXX: TechniqueID
        /// _YYY: Optional, In case of subtechnique, YYY is the subtechnique ID
        /// </summary>
        /// <returns>Dictionary with the enumeration findings</returns>
        public static Dictionary<string, Mitigation> TXXXX_YYY()
        {

            // Step 1 is always to initiate the dictionary carrying the results
            Dictionary<string, Mitigation> results = InitiateMitigation(
                "Description of 1st applicable control/configuration",
                "Description of 2nd applicable control/configuration",
                "Description of 3rd applicable control/configuration",
                "..."
                );

            // Check 1: Checking for 1st control

            // Enumeration of 1st application control goes here
            var EnumerationResult1 = false;

            // Use the AddMitigationResultMethod the add the results of the enumeration to the Dictionary as follows
            // EnumerationResult can either be a boolean, a Mitigation enum value or a Dictionary<string,bool> for more complex cases
            AddMitigationResult(results, "Description of 2nd applicable control/configuration", EnumerationResult1);



            // Enumeration of 2nd application control goes here
            var EnumerationResult2 = Mitigation.NA;


            AddMitigationResult(results, "Description of 2nd applicable control/configuration", EnumerationResult2);

            // ... //

            return results;
        }

        /*--------------------------------*/
        /* Enumeration methods begin here */
        /*--------------------------------*/

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
                "Protected View",
                "Default system-wide COM permissions hardened",
                "COM Class IDs with none default permissions"
                );

            // Check 1: Is protected view enabled? //
            try
            {
                var ProtectedViewInfo = OfficeUtils.GetProtectedViewInfo();
                AddMitigationResult(results, "Protected View", ProtectedViewInfo);
            }
            catch (OfficeUtils.OfficeNotInstallException ex)
            {
                AddMitigationResult(results, "Protected View", Mitigation.NA);
                PrintUtils.ErrorPrint(ex.Message);
            }
            catch (Exception ex)
            {
                AddMitigationResult(results, "Protected View", Mitigation.TestFailed);
                PrintUtils.ErrorPrint(ex.Message);
            }

            // Check 2: Hardened system-wide permissions //
            try
            {
                AddMitigationResult(results, "Default system-wide COM permissions hardened", SystemUtils.GetDefaultComPermissions());
            }
            catch (Exception ex)
            {
                AddMitigationResult(results, "Default system-wide COM permissions hardened", Mitigation.TestFailed);
                PrintUtils.ErrorPrint(ex.Message);
            }

            // Check 3: Checking individual com app permissions
            try
            {
                AddMitigationResult(
                    results,
                    "COM Class IDs with none default permissions",
                    SystemUtils.CheckAllComAccessPermissions(),
                    Program.Arguments.Verbose
                    );
            }
            catch (Exception ex)
            {
                AddMitigationResult(
                    results,
                    "COM Class IDs with none default permissions",
                    Mitigation.TestFailed
                    );
                PrintUtils.ErrorPrint(ex.Message);
            }
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
                "Disabled automatic DDE/OLE execution",
                "Disabled embedded files in OneNote"
                );
            // Check 1: Is protected view enabled? //
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
                AddMitigationResult(results, "Protected View Enabled", Mitigation.TestFailed);
                PrintUtils.ErrorPrint(ex.Message);
            }

            // Check 2: Check for Attack Surface Reduction Rules //
            //TODO ASR
            results["Attack Surface Reduction Rules"] = Mitigation.TestNotImplemented;

            // Check 3: Disabled automatic DDE/OLE execution //
            //https://gist.github.com/wdormann/732bb88d9b5dd5a66c9f1e1498f31a1b
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
                AddMitigationResult(results, "Disabled automatic DDE/OLE execution", Mitigation.TestFailed);
                PrintUtils.ErrorPrint(ex.Message);
            }
            // Check 4: Disable embedded files in OneNote //
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
                AddMitigationResult(results, "Disabled embedded files in OneNote", Mitigation.TestFailed);
                PrintUtils.ErrorPrint(ex.Message);
            }
            return results;
        }

        ///////////////////////////////
        // Domain Accounts:T1078.002 //
        ///////////////////////////////
        public static Dictionary<string, Mitigation> T1078_002()
        {
            Dictionary<string, Mitigation> results = InitiateMitigation("MFA", "No domain accounts in local admin group");
            // Check 1: Are any domain users part of the local admin group?
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
            AddMitigationResult(results, "LAPS Enabled", SystemUtils.IsLapsEnabled());
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
            string[] SatisfyingPolicies = { "AllSigned", "RemoteSigned", "Restricted" };
            string ExecutionPolicy = SystemUtils.GetPowershellExecutionPolicy();
            AddMitigationResult(results, "Execute only signed scripts", SatisfyingPolicies.Contains(ExecutionPolicy));

            // Check 2: Check if PS is accessble
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
            AddMitigationResult(results, "AppLocker Enabled", SystemUtils.IsAppLockerEnabled());

            //Check 2: Windows Defender Application Control
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
            AddMitigationResult(results, "AppLocker Enabled", SystemUtils.IsAppLockerEnabled());

            //Check 2: Windows Defender Application Control
            AddMitigationResult(results, "WDAC Enabled", SystemUtils.IsWDACEnabled());

            //Check 3: Are the scripts accessibled?
            AddMitigationResult(results, "Restrict Access to VBScripts", !(Utils.CommandFileExists("Cscript.exe") || Utils.CommandFileExists("Wscript.exe")));

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
            var WDAGStatus = SystemUtils.IsWDApplicationGuardEnabled();
            AddMitigationResult(results, "WDAG Enabled", WDAGStatus);

            //Check 2: Checking for exploit guard
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
            var WDAGStatus = SystemUtils.IsWDApplicationGuardEnabled();
            AddMitigationResult(results, "WDAG Enabled", WDAGStatus);

            //Check 2: Applocker
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
            AddMitigationResult(results, "Do not run as SYSTEM", SystemUtils.RunAtInUserContext());

            // Check 2: at deprecated
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
            AddMitigationResult(results, "Do not run as SYSTEM", SystemUtils.RunAtInUserContext());

            return results;
        }

        //////////////////////
        // BITS Jobs: T1197 //
        //////////////////////
        public static Dictionary<string, Mitigation> T1197()
        {
            Dictionary<string, Mitigation> results = InitiateMitigation(
                "BITS Host firewall rules",
                "Reduce BITS job lifetime",
                "Limit User Access");

            AddMitigationResult(results, "Reduce BITS job lifetime", SystemUtils.GetBITSConfigInfo());

            // Check 2: Firewall rules
            var MitigationResult = Mitigation.TestNotImplemented;
            try
            {
                var FirewallRules = FirewallUtils.GetEnabledInboundRules();
                var BITsRules = FirewallRules.Where(o => o.serviceName.ToString() == "BITS");
                MitigationResult = BITsRules != null ? Mitigation.True : Mitigation.False;
                AddMitigationResult(results, "BITS host firewall rules", MitigationResult);
            }
            catch (Exception ex)
            {
                AddMitigationResult(results, "BITS host firewall rules", Mitigation.TestFailed);
                PrintUtils.ErrorPrint(ex.Message);
            }
            return results;
        }

        ///////////////////////////////////////////////
        // Windows Management Instrumentation: T1047 //
        ///////////////////////////////////////////////
        public static Dictionary<string, Mitigation> T1047()
        {
            Dictionary<string, Mitigation> results = InitiateMitigation("" +
                "LAPS Enabled",
                $"No remote WMI access to {Program.UserToCheck.SamAccountName}");

            // Check 1: Is LAPS enabled?
            AddMitigationResult(results, "LAPS Enabled", SystemUtils.IsLapsEnabled());

            // Check 2: WMI Permissions
            try
            {
                var wmiRemoteDeny = new Dictionary<string, bool>();
                ViewNameSpaceSecurity viewns = new ViewNameSpaceSecurity(@"root\cimv2", false);
                foreach (var item in viewns.GetNameSpaceSDDL(Environment.MachineName))
                {
                    var NameSpace = item.Key;
                    var SDDLString = item.Value;
                    var DecodedSDDL = Utils.PermissionsDecoder.DecodeSddlString<Utils.WMIPermissionsMask>(SDDLString);
                    var SIDsToCheckPermissions = DecodedSDDL.DACL.Where(o => Program.SIDsToCheck.Contains(o.Trustee) && o.AccessType == "AccessAllowed")
                                                                    .Select(o => o.Permissions);

                    wmiRemoteDeny[NameSpace] = true;
                    foreach (var permission in SIDsToCheckPermissions)
                    {
                        if (permission.Contains("WMI_REMOTE_ENABLE") && permission.Contains("WMI_ENABLE_ACCOUNT"))
                        {
                            wmiRemoteDeny[NameSpace] = false;
                            break;
                        }
                    }
                }
                AddMitigationResult(results, $"No remote WMI access to {Program.UserToCheck.SamAccountName}", wmiRemoteDeny);
            }
            catch (Exception ex)
            {
                AddMitigationResult(results, $"No remote WMI access to {Program.UserToCheck.SamAccountName}", Mitigation.TestFailed);
                PrintUtils.ErrorPrint(ex.Message);

            }

            return results;
        }

        ///////////////////////////////////////
        // Authentication Package: T1547.002 //
        ///////////////////////////////////////
        public static Dictionary<string, Mitigation> T1547_002()
        {
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
            string W32TimeDLLPath = String.Format($"C:\\{Environment.SpecialFolder.Windows}\\System32\\W32Time.dll");
            AddMitigationResult(results,
                "Block additions / modification to W32Time DLL",
                !Utils.FileWritePermissions(W32TimeDLLPath, Program.SIDsToCheck)
                );

            // Check 2: Reg Permissions
            Dictionary<string, bool> RegPermissionsNoWrite = new Dictionary<string, bool>(); ;
            string[] RegPaths = {
                @"SYSTEM\CurrentControlSet\Services\W32Time\Config",
                @"SYSTEM\CurrentControlSet\Services\W32Time\Parameters",
                @"SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders",
                @"SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpClient",
                @"SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpServer"
            };
            foreach (string RegPath in RegPaths)
            {
                RegPermissionsNoWrite[RegPath] = !Utils.RegWritePermissions("HKLM", RegPath, Program.SIDsToCheck);
            }
            AddMitigationResult(results, "Block modification to W32Time parameters in registry", RegPermissionsNoWrite);
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
            AddMitigationResult(results, "DLL Whitelisting(Applocker)", SystemUtils.IsAppLockerEnabled());

            //Check 2: Winlogon permissions
            AddMitigationResult(results, "Registry Key Permissions", SystemUtils.GetWinlogonRegPermissions());

            return results;
        }

        //////////////////////////////////////////
        // Security Support Provider: T1547.005 //
        //////////////////////////////////////////
        public static Dictionary<string, Mitigation> T1547_005()
        {
            Dictionary<string, Mitigation> results = InitiateMitigation("Make LSA run as Protected Process Light");

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
            AddMitigationResult(results, "Make LSA run as Protected Process Light", SystemUtils.IsLsaRunAsPPL());

            // Check 2: Windows Defender Credential Guard
            AddMitigationResult(results, "WDCG Enabled", SystemUtils.IsCredentialGuardEnabled());

            // Check 3: Is DLL search mode enabled?
            //https://docs.microsoft.com/en-gb/windows/win32/dlls/dynamic-link-library-search-order
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
            try
            {
                List<string> AccountSIDs = UserUtils.GetUsersWithPrivilege("SeCreateSymbolicLinkPrivilege");
                if (AccountSIDs.Count() == 0)
                {
                    // Only Local Admins have the permission
                    AddMitigationResult(results, "Only administrators are allowed to create symbolic links", Mitigation.True);
                }
                else
                {
                    bool AccountsInInterestingSIDs = !AccountSIDs.Intersect(Program.SIDsToCheck).Any();
                    AddMitigationResult(results, "Only administrators are allowed to create symbolic links", AccountsInInterestingSIDs);
                }
            }
            catch (UnauthorizedAccessException)
            {
                AddMitigationResult(results, "Only administrators are allowed to create symbolic links", Mitigation.TestFailed);
                PrintUtils.ErrorPrint("Insufficient rights for this check");
            }
            catch (Exception ex)
            {
                AddMitigationResult(results, "Only administrators are allowed to create symbolic links", Mitigation.TestFailed);
                PrintUtils.ErrorPrint(ex.Message);
            }

            return results;
        }

        ///////////////////////////////////////
        // Logon Script (Windows): T1037.001 //
        ///////////////////////////////////////
        public static Dictionary<string, Mitigation> T1037_001()
        {
            Dictionary<string, Mitigation> results = InitiateMitigation(@"Hardened HKCU\Environment registry permissions");

            //Check 1: Hardened registry permissions
            AddMitigationResult(results,
                @"Hardened HKCU\Environment registry permissions",
                !Utils.RegWritePermissions("HKCU", "Environment", Program.SIDsToCheck)
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
                "Chrome browser extensions whitelist",
                "Chrome only trusted browser extensions",
                "User training");
            results["Audit"] = Mitigation.NA;
            results["User training"] = Mitigation.NA;

            // Check 1: Extension whitelist
            // Checking only chrome for now
            AddMitigationResult(results, "Chrome browser extensions whitelist", SystemUtils.IsChromeExtensionWhitelistEnabled());

            // Check 2: Only trusted extensions
            AddMitigationResult(results, "Chrome only trusted browser extensions", SystemUtils.IsChromeExternalExtectionsBlocked());

            return results;
        }

        ////////////////////////////
        // Screensaver: T1546.002 //
        ////////////////////////////
        public static Dictionary<string, Mitigation> T1546_002()
        {
            Dictionary<string, Mitigation> results = InitiateMitigation("Screen Saver Disabled");
            //https://getadmx.com/?Category=Windows_10_2016&Policy=Microsoft.Policies.ControlPanelDisplay::CPL_Personalization_EnableScreenSaver

            AddMitigationResult(results, "Screen Saver Disabled", SystemUtils.IsScreenSaverDisabled());

            return results;
        }

        ///////////////////////////////////
        // PowerShell Profile: T1546.013 //
        ///////////////////////////////////

        public static Dictionary<string, Mitigation> T1546_013()
        {
            Dictionary<string, Mitigation> results = InitiateMitigation(
                "Enforce execution of only signed PowerShell scripts",
                "Make Profile Files immutable. Allow only certain admins to changes them",
                "Avoid PowerShell profiles"
                );

            // Check 1: Powershell execution policy
            string[] SatisfyingPolicies = { "AllSigned", "RemoteSigned", "Restricted" };
            string ExecutionPolicy = SystemUtils.GetPowershellExecutionPolicy();
            AddMitigationResult(results, "Enforce execution of only signed PowerShell scripts", SatisfyingPolicies.Contains(ExecutionPolicy));

            // Check 2: Are profile files immutable by non privileged users?

            AddMitigationResult(
                results,
               "Make Profile Files immutable. Allow only certain admins to changes them",
                SystemUtils.GetPowerShellProfilePermissions(Program.SIDsToCheck)
               );

            // Avoiding PowerShell profiles is not measurable
            AddMitigationResult(results, "Avoid PowerShell profiles", Mitigation.CannotBeMeasured);

            return results;
        }

        //////////////////////////////////////
        // T1546.008: Accessibility Features //
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
            bool ExecutionPrevention = SystemUtils.IsAppLockerEnabled() || SystemUtils.IsWDACEnabled();
            AddMitigationResult(results, "Execution Prevention", ExecutionPrevention);

            //Check 3: NLA for RDP
            AddMitigationResult(results, "Enabled Network Level Authentication for RDP", SystemUtils.IsRdpNLAEnabled());

            return results;
        }

        /////////////////////////////
        // T1546.009: AppCert DLLs //
        /////////////////////////////
        public static Dictionary<string, Mitigation> T1546_009()
        {
            Dictionary<string, Mitigation> results = InitiateMitigation(
                   "Attack Surface Reduction Rules",
                   "AppLocker Rules on DLLs"
               );

            // Check 1: ASR

            try
            {
                if (SystemUtils.IsASREnabled())
                {
                    List<string> RelevantRuleGuids = new List<string>()
                    {
                        {"BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550"},
                        {"01443614-cd74-433a-b99e-2ecdc07bfc25"},
                        {"b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4"}
                    };
                    AddMitigationResult(results, "Attack Surface Reduction Rules", SystemUtils.GetASRRulesStatus(RelevantRuleGuids));
                }
                else
                {
                    AddMitigationResult(results, "Attack Surface Reduction Rules", false);
                }
            }
            catch (Exception ex)
            {
                AddMitigationResult(results, "Attack Surface Reduction Rules", Mitigation.TestFailed);
                PrintUtils.ErrorPrint(ex.Message);
            }

            // Check 2: AppLocker on DLLs
            try
            {
                if (SystemUtils.IsAppLockerEnabled("DLL"))
                {
                    var DllRules = SystemUtils.GetAppLockerRules("DLL");
                    if (DllRules.Count() > 0)
                    {
                        AddMitigationResult(results, "AppLocker Rules on DLLs", DllRules);
                    }
                    else
                    {
                        AddMitigationResult(results, "AppLocker Rules on DLLs", false);
                    }
                }
            }
            catch (Exception ex)
            {
                AddMitigationResult(results, "AppLocker Rules on DLLs", Mitigation.TestFailed);
                PrintUtils.ErrorPrint(ex.Message);
            }

            return results;
        }

        /////////////////////////////
        // T1546.010: AppInit DLLs //
        /////////////////////////////
        public static Dictionary<string, Mitigation> T1546_010()
        {
            Dictionary<string, Mitigation> results = InitiateMitigation(
                "Attack Surface Reduction Rules",
                "AppLocker Rules on DLLs",
                "Secure Boot"
                );
            // Check 1: Application Whitelisting
            // Check 1: ASR

            if (SystemUtils.IsASREnabled())
            {
                List<string> RelevantRuleGuids = new List<string>()
                {
                    {"BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550"},
                    {"01443614-cd74-433a-b99e-2ecdc07bfc25"},
                    {"b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4"}
                };
                AddMitigationResult(results, "Attack Surface Reduction Rules", SystemUtils.GetASRRulesStatus(RelevantRuleGuids));
            }
            else
            {
                AddMitigationResult(results, "Attack Surface Reduction Rules", false);
            }

            // Check 2: AppLocker on DLLs
            try
            {
                if (SystemUtils.IsAppLockerEnabled("DLL"))
                {
                    var DllRules = SystemUtils.GetAppLockerRules("DLL");
                    if (DllRules.Count() > 0)
                    {
                        AddMitigationResult(results, "AppLocker Rules on DLLs", DllRules);
                    }
                    else
                    {
                        AddMitigationResult(results, "AppLocker Rules on DLLs", false);
                    }
                }
            }
            catch (Exception ex)
            {
                AddMitigationResult(results, "Attack Surface Reduction Rules", Mitigation.TestFailed);
                PrintUtils.ErrorPrint(ex.Message);
            }

            // Check 3: Secure Boot
            AddMitigationResult(results, "Secure Boot", SystemUtils.IsSecureBootEnabled());

            return results;
        }

        ///////////////////////////////////////
        // T1137.001: Office Template Macros //
        ///////////////////////////////////////
        public static Dictionary<string, Mitigation> T1137_001()
        {
            Dictionary<string, Mitigation> results = InitiateMitigation(
                "Disable or only allow signed macros",
                "Disable or only allow signed addins");
            try
            {
                // Check 1: Disabled/Signed Macros
                // Disabled holistically?
                if (OfficeUtils.IsVBADisabled())
                {
                    AddMitigationResult(results, "Disable or only allow signed macros", true);
                }
                else
                {
                    // Disabled on the application level?
                    AddMitigationResult(results, "Disable or only allow signed macros", OfficeUtils.GetMacroConf());
                }
                // Maybe I will add a check for disabled macros downloaded from the internet or ASR rule checks (https://www.ncsc.gov.uk/guidance/macro-security-for-microsoft-office)
            }
            catch (OfficeUtils.OfficeNotInstallException ex)
            {
                AddMitigationResult(results, "Disable or only allow signed macros", Mitigation.NA);
                PrintUtils.ErrorPrint(ex.Message);
            }
            catch (Exception ex)
            {
                AddMitigationResult(results, "Disable or only allow signed macros", Mitigation.TestFailed);
                PrintUtils.ErrorPrint(ex.Message);
            }
            // Check 2: Disabled/Signed Addins
            try
            {
                AddMitigationResult(results, "Disable or only allow signed addins", OfficeUtils.GetAddinsConf());
            }
            catch (OfficeUtils.OfficeNotInstallException ex)
            {
                AddMitigationResult(results, "Disable or only allow signed addins", Mitigation.NA);
                PrintUtils.ErrorPrint(ex.Message);
            }
            catch (Exception ex)
            {
                AddMitigationResult(results, "Disable or only allow signed addins", Mitigation.TestFailed);
                PrintUtils.ErrorPrint(ex.Message);
            }
            return results;
        }

        ////////////////////////////
        // T1137.002: Office Test //
        ////////////////////////////
        public static Dictionary<string, Mitigation> T1137_002()
        {
            Dictionary<string, Mitigation> results = InitiateMitigation(
                @"Create registry and harden its permissions");

            try
            {
                AddMitigationResult(results, @"Create registry and harden its permissions", OfficeUtils.CheckTestRegKey());
            }
            catch (OfficeUtils.OfficeNotInstallException ex)
            {
                AddMitigationResult(results, @"Create registry and harden its permissions", Mitigation.TestFailed);
                PrintUtils.ErrorPrint(ex.Message);
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
            AddMitigationResult(results, "Secure Boot", SystemUtils.IsSecureBootEnabled());

            return results;
        }

        //////////////////////////////////
        // T1110.001: Password Guessing //
        //////////////////////////////////
        public static Dictionary<string, Mitigation> T1110_001()
        {
            Dictionary<string, Mitigation> results = InitiateMitigation(
                "Windows Lockout Policy",
                "MFA",
                "Hardened Password Policy"
                );

            // Check 1: Windows Lockout Policy
            AddMitigationResult(results, "Windows Lockout Policy", UserUtils.IsLockOutPolicySet());

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
            Dictionary<string, Mitigation> results = InitiateMitigation("Chrome Password Manager Disabled");

            // Check 1: Is Chrome PW manager disabled?
            AddMitigationResult(results, "Chrome Password Manager Disabled", SystemUtils.IsChromePasswordManagerDisabled());

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
                    bool AccountsInInterestingSIDs = !AccountSIDs.Intersect(Program.SIDsToCheck).Any();
                    AddMitigationResult(results, "Hardened create token object rights", AccountsInInterestingSIDs);
                }
            }
            catch (UnauthorizedAccessException)
            {
                AddMitigationResult(results, "Hardened create token object rights", Mitigation.TestFailed);
                PrintUtils.ErrorPrint("Insufficient rights for this check");
            }
            catch (Exception ex)
            {
                AddMitigationResult(results, "Hardened create token object rights", Mitigation.TestFailed);
                PrintUtils.ErrorPrint(ex.Message);
            }
            // Check 2: Which users/groups can replace token object rights
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
                    bool AccountsInInterestingSIDs = !AccountSIDs.Intersect(Program.SIDsToCheck).Any();
                    AddMitigationResult(results, "Hardened replace token object rights", AccountsInInterestingSIDs);
                }
            }
            catch (UnauthorizedAccessException)
            {
                AddMitigationResult(results, "Hardened replace token object rights", Mitigation.TestFailed);
                PrintUtils.ErrorPrint("Insufficient rights for this check");
            }
            catch (Exception ex)
            {
                AddMitigationResult(results, "Hardened replace token object rights", Mitigation.TestFailed);
                PrintUtils.ErrorPrint(ex.Message);
            }
            // Check 3: Is LAPS enabled?
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
                "KB2871997 installed and configured",
                "PtH to apply UAC restring to local account on network logon",
                "No domain users as local admins");

            // Check 1: Checking for KB2871997
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
                    AddMitigationResult(results, "KB2871997 installed and configured", Mitigation.True);
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
                AddMitigationResult(results, "KB2871997 installed and configured", Mitigation.TestFailed);
                PrintUtils.ErrorPrint(ex.Message);
            }

            // Check 2: PtH to apply UAC restring to local account on network logon
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
                AddMitigationResult(results, "PtH to apply UAC restring to local account on network logon", Mitigation.TestFailed);
                PrintUtils.ErrorPrint(ex.Message);
            }

            // Check 3: No domain accounts as local admins
            try
            {
                AddMitigationResult(results, "No domain users as local admins", !UserUtils.IsADomainUserMemberofLocalAdmins());
            }
            catch (Exception ex)
            {
                AddMitigationResult(results, "No domain users as local admins", Mitigation.TestFailed);
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
            AddMitigationResult(results, "LAPS enabled", SystemUtils.IsLapsEnabled());

            // Check 2: No domain accounts as local admins
            try
            {
                AddMitigationResult(results, "No domain users as local admins", !UserUtils.IsADomainUserMemberofLocalAdmins());
            }
            catch (Exception ex)
            {
                AddMitigationResult(results, "No domain users as local admins", Mitigation.TestFailed);
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
            AddMitigationResult(results, "Windows Credential Guard", SystemUtils.IsCredentialGuardEnabled());

            // Check 2: Disabling Outbound NTLM
            AddMitigationResult(results, "UAC privilege elevation default deny", SystemUtils.IsOutboundNTLMDisabled());

            // Check 3: LAPS
            AddMitigationResult(results, "LAPS enabled", SystemUtils.IsLapsEnabled());

            // Check 4: Domain Users in local admin group
            try
            {
                AddMitigationResult(results, "No domain users as local admins", !UserUtils.IsADomainUserMemberofLocalAdmins());
            }
            catch (Exception ex)
            {
                AddMitigationResult(results, "No domain users as local admins", Mitigation.TestFailed);
                PrintUtils.ErrorPrint(ex.Message);
            }

            // Check 5: LSASS as PPL
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
            AddMitigationResult(results, "Disabling/Restricting Outbound NTLM", SystemUtils.IsOutboundNTLMDisabled());

            // Check 2: LAPS
            AddMitigationResult(results, "LAPS enabled", SystemUtils.IsLapsEnabled());

            // Check 3: Domain Users in local admin group
            try
            {
                AddMitigationResult(results, "No domain users as local admins", !UserUtils.IsADomainUserMemberofLocalAdmins());
            }
            catch (Exception ex)
            {
                AddMitigationResult(results, "No domain users as local admins", Mitigation.TestFailed);
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
                AddMitigationResult(results, "Protected View Enabled", Mitigation.TestFailed);
                PrintUtils.ErrorPrint(ex.Message);
            }
            // Check 2: Is DCOM disabled?
            AddMitigationResult(results, "Disable DCOM", SystemUtils.IsDCOMDisabled());

            // Check 3: Windows Firewall rules //TODO

            // Check 4: Default DCOM permissions hardened
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
                "Least Privilege on RDP Users"
                );

            AddMitigationResult(results, "Audit", Mitigation.CannotBeMeasured);
            AddMitigationResult(results, "Use remote desktop gateways", Mitigation.CannotBeMeasured);
            AddMitigationResult(results, "Use MFA", Mitigation.CannotBeMeasured);
            AddMitigationResult(results, "Least Privilege on RDP Users", Mitigation.CannotBeMeasured);

            // Check 1: Is RDP disabled on the machine //
            AddMitigationResult(results, "RDP Disabled", SystemUtils.IsRDPDisabled());


            // Check 2: Shorter session timeout and session max time
            AddMitigationResult(results, "Shorter session timeout and session max time", SystemUtils.GetRDPSessionConfig());

            // Check 3: Local Admin Groups in RDP
            try
            {
                List<string> AllowedSIDs = UserUtils.GetUsersWithPrivilege("SeRemoteInteractiveLogonRight");
                List<string> BlockedSIDs = UserUtils.GetUsersWithPrivilege("SeDenyRemoteInteractiveLogonRight");
                AddMitigationResult(results, "Remove Local Admins from RDP groups", !UserUtils.IsAdmin(AllowedSIDs) || UserUtils.IsAdmin(BlockedSIDs));
            }
            catch (UnauthorizedAccessException)
            {
                AddMitigationResult(results, "Remove Local Admins from RDP groups", Mitigation.TestFailed);
                PrintUtils.ErrorPrint("Insufficient rights for this check");
            }
            catch (Exception ex)
            {
                AddMitigationResult(results, "Remove Local Admins from RDP groups", Mitigation.TestFailed);
                PrintUtils.ErrorPrint(ex.Message);
            }

            return results;
        }
        ////////////////////////////////
        // T1563.002: RDP Hijackings //
        ///////////////////////////////
        public static Dictionary<string, Mitigation> T1563_002()
        {
            // Same mitigations as RDP(T1021.001)
            return T1021_001();
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
            AddMitigationResult(results, "LAPS enabled", SystemUtils.IsLapsEnabled());

            // Check 2: Remote local admin login
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
                AddMitigationResult(results, "Deny remote use of local admin credentials to log into the system", Mitigation.TestFailed);
                PrintUtils.ErrorPrint("Insufficient rights for this check");
            }
            catch (Exception ex)
            {
                AddMitigationResult(results, "Deny remote use of local admin credentials to log into the system", Mitigation.TestFailed);
                PrintUtils.ErrorPrint(ex.Message);
            }

            // Check 3: No domain users as local admins
            try
            {
                AddMitigationResult(results, "No domain users as local admins", !UserUtils.IsADomainUserMemberofLocalAdmins());
            }
            catch (Exception ex)
            {
                AddMitigationResult(results, "No domain users as local admins", Mitigation.TestFailed);
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
                "Inbound traffic restricted by Windows Firewall",
                "Inbound traffic restricted by GPO",
                "No domain users as local admins"
                );

            // Check 1: Disable WinRM
            var ServiceConfig = Utils.GetServiceConfig("WinRM");
            if (ServiceConfig["StartUpType"] != "AUTOMATIC")
            {
                AddMitigationResult(results, "Disabled WinRM", true);
            }
            else
            {
                AddMitigationResult(results, "Disabled WinRM", false);
            }

            // Check 2: Check if WinRM is configured to only allow traffic from specific devices
            try
            {
                // Is traffic restricted on host firewall
                AddMitigationResult(
                    results,
                    "Inbound traffic restricted by Windows Firewall",
                    FirewallUtils.TrafficRestrictedToSpecificIPs("5985", "5986")
                    );
            }
            catch (Exception ex)
            {
                AddMitigationResult(results, "Inbound traffic restricted by Windows Firewall", Mitigation.TestFailed);
                PrintUtils.ErrorPrint(ex.Message);
            }
            // Check 3: Traffic limited on the application level by GPO
            try
            {
                AddMitigationResult(results, "Inbound traffic restricted by GPO", SystemUtils.IsWinRMFilteredByGPO());
            }
            catch (Exception ex)
            {
                AddMitigationResult(results, "Inbound traffic restricted by GPO", Mitigation.TestFailed);
                PrintUtils.ErrorPrint(ex.Message);
            }

            // Check 4: No domain users as local admins
            try
            {
                AddMitigationResult(results, "No domain users as local admins", !UserUtils.IsADomainUserMemberofLocalAdmins());
            }
            catch (Exception ex)
            {
                AddMitigationResult(results, "No domain users as local admins", Mitigation.TestFailed);
                PrintUtils.ErrorPrint(ex.Message);
            }
            return results;
        }
        /////////////////////////////////////////////////////
        // T1557.001: LLMNR/NBT-NS Poisoning and SMB Relay //
        /////////////////////////////////////////////////////
        public static Dictionary<string, Mitigation> T1557_001()
        {
            Dictionary<string, Mitigation> results = InitiateMitigation(
                "Disable LLMNR",
                "Disable NetBIOS",
                "Firewall drop rules on inbound LLMNR/NetBIOS ports",
                "SMB Signing",
                "IDS/IPS",
                "Network Segmentation"
                );

            // Check 1: LLMNR status
            AddMitigationResult(results, "Disable LLMNR", SystemUtils.IsLLMNRDisabled());

            // Check 2: NetBIOS status
            AddMitigationResult(results, "Disable NetBIOS", SystemUtils.GetNetBIOSConfig());

            // Check 3: FW rules
            // UDP 137, UDP 138, TCP 139, TCP 5355, and UDP 5355
            try
            {

                AddMitigationResult(
                    results,
                    "Firewall drop rules on inbound LLMNR/NetBIOS ports",
                    FirewallUtils.TrafficRestrictedToSpecificIPs("137", "138", "139", "5355", "5355"));
            }
            catch (Exception ex)
            {
                AddMitigationResult(results, "Firewall drop rules on inbound LLMNR/NetBIOS ports", Mitigation.TestFailed);
                PrintUtils.ErrorPrint(ex.Message);
            }

            // Check 4: SMB Signing Enforced
            AddMitigationResult(results, "SMB Signing", SystemUtils.IsSMBSigningForced());

            return results;
        }

        ///////////////////////////////////
        // T1218.001: Compiled HTML File //
        ///////////////////////////////////
        public static Dictionary<string, Mitigation> T1218_001()
        {
            Dictionary<string, Mitigation> results = InitiateMitigation(
                    "Prevent execution of hh.exe",
                    "Block .chm files from the internet"
                );
            // Check 1: Checking for hh.exe
            AddMitigationResult(results, "Prevent execution of hh.exe", Utils.CommandFileAccessible("hh.exe"));

            // Check 2: Checking from webcontent restrictions
            try
            {
                AddMitigationResult(results, "Block .chm files from the internet", NetworkRestrictionUtils.IsFileTypeBlocked("chm"));
            }
            catch (Exception ex)
            {
                AddMitigationResult(results, "Block .chm files from the internet", Mitigation.TestFailed);
                PrintUtils.ErrorPrint(ex.Message);
            }

            return results;
        }
        //////////////////////
        // T1218.003: CMSTP //
        //////////////////////
        public static Dictionary<string, Mitigation> T1218_003()
        {
            Dictionary<string, Mitigation> results = InitiateMitigation(
                    "Prevent execution of cmstp.exe"
                );
            AddMitigationResult(results, "Prevent execution of cmstp.exe", Utils.CommandFileAccessible("cmstp.exe /s"));

            return results;
        }
        ////////////////////////////
        // T1218.004: InstallUtil //
        ////////////////////////////
        public static Dictionary<string, Mitigation> T1218_004()
        {
            Dictionary<string, Mitigation> results = InitiateMitigation(
                    "Prevent execution of InstallUtil.exe"
                );
            AddMitigationResult(results, "Prevent execution of InstallUtil.exe", Utils.CommandFileAccessible("InstallUtils.exe"));

            return results;
        }
        //////////////////////
        // T1218.005: Mshta //
        //////////////////////
        public static Dictionary<string, Mitigation> T1218_005()
        {
            Dictionary<string, Mitigation> results = InitiateMitigation(
                    "Prevent execution of Mshta.exe"
                );
            AddMitigationResult(results, "Prevent execution of Mshta.exe", Utils.CommandFileAccessible("Mshta.exe"));

            return results;
        }
        /////////////////////////
        // T1218.008: Odbcconf //
        /////////////////////////
        public static Dictionary<string, Mitigation> T1218_008()
        {
            Dictionary<string, Mitigation> results = InitiateMitigation(
                    "Prevent execution of Odbcconf.exe"
                );
            AddMitigationResult(results, "Prevent execution of Odbcconf.exe", Utils.CommandFileAccessible("Odbcconf.exe /s"));

            return results;
        }
        ///////////////////////////////
        // T1218.008: Regsvcs/Regasm //
        ///////////////////////////////
        public static Dictionary<string, Mitigation> T1218_009()
        {
            Dictionary<string, Mitigation> results = InitiateMitigation(
                    "Prevent execution of Regsvcs.exe",
                    "Prevent execution of Regasm.exe"
                );
            AddMitigationResult(results, "Prevent execution of Regsvcs.exe", Utils.CommandFileAccessible("Regsvcs.exe"));

            AddMitigationResult(results, "Prevent execution of Regasm.exe", Utils.CommandFileAccessible("Regasm.exe"));

            return results;
        }
        /////////////////////////
        // T1218.011: Rundll32 //
        /////////////////////////
        public static Dictionary<string, Mitigation> T1218_011()
        {
            Dictionary<string, Mitigation> results = InitiateMitigation(
                    "Attack Surface Reduction Rules",
                    "AppLocker Rules on DLLs"
                );

            // Check 1: ASR

            if (SystemUtils.IsASREnabled())
            {
                List<string> RelevantRuleGuids = new List<string>()
                {
                    {"BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550"},
                    {"01443614-cd74-433a-b99e-2ecdc07bfc25"},
                    {"b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4"}
                };
                AddMitigationResult(results, "Attack Surface Reduction Rules", SystemUtils.GetASRRulesStatus(RelevantRuleGuids));
            }
            else
            {
                AddMitigationResult(results, "Attack Surface Reduction Rules", false);
            }

            // Check 2: AppLocker on DLLs
            try
            {
                if (SystemUtils.IsAppLockerEnabled("DLL"))
                {
                    var DllRules = SystemUtils.GetAppLockerRules("DLL");
                    if (DllRules.Count() > 0)
                    {
                        AddMitigationResult(results, "AppLocker Rules on DLLs", DllRules);
                    }
                    else
                    {
                        AddMitigationResult(results, "AppLocker Rules on DLLs", false);
                    }
                }
            }
            catch (Exception ex)
            {
                AddMitigationResult(results, "AppLocker Rules on DLLs", Mitigation.TestFailed);
                PrintUtils.ErrorPrint(ex.Message);
            }

            return results;
        }
        /////////////////////////
        // T1218.010: Runsrv32 //
        /////////////////////////
        public static Dictionary<string, Mitigation> T1218_010()
        {
            return T1218_011();
        }

        ////////////////////////
        // T1127.001: MSBuild //
        ////////////////////////
        public static Dictionary<string, Mitigation> T1127_001()
        {
            Dictionary<string, Mitigation> results = InitiateMitigation(
                    "Remove MSBuild.exe"
                );
            AddMitigationResult(results, "Remove MSBuild.exe", Utils.CommandFileAccessible("MSBuild.exe"));

            return results;
        }

        //////////////////////////////////////////
        // T1129: Execution through Module Load //
        //////////////////////////////////////////
        public static Dictionary<string, Mitigation> T1129()
        {
            Dictionary<string, Mitigation> results = InitiateMitigation(
                   "Attack Surface Reduction Rules",
                   "AppLocker Rules on DLLs"
               );

            // Check 1: ASR

            if (SystemUtils.IsASREnabled())
            {
                List<string> RelevantRuleGuids = new List<string>()
                {
                    {"BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550"},
                    {"01443614-cd74-433a-b99e-2ecdc07bfc25"},
                    {"b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4"}
                };
                AddMitigationResult(results, "Attack Surface Reduction Rules", SystemUtils.GetASRRulesStatus(RelevantRuleGuids));
            }
            else
            {
                AddMitigationResult(results, "Attack Surface Reduction Rules", false);
            }

            // Check 2: AppLocker on DLLs
            try
            {
                if (SystemUtils.IsAppLockerEnabled("DLL"))
                {
                    var DllRules = SystemUtils.GetAppLockerRules("DLL");
                    if (DllRules.Count() > 0)
                    {
                        AddMitigationResult(results, "AppLocker Rules on DLLs", DllRules);
                    }
                    else
                    {
                        AddMitigationResult(results, "AppLocker Rules on DLLs", false);
                    }
                }
            }
            catch (Exception ex)
            {
                AddMitigationResult(results, "AppLocker Rules on DLLs", Mitigation.TestFailed);
                PrintUtils.ErrorPrint(ex.Message);
            }

            return results;
        }
        ///////////////////////////////
        // T1221: Template Injection //
        ///////////////////////////////
        public static Dictionary<string, Mitigation> T1221()
        {
            Dictionary<string, Mitigation> results = InitiateMitigation(
                "Antivirus",
                "Macros Disabled/Signed Only",
                "Network Intrusion Prevention",
                "User Training"
                );
            AddMitigationResult(results, "Network Intrusion Prevention", Mitigation.CannotBeMeasured);
            AddMitigationResult(results, "User Training", Mitigation.CannotBeMeasured);

            // Check 1: Antivirus
            AddMitigationResult(results, "Antivirus", SystemUtils.DoesAVExist());

            // Check 2: Macros
            try
            {
                if (OfficeUtils.IsVBADisabled())
                {
                    AddMitigationResult(results, "Macros Disabled/Signed Only", true);

                }
                else
                {
                    AddMitigationResult(results, "Macros Disabled/Signed Only", OfficeUtils.GetMacroConf());
                }
            }
            catch (OfficeUtils.OfficeNotInstallException ex)
            {
                AddMitigationResult(results, "Macros Disabled/Signed Only", Mitigation.NA);
                PrintUtils.ErrorPrint(ex.Message);
            }
            catch (Exception ex)
            {
                AddMitigationResult(results, "Macros Disabled/Signed Only", Mitigation.TestFailed);
                PrintUtils.ErrorPrint(ex.Message);
            }
            return results;
        }
        /////////////////////////////////////////
        // T1553.004: Install Root Certificate //
        /////////////////////////////////////////
        public static Dictionary<string, Mitigation> T1553_004()
        {
            Dictionary<string, Mitigation> results = InitiateMitigation(
                "Prevent non-admin users from making root certificate installations",
                "HTTP Public Key Pinning (HPKP) - Application level control"
                );

            // Can't emumerate application level control
            AddMitigationResult(results, "HTTP Public Key Pinning(HPKP) - Application level control", Mitigation.NA);
            
            // Check 1:
            AddMitigationResult(
                results,
                "Prevent non-admin users from making root certificate installations",
                SystemUtils.CanNonAdminUsersAddRootCertificates()
                );

            return results;
        }
        //////////////////////////////////////////////////////////////////////
        // T1546.003: Windows Management Instrumentation Event Subscription //
        //////////////////////////////////////////////////////////////////////
        public static Dictionary<string, Mitigation> T1546_003()
        {
            Dictionary<string, Mitigation> results = InitiateMitigation(
                    "Enable LAPS",
                    "Attack Surface Reduction Rules",
                    $"No remote WMI access to {Program.UserToCheck.SamAccountName}"
                );

            // Check 1: Is LAPS enabled?
            AddMitigationResult(results, "LAPS Enabled", SystemUtils.IsLapsEnabled());

            // Check 2: WMI Permissions
            try
            {
                var wmiRemoteDeny = new Dictionary<string, bool>();
                ViewNameSpaceSecurity viewns = new ViewNameSpaceSecurity(@"root\cimv2", false);
                foreach (var item in viewns.GetNameSpaceSDDL(Environment.MachineName))
                {
                    var NameSpace = item.Key;
                    var SDDLString = item.Value;
                    var DecodedSDDL = Utils.PermissionsDecoder.DecodeSddlString<Utils.WMIPermissionsMask>(SDDLString);
                    var SIDsToCheckPermissions = DecodedSDDL.DACL.Where(o => Program.SIDsToCheck.Contains(o.Trustee) && o.AccessType == "AccessAllowed")
                                                                    .Select(o => o.Permissions);

                    wmiRemoteDeny[NameSpace] = true;
                    foreach (var permission in SIDsToCheckPermissions)
                    {
                        if (permission.Contains("WMI_REMOTE_ENABLE") && permission.Contains("WMI_ENABLE_ACCOUNT"))
                        {
                            wmiRemoteDeny[NameSpace] = false;
                            break;
                        }
                    }
                }
                AddMitigationResult(results, $"No remote WMI access to {Program.UserToCheck.SamAccountName}", wmiRemoteDeny);
            }
            catch (Exception ex)
            {
                AddMitigationResult(results, $"No remote WMI access to {Program.UserToCheck.SamAccountName}", Mitigation.TestFailed);
                PrintUtils.ErrorPrint(ex.Message);

            }
            // Check 3: ASR Rule
            try
            {
                if (SystemUtils.IsASREnabled())
                {
                    List<string> RelevantRuleGuids = new List<string>()
                {
                    {"e6db77e5-3df2-4cf1-b95a-636979351e5b"},
                };
                    AddMitigationResult(results, "Attack Surface Reduction Rules", SystemUtils.GetASRRulesStatus(RelevantRuleGuids));
                }
                else
                {
                    AddMitigationResult(results, "Attack Surface Reduction Rules", false);
                }
            }
            catch (Exception ex)
            {
                AddMitigationResult(results, "Attack Surface Reduction Rules", Mitigation.TestFailed);
                PrintUtils.ErrorPrint(ex.Message);
            }

            return results;
        }
    }
}