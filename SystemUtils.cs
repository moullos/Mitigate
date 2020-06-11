using Microsoft.Win32;
using NetFwTypeLib;
using System;
using System.Collections;
using System.Collections.Generic;
using System.DirectoryServices.ActiveDirectory;
using System.Linq;
using System.Management;
using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;

namespace Mitigate
{
    class SystemUtils
    {

        public static bool IsDomainJoined()
        {
            try
            {
                System.DirectoryServices.ActiveDirectory.Domain.GetComputerDomain();
                return true;
            }
            catch (ActiveDirectoryObjectNotFoundException)
            {
                return false;
            }
        }
        // https://stackoverflow.com/questions/1331887/detect-antivirus-on-windows-using-c-sharp and winPEAS
        public static bool DoesAVExist()
        {
            string wmipathstr = @"\\" + Environment.MachineName + @"\root\SecurityCenter2";
            try
            {
                ManagementObjectSearcher searcher = new ManagementObjectSearcher(wmipathstr, "SELECT * FROM AntivirusProduct");
                ManagementObjectCollection instances = searcher.Get();
                return (instances.Count > 0);
            }
            catch (Exception ex)
            {
                Console.WriteLine(String.Format("  [X] Exception: {0}", ex));
                return false;
            }
        }

        // https://stackoverflow.com/questions/1331887/detect-antivirus-on-windows-using-c-sharp and winPEAS
        public static List<Dictionary<string, string>> GetAntivirusInfo()
        {
            List<Dictionary<string, string>> results = new List<Dictionary<string, string>>();
            string wmipathstr = @"\\" + Environment.MachineName + @"\root\SecurityCenter2";
            try
            {
                ManagementObjectSearcher searcher = new ManagementObjectSearcher(wmipathstr, "SELECT * FROM AntivirusProduct");
                ManagementObjectCollection instances = searcher.Get();

                foreach (ManagementObject instance in instances)
                {
                    Dictionary<string, string> antivirus = new Dictionary<string, string>();
                    antivirus["Name"] = (string)instance["displayName"];
                    antivirus["ProductEXE"] = (string)instance["pathToSignedProductExe"];
                    antivirus["pathToSignedReportingExe"] = (string)instance["pathToSignedReportingExe"];
                    results.Add(antivirus);
                }
            }

            catch (Exception ex)
            {
                Console.WriteLine(String.Format("  [X] Exception: {0}", ex));
            }

            return results;
        }
        // TODO: Improve this
        public static Dictionary<string, bool> GetDefaultComPermissions()
        {
            Dictionary<string, bool> DefaultComPermission = new Dictionary<string, bool>();
            try
            {

                // Need to do a bit more checking of the parameters here!
                string[] ComKeys = Utils.GetRegSubkeys("HKLM", @"SOFTWARE\Microsoft\Ole");
                // if the key DefaultLaunchPermission exist, the default launch permissions are overriden
                DefaultComPermission["Launch Permission Overridden"] = ComKeys.Contains("DefaultLaunchPermission");
                // if the key DefaultAccessPermission exist, the default access permissions are overriden
                DefaultComPermission["Access Permission Overridden"] = ComKeys.Contains("DefaultAccessPermission");
            }
            catch (Exception ex)
            {
                Console.WriteLine(String.Format("  [X] Exception: {0}", ex));
            }
            return DefaultComPermission;
        }
        // From WinPEAS: https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/winPEAS/winPEASexe/winPEAS/SystemInfo.cs
        // https://getadmx.com/?Category=LAPS&Policy=FullArmor.Policies.C9E1D975_EA58_48C3_958E_3BC214D89A2E::POL_AdmPwd
        public static Dictionary<string, string> GetLapsSettings()
        {
            Dictionary<string, string> results = new Dictionary<string, string>();
            try
            {
                string AdmPwdEnabled = Utils.GetRegValue("HKLM", "Software\\Policies\\Microsoft Services\\AdmPwd", "AdmPwdEnabled");

                if (AdmPwdEnabled != "")
                {
                    results["LAPS Enabled"] = AdmPwdEnabled;
                    results["LAPS Admin Account Name"] = Utils.GetRegValue("HKLM", "Software\\Policies\\Microsoft Services\\AdmPwd", "AdminAccountName");
                    results["LAPS Password Complexity"] = Utils.GetRegValue("HKLM", "Software\\Policies\\Microsoft Services\\AdmPwd", "PasswordComplexity");
                    results["LAPS Password Length"] = Utils.GetRegValue("HKLM", "Software\\Policies\\Microsoft Services\\AdmPwd", "PasswordLength");
                    results["LAPS Expiration Protection Enabled"] = Utils.GetRegValue("HKLM", "Software\\Policies\\Microsoft Services\\AdmPwd", "PwdExpirationProtectionEnabled");
                }
                else
                {
                    results["LAPS Enabled"] = "LAPS not installed";
                }
            }
            catch (Exception ex)
            {
                PrintUtils.ErrorPrint(ex.Message);
            }
            return results;
        }
        public static bool IsLapsEnabled()
        {
            Dictionary<string, string> LapsSettings = GetLapsSettings();
            if (LapsSettings["LAPS Enabled"] == "1")
                return true;
            return false;
        }

        public static string GetPowershellExecutionPolicy()
        {
            Dictionary<string, string> results = new Dictionary<string, string>();
            // Priority is: Machine Group Policy, Current User Group Policy, Current Session, Current User, Local Machine

            string ExecutionPolicy = "";
            // Machine Group Policy
            ExecutionPolicy = Utils.GetRegValue("HKLM", @"Software\Policies\Microsoft\Windows\PowerShell", "ExecutionPolicy");
            if (ExecutionPolicy != "")
            {
                return ExecutionPolicy;
            }
            // Current User Group Policy
            ExecutionPolicy = Utils.GetRegValue("HKCU", @"Software\Policies\Microsoft\Windows\PowerShell", "ExecutionPolicy");
            if (ExecutionPolicy != "")
            {
                return ExecutionPolicy;
            }
            // Execution Policy is not set by Group Policy. Policy restrictions can be bypassed.
            return "Unrestricted";
        }
        public static bool IsAppLockerEnabled()
        {
            var AppLockerRules = Utils.GetRegSubkeys("HKLM", @"Software\Policies\Microsoft\Windows\SrpV2");
            if (AppLockerRules.Length > 0)
            {
                return true;
            }
            return false;
        }
        public static bool IsWDACEnabled()
        {
            var WDAGStatus = Utils.GetRegValue("HKLM", @"SOFTWARE\Policies\Microsoft\Windows", "DeviceGuard");
            return (WDAGStatus == "1" ? true : false);
        }
        public static Dictionary<string, bool> IsWDApplicationGuardEnabled()
        {
            Dictionary<string, bool> results = new Dictionary<string, bool>();
            var WDAGStatus = Utils.GetRegValue("HKLM", @"SOFTWARE\Policies\Microsoft\AppHVSI", "AllowAppHVSI_ProviderSet");
            results["Edge"] = false;
            results["Office"] = false;
            if (WDAGStatus == "1")
            {
                results["Edge"] = true;
            }
            if (WDAGStatus == "2")
            {
                results["Office"] = true;
            }
            if (WDAGStatus == "3")
            {
                results["Office"] = true;
                results["Edge"] = true;
            }
            return results;
        }
        public static bool IsWDExploitGuardEnabled()
        {

            var WDEGStatus = Utils.GetRegValue("HKLM", @"Software\Policies\Microsoft\Windows Defender ExploitGuard\Exploit Protection", "ExploitProtectionSettings");
            if (WDEGStatus != "")
                return true;
            else
                return false;
        }
        public static bool RunAtInUserContext()
        {
            return Utils.GetRegValue("HKML", @"SYSTEM\CurrentControlSet\Control\Lsa\", "SubmitControl") == "0" ? true : false;
        }
        // All firewall utils are courtesy of Seatbelt and WinPEAS with some fixes from https://stackoverflow.com/questions/10342260/is-there-any-net-api-to-get-all-the-firewall-rules        [Flags]
        public enum FirewallProfiles : int
        {
            DOMAIN = 1,
            PRIVATE = 2,
            PUBLIC = 4,
            ALL = 2147483647
        }
        public static string GetFirewallProfiles()
        {
            string result = "";
            try
            {
                Type firewall = Type.GetTypeFromCLSID(new Guid("E2B3C97F-6AE1-41AC-817A-F6F92166D7DD"));
                Object firewallObj = Activator.CreateInstance(firewall);
                Object types = firewallObj.GetType().InvokeMember("CurrentProfileTypes", BindingFlags.GetProperty, null, firewallObj, null);
                result = String.Format("{0}", (FirewallProfiles)Int32.Parse(types.ToString()));
            }
            catch (Exception ex)
            {
                PrintUtils.ErrorPrint(ex.Message);
            }
            return result;
        }
        public static Dictionary<string, string> GetFirewallBooleans()
        {
            Dictionary<string, string> results = new Dictionary<string, string>();
            try
            {
                // GUID for HNetCfg.FwPolicy2 COM object
                Type firewall = Type.GetTypeFromCLSID(new Guid("E2B3C97F-6AE1-41AC-817A-F6F92166D7DD"));
                Object firewallObj = Activator.CreateInstance(firewall);
                Console.WriteLine(Newtonsoft.Json.JsonConvert.SerializeObject(firewallObj));
                Object enabledDomain = firewallObj.GetType().InvokeMember("FirewallEnabled", BindingFlags.GetProperty, null, firewallObj, new object[] { 1 });
                Object enabledPrivate = firewallObj.GetType().InvokeMember("FirewallEnabled", BindingFlags.GetProperty, null, firewallObj, new object[] { 2 });
                Object enabledPublic = firewallObj.GetType().InvokeMember("FirewallEnabled", BindingFlags.GetProperty, null, firewallObj, new object[] { 4 });
                results = new Dictionary<string, string>() {
                    { "FirewallEnabled (Domain)", String.Format("{0}", enabledDomain) },
                    { "FirewallEnabled (Private)", String.Format("{0}", enabledPrivate) },
                    { "FirewallEnabled (Public)", String.Format("{0}", enabledPublic) },
                };
            }
            catch (Exception ex)
            {
                PrintUtils.ErrorPrint(ex.Message);
            }
            return results;
        }
        /// <summary>
        /// Method that retreives enabled and inbound windows firewall rules
        /// </summary>
        /// <returns>List of rules</returns>
        public static List<INetFwRule> GetEnabledFirewallRules()
        {
            List<INetFwRule> results = new List<INetFwRule>();
            // GUID for HNetCfg.FwPolicy2 COM object
            Type tNetFwPolicy2 = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
            dynamic fwPolicy2 = Activator.CreateInstance(tNetFwPolicy2) as dynamic;
            var Rules = fwPolicy2.Rules as IEnumerable;
            foreach (INetFwRule rule in Rules)
            {
                if (rule.Enabled && rule.Direction == NET_FW_RULE_DIRECTION_.NET_FW_RULE_DIR_IN)
                    results.Add(rule);
            }
            // return only enabled
            return results;
        }

        public static Dictionary<string, string> GetBITSJobLifetime()
        {
            Dictionary<string, string> results = new Dictionary<string, string>();
            results["JobInactivityTimeout"] = Utils.GetRegValue("HKLM", @"Software\Policies\Microsoft\Windows\BITS", "JobInactivityTimeout");
            results["MaxDownloadTime"] = Utils.GetRegValue("HKLM", @"Software\Policies\Microsoft\Windows\BITS", "MaxDownloadTime");
            return results;
        }
        public static Dictionary<string, bool> GetBITSJobInfo()
        {
            Dictionary<string, bool> info = new Dictionary<string, bool>();
            var regKeys = GetBITSJobLifetime();
            info["JobInactivityTimeout"] = false;
            info["MaxDownloadTime"] = false;
            if (regKeys["JobInactivityTimeout"] == null)
            {
                info["JobInactivityTimeout"] = false;
            }
            else
            {
                try
                {
                    int timeout = int.Parse(regKeys["JobInactivityTimeout"]);
                    if (timeout < 90)
                        info["JobInactivityTimeout"] = true;
                }
                catch (Exception ex)
                {
                    PrintUtils.ExceptionPrint(ex.Message);
                }
            }
            if (regKeys["MaxDownloadTime"] == null)
            {
                info["MaxDownloadTime"] = false;
            }
            else
            {
                try
                {
                    int timeout = int.Parse(regKeys["MaxDownloadTime"]);
                    if (timeout < 54000)
                        info["MaxDownloadTime"] = true;
                }
                catch (Exception ex)
                {
                    PrintUtils.ExceptionPrint(ex.Message);
                }
            }
            return info;
        }
        public static bool IsLsaRunAsPPL()
        {
            string RunAsPPL = Utils.GetRegValue("HKLM", @"System\CurrentControlSet\Control\Lsa", "RunAsPPL");
            return RunAsPPL == "1" ? true : false;

        }
        public static bool IsCredentialGuardEnabled()
        {
            string regPath = @"System\CurrentControlSet\Control\DeviceGuard";
            if (Utils.GetRegValue("HKLM", regPath, "EnableVirtualizationBasedSecurity") != "1")
                return false;
            string regValue = Utils.GetRegValue("HKLM", regPath, "RequirePlatformSecurityFeatures");
            if (regValue != "1" && regValue != "3")
            {
                return false;
            }
            regValue = Utils.GetRegValue("HKLM", @"System\CurrentControlSet\Control\LSA", "LsaCfgFlags");
            if (regValue != "1" || regValue != "2")
            {
                return false;
            }
            return true;
        }
        public static bool IsSafeDllSafeSearchModeOn()
        {
            var RegValue = Utils.GetRegValue("HKLM", @"System\CurrentControlSet\Control\Session Manager", "SafeDllSearchMode ");
            if (RegValue == "")
            {
                // Default value is on
                return true;
            }
            return RegValue == "1" ? true : false;
        }
        public static Dictionary<string, bool> GetWinlogonRegPermissions()
        {
            // https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order?redirectedfrom=MSDN
            Dictionary<string, bool> regPermResults = new Dictionary<string, bool>();
            var regPath = @"Software\Microsoft\Windows NT\CurrentVersion\Winlogon";
            var RegPermissions = Utils.GetRegPermissions("HKLM", regPath, Program.InterestingSIDs);
            regPermResults["HKLM"] = RegPermissions == null ? true : false;
            RegPermissions = Utils.GetRegPermissions("HKCU", regPath, Program.InterestingSIDs);
            regPermResults["HKCU"] = RegPermissions == null ? true : false;
            return regPermResults;
        }
        public static bool IsChromeExtensionWhitelistEnabled()
        {
            // https://cloud.google.com/docs/chrome-enterprise/policies/?policy=ExtensionInstallWhitelist
            // Looking for whitelisted extensions
            string[] WhitelistedExtensions = Utils.GetRegSubkeys("HKLM", @"Software\Policies\Google\Chrome\ExtensionInstallWhitelist");
            if (WhitelistedExtensions.Length > 0)
            {
                //  Whitelist only applies if all extensions have been blacklisted 
                // https://cloud.google.com/docs/chrome-enterprise/policies/?policy=ExtensionInstallBlacklist
                string[] BlacklistedExtensions = Utils.GetRegSubkeys("HKLM", @"Software\Policies\Google\Chrome\ExtensionInstallBlacklist");
                foreach (string id in BlacklistedExtensions)
                {
                    if (Utils.GetRegValue("HKLM", @"Software\Policies\Google\Chrome\ExtensionInstallBlacklist", id) == "*")
                        return true;

                }
            }
            return false;
        }
        public static bool IsChromePasswordManagerDisabled()
        {
            // https://cloud.google.com/docs/chrome-enterprise/policies/?policy=PasswordManagerEnabled
            var RegValue = Utils.GetRegValue("HKLM", @"Software\Policies\Google\Chrome", "PasswordManagerEnabled");
            return RegValue == "1" ? true : false;
        }

        /// <summary>
        /// Checks if external extensions are blocked by Chrome
        /// </summary>
        /// <returns> True if blocked, false if not</returns>
        public static bool IsChromeExternalExtectionsBlocked()
        {
            //https://cloud.google.com/docs/chrome-enterprise/policies/?policy=BlockExternalExtensions
            return Utils.GetRegValue("HKLM", @"Software\Policies\Google\Chrome\", "BlockExternalExtensions") == "1" ? true : false;
        }

        /// <summary>
        /// Checks if Screen Savers are disabled
        /// </summary>
        /// <returns>True if disabled, false if not</returns>
        public static bool IsScreenSaverDisabled()
        {
            return Utils.GetRegValue("HKLM", @"Software\Policies\Microsoft\Windows\Control Panel\Desktop", "ScreenSaveActive") == "0";
        }

        /// <summary>
        /// Checks if RDP network level authentication is enforced.
        /// </summary>
        /// <returns>True if enabled, false if not</returns>
        public static bool IsRdpNLAEnabled()
        {
            return Utils.GetRegValue(
                "HKLM",
                @"\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
                "UserAuthentication")
                == "1";
        }

        /// <summary>
        /// Checks is secureboot is enabled
        /// </summary>
        /// <returns>True if enabled, false if not </returns>
        public static bool IsSecureBootEnabled()
        {
            return Utils.GetRegValue(
                "HKLM",
                @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecureBoot\State",
                "UEFISecureBootEnabled")
                == "1";
        }

        /// <summary>
        /// Checks if a hotfix is installed using WMIC
        /// </summary>
        /// <param name="HotFixID"></param>
        /// <returns>True if installed, false if not</returns>
        public static bool IsHotFixInstalled(string HotFixID)
        {
            string wmipathstr = @"\\" + Environment.MachineName + @"\root\cimv2";

            ManagementObjectSearcher searcher = new ManagementObjectSearcher(wmipathstr, "SELECT * FROM Win32_QuickFixEngineering WHERE HotFixID='" + HotFixID + "'");
            ManagementObjectCollection instances = searcher.Get();
            if (instances.Count == 1)
            {
                return true;
            }
            return false;
        }

        /// <summary>
        /// Gets the version of the OS through WMIC
        /// </summary>
        /// <returns>A string with the version</returns>
        public static string GetOSVersion()
        {
            string wmipathstr = @"\\" + Environment.MachineName + @"\root\cimv2";

            ManagementObjectSearcher searcher = new ManagementObjectSearcher(wmipathstr, "SELECT Version FROM Win32_OperatingSystem");
            ManagementObjectCollection instances = searcher.Get();
            foreach (ManagementObject test in instances)
            {
                return test["Version"].ToString();
            }
            // Should never reach this. In case it does:
            throw new Exception("Couldn't get windows version");
        }

        public static bool IsSafeDLLSearchEnabled()
        {
            var RegPath = @"System\CurrentControlSet\Control\Session Manager";
            var RegKey = "SafeDllSearchMode ";

            var RegValue = Utils.GetRegValue("HKLM", RegPath, RegKey);
            if (RegValue != "0")
            {
                return false;
            }
            return true;
        }

        public static bool IsUACSetToDefaultDeny()
        {

            // Consent Behaviour Settings
            var RegPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
            var RegName = @"ConsentPromptBehaviorUser";

            // If equals 0 all UAC is automatically declined
            return Utils.GetRegValue("HKLM", RegPath, RegName) == "0" ? true : false;

        }

        public static bool IsOutboundNTLMDisabled()
        {
            var RegPath = @"System\CurrentControlSet\Control\Lsa\MSV1_0";
            var RegName = "RestrictSendingNTLMTraffic";

            return Utils.GetRegValue("HKLM", RegPath, RegName) == "2" ? true : false;
        }

        public static bool IsDCOMDisabled()
        {
            var RegPath = @"Software\Microsoft\OLE";
            var RegName = "EnableDCOM";

            return Utils.GetRegValue("HKLM", RegPath, RegName) == "N" ? true : false;
        }

        public static bool IsRDPDisabled()
        {
            var RegPath = @"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services";
            var RegName = "fDenyTSConnections";

            return Utils.GetRegValue("HKLM", RegPath, RegName) == "1" ? true : false;
        }

        public static Dictionary<string,bool> GetRDPSessionConfig()
        {
            Dictionary<string, bool> config = new Dictionary<string, bool>();

            // Firstly check if RDP is configured to end sessions when time limits are reached
            // https://getadmx.com/?Category=Windows_10_2016&Policy=Microsoft.Policies.TerminalServer::TS_Session_End_On_Limit_2

            var RegPath = @"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services";

            // 1. Max Idle Time
            var MaxIdleTimeStr = Utils.GetRegValue("HKLM", RegPath, "MaxIdleTime");
            try
            {
                var MaxIdleTime = int.Parse(MaxIdleTimeStr);
                if (MaxIdleTime >= 60000)
                    config["MaxIdleTime"] = true;
                else
                    config["MaxIdleTime"] = false;
            }
            catch (Exception)
            {
                config["MaxIdleTime"] = false;
            }

            // 2. Max Session Time
            var MaxConnectionTimeStr = Utils.GetRegValue("HKLM", RegPath, "MaxConnectionTime");
            try
            {
                var MaxIdleTime = int.Parse(MaxIdleTimeStr);
                if (MaxIdleTime >= 60000)
                    config["MaxConnectionTime"] = true;
                else
                    config["MaxConnectionTime"] = false;
            }
            catch (Exception)
            {
                config["MaxConnectionTime"] = false;
            }

            return config;
        }

        public static bool IsWinrmGPODefined()
        {
            string RegPath = @"Software\Policies\Microsoft\Windows\WinRM\Service";
            string RegKey = "AllowAutoConfig";

            return Utils.GetRegValue("HKLM", RegPath, RegKey) == "1" ? true : false;
        }

        public static bool IsWinRMFilteredByGPO()
        {
            if (IsWinrmGPODefined()) 
            {
                string RegPath = @"Software\Policies\Microsoft\Windows\WinRM\Service";
                var IPv4Filter = Utils.GetRegValue("HKLM", RegPath, "IPv4Filter");
                return IPv4Filter != "*" ? true : false;
            }
            return false;
        }
    }
}