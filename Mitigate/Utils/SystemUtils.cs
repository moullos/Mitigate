using System;
using System.Collections;
using System.Collections.Generic;
using System.Data;
using System.IO;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;

namespace Mitigate.Utils
{
    class SystemUtils
    {

        //////////////////////
        /// IsDomainJoined ///
        //////////////////////
        /// The clases and functions here are dedicated to discover if the current host is joined in a domain or not, and get the domain name if so
        /// It can be done using .Net (default) and WMI (used if .Net fails)
        internal class Win32
        {
            public const int ErrorSuccess = 0;

            [DllImport("Netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
            public static extern int NetGetJoinInformation(string server, out IntPtr domain, out NetJoinStatus status);

            [DllImport("Netapi32.dll")]
            public static extern int NetApiBufferFree(IntPtr Buffer);

            public enum NetJoinStatus
            {
                NetSetupUnknownStatus = 0,
                NetSetupUnjoined,
                NetSetupWorkgroupName,
                NetSetupDomainName
            }

        }

        public static bool IsDomainJoined()
        {
            // returns Compuer Domain if the system is inside an AD (an nothing if it is not)
            try
            {
                Win32.NetJoinStatus status = Win32.NetJoinStatus.NetSetupUnknownStatus;
                IntPtr pDomain = IntPtr.Zero;
                int result = Win32.NetGetJoinInformation(null, out pDomain, out status);
                if (pDomain != IntPtr.Zero)
                {
                    Win32.NetApiBufferFree(pDomain);
                }

                if (result == Win32.ErrorSuccess)
                {
                    // If in domain, return domain name, if not, return empty
                    if (status == Win32.NetJoinStatus.NetSetupDomainName)
                        return true;
                    return false;
                }

            }

            catch (Exception ex)
            {
                PrintUtils.Debug(ex.StackTrace);
                IsDomainJoinedWmi();
            }
            return false;
        }

        private static bool IsDomainJoinedWmi()
        {
            try
            {
                ManagementObject ComputerSystem;
                using (ComputerSystem = new ManagementObject(String.Format("Win32_ComputerSystem.Name='{0}'", Environment.MachineName)))
                {
                    ComputerSystem.Get();
                    object Result = ComputerSystem["PartOfDomain"];
                    return (Result != null && (bool)Result);
                }
            }
            catch (Exception ex)
            {
                PrintUtils.Debug(ex.StackTrace);
            }
            //By default local
            return false;
        }

        

        /// <summary>
        /// Checks if the default COM permissions are equal to the Microsoft default permissions
        /// </summary>
        /// <returns>Dictionary with bools for Launch and Access Permissions</returns>
        public static Dictionary<string, bool> DefaultComPermissions()
        {
            Dictionary<string, bool> DefaultComPermission = new Dictionary<string, bool>();
            DefaultComPermission["Default Launch Permissions"] = true;
            DefaultComPermission["Default Access Permissions"] = true;

            string[] ComKeys = Helper.GetRegSubkeys("HKLM", @"SOFTWARE\Microsoft\Ole");
            if (Helper.RegExists("HKLM", @"SOFTWARE\Microsoft\Ole", "DefaultLaunchPermission"))
            {
                var RawLaunchPermission = Helper.GetRegValueBytes("HKLM", @"SOFTWARE\Microsoft\Ole", "DefaultLaunchPermission");
                DefaultComPermission["Default Launch Permissions"] = Helper.EqualsDefaultLaunchPermissions(RawLaunchPermission);
            }
            if (Helper.RegExists("HKLM", @"SOFTWARE\Microsoft\Ole", "DefaultAccessPermission"))
            {
                var RawAccessPermission = Helper.GetRegValueBytes("HKLM", @"SOFTWARE\Microsoft\Ole", "DefaultAccessPermission");
                DefaultComPermission["Default Access Permissions"] = Helper.EqualsDefaultAccessPermissions(RawAccessPermission);
            }
            return DefaultComPermission;
        }
        //TODO: Make sure this is done in the new version and then remove
        /*
        public static Dictionary<string, Mitigation> CheckForOverridenComPermissions(bool FullChecks)
        {
            // If Full checks is defined, then the individual app permissions are parse and are checked for loose permissions
            Dictionary<string, Mitigation> AppDefaultComPermissionsOverriden = new Dictionary<string, Mitigation>();
            var AllAppGUIDs = Utils.GetRegSubkeys("HKLM", @"SOFTWARE\Classes\AppID\").Where(o => o.StartsWith("{"));
            foreach (var AppGUID in AllAppGUIDs)
            {
                var RegPath = String.Format(@"SOFTWARE\Classes\AppID\{0}", AppGUID);
                // Check for app Access Permission
                var DictKey = $"{AppGUID} - Default Access Permissions";
                if (Utils.RegExists("HKLM", RegPath, "AccessPermission"))
                {
                    try
                    {
                        if (FullChecks)
                        {
                            var RawAccessPermission = Utils.GetRegValueBytes("HKLM", RegPath, "AccessPermission");
                            var DefaultPermisssions = Utils.EqualsDefaultAccessPermissions(RawAccessPermission);
                            AppDefaultComPermissionsOverriden[DictKey] = DefaultPermisssions ? Mitigation.True : Mitigation.False;
                        }
                        else
                        {
                            AppDefaultComPermissionsOverriden[DictKey] = Mitigation.False;
                        }
                    }
                    catch
                    {
                        AppDefaultComPermissionsOverriden[DictKey] = Mitigation.TestFailed;
                    }
                }
                else
                {
                    AppDefaultComPermissionsOverriden[DictKey] = Mitigation.True;
                }
                // Check for app launch Permission
                DictKey = $"{AppGUID} - Default Launch Permissions";
                if (Utils.RegExists("HKLM", RegPath, "LaunchPermission"))
                {
                    try
                    {
                        if (FullChecks)
                        {
                            var RawAccessPermission = Utils.GetRegValueBytes("HKLM", RegPath, "LaunchPermission");
                            var DefaultPermisssions = Utils.EqualsDefaultAccessPermissions(RawAccessPermission);
                            AppDefaultComPermissionsOverriden[DictKey] = DefaultPermisssions ? Mitigation.True : Mitigation.False;
                        }
                        else
                        {
                            AppDefaultComPermissionsOverriden[DictKey] = Mitigation.False;
                        }
                    }
                    catch
                    {
                        AppDefaultComPermissionsOverriden[DictKey] = Mitigation.TestFailed;
                    }
                }
                else
                {
                    AppDefaultComPermissionsOverriden[DictKey] = Mitigation.True;
                }
            }
            return AppDefaultComPermissionsOverriden;
        }
        */

        // From WinPEAS: https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/winPEAS/winPEASexe/winPEAS/SystemInfo.cs
        // https://getadmx.com/?Category=LAPS&Policy=FullArmor.Policies.C9E1D975_EA58_48C3_958E_3BC214D89A2E::POL_AdmPwd
        public static Dictionary<string, string> GetLapsSettings()
        {
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
        public static bool IsLapsEnabled()
        {
            Dictionary<string, string> LapsSettings = GetLapsSettings();
            if (LapsSettings["LAPS Enabled"] == "1")
                return true;
            return false;
        }

        public static string GetPowershellExecutionPolicy()
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
        public static bool IsWDACEnabled()
        {
            var WDAGStatus = Helper.GetRegValue("HKLM", @"SOFTWARE\Policies\Microsoft\Windows", "DeviceGuard");
            return (WDAGStatus == "1" ? true : false);
        }

        public static Dictionary<string, bool> IsWDApplicationGuardEnabled()
        {
            //https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-application-guard/configure-md-app-guard
            Dictionary<string, bool> results = new Dictionary<string, bool>();
            var WDAGStatus = Helper.GetRegValue("HKLM", @"SOFTWARE\Policies\Microsoft\AppHVSI", "AllowAppHVSI_ProviderSet");
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
        public static Dictionary<string, bool> GetWDApplicationGuardConf()
        {
            //https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-application-guard/configure-md-app-guard
            Dictionary<string, bool> results = new Dictionary<string, bool>();

            // Clipboard behaviour: https://getadmx.com/?Category=Windows_10_2016&Policy=Microsoft.Policies.AppHVSI::AppHVSI_ClipboardConfig
            var RegPath = @"SOFTWARE\Policies\Microsoft\AppHVSI";
            var RegValue = Helper.GetRegValue("HKLM", RegPath, "AppHVSIClipboardSettings");
            var ClipBoardBlocked = string.IsNullOrEmpty(RegValue) || RegValue == "0";
            results.Add("Disable copying to and from isolated sessions", ClipBoardBlocked);

            // Print settings: https://getadmx.com/?Category=Windows_10_2016&Policy=Microsoft.Policies.AppHVSI::AppHVSI_PrintingConfig
            RegValue = Helper.GetRegValue("HKLM", RegPath, "AppHVSIPrintingSettings");
            var PrintingBlocked = string.IsNullOrEmpty(RegValue) || RegValue == "0";
            results.Add("Disable printing from isolated sessions", PrintingBlocked);

            // Block non-enterprise content on enterprise websites :https://getadmx.com/?Category=Windows_10_2016&Policy=Microsoft.Policies.AppHVSI::AppHVSI_BlockNonEnterpriseContentConfig
            RegValue = Helper.GetRegValue("HKLM", RegPath, "BlockNonEnterpriseContent");
            var NonEnterpriseContentBlocked = string.IsNullOrEmpty(RegValue) || RegValue == "0";
            results.Add("Block non-enterprise content on enterprise websites", NonEnterpriseContentBlocked);

            // Block file downloads from isolated sessions
            RegValue = Helper.GetRegValue("HKLM", RegPath, "SaveFilesToHost");
            var DownloadsBlocked = string.IsNullOrEmpty(RegValue) || RegValue == "0";
            results.Add("Block file downloads from isolated sessions", DownloadsBlocked);

            // Block microphone and camera access from isolated sessions
            RegValue = Helper.GetRegValue("HKLM", RegPath, "AllowCameraMicrophoneRedirection");
            var MicCamBlocked = string.IsNullOrEmpty(RegValue) || RegValue == "0";
            results.Add("Block microphone/camera from isolated sessions", MicCamBlocked);

            // Don't allow users to trust file opened in application guard
            RegValue = Helper.GetRegValue("HKLM", RegPath, "FileTrustCriteria");
            var UserNotAbleToTrustFiles = string.IsNullOrEmpty(RegValue) || RegValue == "0" || RegValue == "2";
            results.Add("Don't allow users to trust files opened from isolated sessions", UserNotAbleToTrustFiles);

            return results;
        }


        // TODO: TEST THIS
        public static Dictionary<string, bool> GetExploitProtectionConfig()
        {
            Dictionary<string, bool> results = new Dictionary<string, bool>();
            // https://cqureacademy.com/blog/cqlabs-windows-defender-exploit-guard -> partially inaccurate. Trial and error got the actual flag format
            var MitigationFlagsRaw = Helper.GetRegValueBytes("HKLM", @"System\CurrentControlSet\Control\Session Manager\kernel", "MitigationOptions");
            BitArray MitigationFlags = new BitArray(MitigationFlagsRaw);

            //System-wide settings
            results.Add("Data Execution Prevention (DEP)", AreBitsSet(MitigationFlags, 0, true));
            results.Add("Validate Exception Chains (SEHOP)", AreBitsSet(MitigationFlags, 4, true));
            results.Add("Force Randomisation (Mandatory ASRL)", AreBitsSet(MitigationFlags, 8, false));
            results.Add("High-entropy ASRL", AreBitsSet(MitigationFlags, 12, true));
            results.Add("Bottom-Up ASLR", AreBitsSet(MitigationFlags, 16, true));
            results.Add("High-entropy ASLR", AreBitsSet(MitigationFlags, 20, true));
            results.Add("Control Flow Guard", AreBitsSet(MitigationFlags, 40, true));


            //TODO 
            //App-level settings for supporting app-level enumeration

            /*
            results.Add("resultsStrictHandleChecks" , AreBitsSet(MitigationFlags, 24, false)); 
            results.Add("DisableExtensionPoint", AreBitsSet(MitigationFlags, 32, false));
            results.Add("DisableDynamicCode", AreBitsSet(MitigationFlags, 36, false));
            results.Add("BlockNonMicrosoftBinaries", AreBitsSet(MitigationFlags, 44, false));
            results.Add("BlockNonSystemFonts", AreBitsSet(MitigationFlags, 48, false));
            results.Add("DisableRemoteLoads", AreBitsSet(MitigationFlags, 52, false));
            results.Add("DisableLowIntegrityLoads", AreBitsSet(MitigationFlags, 56, false));
            results.Add("PreferSystemImages", AreBitsSet(MitigationFlags, 60, false));
            */

            bool AreBitsSet(BitArray flags, int enabledBit, bool defaultValue)
            {
                var disabledBit = enabledBit + 1;
                if (MitigationFlags.Get(enabledBit) && MitigationFlags.Get(disabledBit))
                {
                    throw new Exception("Not possible. Probably a bug. Care to fix it?");
                }

                if (!MitigationFlags.Get(enabledBit) && !MitigationFlags.Get(disabledBit))
                {
                    // No system-wide settings set -> returning the default
                    return defaultValue;
                }

                return MitigationFlags.Get(enabledBit);
            }

            return results;

        }

        public static bool RunAtInUserContext()
        {
            return Helper.GetRegValue("HKML", @"SYSTEM\CurrentControlSet\Control\Lsa\", "SubmitControl") == "0" ? true : false;
        }


        public static Dictionary<string, string> GetBITSJobLifetime()
        {
            Dictionary<string, string> results = new Dictionary<string, string>();
            results["JobInactivityTimeout"] = Helper.GetRegValue("HKLM", @"Software\Policies\Microsoft\Windows\BITS", "JobInactivityTimeout");
            results["MaxDownloadTime"] = Helper.GetRegValue("HKLM", @"Software\Policies\Microsoft\Windows\BITS", "MaxDownloadTime");
            return results;
        }
        public static Dictionary<string, bool> GetBITSConfigInfo()
        {
            Dictionary<string, bool> info = new Dictionary<string, bool>();
            var regKeys = GetBITSJobLifetime();
            info["Job Inactivity Timeout < 90 days"] = false;
            info["Max Download Time < 54000 seconds"] = false;
            if (string.IsNullOrEmpty(regKeys["JobInactivityTimeout"]))
            {
                info["Job Inactivity Timeout < 90 days"] = false;
            }
            else
            {
                try
                {
                    int timeout = int.Parse(regKeys["JobInactivityTimeout"]);
                    if (timeout < 90)
                        info["Job Inactivity Timeout < 90 days"] = true;
                }
                catch (Exception ex)
                {
                    PrintUtils.Debug(ex.StackTrace);
                }
            }
            if (regKeys["MaxDownloadTime"] == null)
            {
                info["Max Download Time < 54000 seconds"] = false;
            }
            else
            {
                try
                {
                    int timeout = int.Parse(regKeys["MaxDownloadTime"]);
                    if (timeout < 54000)
                        info["Max Download Time < 54000 seconds"] = true;
                }
                catch (Exception ex)
                {
                    PrintUtils.Debug(ex.StackTrace);
                }
            }
            return info;
        }
        public static bool IsLsaRunAsPPL()
        {
            string RunAsPPL = Helper.GetRegValue("HKLM", @"System\CurrentControlSet\Control\Lsa", "RunAsPPL");
            return RunAsPPL == "1" ? true : false;

        }
        public static bool IsCredentialGuardEnabled()
        {
            string regPath = @"System\CurrentControlSet\Control\DeviceGuard";
            if (Helper.GetRegValue("HKLM", regPath, "EnableVirtualizationBasedSecurity") != "1")
                return false;
            string regValue = Helper.GetRegValue("HKLM", regPath, "RequirePlatformSecurityFeatures");
            if (regValue != "1" && regValue != "3")
            {
                return false;
            }
            regValue = Helper.GetRegValue("HKLM", @"System\CurrentControlSet\Control\LSA", "LsaCfgFlags");
            if (regValue != "1" || regValue != "2")
            {
                return false;
            }
            return true;
        }
        public static bool IsSafeDllSafeSearchModeOn()
        {
            var RegValue = Helper.GetRegValue("HKLM", @"System\CurrentControlSet\Control\Session Manager", "SafeDllSearchMode ");
            if (RegValue == "")
            {
                // Default value is on
                return true;
            }
            return RegValue == "1" ? true : false;
        }
        public static Dictionary<string, bool> CanSIDsWriteWinlogonRegistries(List<string> SIDsToCheck)
        {
            // https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order?redirectedfrom=MSDN
            Dictionary<string, bool> regPermResults = new Dictionary<string, bool>();
            var regPath = @"Software\Microsoft\Windows NT\CurrentVersion\Winlogon";
            regPermResults[$"HKCU\\{regPath}"] = !Helper.RegWritePermissions("HKCU", regPath, SIDsToCheck);
            regPermResults[$"HKLM\\{regPath}"] = !Helper.RegWritePermissions("HKLM", regPath, SIDsToCheck);

            return regPermResults;
        }
        public static bool IsChromeExtensionWhitelistEnabled()
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
        public static bool IsChromePasswordManagerDisabled()
        {
            // https://cloud.google.com/docs/chrome-enterprise/policies/?policy=PasswordManagerEnabled
            var RegValue = Helper.GetRegValue("HKLM", @"Software\Policies\Google\Chrome", "PasswordManagerEnabled");
            return RegValue == "1" ? true : false;
        }

        /// <summary>
        /// Checks if external extensions are blocked by Chrome
        /// </summary>
        /// <returns> True if blocked, false if not</returns>
        public static bool IsChromeExternalExtectionsBlocked()
        {
            //https://cloud.google.com/docs/chrome-enterprise/policies/?policy=BlockExternalExtensions
            return Helper.GetRegValue("HKLM", @"Software\Policies\Google\Chrome\", "BlockExternalExtensions") == "1" ? true : false;
        }

        /// <summary>
        /// Checks if Screen Savers are disabled
        /// </summary>
        /// <returns>True if disabled, false if not</returns>
        public static bool IsScreenSaverDisabled()
        {
            return Helper.GetRegValue("HKLM", @"Software\Policies\Microsoft\Windows\Control Panel\Desktop", "ScreenSaveActive") == "0";
        }

        /// <summary>
        /// Checks if RDP network level authentication is enforced.
        /// </summary>
        /// <returns>True if enabled, false if not</returns>
        public static bool IsRdpNLAEnabled()
        {
            return Helper.GetRegValue(
                "HKLM",
                @"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
                "UserAuthentication")
                == "1";
        }

        /// <summary>
        /// Checks is secureboot is enabled
        /// </summary>
        /// <returns>True if enabled, false if not </returns>
        public static bool IsSecureBootEnabled()
        {
            return Helper.GetRegValue(
                "HKLM",
                @"SYSTEM\CurrentControlSet\Control\SecureBoot\State",
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
        public static Version GetOSVersion()
        {
            string wmipathstr = @"\\" + Environment.MachineName + @"\root\cimv2";

            ManagementObjectSearcher searcher = new ManagementObjectSearcher(wmipathstr, "SELECT Version FROM Win32_OperatingSystem");
            ManagementObjectCollection instances = searcher.Get();
            foreach (ManagementObject test in instances)
            {
                return new Version(test["Version"].ToString());
            }
            // Should never reach this. In case it does:
            throw new Exception("Couldn't get windows version");
        }


        public static bool IsSafeDLLSearchEnabled()
        {
            var RegPath = @"System\CurrentControlSet\Control\Session Manager";
            var RegKey = "SafeDllSearchMode ";

            var RegValue = Helper.GetRegValue("HKLM", RegPath, RegKey);
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
            return Helper.GetRegValue("HKLM", RegPath, RegName) == "0" ? true : false;

        }

        public static bool IsOutboundNTLMDisabled()
        {
            var RegPath = @"System\CurrentControlSet\Control\Lsa\MSV1_0";
            var RegName = "RestrictSendingNTLMTraffic";

            return Helper.GetRegValue("HKLM", RegPath, RegName) == "2" ? true : false;
        }

        public static bool IsDCOMDisabled()
        {
            var RegPath = @"Software\Microsoft\OLE";
            var RegName = "EnableDCOM";

            return Helper.GetRegValue("HKLM", RegPath, RegName) == "N" ? true : false;
        }

        public static bool IsRDPDisabled()
        {
            var RegPath = @"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services";
            var RegName = "fDenyTSConnections";

            return Helper.GetRegValue("HKLM", RegPath, RegName) == "1" ? true : false;
        }

        public static Dictionary<string, bool> GetRDPSessionConfig()
        {
            Dictionary<string, bool> config = new Dictionary<string, bool>();

            // Firstly check if RDP is configured to end sessions when time limits are reached
            // https://getadmx.com/?Category=Windows_10_2016&Policy=Microsoft.Policies.TerminalServer::TS_Session_End_On_Limit_2

            var RegPath = @"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services";

            // 1. Max Idle Time
            var MaxIdleTimeStr = Helper.GetRegValue("HKLM", RegPath, "MaxIdleTime");
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
            var MaxConnectionTimeStr = Helper.GetRegValue("HKLM", RegPath, "MaxConnectionTime");
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

            return Helper.GetRegValue("HKLM", RegPath, RegKey) == "1" ? true : false;
        }

        public static bool IsWinRMFilteredByGPO()
        {
            if (IsWinrmGPODefined())
            {
                string RegPath = @"Software\Policies\Microsoft\Windows\WinRM\Service";
                var IPv4Filter = Helper.GetRegValue("HKLM", RegPath, "IPv4Filter");
                return IPv4Filter != "*" ? true : false;
            }
            return false;
        }

        public static bool IsLLMNRDisabled()
        {
            string RegPath = @"Software\Policies\Microsoft\Windows NT\DNSClient";
            string RegKey = "EnableMulticast";
            return Helper.GetRegValue("HKLM", RegPath, RegKey) == "1" ? true : false;
        }

        public static Dictionary<string, bool> GetNetBIOSConfig()
        {
            try
            {
                Dictionary<string, bool> NetBIOSDisabled = new Dictionary<string, bool>();
                // Trying over WMI first
                string wmipathstr = @"\\" + Environment.MachineName + @"\root\cimv2";

                ManagementObjectSearcher searcher = new ManagementObjectSearcher(wmipathstr, "SELECT * FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled='true'");
                ManagementObjectCollection instances = searcher.Get();

                foreach (var instance in instances)
                {
                    var Description = (string)instance["Description"];
                    var NetBIOSStatus = (UInt32)instance["TcpipNetbiosOptions"];
                    NetBIOSDisabled[Description] = NetBIOSStatus == 2 ? true : false;
                }
                return NetBIOSDisabled;
            }
            catch
            {
                return GetNetBIOSConfigReg();
            }
        }
        public static Dictionary<string, bool> GetNetBIOSConfigReg()
        {
            Dictionary<string, bool> config = new Dictionary<string, bool>();
            string RegPath = @"SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces";
            string[] TCPGuid = Helper.GetRegSubkeys("HKLM", RegPath);
            foreach (string interfaceID in TCPGuid)
            {
                RegPath = String.Format(@"SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\{0}", interfaceID);
                config[interfaceID] = Helper.GetRegValue("HKLM", RegPath, "NetbiosOptions") == "2" ? true : false;
            }
            return config;
        }

        public static bool IsSMBSigningForced()
        {
            string RegPath = @"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\";
            string RegKey = "RequireSecuritySignature";

            return Helper.GetRegValue("HKLM", RegPath, RegKey) == "1" ? true : false;
        }

        public static bool IsASREnabled()
        {
            string RegPath = @"SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR";
            string RegKey = "ExploitGuard_ASR_Rules";

            return Helper.GetRegValue("HKLM", RegPath, RegKey) == "1" ? true : false;
        }

        public static Dictionary<string, bool> GetASRRulesStatus(List<string> RuleGUIDs = null)
        {
            // Well-known ASR rules
            Dictionary<string, string> Guid2Description = new Dictionary<string, string>()
            {
                {"BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550","Block executable content from email client and webmail"},
                {"D4F940AB-401B-4EFC-AADC-AD5F3C50688A","Block all Office applications from creating child processes"},
                {"3B576869-A4EC-4529-8536-B80A7769E899","Block Office applications from creating executable content"},
                {"75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84","Block Office applications from injecting code into other processes"},
                {"D3E037E1-3EB8-44C8-A917-57927947596D","Block JavaScript or VBScript from launching downloaded executable content"},
                {"5BEB7EFE-FD9A-4556-801D-275E5FFC04CC","Block execution of potentially obfuscated scripts"},
                {"92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B","Block Win32 API calls from Office macros"},
                {"01443614-cd74-433a-b99e-2ecdc07bfc25","Block executable files from running unless they meet a prevalence, age, or trusted list criterion(Requires cloud delivered protection) "},
                {"c1db55ab-c21a-4637-bb3f-a12568109d35","Use advanced protection against ransomware"},
                {"9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2","Block credential stealing from the windows local security authority subsystem (lsass.exe)"},
                {"d1e49aac-8f56-4280-b9ba-993a6d77406c","Block process creations originating from psexec and wmi commands"},
                {"b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4","Block untrusted and unsigned processes that run from usb"},
                {"26190899-1602-49e8-8b27-eb1d0a1ce869","Block office communication application from creating child processes"},
                {"7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c","Block adobe reader from creating child processes"},
                {"e6db77e5-3df2-4cf1-b95a-636979351e5b","Block persistence through WMI event subscription"}
            };
            if (RuleGUIDs == null)
            {
                RuleGUIDs = Guid2Description.Keys.ToList();
            }
            Dictionary<string, bool> ASRRulesStatus = new Dictionary<string, bool>();
            string RegPath = @"SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules";
            foreach (string ruleGUID in RuleGUIDs)
            {
                string RuleDescription;
                if (Guid2Description.ContainsKey(ruleGUID))
                {
                    // It's a known rule
                    RuleDescription = Guid2Description[ruleGUID];
                }
                else
                {
                    RuleDescription = String.Format("Unknown Rule({0})", ruleGUID);
                }
                // ruleGUID key needs to be set to 1 for blocking
                ASRRulesStatus[RuleDescription] = Helper.GetRegValue("HKLM", RegPath, ruleGUID) == "1" ? true : false;
            }
            return ASRRulesStatus;
        }
        public static Dictionary<string, bool> GetPowerShellProfilePermissions(List<string> UnprivilegedSIDs)
        {
            // from https://static1.squarespace.com/static/552092d5e4b0661088167e5c/t/5760096ecf80a129e0b17634/1465911664070/Windows+PowerShell+Logging+Cheat+Sheet+ver+June+2016+v2.pdf
            var windir = Environment.SpecialFolder.Windows;
            var homedrive = Environment.GetEnvironmentVariable("HOMEDRIVE");
            var user = Program.UserToCheck.SamAccountName;
            List<string> ProfilePaths = new List<string>()
                {

                    {$"{homedrive}\\{windir}\\System32\\WindowsPowerShell\\v1.0\\profile.ps1"},
                    {$"{homedrive}\\{windir}\\SysWOW64\\WindowsPowerShell\\v1.0\\profile.ps1"},
                    {$"{homedrive}\\{windir}\\System32\\WindowsPowerShell\\v1.0\\Microsoft.PowerShell_profile.ps1"},
                    {$"{homedrive}\\{windir}\\System32\\WindowsPowerShell\\v1.0\\Microsoft.PowerShellISE_profile.ps1"},
                    {$"{homedrive}\\{windir}\\SysWOW64\\WindowsPowerShell\\v1.0\\Microsoft.PowerShell_profile.ps1"},
                    {$"{homedrive}\\{windir}\\SysWOW64\\WindowsPowerShell\\v1.0\\Microsoft.PowerShellISE_profile.ps1"},
                };
            if (Directory.Exists($"{homedrive}\\Users\\{user}\\Documents"))
            {
                ProfilePaths.Add($"{homedrive}\\Users\\{user}\\Documents\\profile.ps1");
                ProfilePaths.Add($"{homedrive}\\Users\\{user}\\Documents\\Microsoft.PowerShell_profile.ps1");
                ProfilePaths.Add($"{homedrive}\\Users\\{user}\\Documents\\Microsoft.PowerShellISE_profile.ps1");
            }
            Dictionary<string, bool> ProfilePermissions = new Dictionary<string, bool>();
            foreach (var profilePath in ProfilePaths)
            {
                ProfilePermissions[profilePath] = !Helper.FileWritePermissions(profilePath, UnprivilegedSIDs);
            }
            return ProfilePermissions;
        }
        public static bool CanNonAdminUsersAddRootCertificates()
        {
            //https://posts.specterops.io/code-signing-certificate-cloning-attacks-and-defenses-6f98657fc6ec
            var RegPath = @"SOFTWARE\Policies\Microsoft\SystemCertificates\Root\ProtectedRoots";

            return Helper.GetRegValue("HKLM", RegPath, "Flags") == "1";
        }
    }
}

