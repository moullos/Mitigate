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
        public static Dictionary<string, bool> CanSIDsWriteWinlogonRegistries(List<string> SIDsToCheck)
        {
            // https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order?redirectedfrom=MSDN
            Dictionary<string, bool> regPermResults = new Dictionary<string, bool>();
            var regPath = @"Software\Microsoft\Windows NT\CurrentVersion\Winlogon";
            regPermResults[$"HKCU\\{regPath}"] = !Helper.RegWritePermissions("HKCU", regPath, SIDsToCheck);
            regPermResults[$"HKLM\\{regPath}"] = !Helper.RegWritePermissions("HKLM", regPath, SIDsToCheck);

            return regPermResults;
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

        public static bool CanNonAdminUsersAddRootCertificates()
        {
            //https://posts.specterops.io/code-signing-certificate-cloning-attacks-and-defenses-6f98657fc6ec
            var RegPath = @"SOFTWARE\Policies\Microsoft\SystemCertificates\Root\ProtectedRoots";

            return Helper.GetRegValue("HKLM", RegPath, "Flags") == "1";
        }
    }
}

