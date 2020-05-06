using System;
using System.Management;
using System.Collections.Generic;
using System.Text;
using System.Linq;
using System.IO;
using Microsoft.Win32;
using System.Runtime.InteropServices;
using System.Reflection;
using System.Collections;
using System.Dynamic;
using System.Security.Cryptography.X509Certificates;
using System.DirectoryServices.ActiveDirectory;
using System.CodeDom.Compiler;
using System.ComponentModel;

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
        // TODO: Move to office utils
        public static Dictionary<string, bool> GetProtectedViewInfo()
        {
            // Currently only works for office 365/2016
            // All office version as represented in registry keys
            string[] officeVersions = { "7.0", "8.0", "9.0", "10.0", "11.0", "12.0", "13.0", "14.0", "15.0", "16.0" };
            string[] office = Utils.GetRegSubkeys("HKLM", @"Software\Microsoft\Office");
            if (!office.Contains("16.0"))
            {
                // office is not installed/not supported version
                throw new Exception("Office is not installed/not supported version");
            }
            Dictionary<string, bool> ProtectedViewInfo = new Dictionary<string, bool>();
            // Pulling all the setting from the registry
            string version = "16.0";
            var pathWord = String.Format(@"Software\Microsoft\Office\{0}\{1}\Security\ProtectedView", version, "Word");
            var pathExcel = String.Format(@"Software\Microsoft\Office\{0}\{1}\Security\ProtectedView", version, "Excel");
            var pathPowerPoint = String.Format(@"Software\Microsoft\Office\{0}\{1}\Security\ProtectedView", version, "PowerPoint");

            //https://getadmx.com/?Category=Office2016&Policy=word16.Office.Microsoft.Policies.Windows::L_DoNotOpenFilesFromTheInternetZoneInProtectedView
            //Check for protected view on files downloaded from the internet
            ProtectedViewInfo["InternetFiles:Word"] = (Utils.GetRegValue("HKLM", pathWord, "disableinternetfilesinpv") == "0");
            ProtectedViewInfo["InternetFiles:Excel"] = (Utils.GetRegValue("HKLM", pathExcel, "disableinternetfilesinpv") == "0");
            ProtectedViewInfo["InternetFiles:PPT"] = (Utils.GetRegValue("HKLM", pathExcel, "disableinternetfilesinpv") == "0");

            // Check for protected view on files opened from unsafe locations
            ProtectedViewInfo["UnsafeLocations:Word"] = (Utils.GetRegValue("HKLM", pathWord, "disableunsafelocationsinpv") == "0");
            ProtectedViewInfo["UnsafeLocations:Excel"] = (Utils.GetRegValue("HKLM", pathExcel, "disableunsafelocationsinpv") == "0");
            ProtectedViewInfo["UnsafeLocations:PPT"] = (Utils.GetRegValue("HKLM", pathExcel, "disableunsafelocationsinpv") == "0");

            // Check for protected view on files opened from local intranet UNC shares
            ProtectedViewInfo["Intranet:Word"] = (Utils.GetRegValue("HKLM", pathWord, "disableintranetcheck") == "0");
            ProtectedViewInfo["Intranet:Excel"] = (Utils.GetRegValue("HKLM", pathExcel, "disableintranetcheck") == "0");
            ProtectedViewInfo["Intranet:PPT"] = (Utils.GetRegValue("HKLM", pathExcel, "disableintranetcheck") == "0");

            // Check for protected view on files opened from OutLook
            ProtectedViewInfo["Outlook:Word"] = (Utils.GetRegValue("HKLM", pathWord, "disableattachmentsinpv") == "0");
            ProtectedViewInfo["Outlook:Excel"] = (Utils.GetRegValue("HKLM", pathExcel, "disableattachmentsinpv") == "0");
            ProtectedViewInfo["Outlook:PPT"] = (Utils.GetRegValue("HKLM", pathExcel, "disableattachmentsinpv") == "0");
            return ProtectedViewInfo;
        }
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
        // TODO: Move to office utils
        public static Dictionary<string, bool> GetAutomaticDDEExecutionConf()
        {
            Dictionary<string, bool> AutomaticDDEExecutionConf = new Dictionary<string, bool>();
            //TODO - Extend check to other office versions
            string[] supportedofficeVersions = { "16.0" };
            string[] office = Utils.GetRegSubkeys("HKCU", @"Software\Microsoft\Office");
            var version = supportedofficeVersions.AsQueryable().Intersect(office);
            if (version.Count() == 1)
            {
                //https://gist.github.com/wdormann/732bb88d9b5dd5a66c9f1e1498f31a1b
                var pathWord = String.Format(@"Software\Microsoft\Office\{0}\{1}\Options", version, "Word");
                AutomaticDDEExecutionConf["Word:Dont update links"] = (Utils.GetRegValue("HKCU", pathWord, "DontUpdateLinks") == "1");
                var pathWordMail = String.Format(@"Software\Microsoft\Office\{0}\{1}\Options\WordMail", version, "Word");
                AutomaticDDEExecutionConf["WordMail:Dont update links"] = (Utils.GetRegValue("HKCU", pathWordMail, "DontUpdateLinks") == "1");
                var pathExcel = String.Format(@"Software\Microsoft\Office\{0}\{1}\Options", version, "Excel");
                AutomaticDDEExecutionConf["Excel:Dont update links"] = (Utils.GetRegValue("HKCU", pathExcel, "DontUpdateLinks") == "1");
                AutomaticDDEExecutionConf["Excel:DDE Disabled"] = (Utils.GetRegValue("HKCU", pathExcel, "DDEAllowed") == "0");
                AutomaticDDEExecutionConf["Excel:DDE Cleaned"] = (Utils.GetRegValue("HKCU", pathExcel, "DDECleaned") == "1");
                // TODO - Check what this does for version 14.0 and 15.0
                //AutomaticDDEExecutionConf["Excel:Options"] = (Utils.GetRegValue("HKCU", pathExcel, "Options") == "117");
            }
            return AutomaticDDEExecutionConf;
        }
        // TODO: Move to office utils.
        public static Dictionary<string, bool> GetEmbeddedFilesOneNoteConf()
        {
            Dictionary<string, bool> EmbeddedFilesOneNoteConf = new Dictionary<string, bool>();
            string[] supportedofficeVersions = { "15.0", "16.0" };
            string[] office = Utils.GetRegSubkeys("HKCU", @"Software\Microsoft\Office");
            var version = supportedofficeVersions.AsQueryable().Intersect(office);
            if (version.Count() == 1)
            {
                //https://gist.github.com/wdormann/732bb88d9b5dd5a66c9f1e1498f31a1b
                var path = String.Format(@"Software\Microsoft\Office\{0}\OneNote\Options", version.First());
                EmbeddedFilesOneNoteConf["Embedded Files Disabled"] = (Utils.GetRegValue("HKCU", path, "DisableEmbeddedFiles") == "1");
            }
            return EmbeddedFilesOneNoteConf;
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

            string ScriptsEnabled = "";
            string ExecutionPolicy = "";
            // Machine Group Policy
            try
            {
                ExecutionPolicy = Utils.GetRegValue("HKLM", @"Software\Policies\Microsoft\Windows\PowerShell", "ExecutionPolicy");
            }
            catch (Exception ex)
            {
                PrintUtils.ErrorPrint(ex.Message);
            }
            if (ExecutionPolicy != "")
            {
                return ExecutionPolicy;
            }
            // Current User Group Policy
            try
            {
                ExecutionPolicy = Utils.GetRegValue("HKCU", @"Software\Policies\Microsoft\Windows\PowerShell", "ExecutionPolicy");
            }
            catch (Exception ex)
            {
                PrintUtils.ErrorPrint(ex.Message);
            }
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
        public static List<Dictionary<string, string>> GetFirewallRules()
        {
            List<Dictionary<string, string>> results = new List<Dictionary<string, string>>();
            try
            {
                // TODO: THIS DOES NOT WORK - Need to fix at some point
                // GUID for HNetCfg.FwPolicy2 COM object
                Type tNetFwPolicy2 = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
                dynamic fwPolicy2 = Activator.CreateInstance(tNetFwPolicy2) as dynamic;
                IEnumerable Rules = fwPolicy2.Rules as IEnumerable;

                // manually get the enumerator() method
                System.Collections.IEnumerator enumerator = (System.Collections.IEnumerator)Rules.GetType().InvokeMember("GetEnumerator", BindingFlags.InvokeMethod, null, Rules, null);

                // move to the first item
                enumerator.MoveNext();
                Object currentItem = enumerator.Current;
                while (currentItem != null)
                {
                    // only display enabled rules
                    Object Enabled = currentItem.GetType().InvokeMember("Enabled", BindingFlags.GetProperty, null, currentItem, null);
                    if (Enabled.ToString() == "True")
                    {
                        Object Action = currentItem.GetType().InvokeMember("Action", BindingFlags.GetProperty, null, currentItem, null);
                        if (Action.ToString() == "0") //Only DENY rules
                        {
                            // extract all of our fields
                            Object Name = currentItem.GetType().InvokeMember("Name", BindingFlags.GetProperty, null, currentItem, null);
                            Object Description = currentItem.GetType().InvokeMember("Description", BindingFlags.GetProperty, null, currentItem, null);
                            Object Protocol = currentItem.GetType().InvokeMember("Protocol", BindingFlags.GetProperty, null, currentItem, null);
                            Object ApplicationName = currentItem.GetType().InvokeMember("ApplicationName", BindingFlags.GetProperty, null, currentItem, null);
                            Object LocalAddresses = currentItem.GetType().InvokeMember("LocalAddresses", BindingFlags.GetProperty, null, currentItem, null);
                            Object LocalPorts = currentItem.GetType().InvokeMember("LocalPorts", BindingFlags.GetProperty, null, currentItem, null);
                            Object RemoteAddresses = currentItem.GetType().InvokeMember("RemoteAddresses", BindingFlags.GetProperty, null, currentItem, null);
                            Object RemotePorts = currentItem.GetType().InvokeMember("RemotePorts", BindingFlags.GetProperty, null, currentItem, null);
                            Object Direction = currentItem.GetType().InvokeMember("Direction", BindingFlags.GetProperty, null, currentItem, null);
                            Object Profiles = currentItem.GetType().InvokeMember("Profiles", BindingFlags.GetProperty, null, currentItem, null);

                            string ruleAction = "ALLOW";
                            if (Action.ToString() != "1")
                                ruleAction = "DENY";

                            string ruleDirection = "IN";
                            if (Direction.ToString() != "1")
                                ruleDirection = "OUT";

                            string ruleProtocol = "TCP";
                            if (Protocol.ToString() != "6")
                                ruleProtocol = "UDP";

                            Dictionary<string, string> rule = new Dictionary<string, string> { };
                            rule["Name"] = String.Format("{0}", Name);
                            rule["Description"] = String.Format("{0}", Description);
                            rule["AppName"] = String.Format("{0}", ApplicationName);
                            rule["Protocol"] = String.Format("{0}", ruleProtocol);
                            rule["Action"] = String.Format("{0}", ruleAction);
                            rule["Direction"] = String.Format("{0}", ruleDirection);
                            rule["Profiles"] = String.Format("{0}", Int32.Parse(Profiles.ToString()));
                            rule["Local"] = String.Format("{0}:{1}", LocalAddresses, LocalPorts);
                            rule["Remote"] = String.Format("{0}:{1}", RemoteAddresses, RemotePorts);
                            results.Add(rule);
                        }
                    }
                    // manually move the enumerator
                    enumerator.MoveNext();
                    currentItem = enumerator.Current;
                }
            }
            catch (Exception ex)
            {
                PrintUtils.ErrorPrint("Couldn't get firewall rules");
                PrintUtils.ExceptionPrint(ex.Message);
            }
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
            return Utils.GetRegValue("HKLM", @"System\CurrentControlSet\Control\Session Manager", "SafeDllSearchMode ") == "1";
        }
        public static Dictionary<string, bool> GetWinlogonRegPermissions()
        {
            Dictionary<string, bool> regPermResults = new Dictionary<string, bool>();
            var regPath = @"Software\Microsoft\Windows NT\CurrentVersion\Winlogon";
            var RegPermissions = Utils.GetRegPermissions("HKLM", regPath, Program.InterestingUsers);
            regPermResults["HKLM"] = RegPermissions == null ? true : false;
            RegPermissions = Utils.GetRegPermissions("HKCU", regPath, Program.InterestingUsers);
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
        public static bool IsChromeExternalExtectionsBlocked()
        {
            //https://cloud.google.com/docs/chrome-enterprise/policies/?policy=BlockExternalExtensions
            return Utils.GetRegValue("HKLM", @"Software\Policies\Google\Chrome\", "BlockExternalExtensions") == "1" ? true : false;
        }
        public static bool IsScreenSaverDisabled()
        {
            return Utils.GetRegValue("HKLM", @"Software\Policies\Microsoft\Windows\Control Panel\Desktop", "ScreenSaveActive") == "0";
        }
        public static bool IsRdpNLAEnabled()
        {
            return Utils.GetRegValue(
                "HKLM",
                @"\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
                "UserAuthentication")
                == "1";
        }
        public static bool IsSecureBootEnabled()
        {
            return Utils.GetRegValue(
                "HKLM",
                @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecureBoot\State",
                "UEFISecureBootEnabled")
                == "1";
        }
    }
}