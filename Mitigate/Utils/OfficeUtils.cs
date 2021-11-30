using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.Serialization;

namespace Mitigate.Utils
{

    class OfficeUtils
    {
        public static string GetOfficeVersion()
        {
            //https://stackoverflow.com/questions/3266675/how-to-detect-installed-version-of-ms-office
            string[] AllOfficeVersions = { "16.0", "15.0", "14.0", "12.0" }; // don't really care for versions before Office 2003
            string[] OfficeSubKeys = Helper.GetRegSubkeys("HKCU", @"Software\Microsoft\Office");
            foreach (string version in AllOfficeVersions)
            {
                if (OfficeSubKeys.Contains(version))
                    return version;
            }
            throw new OfficeNotInstalledException();
        }

        public static Dictionary<string, bool> CheckTestRegKey()
        {
            Dictionary<string, bool> info = new Dictionary<string, bool>();
            string version = GetOfficeVersion();
            string RegPath = @"Software\Microsoft\Office test\Special\Perf";
            if (!Helper.RegExists("HKCU", RegPath, "Default"))
            {
                info["HKCU hive"] = false;
            }
            else
            {
                info["HKCU hive"] = Helper.RegWritePermissions("HKCU", RegPath, Program.SIDsToCheck);
            }
            if (!Helper.RegExists("HKLM", RegPath, "Default"))
            {
                info["HKLM hive"] = false;
            }
            else
            {
                info["HKLM hive"] = Helper.RegWritePermissions("HKLM", RegPath, Program.SIDsToCheck);
            }
            return info;
        }
        public static bool IsVBADisabled()
        {
            //First, check if office is installed and get it's version
            string version = GetOfficeVersion();

            // https://www.ncsc.gov.uk/guidance/macro-security-for-microsoft-office

            // Check if VBA engine is disabled holistically for office
            string RegPath = String.Format(@"software\policies\microsoft\office\{0}\common", version);
            if (Helper.GetRegValue("HKLM", RegPath, "vbaoff") == "1")
                return true;
            return false;
        }
        // Check if macros are disabled or set to only signed on the application level. Can be easily extended to Publisher, Project and Vision
        public static Dictionary<string, bool> GetMacroConf()
        {

            Dictionary<string, bool> results = new Dictionary<string, bool>();
            string version = GetOfficeVersion();
            string[] OfficeApplications = { "Word", "Excel", "PowerPoint", "Outlook" };
            foreach (string application in OfficeApplications)
            {
                var RegPath = String.Format(@"software\policies\microsoft\office\{0}\{1}\security", version, application);
                string setting = Helper.GetRegValue("HKCU", RegPath, "vbawarnings");
                // 4 = Disabled without notification
                // 3 = Only digitally signed
                // 2 = Disabled with notification
                // 1 = Enable all macros
                // We consider "good" only 3 or 4
                if ((setting == "3") || (setting == "4"))
                {
                    results[application] = true;
                }
                else
                {
                    results[application] = false;
                }
            }
            return results;
        }
        public static Dictionary<string, bool> GetAddinsConf()
        {
            Dictionary<string, bool> results = new Dictionary<string, bool>();
            string version = GetOfficeVersion();
            string[] OfficeApplications = { "Word", "Excel", "PowerPoint" };
            foreach (string application in OfficeApplications)
            {
                var RegPath = String.Format(@"software\policies\microsoft\office\{0}\{1}\security", version, application);
                
                // Check if disabled
                results[application + " Addins"] = Helper.GetRegValue("HKCU", RegPath, "disablealladdins") == "1";
                
                // Check if only signed
                results[application + " Addins must be signed"] = Helper.GetRegValue("HKCU", RegPath, "requireaddinsig") == "1";
            }
            return results;
        }
        public static Dictionary<string, bool> GetProtectedViewInfo()
        {
            Dictionary<string, bool> ProtectedViewInfo = new Dictionary<string, bool>();

            // Currently only works for office 365/2016
            // Get Office Version
            string version = GetOfficeVersion();
            if (version != "16.0")
            {
                throw new OfficeNotInstalledException("Unsupported office version");
            }

            // Pulling all the setting from the registry
            var pathWord = String.Format(@"Software\Microsoft\Office\{0}\{1}\Security\ProtectedView", version, "Word");
            var pathExcel = String.Format(@"Software\Microsoft\Office\{0}\{1}\Security\ProtectedView", version, "Excel");
            var pathPowerPoint = String.Format(@"Software\Microsoft\Office\{0}\{1}\Security\ProtectedView", version, "PowerPoint");

            //https://getadmx.com/?Category=Office2016&Policy=word16.Office.Microsoft.Policies.Windows::L_DoNotOpenFilesFromTheInternetZoneInProtectedView
            //Check for protected view on files downloaded from the internet
            ProtectedViewInfo["Word:  PV on Internet Files"] = (Helper.GetRegValue("HKLM", pathWord, "disableinternetfilesinpv") != "1");
            ProtectedViewInfo["Excel: PV on Internet Files"] = (Helper.GetRegValue("HKLM", pathExcel, "disableinternetfilesinpv") != "1");
            ProtectedViewInfo["PPT: PV on Internet Files"] = (Helper.GetRegValue("HKLM", pathPowerPoint, "disableinternetfilesinpv") != "1");

            // Check for protected view on files opened from unsafe locations
            ProtectedViewInfo["Word:  PV on Files in Unsafe Locations"] = (Helper.GetRegValue("HKLM", pathWord, "disableunsafelocationsinpv") != "1");
            ProtectedViewInfo["Excel: PV on Files in Unsafe Locations"] = (Helper.GetRegValue("HKLM", pathExcel, "disableunsafelocationsinpv") != "1");
            ProtectedViewInfo["PPT:   PV on Files in Unsafe Locations"] = (Helper.GetRegValue("HKLM", pathPowerPoint, "disableunsafelocationsinpv") != "!");

            // Check for protected view on files opened from local intranet UNC shares
            ProtectedViewInfo["Word:  PV on files from the intranet"] = (Helper.GetRegValue("HKLM", pathWord, "disableintranetcheck") == "0");
            ProtectedViewInfo["Excel: PV on files from the intranet"] = (Helper.GetRegValue("HKLM", pathExcel, "disableintranetcheck") == "0");
            ProtectedViewInfo["PPT:   PV on files from the intranet"] = (Helper.GetRegValue("HKLM", pathPowerPoint, "disableintranetcheck") == "0");

            // Check for protected view on files opened from OutLook
            ProtectedViewInfo["Word outlook attachments in PV"] = (Helper.GetRegValue("HKLM", pathWord, "disableattachmentsinpv") != "1");
            ProtectedViewInfo["Excel outlook attachments in PV"] = (Helper.GetRegValue("HKLM", pathExcel, "disableattachmentsinpv") != "1");
            ProtectedViewInfo["PPT outlook attachment in PV"] = (Helper.GetRegValue("HKLM", pathPowerPoint, "disableattachmentsinpv") != "1");
            return ProtectedViewInfo;
        }
        public static Version GetOutlookVersion()
        {
            var RegPath = @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths\OUTLOOK.EXE";
            var OutlookPath = Helper.GetRegValue("HKLM", RegPath, "");
            if (String.IsNullOrEmpty(OutlookPath))
            {
                RegPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\OUTLOOK.EXE";
                OutlookPath = Helper.GetRegValue("HKLM", RegPath, "");
            }
            if (!string.IsNullOrEmpty(OutlookPath) && File.Exists(OutlookPath))
            {
                var OutLookVersion = FileVersionInfo.GetVersionInfo(OutlookPath).ProductVersion;
                return new Version(OutLookVersion.Replace(",", "."));
            }
            throw new Exception("GetOutlookVersion: Outlook version could not be obtained");
        }
        public static bool IsVBBlockedOutlook()
        {
            string version = GetOfficeVersion();
            if (version != "15.0" && version != "16.0")
            {
                throw new OfficeNotInstalledException("Unsupported office version");
            }
            /*
            Outlook 2016: 16.0.4534.1001 or greater (KB3191938). 
            Outlook 2013: 15.0.4937.1000 or greater.
            */
            var OutlookVersion = GetOutlookVersion();
            Version RequiredVersion;
            if (version == "15.0")
            {
                RequiredVersion = new Version("15.0.4937.1000");
            } 
            else if (version == "16.0")
            {
                RequiredVersion = new Version("16.0.4534.1001");
            }
            else
            {
                throw new Exception("IsVBBlockedOutlook: Unknown Version");
            }

            if (OutlookVersion < RequiredVersion)
            {
                return false;
            }
            else
            {
                var RegPath = String.Format(@"Software\Microsoft\Office\{0}\Outlook\Security", version);
                return Helper.GetRegValue("HKCU", RegPath, "EnableUnsafeClientMailRules") != "1";
            }
        }
        public static bool CustomFormsDisabled()
        {
            //https://support.microsoft.com/en-us/office/custom-form-script-is-now-disabled-by-default-bd8ea308-733f-4728-bfcc-d7cce0120e94//
            string version = GetOfficeVersion();
            if (version !="14.0" && version != "15.0" && version != "16.0")
            {
                throw new OfficeNotInstalledException("Unsupported office version");
            }
            /*
            Outlook 2016: 16.0.4588.1001 or greater (KB4011091).
            Outlook 2013: 15.0.4963.1000 or greater.
            Outlook 2010: 14.0.7188.5000 or greater.
            */
            var OutlookVersion = GetOutlookVersion();
            Version RequiredVersion;
            switch (version)
            {
                case "14.0":
                    RequiredVersion = new Version("14.0.7188.5000");
                    break;
                case "15.0":
                    RequiredVersion = new Version("15.0.4963.1000");
                    break;
                case "16.0":
                    RequiredVersion = new Version("16.0.4588.1001");
                    break;
                default:
                    throw new Exception("CheckForKB4011091: Unknown Version");
            }
            if (OutlookVersion < RequiredVersion)
            {
                return false;
            }
            else
            {
                // 32 bit Office on 64 bit Windows
                var RegPath = String.Format(@"SOFTWARE\Microsoft\Office\{0}\Outlook\Security", version);
                var case1 =  Helper.GetRegValue("HKLM", RegPath, "DisableCustomFormItemScript") != "0";
                //32 bit Office on 32 bit Windows or 64 bit Office on 64 bit Windows
                RegPath = String.Format(@"SOFTWARE\WOW6432Node\Microsoft\Office\{0}\Outlook\Security", version);
                var case2 = Helper.GetRegValue("HKLM", RegPath, "DisableCustomFormItemScript") != "0";
                return case1 && case2;
            }
        }
        public static bool CheckForKB4011162()
        {
            //https://www.fireeye.com/blog/threat-research/2019/12/breaking-the-rules-tough-outlook-for-home-page-attacks.html
            //https://support.microsoft.com/en-us/help/4011162/description-of-the-security-update-for-outlook-2016-october-10-2017
            string version = GetOfficeVersion();
            if (version != "14.0" && version != "15.0" && version != "16.0")
            {
                throw new OfficeNotInstalledException("Unsupported office version");
            }
            Version RequiredVersion;

            switch (version)
            {
                case "14.0":
                    RequiredVersion = new Version("14.0.7189.5000");
                    break;
                case "15.0":
                    RequiredVersion = new Version("15.0.4971.1000");
                    break;
                case "16.0":
                    RequiredVersion = new Version("16.0.4600.1000");
                    break;
                default:
                    throw new Exception("CheckForKB4011162: Unknown Version");
            }
            var OutlookVersion = GetOutlookVersion();
            if (OutlookVersion < RequiredVersion)
            {
                return false;
            }
            else
            {
                var RegPath = String.Format(@"SOFTWARE\Microsoft\Office\{0}\Outlook\Security", version);
                var case1 = Helper.GetRegValue("HKCU", RegPath, "EnableRoamingFolderHomepages") != "1";
                var case2 = Helper.GetRegValue("HKCU", RegPath, "NonDefaultStoreScript") != "1";
                return case1 && case2;
            }
        }
        public static Dictionary<string, bool> GetAutomaticDDEExecutionConf()
        {
            Dictionary<string, bool> AutomaticDDEExecutionConf = new Dictionary<string, bool>();

            string version = GetOfficeVersion();
            if (version != "14.0" && version != "15.0" && version != "16.0")
            {
                throw new OfficeNotInstalledException("Unsupported office version");
            }

            //https://gist.github.com/wdormann/732bb88d9b5dd5a66c9f1e1498f31a1b
            var pathWord = String.Format(@"Software\Microsoft\Office\{0}\{1}\Options", version, "Word");
            AutomaticDDEExecutionConf["Word: Don't update links automatically"] = (Helper.GetRegValue("HKCU", pathWord, "DontUpdateLinks") == "1");
            var pathWordMail = String.Format(@"Software\Microsoft\Office\{0}\{1}\Options\WordMail", version, "Word");
            AutomaticDDEExecutionConf["WordMail: Don't update links automatically"] = (Helper.GetRegValue("HKCU", pathWordMail, "DontUpdateLinks") == "1");
            var pathExcel = String.Format(@"Software\Microsoft\Office\{0}\{1}\Options", version, "Excel");
            AutomaticDDEExecutionConf["Excel: Don't update links automatically"] = (Helper.GetRegValue("HKCU", pathExcel, "DontUpdateLinks") == "1");
            AutomaticDDEExecutionConf["Excel: DDE Disabled"] = (Helper.GetRegValue("HKCU", pathExcel, "DDEAllowed") == "0");
            AutomaticDDEExecutionConf["Excel: DDE Cleaned"] = (Helper.GetRegValue("HKCU", pathExcel, "DDECleaned") == "1");
            // TODO - Check what this does for version 14.0 and 15.0
            //AutomaticDDEExecutionConf["Excel:Options"] = (Utils.GetRegValue("HKCU", pathExcel, "Options") == "117");

            return AutomaticDDEExecutionConf;
        }
        public static Dictionary<string, bool> GetEmbeddedFilesOneNoteConf()
        {
            Dictionary<string, bool> EmbeddedFilesOneNoteConf = new Dictionary<string, bool>();

            string version = GetOfficeVersion();
            if (version != "16.0" && version != "15.0")
            {
                throw new OfficeNotInstalledException();
            }
            //https://gist.github.com/wdormann/732bb88d9b5dd5a66c9f1e1498f31a1b
            var path = String.Format(@"Software\Microsoft\Office\{0}\OneNote\Options", version.First());
            EmbeddedFilesOneNoteConf["Embedded Files Disabled"] = (Helper.GetRegValue("HKCU", path, "DisableEmbeddedFiles") == "1");
            return EmbeddedFilesOneNoteConf;
        }

        [Serializable]
        internal class OfficeNotInstalledException : Exception
        {
            public OfficeNotInstalledException()
            {
            }

            public OfficeNotInstalledException(string message) : base(message)
            {
            }

            public OfficeNotInstalledException(string message, Exception innerException) : base(message, innerException)
            {
            }

            protected OfficeNotInstalledException(SerializationInfo info, StreamingContext context) : base(info, context)
            {
            }
        }
    }
}
