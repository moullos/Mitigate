using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;

namespace Mitigate
{

    class OfficeUtils
    {
        private static string GetOfficeVersion()
        {
            //https://stackoverflow.com/questions/3266675/how-to-detect-installed-version-of-ms-office
            string[] AllOfficeVersions = { "16.0", "15.0", "14.0", "12.0" }; // don't really care for versions before Office 2003
            string[] OfficeSubKeys = Utils.GetRegSubkeys("HKCU", @"Software\Microsoft\Office");
            foreach (string version in AllOfficeVersions)
            {
                if (OfficeSubKeys.Contains(version))
                    return version;
            }
            throw new OfficeUtils.OfficeNotInstallException("Office is not installed");
        }

        public static bool CheckTestRegKey()
        {
            string version = GetOfficeVersion();
            string RegPath = @"Create Software\Microsoft\Office test\Special\Perf key and harden its permissions";
            if (!Utils.RegExists("HKCU", RegPath, "Default"))
            {
                return false;
            }
            else
            {
                var HavePermissionsToAlter = Utils.RegWritePermissions("HKCU", RegPath, Program.SIDsToCheck);
                return HavePermissionsToAlter;
            }
        }
        public static bool IsVBADisabled()
        {
            //First, check if office is installed and get it's version
            string version = GetOfficeVersion();

            // https://www.ncsc.gov.uk/guidance/macro-security-for-microsoft-office

            // Check if VBA engine is disabled holistically for office
            string RegPath = String.Format(@"software\policies\microsoft\office\{0}\common", version);
            if (Utils.GetRegValue("HKLM", RegPath, "vbaoff") == "1")
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
                string setting = Utils.GetRegValue("HKCU", RegPath, "vbawarnings");
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
                if (Utils.GetRegValue("HKCU", RegPath, "disablealladdins") == "1")
                {
                    results[application + ": Addins Disabled"] = true;
                }
                else
                {
                    results[application + ": Addins Disabled"] = false;

                }
                // Check if only signed
                if (Utils.GetRegValue("HKCU", RegPath, "requireaddinsig") == "1")
                {
                    results[application + ": Addins require signing"] = true;
                }
                else
                {
                    results[application + ": Addins require signing"] = false;

                }
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
                throw new OfficeNotInstallException("Unsupported office version");
            }

            // Pulling all the setting from the registry
            var pathWord = String.Format(@"Software\Microsoft\Office\{0}\{1}\Security\ProtectedView", version, "Word");
            var pathExcel = String.Format(@"Software\Microsoft\Office\{0}\{1}\Security\ProtectedView", version, "Excel");
            var pathPowerPoint = String.Format(@"Software\Microsoft\Office\{0}\{1}\Security\ProtectedView", version, "PowerPoint");

            //https://getadmx.com/?Category=Office2016&Policy=word16.Office.Microsoft.Policies.Windows::L_DoNotOpenFilesFromTheInternetZoneInProtectedView
            //Check for protected view on files downloaded from the internet
            ProtectedViewInfo["Word:  PV on Internet Files"] = (Utils.GetRegValue("HKLM", pathWord, "disableinternetfilesinpv") != "1");
            ProtectedViewInfo["Excel: PV on Internet Files"] = (Utils.GetRegValue("HKLM", pathExcel, "disableinternetfilesinpv") != "1");
            ProtectedViewInfo["PPT: PV on Internet Files"] = (Utils.GetRegValue("HKLM", pathPowerPoint, "disableinternetfilesinpv") != "1");

            // Check for protected view on files opened from unsafe locations
            ProtectedViewInfo["Word:  PV on Files in Unsafe Locations"] = (Utils.GetRegValue("HKLM", pathWord, "disableunsafelocationsinpv") != "1");
            ProtectedViewInfo["Excel: PV on Files in Unsafe Locations"] = (Utils.GetRegValue("HKLM", pathExcel, "disableunsafelocationsinpv") != "1");
            ProtectedViewInfo["PPT:   PV on Files in Unsafe Locations"] = (Utils.GetRegValue("HKLM", pathPowerPoint, "disableunsafelocationsinpv") != "!");

            // Check for protected view on files opened from local intranet UNC shares
            ProtectedViewInfo["Word:  PV on files from the intranet"] = (Utils.GetRegValue("HKLM", pathWord, "disableintranetcheck") == "0");
            ProtectedViewInfo["Excel: PV on files from the intranet"] = (Utils.GetRegValue("HKLM", pathExcel, "disableintranetcheck") == "0");
            ProtectedViewInfo["PPT:   PV on files from the intranet"] = (Utils.GetRegValue("HKLM", pathPowerPoint, "disableintranetcheck") == "0");

            // Check for protected view on files opened from OutLook
            ProtectedViewInfo["Word outlook attachments in PV"] = (Utils.GetRegValue("HKLM", pathWord, "disableattachmentsinpv") != "1");
            ProtectedViewInfo["Excel outlook attachments in PV"] = (Utils.GetRegValue("HKLM", pathExcel, "disableattachmentsinpv") != "1");
            ProtectedViewInfo["PPT outlook attachment in PV"] = (Utils.GetRegValue("HKLM", pathPowerPoint, "disableattachmentsinpv") != "1");
            return ProtectedViewInfo;
        }
        public static Dictionary<string, bool> GetAutomaticDDEExecutionConf()
        {
            Dictionary<string, bool> AutomaticDDEExecutionConf = new Dictionary<string, bool>();

            string version = GetOfficeVersion();
            if (version != "14.0" && version != "15.0" && version != "16.0")
            {
                throw new OfficeNotInstallException("Unsupported office version");
            }

            //https://gist.github.com/wdormann/732bb88d9b5dd5a66c9f1e1498f31a1b
            var pathWord = String.Format(@"Software\Microsoft\Office\{0}\{1}\Options", version, "Word");
            AutomaticDDEExecutionConf["Word: Don't update links automatically"] = (Utils.GetRegValue("HKCU", pathWord, "DontUpdateLinks") == "1");
            var pathWordMail = String.Format(@"Software\Microsoft\Office\{0}\{1}\Options\WordMail", version, "Word");
            AutomaticDDEExecutionConf["WordMail: Don't update links automatically"] = (Utils.GetRegValue("HKCU", pathWordMail, "DontUpdateLinks") == "1");
            var pathExcel = String.Format(@"Software\Microsoft\Office\{0}\{1}\Options", version, "Excel");
            AutomaticDDEExecutionConf["Excel: Don't update links automatically"] = (Utils.GetRegValue("HKCU", pathExcel, "DontUpdateLinks") == "1");
            AutomaticDDEExecutionConf["Excel: DDE Disabled"] = (Utils.GetRegValue("HKCU", pathExcel, "DDEAllowed") == "0");
            AutomaticDDEExecutionConf["Excel: DDE Cleaned"] = (Utils.GetRegValue("HKCU", pathExcel, "DDECleaned") == "1");
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
                throw new OfficeNotInstallException();
            }
            //https://gist.github.com/wdormann/732bb88d9b5dd5a66c9f1e1498f31a1b
            var path = String.Format(@"Software\Microsoft\Office\{0}\OneNote\Options", version.First());
            EmbeddedFilesOneNoteConf["Embedded Files Disabled"] = (Utils.GetRegValue("HKCU", path, "DisableEmbeddedFiles") == "1");
            return EmbeddedFilesOneNoteConf;
        }

        [Serializable]
        internal class OfficeNotInstallException : Exception
        {
            public OfficeNotInstallException()
            {
            }

            public OfficeNotInstallException(string message) : base(message)
            {
            }

            public OfficeNotInstallException(string message, Exception innerException) : base(message, innerException)
            {
            }

            protected OfficeNotInstallException(SerializationInfo info, StreamingContext context) : base(info, context)
            {
            }
        }
    }
}
