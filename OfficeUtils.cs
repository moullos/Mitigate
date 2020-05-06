using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using System.Text;

namespace Mitigate
{

    class OfficeUtils
    {
        private static string GetOfficeVersion()
        {
            //https://stackoverflow.com/questions/3266675/how-to-detect-installed-version-of-ms-office
            string[] AllOfficeVersions = { "16.0", "15.0", "14.0", "12.0" }; // don't really care for version before Office 2003
            string[] OfficeSubKeys = Utils.GetRegSubkeys("HKCU", @"Software\Microsoft\Office");
            foreach (string version in AllOfficeVersions)
            {
                if (OfficeSubKeys.Contains(version))
                    return version;
            }
            throw new OfficeUtils.OfficeNotInstallException("Office is not installed");
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
            string[] OfficeApplications = { "Word", "Excel", "PowerPoint" };
            foreach (string application in OfficeApplications)
            {
                var RegPath = String.Format(@"software\policies\microsoft\office\16.0\{0}\security", application);
                // Check if disabled
                if (Utils.GetRegValue("HKCU", RegPath, "disablealladdins") == "1")
                {
                    results[application] = true;
                    continue;
                }
                // Check if only signed
                if (Utils.GetRegValue("HKCU", RegPath, "requireaddinsig") == "1")
                {
                    results[application] = true;
                }
            }
            return results;
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
