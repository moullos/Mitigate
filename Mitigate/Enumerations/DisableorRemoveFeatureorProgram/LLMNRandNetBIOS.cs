using Mitigate.Utils;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management;
using System.Runtime.CompilerServices;
using System.Text;

namespace Mitigate.Enumerations.DisabldorRemoveFeatureorProgram
{
  
    class LLMNRandNetBios : Enumeration
    {
        public override string Name => "LLMNR and NetBIOS disabled";
        public override string MitigationType => "Disable or Remove Feature or Program";
        public override string MitigationDescription => "Disable LLMNR and NetBIOS in local computer security settings or by group policy if they are not needed within an environment.";
        public override string EnumerationDescription => "Checks LLMNR and NetBIOS are disabled";

        public override string[] Techniques => new string[] {
            "T1557.001",
        };

        public override IEnumerable<EnumerationResults> Enumerate(Context context)
        {
            foreach (var InterfaceConfig in GetNetBIOSConfig())
            {
                yield return new DisabledFeature($"NetBIOS on {InterfaceConfig.Key}", InterfaceConfig.Value);
            }
            yield return new DisabledFeature("LLMNR", IsLLMNRDisabled());
        }

        private static Dictionary<string, bool> GetNetBIOSConfig()
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
        private static Dictionary<string, bool> GetNetBIOSConfigReg()
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
        private static bool IsLLMNRDisabled()
        {
            string RegPath = @"Software\Policies\Microsoft\Windows NT\DNSClient";
            string RegKey = "EnableMulticast";
            return Helper.GetRegValue("HKLM", RegPath, RegKey) == "1" ? true : false;
        }
    }
}
