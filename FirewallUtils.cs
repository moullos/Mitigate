using NetFwTypeLib;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text.RegularExpressions;

namespace Mitigate
{
    class FirewallUtils
    {
        // All firewall utils are courtesy of Seatbelt and WinPEAS with some fixes from https://stackoverflow.com/questions/10342260/is-there-any-net-api-to-get-all-the-firewall-rules        
        [Flags]
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
                Type tNetFwPolicy2 = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
                INetFwPolicy2 fwPolicy2 = (INetFwPolicy2)Activator.CreateInstance(tNetFwPolicy2);
                var types = fwPolicy2.CurrentProfileTypes.ToString();
                result = String.Format("{0}", (FirewallProfiles)Int32.Parse(types.ToString()));
            }
            catch (Exception ex)
            {
                PrintUtils.TestError(ex.Message);
            }
            return result;
        }
        public int getFirewallDefaultAction(int profile)
        {
            Type tNetFwPolicy2 = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
            INetFwPolicy2 fwPolicy2 = (INetFwPolicy2)Activator.CreateInstance(tNetFwPolicy2);
            return (int)fwPolicy2.DefaultInboundAction[(NET_FW_PROFILE_TYPE2_)profile];
        }
        public static Dictionary<string, bool> GetFirewallBooleans()
        {
            Dictionary<string, bool> results;
            // GUID for HNetCfg.FwPolicy2 COM object
            Type tNetFwPolicy2 = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
            INetFwPolicy2 fwPolicy2 = (INetFwPolicy2)Activator.CreateInstance(tNetFwPolicy2);
            results = new Dictionary<string, bool>() {
                { "Firewall Enabled (Domain)", fwPolicy2.FirewallEnabled[NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_DOMAIN] },
                { "Firewall Enabled (Private)", fwPolicy2.FirewallEnabled[NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PRIVATE] },
                { "Firewall Enabled (Public)",fwPolicy2.FirewallEnabled[NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PUBLIC] },
            };
            return results;
        }

        /// <summary>
        /// Method that retrieves enabled and inbound windows firewall rules
        /// </summary>
        /// <returns>List of rules</returns>
        public static IEnumerable<INetFwRule> GetEnabledInboundRules()
        {
            Type tNetFwPolicy2 = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
            INetFwPolicy2 fwPolicy2 = (INetFwPolicy2)Activator.CreateInstance(tNetFwPolicy2);
            var Rules = fwPolicy2.Rules.Cast<INetFwRule>().ToList();
            return Rules.Where(o => o.Enabled && o.Direction == NET_FW_RULE_DIRECTION_.NET_FW_RULE_DIR_IN);
        }

        public static IEnumerable<INetFwRule> GetEnabledInboundRules(params string[] ports)
        {
            Type tNetFwPolicy2 = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
            INetFwPolicy2 fwPolicy2 = (INetFwPolicy2)Activator.CreateInstance(tNetFwPolicy2);
            var Rules = fwPolicy2.Rules.Cast<INetFwRule>().ToList();
            return Rules.Where(o=> o.Enabled)
                        .Where(o => !String.IsNullOrEmpty(o.LocalPorts))
                        .Where(o => ports.Any(j => o.LocalPorts.Contains(j)));
        }
        public static Dictionary<string, bool> TrafficRestrictedToSpecificIPs(params string[] dPorts)
        {
            var results = new Dictionary<string, bool>();
            // Get rules to destination ports
            var RelevantRules = GetEnabledInboundRules(dPorts);

            // Domain Rules
            results["Domain profile"] = FilteredToSpecificIP(RelevantRules, (int)NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_DOMAIN);
            results["Private profile"] = FilteredToSpecificIP(RelevantRules, (int)NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PRIVATE);
            results["Public profile"] = FilteredToSpecificIP(RelevantRules, (int)NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PUBLIC);

            return results;
        }
        private static bool FilteredToSpecificIP(IEnumerable<INetFwRule> RelevantRules, int profile)
        {
            var ProfileRules = RelevantRules.Where(o => (o.Profiles & profile)!=0);
            if (ProfileRules == null)
            {
                // All traffic is blocked; return true
                return true;
            }
            return ProfileRules.All(o => IsSpecific(o.RemoteAddresses));
        }

        private static bool IsSpecific(string RemoteAddresses)
        {
            // https://docs.microsoft.com/en-us/windows/win32/api/netfw/nf-netfw-inetfwrule-get_remoteaddresses
            var ips = RemoteAddresses.Split(',');
            return ips.All(o => IPAddress.TryParse(o.Trim(), out _) || Regex.IsMatch(o.Trim(), 
                @"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/(3[0-2]|[1-2][0-9]|[0-9]))$"));

        }

    }
}
