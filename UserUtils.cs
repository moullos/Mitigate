using System;
using System.Collections.Generic;
using System.Text;
using System.Security.Principal;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.DirectoryServices.AccountManagement;
using System.ComponentModel;
using System.Net;
using System.Security.Principal;
using System.Management;
using System.Security.AccessControl;
using Microsoft.VisualBasic;
using System.DirectoryServices.ActiveDirectory;
using System.Linq;

namespace Mitigate
{
    class UserUtils
    {
        // https://stackoverflow.com/questions/31464835/how-to-programmatically-check-the-password-must-meet-complexity-requirements-g
        public sealed class SamServer : IDisposable
        {
            private IntPtr _handle;

            public SamServer(string name, SERVER_ACCESS_MASK access)
            {
                Name = name;
                Check(SamConnect(new UNICODE_STRING(name), out _handle, access, IntPtr.Zero));
            }

            public string Name { get; }

            public void Dispose()
            {
                if (_handle != IntPtr.Zero)
                {
                    SamCloseHandle(_handle);
                    _handle = IntPtr.Zero;
                }
            }

            public void SetDomainPasswordInformation(SecurityIdentifier domainSid, DOMAIN_PASSWORD_INFORMATION passwordInformation)
            {
                if (domainSid == null)
                    throw new ArgumentNullException(nameof(domainSid));

                var sid = new byte[domainSid.BinaryLength];
                domainSid.GetBinaryForm(sid, 0);

                Check(SamOpenDomain(_handle, DOMAIN_ACCESS_MASK.DOMAIN_WRITE_PASSWORD_PARAMS, sid, out IntPtr domain));
                IntPtr info = Marshal.AllocHGlobal(Marshal.SizeOf(passwordInformation));
                Marshal.StructureToPtr(passwordInformation, info, false);
                try
                {
                    Check(SamSetInformationDomain(domain, DOMAIN_INFORMATION_CLASS.DomainPasswordInformation, info));
                }
                finally
                {
                    Marshal.FreeHGlobal(info);
                    SamCloseHandle(domain);
                }
            }

            public DOMAIN_PASSWORD_INFORMATION GetDomainPasswordInformation(SecurityIdentifier domainSid)
            {
                if (domainSid == null)
                    throw new ArgumentNullException(nameof(domainSid));

                var sid = new byte[domainSid.BinaryLength];
                domainSid.GetBinaryForm(sid, 0);

                Check(SamOpenDomain(_handle, DOMAIN_ACCESS_MASK.DOMAIN_READ_PASSWORD_PARAMETERS, sid, out IntPtr domain));
                var info = IntPtr.Zero;
                try
                {
                    Check(SamQueryInformationDomain(domain, DOMAIN_INFORMATION_CLASS.DomainPasswordInformation, out info));
                    return (DOMAIN_PASSWORD_INFORMATION)Marshal.PtrToStructure(info, typeof(DOMAIN_PASSWORD_INFORMATION));
                }
                finally
                {
                    SamFreeMemory(info);
                    SamCloseHandle(domain);
                }
            }

            public SecurityIdentifier GetDomainSid(string domain)
            {
                if (domain == null)
                    throw new ArgumentNullException(nameof(domain));

                Check(SamLookupDomainInSamServer(_handle, new UNICODE_STRING(domain), out IntPtr sid));
                return new SecurityIdentifier(sid);
            }

            public IEnumerable<string> EnumerateDomains()
            {
                int cookie = 0;
                while (true)
                {
                    var status = SamEnumerateDomainsInSamServer(_handle, ref cookie, out IntPtr info, 1, out int count);
                    if (status != NTSTATUS.STATUS_SUCCESS && status != NTSTATUS.STATUS_MORE_ENTRIES)
                        Check(status);

                    if (count == 0)
                        break;

                    var us = (UNICODE_STRING)Marshal.PtrToStructure(info + IntPtr.Size, typeof(UNICODE_STRING));
                    SamFreeMemory(info);
                    yield return us.ToString();
                    us.Buffer = IntPtr.Zero; // we don't own this one
                }
            }

            private enum DOMAIN_INFORMATION_CLASS
            {
                DomainPasswordInformation = 1,
            }

            [Flags]
            public enum PASSWORD_PROPERTIES
            {
                DOMAIN_PASSWORD_COMPLEX = 0x00000001,
                DOMAIN_PASSWORD_NO_ANON_CHANGE = 0x00000002,
                DOMAIN_PASSWORD_NO_CLEAR_CHANGE = 0x00000004,
                DOMAIN_LOCKOUT_ADMINS = 0x00000008,
                DOMAIN_PASSWORD_STORE_CLEARTEXT = 0x00000010,
                DOMAIN_REFUSE_PASSWORD_CHANGE = 0x00000020,
            }

            [Flags]
            private enum DOMAIN_ACCESS_MASK
            {
                DOMAIN_READ_PASSWORD_PARAMETERS = 0x00000001,
                DOMAIN_WRITE_PASSWORD_PARAMS = 0x00000002,
                DOMAIN_READ_OTHER_PARAMETERS = 0x00000004,
                DOMAIN_WRITE_OTHER_PARAMETERS = 0x00000008,
                DOMAIN_CREATE_USER = 0x00000010,
                DOMAIN_CREATE_GROUP = 0x00000020,
                DOMAIN_CREATE_ALIAS = 0x00000040,
                DOMAIN_GET_ALIAS_MEMBERSHIP = 0x00000080,
                DOMAIN_LIST_ACCOUNTS = 0x00000100,
                DOMAIN_LOOKUP = 0x00000200,
                DOMAIN_ADMINISTER_SERVER = 0x00000400,
                DOMAIN_ALL_ACCESS = 0x000F07FF,
                DOMAIN_READ = 0x00020084,
                DOMAIN_WRITE = 0x0002047A,
                DOMAIN_EXECUTE = 0x00020301
            }

            [Flags]
            public enum SERVER_ACCESS_MASK
            {
                SAM_SERVER_CONNECT = 0x00000001,
                SAM_SERVER_SHUTDOWN = 0x00000002,
                SAM_SERVER_INITIALIZE = 0x00000004,
                SAM_SERVER_CREATE_DOMAIN = 0x00000008,
                SAM_SERVER_ENUMERATE_DOMAINS = 0x00000010,
                SAM_SERVER_LOOKUP_DOMAIN = 0x00000020,
                SAM_SERVER_ALL_ACCESS = 0x000F003F,
                SAM_SERVER_READ = 0x00020010,
                SAM_SERVER_WRITE = 0x0002000E,
                SAM_SERVER_EXECUTE = 0x00020021
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct DOMAIN_PASSWORD_INFORMATION
            {
                public short MinPasswordLength;
                public short PasswordHistoryLength;
                public PASSWORD_PROPERTIES PasswordProperties;
                private long _maxPasswordAge;
                private long _minPasswordAge;

                public TimeSpan MaxPasswordAge
                {
                    get
                    {
                        return -new TimeSpan(_maxPasswordAge);
                    }
                    set
                    {
                        _maxPasswordAge = value.Ticks;
                    }
                }

                public TimeSpan MinPasswordAge
                {
                    get
                    {
                        return -new TimeSpan(_minPasswordAge);
                    }
                    set
                    {
                        _minPasswordAge = value.Ticks;
                    }
                }
            }

            [StructLayout(LayoutKind.Sequential)]
            private class UNICODE_STRING : IDisposable
            {
                public ushort Length;
                public ushort MaximumLength;
                public IntPtr Buffer;

                public UNICODE_STRING()
                    : this(null)
                {
                }

                public UNICODE_STRING(string s)
                {
                    if (s != null)
                    {
                        Length = (ushort)(s.Length * 2);
                        MaximumLength = (ushort)(Length + 2);
                        Buffer = Marshal.StringToHGlobalUni(s);
                    }
                }

                public override string ToString() => Buffer != IntPtr.Zero ? Marshal.PtrToStringUni(Buffer) : null;

                protected virtual void Dispose(bool disposing)
                {
                    if (Buffer != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(Buffer);
                        Buffer = IntPtr.Zero;
                    }
                }

                ~UNICODE_STRING() => Dispose(false);

                public void Dispose()
                {
                    Dispose(true);
                    GC.SuppressFinalize(this);
                }
            }

            private static void Check(NTSTATUS err)
            {
                if (err == NTSTATUS.STATUS_SUCCESS)
                    return;

                throw new Win32Exception("Error " + err + " (0x" + ((int)err).ToString("X8") + ")");
            }

            private enum NTSTATUS
            {
                STATUS_SUCCESS = 0x0,
                STATUS_MORE_ENTRIES = 0x105,
                STATUS_INVALID_HANDLE = unchecked((int)0xC0000008),
                STATUS_INVALID_PARAMETER = unchecked((int)0xC000000D),
                STATUS_ACCESS_DENIED = unchecked((int)0xC0000022),
                STATUS_OBJECT_TYPE_MISMATCH = unchecked((int)0xC0000024),
                STATUS_NO_SUCH_DOMAIN = unchecked((int)0xC00000DF),
            }

            [DllImport("samlib.dll", CharSet = CharSet.Unicode)]
            private static extern NTSTATUS SamConnect(UNICODE_STRING ServerName, out IntPtr ServerHandle, SERVER_ACCESS_MASK DesiredAccess, IntPtr ObjectAttributes);

            [DllImport("samlib.dll", CharSet = CharSet.Unicode)]
            private static extern NTSTATUS SamCloseHandle(IntPtr ServerHandle);

            [DllImport("samlib.dll", CharSet = CharSet.Unicode)]
            private static extern NTSTATUS SamFreeMemory(IntPtr Handle);

            [DllImport("samlib.dll", CharSet = CharSet.Unicode)]
            private static extern NTSTATUS SamOpenDomain(IntPtr ServerHandle, DOMAIN_ACCESS_MASK DesiredAccess, byte[] DomainId, out IntPtr DomainHandle);

            [DllImport("samlib.dll", CharSet = CharSet.Unicode)]
            private static extern NTSTATUS SamLookupDomainInSamServer(IntPtr ServerHandle, UNICODE_STRING name, out IntPtr DomainId);

            [DllImport("samlib.dll", CharSet = CharSet.Unicode)]
            private static extern NTSTATUS SamQueryInformationDomain(IntPtr DomainHandle, DOMAIN_INFORMATION_CLASS DomainInformationClass, out IntPtr Buffer);

            [DllImport("samlib.dll", CharSet = CharSet.Unicode)]
            private static extern NTSTATUS SamSetInformationDomain(IntPtr DomainHandle, DOMAIN_INFORMATION_CLASS DomainInformationClass, IntPtr Buffer);

            [DllImport("samlib.dll", CharSet = CharSet.Unicode)]
            private static extern NTSTATUS SamEnumerateDomainsInSamServer(IntPtr ServerHandle, ref int EnumerationContext, out IntPtr EnumerationBuffer, int PreferedMaximumLength, out int CountReturned);
        }
        // https://stackoverflow.com/questions/31464835/how-to-programmatically-check-the-password-must-meet-complexity-requirements-g
        public static List<Dictionary<string, string>> GetPasswordPolicy()
        {
            List<Dictionary<string, string>> results = new List<Dictionary<string, string>>();
            try
            {
                using (SamServer server = new SamServer(null, SamServer.SERVER_ACCESS_MASK.SAM_SERVER_ENUMERATE_DOMAINS | SamServer.SERVER_ACCESS_MASK.SAM_SERVER_LOOKUP_DOMAIN))
                {
                    foreach (string domain in server.EnumerateDomains())
                    {
                        var sid = server.GetDomainSid(domain);
                        var pi = server.GetDomainPasswordInformation(sid);

                        results.Add(new Dictionary<string, string>()
                        {
                            { "Domain", domain },
                            { "SID", String.Format("{0}", sid) },
                            { "MaxPasswordAge", String.Format("{0}", pi.MaxPasswordAge) },
                            { "MinPasswordAge", String.Format("{0}", pi.MinPasswordAge) },
                            { "MinPasswordLength", String.Format("{0}", pi.MinPasswordLength) },
                            { "PasswordHistoryLength", String.Format("{0}", pi.PasswordHistoryLength) },
                            { "PasswordProperties", String.Format("{0}", pi.PasswordProperties) },
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(String.Format("  [X] Exception: {0}", ex));
            }
            return results;
        }
        // https://www.pinvoke.net/default.aspx/netapi32.netusermodalsget
        [DllImport("netapi32.dll", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.StdCall, SetLastError = true)]
        static extern uint NetUserModalsGet(
        string server,
        int level,
        out IntPtr BufPtr);
        public struct USER_MODALS_INFO_0
        {
            public uint usrmod0_min_passwd_len;
            public uint usrmod0_max_passwd_age;
            public uint usrmod0_min_passwd_age;
            public uint usrmod0_force_logoff;
            public uint usrmod0_password_hist_len;
        };

        public struct USER_MODALS_INFO_1
        {
            public uint usrmod1_role;
            public string usrmod1_primary;
        };

        public struct USER_MODALS_INFO_2
        {
            public string usrmod2_domain_name;
            public uint usrmod2_domain_id;
        };

        public struct USER_MODALS_INFO_3
        {
            public uint usrmod3_lockout_duration;
            public uint usrmod3_lockout_observation_window;
            public uint usrmod3_lockout_threshold;
        };
        public static Dictionary<string, string> GetLockoutPolicy()
        {
            Dictionary<string, string> results = new Dictionary<string, string>();
            try
            {
                USER_MODALS_INFO_3 objUserModalsInfo3 = new USER_MODALS_INFO_3();
                IntPtr bufPtr;
                uint lngReturn = NetUserModalsGet(@"\\" + Environment.MachineName, 3, out bufPtr);
                if (lngReturn == 0)
                {
                    objUserModalsInfo3 = (USER_MODALS_INFO_3)Marshal.PtrToStructure(bufPtr, typeof(USER_MODALS_INFO_3));
                }
                results.Add("Lockout duration", String.Format("{0}", objUserModalsInfo3.usrmod3_lockout_duration));
                results.Add("Lockout Obversation Window", String.Format("{0}", objUserModalsInfo3.usrmod3_lockout_observation_window));
                results.Add("Lockout Threshold", String.Format("{0}", objUserModalsInfo3.usrmod3_lockout_threshold));
                //NetApiBufferFree(bufPtr);
                bufPtr = IntPtr.Zero;
            }
            catch (Exception ex)
            {
                PrintUtils.ExceptionPrint(ex.Message);
            }
            return results;

        }
        public static bool IsADomainUserMemberofLocalAdmins()
        {
            //https://stackoverflow.com/questions/6318611/how-to-get-all-user-account-names-in-xp-vist-7-for-32-or-64-bit-and-any-os
            SecurityIdentifier builtinAdminSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            PrincipalContext ctx = new PrincipalContext(ContextType.Machine);
            GroupPrincipal group = GroupPrincipal.FindByIdentity(ctx, builtinAdminSid.Value);
            foreach (Principal p in group.Members)
            {
                if (p.Context.ContextType == ContextType.Domain)
                {
                    Console.WriteLine("        [X] Domain user {0} is part of the local administrator", p.Name);
                    return true;
                }
            }
            return false;
        }
        public static List<string> GetInterestingUsers()
        {
            HashSet<string> LoggedInSIDs = new HashSet<string>();

            PrincipalContext domainContext = null;
            if (Program.IsDomainJoined)
                domainContext = new PrincipalContext(ContextType.Domain);
            PrincipalContext machineContext = new PrincipalContext(ContextType.Machine);
            UserPrincipal user;

            // Get users that have logged in
            SelectQuery query = new SelectQuery("Win32_UserProfile");
            var searcher = new ManagementObjectSearcher(query);

            //https://stackoverflow.com/questions/18835134/how-to-create-windowsidentity-windowsprincipal-from-username-in-domain-user-form/32165726

            foreach (ManagementObject sid in searcher.Get())
            {
                SecurityIdentifier sidObject = new SecurityIdentifier(sid["SID"].ToString());
                if (!sidObject.IsAccountSid())
                    continue;
                // Is domain user?
                if (domainContext != null)
                {
                    user = UserPrincipal.FindByIdentity(domainContext, IdentityType.Sid, sid["SID"].ToString());
                    if (user != null)
                    {
                        LoggedInSIDs.Add(user.Sid.Value);
                        var userIsMemberOf = user.GetAuthorizationGroups().Where(o => o.Guid != null).Select(o => o.Sid.ToString());
                        foreach (string groupSid in userIsMemberOf)
                            LoggedInSIDs.Add(groupSid);
                    }
                }

                // Is machine user?
                user = UserPrincipal.FindByIdentity(machineContext, IdentityType.Sid, sid["SID"].ToString());
                if (user != null)
                {
                    LoggedInSIDs.Add(user.Sid.Value);
                    var userIsMemberOf = user.GetAuthorizationGroups().Select(o => o.Sid.Value);
                    foreach (string groupSid in userIsMemberOf)
                        LoggedInSIDs.Add(groupSid);
                }
            }
            return LoggedInSIDs.ToList();
        }
        /*
        public static void CanNonAdminUserWriteToFile(string FilePath)
        {
            bool result = false;

            // Get File Permissions
            //AuthorizationRuleCollection rules = Utils.GetFilePermissions(FilePath);

            PrincipalContext ctx = new PrincipalContext(ContextType.Machine);

            // Get Local Admin Group
            SecurityIdentifier builtinAdminSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            GroupPrincipal group = GroupPrincipal.FindByIdentity(ctx, builtinAdminSid.Value);

            // This doesn't work. No idea why
            foreach (FileSystemAccessRule rule in rules)
            {
                Console.WriteLine(rule.IdentityReference);
                Console.WriteLine(rule.FileSystemRights);
                Console.WriteLine(rule.AccessControlType);
                FileSystemRights FsRights = Utils.FileSystemRightsCorrector(rule.FileSystemRights);
                Console.WriteLine(FsRights);
                // Using flags to check whether the rules grants write rights
                if (0== (FsRights & (FileSystemRights.FullControl | FileSystemRights.Modify)))
                {
                    continue;
                }
                UserPrincipal user = UserPrincipal.FindByIdentity(ctx, IdentityType.Sid, rule.IdentityReference.Value);
                if (!user.IsMemberOf(group))
                {
                    Console.WriteLine(user.DistinguishedName);
                }
            }
        }
        */
    }
}
