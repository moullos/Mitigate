using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.DirectoryServices.AccountManagement;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Principal;
using LSA_HANDLE = System.IntPtr;

namespace Mitigate.Utils
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
        public static Dictionary<string, bool> CheckPasswordPolicyAgainstCIS()
        {
            using (SamServer server = new SamServer(null, SamServer.SERVER_ACCESS_MASK.SAM_SERVER_ENUMERATE_DOMAINS | SamServer.SERVER_ACCESS_MASK.SAM_SERVER_LOOKUP_DOMAIN))
            {
                var AllDomains = server.EnumerateDomains();
                var HostName = Environment.MachineName.ToString();
                SecurityIdentifier sid;
                SamServer.DOMAIN_PASSWORD_INFORMATION pi;
                sid = server.GetDomainSid(HostName);
                pi = server.GetDomainPasswordInformation(sid);
                return new Dictionary<string, bool>()
                    {
                        { "Max Password Age <= 60", pi.MaxPasswordAge.Days <= 60 & pi.MaxPasswordAge.Days != 0 },
                        { "Password History Length >= 24", pi.PasswordHistoryLength >=24},
                        { "Password Complexity Enforced", pi.PasswordProperties.HasFlag(SamServer.PASSWORD_PROPERTIES.DOMAIN_PASSWORD_COMPLEX) },
                        { "Min Password Age >=1", pi.MinPasswordAge.Days >= 1},
                        { "Min Password Length >= 14" , pi.MinPasswordLength >=14 },
                        { "Not Stored in Cleartext", !pi.PasswordProperties.HasFlag(SamServer.PASSWORD_PROPERTIES.DOMAIN_PASSWORD_STORE_CLEARTEXT) }
                    };
            }
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
        public static Dictionary<string, string> GetPasswordComplexityPolicy()
        {
            /*
            public uint usrmod0_min_passwd_len;
            public uint usrmod0_max_passwd_age;
            public uint usrmod0_min_passwd_age;
            public uint usrmod0_force_logoff;
            public uint usrmod0_password_hist_len;
            */
            Dictionary<string, string> results = new Dictionary<string, string>();
            try
            {
                USER_MODALS_INFO_0 objUserModalsInfo0 = new USER_MODALS_INFO_0();
                IntPtr bufPtr;
                uint lngReturn = NetUserModalsGet(@"\\" + Environment.MachineName, 0, out bufPtr);
                if (lngReturn == 0)
                {
                    objUserModalsInfo0 = (USER_MODALS_INFO_0)Marshal.PtrToStructure(bufPtr, typeof(USER_MODALS_INFO_0));
                }
                results.Add("Minimum Password Length", objUserModalsInfo0.usrmod0_min_passwd_len.ToString());
                results.Add("Max Password Age", objUserModalsInfo0.usrmod0_max_passwd_age.ToString());
                results.Add("Min Password Age", objUserModalsInfo0.usrmod0_min_passwd_age.ToString());
                results.Add("Force Logoff", objUserModalsInfo0.usrmod0_force_logoff.ToString());
                results.Add("Password History Length", objUserModalsInfo0.usrmod0_password_hist_len.ToString());

                //NetApiBufferFree(bufPtr);
                bufPtr = IntPtr.Zero;
            }
            catch (Exception ex)
            {
                PrintUtils.Debug(ex.StackTrace);
            }
            return results;
        }
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
                PrintUtils.Debug(ex.StackTrace);
            }
            return results;
        }
        public static bool IsLockOutPolicySet()
        {
            var policy = GetLockoutPolicy();
            try
            {
                if (int.Parse(policy["Lockout Threshold"]) > 1)
                {
                    return true;
                }
            }
            catch { }
            return false;
        }
        public static bool IsADomainUserMemberofLocalAdmins()
        {
            // https://stackoverflow.com/questions/6318611/how-to-get-all-user-account-names-in-xp-vist-7-for-32-or-64-bit-and-any-os
            SecurityIdentifier builtinAdminSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            PrincipalContext ctx = new PrincipalContext(ContextType.Machine);
            GroupPrincipal group = GroupPrincipal.FindByIdentity(ctx, builtinAdminSid.Value);
            foreach (Principal p in group.Members)
            {
                if (p.Context.ContextType == ContextType.Domain)
                {
                    return true;
                }
            }
            return false;
        }

        /// <summary>
        /// This methods checks whether any of the specified SIDs belong to an administrator or are an administrator group
        /// </summary>
        /// <param name="SIDs"></param>
        /// <returns></returns>
        public static bool IsAdmin(List<string> SIDs)
        {
            SecurityIdentifier builtinAdminSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);

            // In case SID belongs to a group we can directly compare the SID values
            foreach (var SID in SIDs)
            {

                if (builtinAdminSid.ToString().Equals(SID))
                    return true;
            }

            // If it not we need to compare with the members of the builtin admin group
            PrincipalContext ctx = new PrincipalContext(ContextType.Machine);
            GroupPrincipal group = GroupPrincipal.FindByIdentity(ctx, builtinAdminSid.Value);
            foreach (Principal p in group.Members)
            {
                if (SIDs.Contains(p.Sid.ToString()))
                {
                    return true;
                }
            }
            return false;
        }

        public static bool IsDomainUser(UserPrincipal userToCheck)
        {
            //userToCheck.Context.Name;
            return true;
        }

        public static bool IsItRunningAsAdmin()
        {
            var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
        /// <summary>
        /// Obtains a list of users SID that have previously logged into the device
        /// </summary>
        /// <returns>List of user SIDs</returns>
        public static UserPrincipal GetLastLoggedInUser()
        {
            PrincipalContext domainContext = null;
            if (Program.IsDomainJoined)
                domainContext = new PrincipalContext(ContextType.Domain);
            PrincipalContext machineContext = new PrincipalContext(ContextType.Machine);
            UserPrincipal user;

            // Get users that have logged in
            SelectQuery query = new SelectQuery("Win32_UserProfile");
            var searcher = new ManagementObjectSearcher(query);
            var results = searcher.Get();
            var OrderedResults = results.Cast<ManagementObject>().OrderBy(o => o["LastUseTime"]);

            //https://stackoverflow.com/questions/18835134/how-to-create-windowsidentity-windowsprincipal-from-username-in-domain-user-form/32165726
            foreach (ManagementObject sid in OrderedResults)
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
                        return user;
                    }
                }

                // Is machine user?
                user = UserPrincipal.FindByIdentity(machineContext, IdentityType.Sid, sid["SID"].ToString());
                if (user != null)
                {
                    return user;
                }
            }
            throw new Exception("No previously logged users found");
        }
        public static List<string> GetGroups(UserPrincipal user)
        {
            HashSet<string> AllSIDs = new HashSet<string>();

            AllSIDs.Add(user.Sid.Value);
            var userIsMemberOf = user.GetAuthorizationGroups().Select(o => o.Sid.Value);
            AllSIDs.UnionWith(userIsMemberOf);
            return AllSIDs.ToList();
        }

        public static UserPrincipal GetUser(string UserName)
        {
            PrincipalContext domainContext = null;
            if (Program.IsDomainJoined)
                domainContext = new PrincipalContext(ContextType.Domain);
            PrincipalContext machineContext = new PrincipalContext(ContextType.Machine);
            UserPrincipal user;

            if (domainContext != null)
            {
                user = UserPrincipal.FindByIdentity(domainContext, IdentityType.SamAccountName, UserName);
                if (user != null)
                {
                    return user;
                }
            }
            user = UserPrincipal.FindByIdentity(machineContext, IdentityType.SamAccountName, UserName);
            if (user != null)
            {
                return user;
            }
            throw new Exception($"User '{UserName}' was not found.");
        }



        public static List<string> GetUsersWithPrivilege(string Privilege)
        {
            using (var LSA = new LsaWrapper())
            {
                return LSA.ReadPrivilege(Privilege);
            }
        }

        /*-------------------------------------------------------------------------------------------------------*/
        /* LSA Utils from https://www.centrel-solutions.com/support/tools.aspx?feature=auditrights (No license)  */
        /*-------------------------------------------------------------------------------------------------------*/
        [StructLayout(LayoutKind.Sequential)]
        struct LSA_OBJECT_ATTRIBUTES
        {
            internal int Length;
            internal IntPtr RootDirectory;
            internal IntPtr ObjectName;
            internal int Attributes;
            internal IntPtr SecurityDescriptor;
            internal IntPtr SecurityQualityOfService;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct LSA_UNICODE_STRING
        {
            internal ushort Length;
            internal ushort MaximumLength;
            [MarshalAs(UnmanagedType.LPWStr)]
            internal string Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct LSA_ENUMERATION_INFORMATION
        {
            internal IntPtr PSid;
        }


        /// <summary>
        /// Provides direct Win32 calls to the security related functions
        /// </summary>
        sealed class Win32Sec
        {

            [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true), SuppressUnmanagedCodeSecurityAttribute]
            internal static extern uint LsaOpenPolicy(
            LSA_UNICODE_STRING[] SystemName,
            ref LSA_OBJECT_ATTRIBUTES ObjectAttributes,
            int AccessMask,
            out IntPtr PolicyHandle
            );

            [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true), SuppressUnmanagedCodeSecurityAttribute]
            internal static extern uint LsaEnumerateAccountsWithUserRight(
            LSA_HANDLE PolicyHandle,
            LSA_UNICODE_STRING[] UserRights,
            out IntPtr EnumerationBuffer,
            out int CountReturned
            );

            [DllImport("advapi32")]
            internal static extern int LsaNtStatusToWinError(int NTSTATUS);

            [DllImport("advapi32")]
            internal static extern int LsaClose(IntPtr PolicyHandle);

            [DllImport("advapi32")]
            internal static extern int LsaFreeMemory(IntPtr Buffer);

        }
        /// <summary>
        /// Provides a wrapper to the LSA classes
        /// </summary>
        public class LsaWrapper : IDisposable
        {
            enum Access : int
            {
                POLICY_READ = 0x20006,
                POLICY_ALL_ACCESS = 0x00F0FFF,
                POLICY_EXECUTE = 0X20801,
                POLICY_WRITE = 0X207F8
            }
            const uint STATUS_ACCESS_DENIED = 0xc0000022;
            const uint STATUS_INSUFFICIENT_RESOURCES = 0xc000009a;
            const uint STATUS_NO_MEMORY = 0xc0000017;
            const uint STATUS_NO_MORE_ENTRIES = 0xc000001A;
            const uint ERROR_NO_MORE_ITEMS = 2147483674;
            const uint ERROR_PRIVILEGE_DOES_NOT_EXIST = 3221225568;
            IntPtr lsaHandle;

            /// <summary>
            /// Creates a new LSA wrapper for the local machine
            /// </summary>
            public LsaWrapper()
                : this(Environment.MachineName)
            {

            }

            /// <summary>
            /// Creates a new LSA wrapper for the specified MachineName
            /// </summary>
            /// <param name="MachineName">The name of the machine that should be connected to</param>
            public LsaWrapper(string MachineName)
            {
                LSA_OBJECT_ATTRIBUTES lsaAttr;
                lsaAttr.RootDirectory = IntPtr.Zero;
                lsaAttr.ObjectName = IntPtr.Zero;
                lsaAttr.Attributes = 0;
                lsaAttr.SecurityDescriptor = IntPtr.Zero;
                lsaAttr.SecurityQualityOfService = IntPtr.Zero;
                lsaAttr.Length = Marshal.SizeOf(typeof(LSA_OBJECT_ATTRIBUTES));
                lsaHandle = IntPtr.Zero;
                LSA_UNICODE_STRING[] system = null;
                if (MachineName != null)
                {
                    system = new LSA_UNICODE_STRING[1];
                    system[0] = InitLsaString(MachineName);
                }
                uint ret = Win32Sec.LsaOpenPolicy(system, ref lsaAttr, (int)Access.POLICY_ALL_ACCESS, out lsaHandle);
                TestReturnValue(ret);
            }


            /// <summary>
            /// Reads the user accounts which have the specific privilege
            /// </summary>
            /// <param name="Privilege">The name of the privilege for which the accounts with this right should be enumerated</param>
            public List<String> ReadPrivilege(string Privilege)
            {
                LSA_UNICODE_STRING[] privileges = new LSA_UNICODE_STRING[1];
                privileges[0] = InitLsaString(Privilege);
                IntPtr buffer;
                int count = 0;
                uint ret = Win32Sec.LsaEnumerateAccountsWithUserRight(lsaHandle, privileges, out buffer, out count);
                List<String> Accounts = new List<String>();

                if (ret == 0)
                {
                    LSA_ENUMERATION_INFORMATION[] LsaInfo = new LSA_ENUMERATION_INFORMATION[count];
                    for (int i = 0, elemOffs = (int)buffer; i < count; i++)
                    {
                        LsaInfo[i] = (LSA_ENUMERATION_INFORMATION)Marshal.PtrToStructure((IntPtr)elemOffs, typeof(LSA_ENUMERATION_INFORMATION));
                        elemOffs += Marshal.SizeOf(typeof(LSA_ENUMERATION_INFORMATION));
                        SecurityIdentifier SID = new SecurityIdentifier(LsaInfo[i].PSid);
                        Accounts.Add(SID.ToString());
                    }
                    return Accounts;
                }
                TestReturnValue(ret);
                return Accounts;
            }


            /// <summary>
            /// Resolves the SID into it's account name. If the SID cannot be resolved the SDDL for the SID (for example "S-1-5-21-3708151440-578689555-182056876-1009") is returned.
            /// </summary>
            /// <param name="SID">The Security Identifier to resolve to an account name</param>
            /// <returns>An account name for example "NT AUTHORITY\LOCAL SERVICE" or SID in SDDL form</returns>
            private String ResolveAccountName(SecurityIdentifier SID)
            {
                try { return SID.Translate(typeof(NTAccount)).Value; }
                catch (Exception) { return SID.ToString(); }
            }


            /// <summary>
            /// Tests the return value from Win32 method calls
            /// </summary>
            /// <param name="ReturnValue">The return value from the a Win32 method call</param>
            private void TestReturnValue(uint ReturnValue)
            {
                if (ReturnValue == 0) return;
                if (ReturnValue == ERROR_PRIVILEGE_DOES_NOT_EXIST) { return; }
                if (ReturnValue == ERROR_NO_MORE_ITEMS) { return; }
                if (ReturnValue == STATUS_ACCESS_DENIED) { throw new UnauthorizedAccessException(); }
                if ((ReturnValue == STATUS_INSUFFICIENT_RESOURCES) || (ReturnValue == STATUS_NO_MEMORY)) { throw new OutOfMemoryException(); }
                throw new Win32Exception(Win32Sec.LsaNtStatusToWinError((int)ReturnValue));
            }


            /// <summary>
            /// Disposes of this LSA wrapper
            /// </summary>
            public void Dispose()
            {
                if (lsaHandle != IntPtr.Zero)
                {
                    Win32Sec.LsaClose(lsaHandle);
                    lsaHandle = IntPtr.Zero;
                }
                GC.SuppressFinalize(this);
            }


            /// <summary>
            /// Occurs on destruction of the LSA Wrapper
            /// </summary>
            ~LsaWrapper()
            {
                Dispose();
            }


            /// <summary>
            /// Converts the specified string to an LSA string value
            /// </summary>
            /// <param name="Value"></param>
            static LSA_UNICODE_STRING InitLsaString(string Value)
            {
                if (Value.Length > 0x7ffe) throw new ArgumentException("String too long");
                LSA_UNICODE_STRING lus = new LSA_UNICODE_STRING();
                lus.Buffer = Value;
                lus.Length = (ushort)(Value.Length * sizeof(char));
                lus.MaximumLength = (ushort)(lus.Length + sizeof(char));
                return lus;
            }
        }
    }
}
