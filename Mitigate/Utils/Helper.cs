using Microsoft.Win32;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Data;
using System.Diagnostics;
using System.DirectoryServices.AccountManagement;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.ServiceProcess;

namespace Mitigate.Utils
{
    class Helper
    {
        public static Tuple<string, string, int> Base64EncodedCommand(string psCommand)
        {
            ;
            var psCommandBytes = System.Text.Encoding.Unicode.GetBytes(psCommand);
            var psCommandBase64 = Convert.ToBase64String(psCommandBytes);

            var process = new Process();
            process.StartInfo.FileName = "powershell.exe";
            process.StartInfo.Arguments = $"-NoProfile -ExecutionPolicy unrestricted -EncodedCommand {psCommandBase64}";
            process.StartInfo.UseShellExecute = false;
            process.StartInfo.RedirectStandardOutput = true;
            process.StartInfo.RedirectStandardError = true;
            process.Start();
            //* Read the output (or the error)
            string output = process.StandardOutput.ReadToEnd();
            string err = process.StandardError.ReadToEnd();
            process.WaitForExit();

            return new Tuple<string, string, int>(output, err, process.ExitCode);
        }

        public static bool CheckForRestrictions(string ExecPath, string UserName)
        {
            if (String.IsNullOrEmpty(ExecPath)) throw new ArgumentNullException();
            if (String.IsNullOrEmpty(UserName)) throw new ArgumentNullException();

            if (!File.Exists(ExecPath))
            {
                PrintUtils.Debug($"File '{ExecPath}' was not found");
                return true;
            }
            // Check 1: AppLocker
            if (AppLockerUtils.IsAppLockerEnabled())
            {
                if (!AppLockerUtils.IsAppLockerRunning())
                {
                    throw new Exception("AppLocker SVC is not running");
                }
                if (CheckApplockerPolicyforDenied(ExecPath, UserName))
                {
                    return true;
                }
            }
            else if (SoftwareRestrictionUtils.IsEnabled())
            {
                // SRPs are only applied if AppLocker is not active
                return SoftwareRestrictionUtils.IsBlocked(ExecPath);
            }
            return false;
        }

        private static bool CheckApplockerPolicyforDenied(string ExecPath, string UserName)
        {
            // Will possible trigger AV
            string CommandMask = @"Get-AppLockerPolicy -Effective | Test-AppLockerPolicy -Path '{0}' -User '{1}' -Filter Denied,DeniedByDefault";
            string Command = String.Format(CommandMask, ExecPath, UserName);
            var CommandResult = Base64EncodedCommand(Command);
            var output = CommandResult.Item1;
            var err = CommandResult.Item2;
            var ExitCode = CommandResult.Item3;
            if (ExitCode != 0)
            {
                throw new Exception($"CheckApplockerPolicyforDenied: Path={ExecPath} Username={UserName}");
            }
            return !string.IsNullOrEmpty(output);
        }

        // All credit for the Registry Utils goes to winPeas
        ///////////////////////////////////////////
        /// Interf. for Keys and Values in Reg. ///
        ///////////////////////////////////////////
        public static string GetRegValue(string hive, string path, string value)
        {
            // returns a single registry value under the specified path in the specified hive (HKLM/HKCU)
            string regKeyValue = "";
            if (hive == "HKCU")
            {
                var regKey = Registry.CurrentUser.OpenSubKey(path);
                if (regKey != null)
                {
                    regKeyValue = String.Format("{0}", regKey.GetValue(value));
                }
                return regKeyValue;
            }
            else if (hive == "HKU")
            {
                var regKey = Registry.Users.OpenSubKey(path);
                if (regKey != null)
                {
                    regKeyValue = String.Format("{0}", regKey.GetValue(value));
                }
                return regKeyValue;
            }
            else
            {
                var regKey = Registry.LocalMachine.OpenSubKey(path);
                if (regKey != null)
                {
                    regKeyValue = String.Format("{0}", regKey.GetValue(value));
                }
                return regKeyValue;
            }
        }

        public static Dictionary<string, object> GetRegValues(string hive, string path)
        {
            // returns all registry values under the specified path in the specified hive (HKLM/HKCU)
            Dictionary<string, object> keyValuePairs = null;
            try
            {
                if (hive == "HKCU")
                {
                    using (var regKeyValues = Registry.CurrentUser.OpenSubKey(path))
                    {
                        if (regKeyValues != null)
                        {
                            var valueNames = regKeyValues.GetValueNames();
                            keyValuePairs = valueNames.ToDictionary(name => name, regKeyValues.GetValue);
                        }
                    }
                }
                else if (hive == "HKU")
                {
                    using (var regKeyValues = Registry.Users.OpenSubKey(path))
                    {
                        if (regKeyValues != null)
                        {
                            var valueNames = regKeyValues.GetValueNames();
                            keyValuePairs = valueNames.ToDictionary(name => name, regKeyValues.GetValue);
                        }
                    }
                }
                else
                {
                    using (var regKeyValues = Registry.LocalMachine.OpenSubKey(path))
                    {
                        if (regKeyValues != null)
                        {
                            var valueNames = regKeyValues.GetValueNames();
                            keyValuePairs = valueNames.ToDictionary(name => name, regKeyValues.GetValue);
                        }
                    }
                }
                return keyValuePairs;
            }
            catch
            {
                return null;
            }
        }

        public static byte[] GetRegValueBytes(string hive, string path, string value)
        {
            // returns a byte array of single registry value under the specified path in the specified hive (HKLM/HKCU)
            byte[] regKeyValue = null;
            if (hive == "HKCU")
            {
                var regKey = Registry.CurrentUser.OpenSubKey(path);
                if (regKey != null)
                {
                    regKeyValue = (byte[])regKey.GetValue(value);
                }
                return regKeyValue;
            }
            else if (hive == "HKU")
            {
                var regKey = Registry.Users.OpenSubKey(path);
                if (regKey != null)
                {
                    regKeyValue = (byte[])regKey.GetValue(value);
                }
                return regKeyValue;
            }
            else
            {
                var regKey = Registry.LocalMachine.OpenSubKey(path);
                if (regKey != null)
                {
                    regKeyValue = (byte[])regKey.GetValue(value);
                }
                return regKeyValue;
            }
        }

        public static string[] GetRegSubkeys(string hive, string path)
        {
            // returns an array of the subkeys names under the specified path in the specified hive (HKLM/HKCU/HKU)
            try
            {
                Microsoft.Win32.RegistryKey myKey = null;
                if (hive == "HKLM")
                {
                    myKey = Registry.LocalMachine.OpenSubKey(path);
                }
                else if (hive == "HKU")
                {
                    myKey = Registry.Users.OpenSubKey(path);
                }
                else
                {
                    myKey = Registry.CurrentUser.OpenSubKey(path);
                }
                String[] subkeyNames = myKey.GetSubKeyNames();
                return myKey.GetSubKeyNames();
            }
            catch (Exception)
            {
                PrintUtils.Debug(String.Format(@"Registry {0}\{1} was not found", hive, path));
                return new string[0];
            }
        }
        public static bool RegExists(string hive, string path)
        {
            Microsoft.Win32.RegistryKey myKey = null;
            if (hive == "HKLM")
            {
                myKey = Registry.LocalMachine.OpenSubKey(path);
            }
            else if (hive == "HKU")
            {
                myKey = Registry.Users.OpenSubKey(path);
            }
            else
            {
                myKey = Registry.CurrentUser.OpenSubKey(path);
            }
            if (myKey is null)
                return false;
            return true;
        }
        // Not a winpeas method
        public static bool RegExists(string hive, string path, string value)
        {
            Microsoft.Win32.RegistryKey myKey = null;
            if (hive == "HKLM")
            {
                myKey = Registry.LocalMachine.OpenSubKey(path);
            }
            else if (hive == "HKU")
            {
                myKey = Registry.Users.OpenSubKey(path);
            }
            else
            {
                myKey = Registry.CurrentUser.OpenSubKey(path);
            }
            if (myKey is null)
                return false;
            object RegValue = myKey.GetValue(value);
            if (RegValue is null)
                return false;
            return true;
        }

        /// <summary>
        /// Checks whether any of the supplied SIDs has write access to the specified registry
        /// </summary>
        /// <param name="hive">Registry Hive</param>
        /// <param name="path">Registry Path</param>
        /// <param name="SIDs">List of SIDs to check</param>
        /// <returns>Boolean</returns>
        public static bool RegWritePermissions(string hive, string path, List<string> SIDs)
        {
            // TODO: TEST THIS
            Dictionary<string, bool> results = new Dictionary<string, bool>();
            Microsoft.Win32.RegistryKey myKey = null;
            if (hive == "HKLM")
            {
                myKey = Registry.LocalMachine.OpenSubKey(path);
            }
            else if (hive == "HKU")
            {
                myKey = Registry.Users.OpenSubKey(path);
            }
            else
            {
                myKey = Registry.CurrentUser.OpenSubKey(path);
            }
            var security = myKey.GetAccessControl();
            var SddlString = security.GetSecurityDescriptorSddlForm(AccessControlSections.All);
            var DecodedSDDL = Helper.PermissionsDecoder.DecodeSddlString<RegistryRights>(SddlString);
            return DecodedSDDL.RegistryWriteAccess(SIDs);
        }

        /// <summary>
        /// Checks is any of the supplied SIDs has write access to the specified file path
        /// </summary>
        /// <param name="FilePath">The relevant filepath</param>
        /// <param name="SIDs">List of SIDs to check</param>
        /// <returns>True if write files exist</returns>

        public static bool FileWritePermissions(string FilePath, List<string> SIDs)
        {
            FileSystemSecurity security;
            if (File.Exists(FilePath))
            {
                FileInfo fInfo = new FileInfo(FilePath);
                security = fInfo.GetAccessControl();
            }
            else
            {
                var DirectoryPath = Path.GetDirectoryName(FilePath);
                return DirectoryRightPermissions(DirectoryPath, SIDs);
            }
            var SDDLString = security.GetSecurityDescriptorSddlForm(AccessControlSections.All);
            var DecodedSDDL = Helper.PermissionsDecoder.DecodeSddlString<FileSystemRights>(SDDLString);
            return DecodedSDDL.FileWriteAccess(SIDs);

        }

        public static bool DirectoryRightPermissions(string DirectoryPath, List<string> SIDs)
        {
            DirectorySecurity security;
            //If the file does not exist check the directory rights
            DirectoryInfo dinfo = new DirectoryInfo(DirectoryPath);
            security = dinfo.GetAccessControl();
            var SDDLString = security.GetSecurityDescriptorSddlForm(AccessControlSections.All);
            var DecodedSDDL = Helper.PermissionsDecoder.DecodeSddlString<FileSystemRights>(SDDLString);
            return DecodedSDDL.DirectoryWriteAccess(SIDs);

        }

        public static string SidToAccountName(SecurityIdentifier sid)
        {
            try
            {
                return (sid.IsValidTargetType(typeof(NTAccount)))
                     ? ((NTAccount)sid.Translate(typeof(NTAccount))).Value
                     : sid.Value;
            }
            catch
            {
                return sid.Value;
            }
        }

        public static Dictionary<string, string> GetServiceConfig(string ServiceName)
        {
            Dictionary<string, string> results = new Dictionary<string, string>();
            // Unfortunately the ServiceController class does not provide the startUpType on this version of .NET
            // So we pull it directly from the register

            var RegPath = $@"SYSTEM\CurrentControlSet\Services\{ServiceName}";
            var RegName = @"Start";

            string StartUpTypeValue = Helper.GetRegValue("HKLM", RegPath, RegName);

            results["StartUpType"] = StartType2String(StartUpTypeValue);

            return results;
        }

        public static bool IsServiceRunning(string ServiceName)
        {
            ServiceController sc = new ServiceController(ServiceName);
            var Running = sc.Status.Equals(ServiceControllerStatus.Running);
            return Running;
        }


        private static string StartType2String(string StartUpTypeValue)
        {
            string startupType = string.Empty;

            switch (StartUpTypeValue)
            {
                case "0":
                    startupType = "BOOT";
                    break;

                case "1":
                    startupType = "SYSTEM";
                    break;

                case "2":
                    startupType = "AUTOMATIC";
                    break;

                case "3":
                    startupType = "MANUAL";
                    break;

                case "4":
                    startupType = "DISABLED";
                    break;

                default:
                    startupType = "UNKNOWN";
                    break;

            }
            return startupType;
        }
        /// <summary>
        /// UTILS TO HANDLE PERMISSIONS
        /// </summary>
        [Flags]
        public enum WMIPermissionsMask : uint
        {
            WMI_ENABLE_ACCOUNT = 0x00000001,
            WMI_EXECUTE_METHODS = 0x00000002,
            WMI_FULL_WRITE = 0x00000004,
            WMI_PARTIAL_WRITE = 0x00000008,
            WMI_PROVIDER_WRITE = 0x00000010,
            WMI_REMOTE_ENABLE = 0x00000020,
            FILE_DELETE_CHILD = 0x00000040,
            FILE_READ_ATTRIBUTES = 0x00000080,
            FILE_WRITE_ATTRIBUTES = 0x00000100,
            DELETE = 0x00010000,
            READ_CONTROL = 0x00020000,
            WRITE_DAC = 0x00040000,
            WRITE_OWNER = 0x00080000,
            SYNCHRONIZE = 0x00100000,
            ACCESS_SYSTEM_SECURITY = 0x01000000,
            MAXIMUM_ALLOWED = 0x02000000,
            GENERIC_ALL = 0x10000000,
            GENERIC_EXECUTE = 0x20000000,
            GENERIC_WRITE = 0x40000000,
            GENERIC_READ = 0x80000000
        }

        [Flags]
        public enum COMPermissionsMask : uint
        {
            COM_RIGHTS_EXECUTE = 1,
            COM_RIGHTS_EXECUTE_LOCAL = 2,
            COM_RIGHTS_EXECUTE_REMOTE = 4,
            COM_RIGHTS_ACTIVATE_LOCAL = 8,
            COM_RIGHTS_ACTIVATE_REMOTE = 16,
            GENERIC_ALL = 0x10000000,
            GENERIC_EXECUTE = 0x20000000,
            GENERIC_WRITE = 0x40000000,
            GENERIC_READ = 0x80000000
        }

        // Source: 
        //https://docs.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights
        //https://devblogs.microsoft.com/oldnewthing/20170310-00/?p=95705
        [Flags]
        public enum ServiceManagerPermissionsMask : uint
        {

            SC_MANAGER_CONNECT = 0x00000001,
            SC_MANAGER_CREATE_SERVICE = 0x00000002,
            SC_MANAGER_ENUMERATE_SERVICE = 0x00000004,
            SC_MANAGER_LOCK = 0x0000008,
            SC_MANAGER_QUERY_LOCK_STATUS = 0x00000010,
            SC_MANAGER_MODIFY_BOOT_CONFIG = 0x00000020,
            SC_MANAGER_ALL_ACCESS = 0x000F003F,
            STANDARD_RIGHTS_READ = 0x00020000,
            STANDARD_RIGHTS_WRITE = 0x00020000,
            STANDARD_RIGHTS_EXECUTE = 0x00020000,
            GENERIC_READ = STANDARD_RIGHTS_READ & SC_MANAGER_ENUMERATE_SERVICE & SC_MANAGER_QUERY_LOCK_STATUS,
            GENERIC_EXECUTE = STANDARD_RIGHTS_EXECUTE & SC_MANAGER_CONNECT & SC_MANAGER_LOCK,
            GENERIC_WRITE = STANDARD_RIGHTS_WRITE & SC_MANAGER_CREATE_SERVICE & SC_MANAGER_MODIFY_BOOT_CONFIG,
            GENERIC_ALL = SC_MANAGER_ALL_ACCESS
        }
        [Flags]
        public enum ServicePermissionsMask : uint
        {
            QueryConfig = 1,
            ChangeConfig = 2,
            QueryStatus = 4,
            EnumerateDependents = 8,
            Start = 16,
            Stop = 32,
            PauseContinue = 64,
            Interrogate = 128,
            UserDefinedControl = 256,
            Delete = 65536,
            ReadControl = 131072,
            WriteDac = 262144,
            WriteOwner = 524288,
            Synchronize = 1048576,
            AccessSystemSecurity = 16777216,
            GenericAll = 268435456,
            GenericExecute = 536870912,
            GenericWrite = 1073741824,
            GenericRead = 2147483648
        }
        public class SDDL
        {
            public SDDL()
            {
                SACL = new List<ACE>();
                DACL = new List<ACE>();
            }
            public string Owner { get; set; }
            public string Group { get; set; }
            public List<ACE> SACL { get; set; }
            public List<ACE> DACL { get; set; }

            public bool RegistryWriteAccess(List<string> SIDs)
            {
                var SIDPermissions = DACL.Where(o => SIDs.Contains(o.Trustee) && o.AccessType == "AccessAllowed")
                                      .Select(o => o.Permissions);
                return SIDPermissions.Any(o => o.Contains("FullControl") ||
                                               o.Contains("SetValue") ||
                                                o.Contains("WriteKey")
                                          );
            }
            public bool FileWriteAccess(List<string> SIDs)
            {
                var SIDPermissions = DACL.Where(o => SIDs.Contains(o.Trustee) && o.AccessType == "AccessAllowed")
                      .Select(o => o.Permissions);
                return SIDPermissions.Any(
                                o =>
                                o.Contains("AllAccess") ||
                                o.Contains("GenericAll") ||
                                o.Contains("TakeOwnership") ||
                                o.Contains("GenericWrite") ||
                                o.Contains("WriteData") ||
                                o.Contains("Modify") ||
                                o.Contains("Write") ||
                                o.Contains("ChangePermissions") ||
                                o.Contains("FullControl")
                                );
            }
            public bool DirectoryWriteAccess(List<string> SIDs)
            {
                var SIDPermissions = DACL.Where(o => SIDs.Contains(o.Trustee) && o.AccessType == "AccessAllowed")
                      .Select(o => o.Permissions);
                return SIDPermissions.Any(
                o =>
                o.Contains("AllAccess") ||
                o.Contains("GenericAll") ||
                o.Contains("TakeOwnership") ||
                o.Contains("GenericWrite") ||
                o.Contains("WriteData") ||
                o.Contains("Modify") ||
                o.Contains("Write") ||
                o.Contains("ChangePermissions") ||
                o.Contains("FullControl")
                );
            }
            public bool COMFullAccess(List<string> SIDs)
            {
                var SIDPermissions = DACL.Where(o => SIDs.Contains(o.Trustee) && o.AccessType == "AccessAllowed")
                      .Select(o => o.Permissions);
                return SIDPermissions.Any(
                o =>
                o.Contains("AllAccess") ||
                o.Contains("GenericAll") ||
                o.Contains("TakeOwnership") ||
                o.Contains("GenericWrite") ||
                o.Contains("WriteData") ||
                o.Contains("Modify") ||
                o.Contains("Write") ||
                o.Contains("ChangePermissions") ||
                o.Contains("FullControl")
                );
            }
        }
        public class ACE
        {
            public ACE()
            {
                Permissions = new List<string>();
            }

            public string Trustee { get; set; }
            public string AuditRights { get; set; }
            public string AccessType { get; set; }
            public List<string> Permissions { get; set; }
        }

        // Inspiration from https://stackoverflow.com/questions/7724110/convert-sddl-to-readable-text-in-net
        public static class PermissionsDecoder
        {
            private static readonly ConcurrentDictionary<Type, Dictionary<uint, string>> _rights
                = new ConcurrentDictionary<Type, Dictionary<uint, string>>();

            public static SDDL DecodeSddlString<TRightsEnum>(string sddl) where TRightsEnum : struct
            {
                var rightsEnumType = typeof(TRightsEnum);
                if (!rightsEnumType.IsEnum ||
                    Marshal.SizeOf(Enum.GetUnderlyingType(rightsEnumType)) != 4 ||
                    !rightsEnumType.GetCustomAttributes(typeof(FlagsAttribute), true).Any())
                {
                    throw new ArgumentException("TRightsEnum must be a 32-bit integer System.Enum with Flags attribute", "TRightsEnum");
                }
                else if (string.IsNullOrWhiteSpace(sddl))
                    throw new ArgumentNullException("sddl");

                var descriptor = new RawSecurityDescriptor(sddl);

                var rights = _rights.GetOrAdd(rightsEnumType,
                                              t => Enum.GetValues(rightsEnumType)
                                                       .Cast<uint>()
                                                       .Where(n => n != 0 && (n & (n - 1)) == 0)
                                                       .Distinct()
                                                       .OrderBy(n => n)
                                                       .Select(v => new { v, n = Enum.GetName(rightsEnumType, v) })
                                                       .ToDictionary(x => x.v, x => x.n));

                var DecodedSDDL = new SDDL();

                if (descriptor.Owner != null)
                {
                    DecodedSDDL.Owner = descriptor.Owner.Value;
                }

                if (descriptor.Group != null)
                {
                    DecodedSDDL.Group = descriptor.Group.Value;
                }

                if (descriptor.SystemAcl != null)
                {
                    DecodeAclEntries(DecodedSDDL.SACL, descriptor.SystemAcl, rights);
                }

                if (descriptor.DiscretionaryAcl != null)
                {
                    DecodeAclEntries(DecodedSDDL.DACL, descriptor.DiscretionaryAcl, rights);
                }

                return DecodedSDDL;
            }

            private static void DecodeAclEntries(List<ACE> DecodedACL, RawAcl acl, Dictionary<uint, string> rights)
            {
                foreach (var ace in acl)
                {
                    var DecodedACE = new ACE();
                    var knownAce = ace as KnownAce;
                    if (knownAce != null)
                    {
                        DecodedACE.Trustee = knownAce.SecurityIdentifier.Value;
                        DecodedACE.AccessType = knownAce.AceType > AceType.MaxDefinedAceType
                                                 ? "Custom Access"
                                                 : knownAce.AceType.ToString();

                        if (knownAce.AceFlags != AceFlags.None)
                        {
                            DecodedACE.AuditRights = knownAce.AceFlags.ToString();
                        }


                        var mask = unchecked((uint)knownAce.AccessMask);

                        foreach (var r in rights.Keys)
                        {
                            if ((mask & r) == r)
                            {
                                DecodedACE.Permissions.Add(rights[r]);
                            }
                        }
                    }
                    else throw new Exception("Not a known ACE Structure");
                    DecodedACL.Add(DecodedACE);
                }
            }
            public static List<ACE> DecodeCOMRawACE<TRightsEnum>(byte[] ACL) where TRightsEnum : struct
            {
                var rightsEnumType = typeof(TRightsEnum);
                if (!rightsEnumType.IsEnum ||
                    Marshal.SizeOf(Enum.GetUnderlyingType(rightsEnumType)) != 4 ||
                    !rightsEnumType.GetCustomAttributes(typeof(FlagsAttribute), true).Any())
                {
                    throw new ArgumentException("TRightsEnum must be a 32-bit integer System.Enum with Flags attribute", "TRightsEnum");
                }
                else if (ACL.Count() == 0)
                    throw new ArgumentNullException("acl");

                RawAcl rawAcl = new RawAcl(ACL, 20); //20 here was trial and error!

                var rights = _rights.GetOrAdd(rightsEnumType,
                                              t => Enum.GetValues(rightsEnumType)
                                                       .Cast<uint>()
                                                       .Where(n => n != 0 && (n & (n - 1)) == 0)
                                                       .Distinct()
                                                       .OrderBy(n => n)
                                                       .Select(v => new { v, n = Enum.GetName(rightsEnumType, v) })
                                                       .ToDictionary(x => x.v, x => x.n));
                var result = new List<ACE>();
                DecodeAclEntries(result, rawAcl, rights);
                return result;
            }
            public static List<ACE> DecodeRawACE<TRightsEnum>(byte[] ACL) where TRightsEnum : struct
            {
                var rightsEnumType = typeof(TRightsEnum);
                if (!rightsEnumType.IsEnum ||
                    Marshal.SizeOf(Enum.GetUnderlyingType(rightsEnumType)) != 4 ||
                    !rightsEnumType.GetCustomAttributes(typeof(FlagsAttribute), true).Any())
                {
                    throw new ArgumentException("TRightsEnum must be a 32-bit integer System.Enum with Flags attribute", "TRightsEnum");
                }
                else if (ACL.Count() == 0)
                    throw new ArgumentNullException("acl");

                RawAcl rawAcl = new RawAcl(ACL, 20); //20 here was trial and error!

                var rights = _rights.GetOrAdd(rightsEnumType,
                                              t => Enum.GetValues(rightsEnumType)
                                                       .Cast<uint>()
                                                       .Where(n => n != 0 && (n & (n - 1)) == 0)
                                                       .Distinct()
                                                       .OrderBy(n => n)
                                                       .Select(v => new { v, n = Enum.GetName(rightsEnumType, v) })
                                                       .ToDictionary(x => x.v, x => x.n));
                var result = new List<ACE>();
                DecodeAclEntries(result, rawAcl, rights);
                return result;
            }
        }
 
        public static bool EqualsDefaultLaunchPermissions(byte[] RawLaunchPermission)
        {
            var LaunchACEs = Helper.PermissionsDecoder.DecodeCOMRawACE<Helper.COMPermissionsMask>(RawLaunchPermission);
            // DefaultPermissions only contain 3 trustees
            if (LaunchACEs.Count() != 3)
            {
                return false;
            }
            // System defaults are SYSTEM, INTERACTIVE and Administrators get full access
            string[] SIDs = { "S-1-5-18", "S-1-5-4", "S-1-5-32-544" };
            foreach (var SID in SIDs)
            {
                var SidPermissions = LaunchACEs.Where(o => o.Trustee == SID && o.AccessType == "AccessAllowed")
                                                .Select(o => o.Permissions).FirstOrDefault();
                if (SidPermissions == null || !COMFullAccess(SidPermissions))
                {
                    return false;
                }
            }
            return true;
        }
        public static bool EqualsDefaultAccessPermissions(byte[] RawAccessPermission)
        {
            var LaunchACEs = Helper.PermissionsDecoder.DecodeCOMRawACE<Helper.COMPermissionsMask>(RawAccessPermission);
            // DefaultPermissions only contain 3 trustees
            if (LaunchACEs.Count() != 3)
            {
                return false;
            }
            // System defaults are SYSTEM, SELF and Administrators get full access
            string[] SIDs = { "S-1-5-18", "S-1-5-10", "S-1-5-32-544" };
            foreach (var SID in SIDs)
            {
                var SidPermissions = LaunchACEs.Where(o => o.Trustee == SID && o.AccessType == "AccessAllowed")
                                                .Select(o => o.Permissions).FirstOrDefault();
                if (SidPermissions == null || !COMFullAccess(SidPermissions))
                {
                    return false;
                }
            }
            return true;
        }

        private static bool COMFullAccess(List<string> Permissions)
        {
            if (Permissions.Contains("COM_RIGHTS_EXECUTE") &&
           Permissions.Contains("COM_RIGHTS_EXECUTE_LOCAL") &&
           Permissions.Contains("COM_RIGHTS_EXECUTE_REMOTE") &&
           Permissions.Contains("COM_RIGHTS_ACTIVATE_LOCAL") &&
           Permissions.Contains("COM_RIGHTS_ACTIVATE_REMOTE")
           )
                return true;
            else
                return false;
        }

        // From seatbelt: https://github.com/GhostPack/Seatbelt/blob/e97b184755d070493a83c3af70da9417e5fd806f/Seatbelt/Interop/Shlwapi.cs
        public static bool IsWindowsServer()
        {
            const int OS_ANYSERVER = 29;
            return IsOS(OS_ANYSERVER);
        }

        [DllImport("shlwapi.dll", SetLastError = true, EntryPoint = "#437")]
        private static extern bool IsOS(int os);

    }
}
