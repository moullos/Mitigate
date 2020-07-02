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

namespace Mitigate
{
    class Utils
    {
        private static Tuple<string, string, int> RunCmd(string cmd)
        {
            Process process = new Process();
            process.StartInfo.FileName = "cmd.exe";
            process.StartInfo.Arguments = "/c " + cmd;
            process.StartInfo.UseShellExecute = false;
            process.StartInfo.RedirectStandardOutput = true;
            process.StartInfo.RedirectStandardError = true;
            process.Start();
            string output = process.StandardOutput.ReadToEnd();
            string err = process.StandardError.ReadToEnd();
            process.WaitForExit();
            return new Tuple<string, string, int>(output, err, process.ExitCode);
        }

        public static bool CommandFileExists(string cmd)
        {
            string output;
            string err;
            int exitCode;
            var result = RunCmd("where.exe " + cmd);
            output = result.Item1;
            err = result.Item2;
            exitCode = result.Item3;
            if (exitCode != 0)
            {
                return false;
            }
            else
            {
                return true;
            }
        }



        public static bool CommandFileAccessible(string cmd)
        {
            string output;
            string err;
            int exitCode;
            var result = RunCmd(cmd);
            output = result.Item1;
            err = result.Item2;
            exitCode = result.Item3;
            if (output.Contains("is not recognized as an internal or external command"))
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        // All credit for the Registry Utils goes to winPeas
        ///////////////////////////////////////////
        /// Interf. for Keys and Values in Reg. ///
        ///////////////////////////////////////////
        /// Functions related to obtain keys and values from the registry
        /// Some parts adapted from Seatbelt
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
            catch (Exception ex)
            {
                PrintUtils.ExceptionPrint(String.Format(@"Registry {0}\{1} was not found", hive, path));
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
            var DecodedSDDL = Utils.PermissionsDecoder.DecodeSddlString<RegistryRights>(SddlString);
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
            var DecodedSDDL = Utils.PermissionsDecoder.DecodeSddlString<FileSystemRights>(SDDLString);
            return DecodedSDDL.FileWriteAccess(SIDs);

        }

        public static bool DirectoryRightPermissions(string DirectoryPath, List<string> SIDs)
        {
            DirectorySecurity security;
            //If the file does not exist check the directory rights
            DirectoryInfo dinfo = new DirectoryInfo(DirectoryPath);
            security = dinfo.GetAccessControl();
            var SDDLString = security.GetSecurityDescriptorSddlForm(AccessControlSections.All);
            var DecodedSDDL = Utils.PermissionsDecoder.DecodeSddlString<FileSystemRights>(SDDLString);
            return DecodedSDDL.DirectoryWriteAccess(SIDs);

        }
        /// From winpeas
        public static string PermInt2Str(int current_perm, bool only_write_or_equivalent = false, bool is_service = false)
        {
            Dictionary<string, int> interesting_perms = new Dictionary<string, int>()
                {
                    // This isn't an exhaustive list of possible permissions. Just the interesting ones.
                    { "AllAccess", 0xf01ff},
                    { "GenericAll", 0x10000000},
                    { "FullControl", (int)FileSystemRights.FullControl },
                    { "TakeOwnership", (int)FileSystemRights.TakeOwnership },
                    { "GenericWrite", 0x40000000 },
                    { "WriteData/CreateFiles", (int)FileSystemRights.WriteData },
                    { "Modify", (int)FileSystemRights.Modify },
                    { "Write", (int)FileSystemRights.Write },
                    { "ChangePermissions", (int)FileSystemRights.ChangePermissions },
                    { "Delete", (int)FileSystemRights.Delete },
                    { "DeleteSubdirectoriesAndFiles", (int)FileSystemRights.DeleteSubdirectoriesAndFiles },
                    { "AppendData/CreateDirectories", (int)FileSystemRights.AppendData },
                    { "WriteAttributes", (int)FileSystemRights.WriteAttributes },
                    { "WriteExtendedAttributes", (int)FileSystemRights.WriteExtendedAttributes },
                };

            if (only_write_or_equivalent)
            {
                interesting_perms = new Dictionary<string, int>()
                {
                    { "AllAccess", 0xf01ff},
                    { "GenericAll", 0x10000000},
                    { "FullControl", (int)FileSystemRights.FullControl }, //0x1f01ff
                    { "TakeOwnership", (int)FileSystemRights.TakeOwnership }, //0x80000
                    { "GenericWrite", 0x40000000 },
                    { "WriteData/CreateFiles", (int)FileSystemRights.WriteData }, //0x2
                    { "Modify", (int)FileSystemRights.Modify }, //0x301bf
                    { "Write", (int)FileSystemRights.Write }, //0x116
                    { "ChangePermissions", (int)FileSystemRights.ChangePermissions }, //0x40000
                };
            }

            if (is_service)
            {
                interesting_perms["Start"] = 0x00000010;
                interesting_perms["Stop"] = 0x00000020;
            }

            try
            {
                foreach (KeyValuePair<string, int> entry in interesting_perms)
                {
                    if ((entry.Value & current_perm) == entry.Value)
                        return entry.Key;
                }
            }
            catch (Exception ex)
            {
                PrintUtils.ErrorPrint("Error in PermInt2Str: " + ex);
            }
            return "";
        }

        public List<GroupPrincipal> Sid2Group(List<string> SIDs)
        {
            List<GroupPrincipal> Groups = new List<GroupPrincipal>();

            PrincipalContext MachineContext = new PrincipalContext(ContextType.Machine);
            PrincipalContext DomainContext = Program.IsDomainJoined ? new PrincipalContext(ContextType.Domain) : null;
            foreach (string SID in SIDs)
            {
                // Checking if the SID corresponds to a machine group
                GroupPrincipal Group = GroupPrincipal.FindByIdentity(MachineContext, IdentityType.Sid, SID);
                if (Group != null)
                {
                    Groups.Add(Group);
                    continue;
                }
                // Checking if the SID corresponds to a domain group
                if (Program.IsDomainJoined)
                {
                    Group = GroupPrincipal.FindByIdentity(DomainContext, IdentityType.Sid, SID);
                    if (Group != null)
                    {
                        Groups.Add(Group);
                    }
                }
            }
            return Groups;
        }

        public static Dictionary<string, string> GetServiceConfig(string ServiceName)
        {
            Dictionary<string, string> results = new Dictionary<string, string>();
            // Unfortunately the ServiceController class does not provide the startUpType on this version of .NET
            // So we pull it directly from the register

            var RegPath = @"SYSTEM\CurrentControlSet\Services\WinRM";
            var RegName = @"Start";

            string StartUpTypeValue = Utils.GetRegValue("HKLM", RegPath, RegName);

            results["StartUpType"] = StartType2String(StartUpTypeValue);


            return results;
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
        [Flags]
        public enum COMPermissionsMask : uint
        {
            COM_RIGHTS_EXECUTE = 1,
            COM_RIGHTS_EXECUTE_LOCAL = 2,
            COM_RIGHTS_EXECUTE_REMOTE = 4,
            COM_RIGHTS_ACTIVATE_LOCAL = 8,
            COM_RIGHTS_ACTIVATE_REMOTE = 16,
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

        // Aspiration from https://stackoverflow.com/questions/7724110/convert-sddl-to-readable-text-in-net
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

                DecodedSDDL.Owner = descriptor.Owner.Value;
                DecodedSDDL.Group = descriptor.Group.Value;

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

            private static string SidToAccountName(SecurityIdentifier sid)
            {
                return (sid.IsValidTargetType(typeof(NTAccount)))
                     ? ((NTAccount)sid.Translate(typeof(NTAccount))).Value
                     : sid.Value;
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
                    else throw new Exception("Unknown ACE Structure");
                    DecodedACL.Add(DecodedACE);
                }
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
    }
}
