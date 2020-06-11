using System;
using System.Diagnostics;
using System.Collections.Generic;
using System.Text;
using Microsoft.Win32;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using System.IO;
using System.DirectoryServices.AccountManagement;
using System.Data;
using System.CodeDom.Compiler;
using System.ServiceProcess;

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
        public static Dictionary<string, bool> GetRegPermissions(string hive, string path, List<string> SIDs)
        {
            //PrintUtils.PrintInfo(String.Format(@"Checking reg permissions for {0}\{1}", hive, path));
            Dictionary<string, bool> results = new Dictionary<string, bool>();
            Microsoft.Win32.RegistryKey myKey = null;
            try
            {

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
                foreach (RegistryAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
                {
                    int current_perm = (int)rule.RegistryRights;
                    string current_perm_str = PermInt2Str(current_perm, true);
                    if (current_perm_str == "")
                        continue;

                    foreach (string SID in SIDs)
                    {
                        if (rule.IdentityReference.Value.Equals(SID))
                        {
                            results[SID] = true;
                            continue;
                        }
                    /*
                    SecurityIdentifier UserSID = new SecurityIdentifier(SID);
                    SecurityIdentifier RuleSID = new SecurityIdentifier(rule.IdentityReference.Value);
                    if (RuleSID.Value == UserSID.Value)
                    {
                            results[SID] = true;
                            continue;
                    }
                    else
                    {
                        PrincipalContext ctx = new PrincipalContext(ContextType.Machine);
                        GroupPrincipal group = GroupPrincipal.FindByIdentity(ctx, RuleSID.Value);
                        if (group!= null)
                         {
                            foreach (Principal p in group.Members)
                                if (p.Sid.Value == UserSID.Value)
                                {
                                    results[SID] = true;
                                    continue;
                                }
                         }

                    }
                    */
                    }
                    
                }
                return results;
            }
            catch
            {
                PrintUtils.ExceptionPrint(String.Format(@"Couldn't get access control rules for {0}\{1}", hive, path));
                return results;
            }
        }
        public static Dictionary<string, bool> GetFileWritePermissions(string FilePath, List<string> SIDs)
        {
            Dictionary<string, bool> results = new Dictionary<string, bool>();
            try
            {
                FileSystemSecurity security;
                if (File.Exists(FilePath))
                {
                    FileInfo fInfo = new FileInfo(FilePath);
                    security = fInfo.GetAccessControl();
                }
                else
                {
                    return results;
                }

                foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
                {
                    int current_perm = (int)rule.FileSystemRights;
                    string current_perm_str = PermInt2Str(current_perm, true);
                    if (current_perm_str == "")
                        continue;
                    foreach (string SID in SIDs)
                    {
                        if (rule.IdentityReference.Value.Equals(SID))
                        {
                            results[SID] = true;
                            continue;
                        }
                        //Tried to get effective permissions but it's too slow
                        /*
                        SecurityIdentifier UserSID = new SecurityIdentifier(SID);
                        SecurityIdentifier RuleSID = new SecurityIdentifier(rule.IdentityReference.Value);
                        if (RuleSID.IsAccountSid())
                        {
                            if (RuleSID.Value == UserSID.Value)
                            {
                                results[SID] = true;
                                continue;

                            }
                        }
                        else
                        {
                            PrincipalContext ctx = new PrincipalContext(ContextType.Machine);
                            GroupPrincipal group = GroupPrincipal.FindByIdentity(ctx, RuleSID.Value);
                            foreach (Principal p in group.Members)
                                if (p.Sid == UserSID)
                                {
                                    results[SID] = true;
                                    continue;
                                }
                        }
                        */
                    }
                }
                return results;
            }
            catch
            {
                PrintUtils.ExceptionPrint(String.Format(@"Could get access control rules for {0}", FilePath));
                return null;
            }

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


            // Unfortunately the ServiceController class does not provide the startUpType.
            // So we pull it directly from the register

            var RegPath = @"\SYSTEM\CurrentControlSet\Services\WinRM";
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


    }
}
