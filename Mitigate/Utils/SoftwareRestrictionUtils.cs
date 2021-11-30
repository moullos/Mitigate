using Microsoft.Win32;
using Mitigate.Interop;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Mitigate.Utils
{
    /// <summary>
    /// Static class that pulls information pertaining to Software Restriction policies
    /// </summary>
    class SoftwareRestrictionUtils
    {
        //Lots of info pulled from here
        // https://www.isssource.com/wp-content/uploads/2012/02/ISSSource-Application_Whitelisting_Using_SRP.pdf

        /// <summary>
        /// Simple enumeration for Software Restriction Default Policies (i.e. actions)
        /// </summary>
        public enum SRPolicy
        {
            Unrestricted,
            Disallowed,
            Undefined
        }

        /// <summary>
        /// Checks if Software Restriction Policies are being enforced
        /// </summary>
        /// <returns>True if they are. False if they are not</returns>
        public static bool IsEnabled()
        {
            // If AppLocker is running SRPs are ignored
            if (Helper.IsServiceRunning("AppIDSvc")) return false;

            // Checking HKLM
            var ConfigRegPath = @"Software\Policies\Microsoft\Windows\Safer\CodeIdentifiers";
            if (Helper.RegExists("HKLM", ConfigRegPath, "TransparentEnabled"))
                return Helper.GetRegValue("HKLM", ConfigRegPath, "TransparentEnabled") == "1"||
                       Helper.GetRegValue("HKLM", ConfigRegPath, "TransparentEnabled") == "2";
            // Next checking HKCU
            if (Helper.RegExists("HKCU", ConfigRegPath, "TransparentEnabled"))
                return Helper.GetRegValue("HKCU", ConfigRegPath, "TransparentEnabled") == "1" ||
                       Helper.GetRegValue("HKCU", ConfigRegPath, "TransparentEnabled") == "2";
            return false;
        }

        public static bool DLLMonitoringEnabled()
        {
            var ConfigRegPath = @"Software\Policies\Microsoft\Windows\Safer\CodeIdentifiers";
            if (Helper.RegExists("HKLM", ConfigRegPath, "TransparentEnabled"))
                return Helper.GetRegValue("HKLM", ConfigRegPath, "TransparentEnabled") == "2";
            // Next checking HKCU
            if (Helper.RegExists("HKCU", ConfigRegPath, "TransparentEnabled"))
                return Helper.GetRegValue("HKCU", ConfigRegPath, "TransparentEnabled") == "2";
            return false;
        }
        public static bool IsBlocked(string FilePath)
        {
            if (String.IsNullOrEmpty(FilePath)) throw new ArgumentNullException("FilePath");
            if (!File.Exists(FilePath))  throw new FileNotFoundException($"File '{FilePath}' was not found"); 

            // Rule Priority:
            // 1. Hash rules
            //    a. Is hash explicitly denied
            //    b. Is hash explicitly allowed
            // 2. Certificate rules(If they are enabled)
            //    a. Is file signer a trusteed publisher?
            //    b. Is file signer a not-trusteed publisher?
            // 3. Path rules
            //    a. Is file in "unrestricted" path
            //    b. Is file in restricted path
            // 4. Internet Zone rules
            //    We will ignore for now. They are rarely used
            // 5. Default rules

            // Hash Rules enum
            if (IsFileHashRestricted(FilePath)) 
            {
                PrintUtils.Debug($"SRP: {FilePath} dissallowed based on hash rule");
                return true; 
            }
            else if (IsFileHashAllowed(FilePath)) 
            { 
                PrintUtils.Debug($"SRP: {FilePath} allowed based on hash rule");
                return false; 
            }

            // Cert Rules
            // Not that cert rules are not saved in the registry. Instead they are managed directly through windows
            if (CertificateRulesEnabled())
            {
                PrintUtils.Debug($"SRP: Certificate rules are enabled");
                var SignatureResult =  WinTrust.GetEmbeddedSignatureStatus(FilePath);
                if (SignatureResult == WinVerifyTrustResult.Success) 
                {
                    PrintUtils.Debug($"SRP: {FilePath} signature is trusted");
                    return false; 
                }
                if (SignatureResult != WinVerifyTrustResult.FileNotSigned) 
                {
                    PrintUtils.Debug($"SRP: {FilePath} is not signed");
                    return true;  
                }
            }
            var PathRuleResult = CheckPathRules(FilePath);
            if (PathRuleResult == SRPolicy.Disallowed) 
            {
                PrintUtils.Debug($"SRP: {FilePath} denied based on path rule");
                return true;
            }
            else if (PathRuleResult == SRPolicy.Unrestricted)
            {
                PrintUtils.Debug($"SRP: {FilePath} allowed based on path rule");
                return false;
            }

            if (GetDefaultPolicy() == SRPolicy.Unrestricted)
            {
                PrintUtils.Debug($"SRP: {FilePath} allowed based on default policy");
                return false;
            }
            else
            {
                PrintUtils.Debug($"SRP: {FilePath} denied based on default policy");
                return true;
            }
        }

        /// <summary>
        /// Gets the SRP default policies
        /// </summary>
        /// <returns>Value in the SRPolicy enum</returns>
        private static SRPolicy GetDefaultPolicy()
        {
            var ConfigRegPath = @"Software\Policies\Microsoft\Windows\Safer\CodeIdentifiers";
            string DefaultPolicyReg;
            if (Helper.RegExists("HKLM", ConfigRegPath, "DefaultLevel"))
            {
                DefaultPolicyReg = Helper.GetRegValue("HKLM", ConfigRegPath, "DefaultLevel");
            }
            else if (Helper.RegExists("HKCU", ConfigRegPath, "DefaultLevel"))
            {
                DefaultPolicyReg = Helper.GetRegValue("HKCU", ConfigRegPath, "DefaultLevel");
            }
            else
            {
                throw new Exception("GetDefaultPolicy: Default SR policy does not seem to be defined. " +
                    "Probably a bug, do you want to try and fix it?");
            }

            // 262144 is Unrestricted i.e. Blacklist based
            // 0 is Restricted i.e Whitelist based
            if (DefaultPolicyReg == "262144") return SRPolicy.Unrestricted;
            else if (DefaultPolicyReg == "0") return SRPolicy.Disallowed;
            else throw new Exception("GetDefaultPolicy: Unknown default policy");
        }

        /// <summary>
        /// Checks if Software restriction policy rules are enabled
        /// </summary>
        /// <returns>True if enabled; false if not</returns>
        public static bool CertificateRulesEnabled()
        {
            if (!IsEnabled()) return false;

            var ConfigRegPath = @"Software\Policies\Microsoft\Windows\Safer\CodeIdentifiers";
            if (Helper.RegExists("HKLM", ConfigRegPath, "authenticodeenabled"))
            {
                return Helper.GetRegValue("HKLM", ConfigRegPath, "authenticodeenabled") == "1";
            }
            else if (Helper.RegExists("HKCU", ConfigRegPath, "authenticodeenabled"))
            {
                return Helper.GetRegValue("HKCU", ConfigRegPath, "authenticodeenabled") == "1";
            }
            else
            {
                throw new Exception("SRPCertificateRulesEnabled: Unknown SRP certificate status " +
                    "Probably a bug, do you want to try and fix it?");
            }
        }
        /// <summary>
        /// Checks if file hash is blacklisted by SRPs
        /// </summary>
        /// <param name="FilePath"></param>
        /// <returns></returns>
        private static bool IsFileHashRestricted(string FilePath)
        {
            if (String.IsNullOrEmpty(FilePath)) throw new ArgumentNullException("FilePath");
            if (!File.Exists(FilePath)) throw new FileNotFoundException($"File '{FilePath}' was not found");

            // Step 1: Check if any restrictive hash rules are defined
            var BlackListRulesRegPath = @"Software\Policies\Microsoft\Windows\Safer\CodeIdentifiers\0\Hashes";
            string hive;
            if (Helper.RegExists("HKLM", BlackListRulesRegPath))
            {
                hive = "HKLM";
            }
            else if (Helper.RegExists("HKCU", BlackListRulesRegPath))
            {
                hive = "HKCU";
            }
            else return false;

            // Step 2: Calculate file MD5 sum
            byte[] FileHash = null;
            using (MD5 md5Hash = MD5.Create())
            {
                FileHash = md5Hash.ComputeHash(File.ReadAllBytes(FilePath));
            }

            foreach (var RuleGuid in Helper.GetRegSubkeys(hive, BlackListRulesRegPath))
            {
                // Step 3: Process Rule
                var RuleRegPath = $@"Software\Policies\Microsoft\Windows\Safer\CodeIdentifiers\0\Hashes\{RuleGuid}";
                var RuleHash = Helper.GetRegValueBytes(hive, RuleRegPath, "ItemData");

                // HashAlg id are found here: https://docs.microsoft.com/en-gb/windows/win32/seccrypto/alg-id?redirectedfrom=MSDN
                // Also here: https://www.pinvoke.net/default.aspx/advapi32.CryptGenKey
                // I will ignore for now, and only deal with MD5
                var hashAlg = Helper.GetRegValue(hive, RuleRegPath, "HashAlg");
                if (hashAlg != "32771")
                {
                    throw new Exception($"IsFileHashRestricted: Unknown hash type {hashAlg}");
                }
                // Step 4: Calculate and check for the hash in the rules
                if (FileHash.SequenceEqual(RuleHash))
                {
                    return true;
                }
            }
            return false;
        }
        /// <summary>
        /// Checks if file has is whitelisted by SRPs
        /// </summary>
        /// <param name="FilePath"></param>
        /// <returns></returns>
        private static bool IsFileHashAllowed(string FilePath)
        {
            if (String.IsNullOrEmpty(FilePath)) throw new ArgumentNullException("FilePath");
            if (!File.Exists(FilePath)) throw new FileNotFoundException($"File '{FilePath}' was not found");

            // Step 1: Check if any restrictive hash rules are defined
            var WhiteListRulesRegPath = @"Software\Policies\Microsoft\Windows\Safer\CodeIdentifiers\262144\Hashes";
            string hive;
            if (Helper.RegExists("HKLM", WhiteListRulesRegPath))
            {
                hive = "HKLM";
            }
            else if (Helper.RegExists("HKCU", WhiteListRulesRegPath))
            {
                hive = "HKCU";
            }
            else return false;

            // Step 2: Calculate file MD5 sum
            byte[] FileHash = null;
            using (MD5 md5Hash = MD5.Create())
            {
                FileHash = md5Hash.ComputeHash(File.ReadAllBytes(FilePath));
            }

            foreach (var RuleGuid in Helper.GetRegSubkeys(hive, WhiteListRulesRegPath))
            {
                // Step 3: Process Rule
                var RuleRegPath = $@"Software\Policies\Microsoft\Windows\Safer\CodeIdentifiers\262144\Hashes\{RuleGuid}";
                var RuleHash = Helper.GetRegValueBytes(hive, RuleRegPath, "ItemData");

                // HashAlg id are found here: https://docs.microsoft.com/en-gb/windows/win32/seccrypto/alg-id?redirectedfrom=MSDN
                // Also here: https://www.pinvoke.net/default.aspx/advapi32.CryptGenKey
                // I will ignore for now, and only deal with MD5
                var hashAlg = Helper.GetRegValue(hive, RuleRegPath, "HashAlg");
                if (hashAlg != "32771")
                {
                    throw new Exception($"IsFileHashAllowed: Unknown hash type {hashAlg}");
                }
                // Step 4: Calculate and check for the hash in the rules
                if (FileHash.SequenceEqual(RuleHash))
                {
                    return true;
                }
            }
            return false;
        }
        /// <summary>
        /// Retreives the SR policy for a particular file based on path rules
        /// </summary>
        /// <param name="FilePath"></param>
        /// <returns></returns>
        private static SRPolicy CheckPathRules(string FilePath)
        {
            if (String.IsNullOrEmpty(FilePath)) throw new ArgumentNullException("FilePath");
            if (!File.Exists(FilePath)) throw new FileNotFoundException($"File '{FilePath}' was not found");


            var WhiteListRegPath = @"Software\Policies\Microsoft\Windows\Safer\CodeIdentifiers\262144\Paths";
            var BlackListRulesRegPath = @"Software\Policies\Microsoft\Windows\Safer\CodeIdentifiers\0\Paths";
            string hive;
            
            if (Helper.RegExists("HKLM", WhiteListRegPath))
            {
                hive = "HKLM";
            }
            else if (Helper.RegExists("HKCU", WhiteListRegPath))
            {
                hive = "HKCU";
            }
            else
            {
                return SRPolicy.Undefined;
            }

            // SRP will apply the most "specific" rule.
            var minDepth = int.MaxValue;
            SRPolicy MostSpecificPolicy = SRPolicy.Undefined;

            foreach (var RuleGuid in Helper.GetRegSubkeys(hive, WhiteListRegPath))
            {
                var RuleRegPath = $@"Software\Policies\Microsoft\Windows\Safer\CodeIdentifiers\262144\Paths\{RuleGuid}";
                var RulePath = Helper.GetRegValue(hive, RuleRegPath, "ItemData");
                var depth = DoesRuleMatch(FilePath, RulePath);
                if (depth >= 0)
                {
                    PrintUtils.Debug($"SRP: {FilePath} was matched by unrestricted rule {RulePath}");
                    if (minDepth > depth)
                    {
                        MostSpecificPolicy = SRPolicy.Unrestricted;
                        minDepth = depth;
                    }
                }
            }

            foreach (var RuleGuid in Helper.GetRegSubkeys(hive, BlackListRulesRegPath))
            {
                var RuleRegPath = $@"Software\Policies\Microsoft\Windows\Safer\CodeIdentifiers\0\Paths\{RuleGuid}";
                var RulePath = Helper.GetRegValue(hive, RuleRegPath, "ItemData");
                var depth = DoesRuleMatch(FilePath, RulePath);
                if (depth >=  0)
                {
                    MostSpecificPolicy = SRPolicy.Disallowed;
                    minDepth = depth;
                }
            }
            return MostSpecificPolicy;
        }

        /// <summary>
        /// Checks if a path rules matches a file.
        /// </summary>
        /// <param name="FilePath"></param>
        /// <param name="RulePath"></param>
        /// <returns>The depth between the FilePath and RulePath if they match. -1 if they don't</returns>
        private static int DoesRuleMatch(string FilePath, string RulePath)
        {
            if (String.IsNullOrEmpty(FilePath)) throw new ArgumentNullException("FilePath");
            if (!File.Exists(FilePath)) throw new FileNotFoundException($"File '{FilePath}' was not found");
            //if Regpath rule
            if (RulePath.StartsWith("%HKEY_"))
            {
                RulePath = RulePath.TrimStart('%').TrimEnd('%');
                var keyName = Path.GetDirectoryName(RulePath);
                var valueName = Path.GetFileName(RulePath);
                var value = Registry.GetValue(keyName, valueName, null);
                if (value!= null)
                {
                    PrintUtils.Debug($"SRP:{RulePath} was evaluated to {value}");
                    RulePath = value.ToString();
                }
            }
            // Expand env variable
            RulePath = Environment.ExpandEnvironmentVariables(RulePath);
            if (Directory.Exists(RulePath))
            {
                var depth = IsParent(RulePath, FilePath);
                if (depth >= 0) return depth;
            }
            if (Shlwapi.DoesPathPatternMatch(FilePath, RulePath))
            {
                return 0;
            }
            return -1;
        }
        /// <summary>
        /// Checks if dir1 is parent directory of dir2
        /// </summary>
        /// <param name="dir1"></param>
        /// <param name="dir2"></param>
        /// <returns>The depth of directories if is parent dir. -1 if not</returns>
        private static int IsParent(string dir1, string dir2)
        {
            var depth = 0;
            DirectoryInfo di1 = new DirectoryInfo(dir1);
            DirectoryInfo di2 = new DirectoryInfo(dir2);
            while (di2.Parent != null)
            {
                if (di2.Parent.FullName == di1.FullName)
                {
                    return depth;
                }
                else
                {
                    di2 = di2.Parent;
                    depth++;
                }
            }
            return -1;
        }

        // 
        // From http://www.pinvoke.net/default.aspx/wintrust.winverifytrust
        #region WinTrustData struct field enums
        enum WinTrustDataUIChoice : uint
        {
            All = 1,
            None = 2,
            NoBad = 3,
            NoGood = 4
        }

        enum WinTrustDataRevocationChecks : uint
        {
            None = 0x00000000,
            WholeChain = 0x00000001
        }

        enum WinTrustDataChoice : uint
        {
            File = 1,
            Catalog = 2,
            Blob = 3,
            Signer = 4,
            Certificate = 5
        }

        enum WinTrustDataStateAction : uint
        {
            Ignore = 0x00000000,
            Verify = 0x00000001,
            Close = 0x00000002,
            AutoCache = 0x00000003,
            AutoCacheFlush = 0x00000004
        }

        [FlagsAttribute]
        enum WinTrustDataProvFlags : uint
        {
            UseIe4TrustFlag = 0x00000001,
            NoIe4ChainFlag = 0x00000002,
            NoPolicyUsageFlag = 0x00000004,
            RevocationCheckNone = 0x00000010,
            RevocationCheckEndCert = 0x00000020,
            RevocationCheckChain = 0x00000040,
            RevocationCheckChainExcludeRoot = 0x00000080,
            SaferFlag = 0x00000100,        // Used by software restriction policies. Should not be used.
            HashOnlyFlag = 0x00000200,
            UseDefaultOsverCheck = 0x00000400,
            LifetimeSigningFlag = 0x00000800,
            CacheOnlyUrlRetrieval = 0x00001000,      // affects CRL retrieval and AIA retrieval
            DisableMD2andMD4 = 0x00002000      // Win7 SP1+: Disallows use of MD2 or MD4 in the chain except for the root
        }

        enum WinTrustDataUIContext : uint
        {
            Execute = 0,
            Install = 1
        }
        #endregion

        #region WinTrust structures
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        class WinTrustFileInfo
        {
            UInt32 StructSize = (UInt32)Marshal.SizeOf(typeof(WinTrustFileInfo));
            IntPtr pszFilePath;                     // required, file name to be verified
            IntPtr hFile = IntPtr.Zero;             // optional, open handle to FilePath
            IntPtr pgKnownSubject = IntPtr.Zero;    // optional, subject type if it is known

            public WinTrustFileInfo(String _filePath)
            {
                pszFilePath = Marshal.StringToCoTaskMemAuto(_filePath);
            }
            public void Dispose()
            {
                if (pszFilePath != IntPtr.Zero)
                {
                    Marshal.FreeCoTaskMem(pszFilePath);
                    pszFilePath = IntPtr.Zero;
                }
            }
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        class WinTrustData
        {
            UInt32 StructSize = (UInt32)Marshal.SizeOf(typeof(WinTrustData));
            IntPtr PolicyCallbackData = IntPtr.Zero;
            IntPtr SIPClientData = IntPtr.Zero;
            // required: UI choice
            WinTrustDataUIChoice UIChoice = WinTrustDataUIChoice.None;
            // required: certificate revocation check options
            WinTrustDataRevocationChecks RevocationChecks = WinTrustDataRevocationChecks.None;
            // required: which structure is being passed in?
            WinTrustDataChoice UnionChoice = WinTrustDataChoice.File;
            // individual file
            IntPtr FileInfoPtr;
            WinTrustDataStateAction StateAction = WinTrustDataStateAction.Ignore;
            IntPtr StateData = IntPtr.Zero;
            String URLReference = null;
            WinTrustDataProvFlags ProvFlags = WinTrustDataProvFlags.RevocationCheckChainExcludeRoot;
            WinTrustDataUIContext UIContext = WinTrustDataUIContext.Execute;

            // constructor for silent WinTrustDataChoice.File check
            public WinTrustData(WinTrustFileInfo _fileInfo)
            {
                // On Win7SP1+, don't allow MD2 or MD4 signatures
                if ((Environment.OSVersion.Version.Major > 6) ||
                    ((Environment.OSVersion.Version.Major == 6) && (Environment.OSVersion.Version.Minor > 1)) ||
                    ((Environment.OSVersion.Version.Major == 6) && (Environment.OSVersion.Version.Minor == 1) && !String.IsNullOrEmpty(Environment.OSVersion.ServicePack)))
                {
                    ProvFlags |= WinTrustDataProvFlags.DisableMD2andMD4;
                }

                WinTrustFileInfo wtfiData = _fileInfo;
                FileInfoPtr = Marshal.AllocCoTaskMem(Marshal.SizeOf(typeof(WinTrustFileInfo)));
                Marshal.StructureToPtr(wtfiData, FileInfoPtr, false);
            }
            public void Dispose()
            {
                if (FileInfoPtr != IntPtr.Zero)
                {
                    Marshal.FreeCoTaskMem(FileInfoPtr);
                    FileInfoPtr = IntPtr.Zero;
                }
            }
        }
        #endregion

        enum WinVerifyTrustResult : uint
        {
            Success = 0,
            ProviderUnknown = 0x800b0001,           // Trust provider is not recognized on this system
            ActionUnknown = 0x800b0002,         // Trust provider does not support the specified action
            SubjectFormUnknown = 0x800b0003,        // Trust provider does not support the form specified for the subject
            SubjectNotTrusted = 0x800b0004,         // Subject failed the specified verification action
            FileNotSigned = 0x800B0100,         // TRUST_E_NOSIGNATURE - File was not signed
            SubjectExplicitlyDistrusted = 0x800B0111,   // Signer's certificate is in the Untrusted Publishers store
            SignatureOrFileCorrupt = 0x80096010,    // TRUST_E_BAD_DIGEST - file was probably corrupt
            SubjectCertExpired = 0x800B0101,        // CERT_E_EXPIRED - Signer's certificate was expired
            SubjectCertificateRevoked = 0x800B010C,     // CERT_E_REVOKED Subject's certificate was revoked
            UntrustedRoot = 0x800B0109          // CERT_E_UNTRUSTEDROOT - A certification chain processed correctly but terminated in a root certificate that is not trusted by the trust provider.
        }

        sealed class WinTrust
        {
            private static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
            // GUID of the action to perform
            private const string WINTRUST_ACTION_GENERIC_VERIFY_V2 = "{00AAC56B-CD44-11d0-8CC2-00C04FC295EE}";

            [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = false, CharSet = CharSet.Unicode)]
            static extern WinVerifyTrustResult WinVerifyTrust(
                [In] IntPtr hwnd,
                [In][MarshalAs(UnmanagedType.LPStruct)] Guid pgActionID,
                [In] WinTrustData pWVTData
            );

            public static WinVerifyTrustResult GetEmbeddedSignatureStatus(string fileName)
            {
                WinTrustFileInfo wtfi = new WinTrustFileInfo(fileName);
                WinTrustData wtd = new WinTrustData(wtfi);
                Guid guidAction = new Guid(WINTRUST_ACTION_GENERIC_VERIFY_V2);
                WinVerifyTrustResult result = WinVerifyTrust(INVALID_HANDLE_VALUE, guidAction, wtd);
                wtfi.Dispose();
                wtd.Dispose();
                return result;
            }
            // call WinTrust.WinVerifyTrust() to check embedded file signature
            public static bool VerifyEmbeddedSignature(string fileName)
            {
                WinTrustFileInfo wtfi = new WinTrustFileInfo(fileName);
                WinTrustData wtd = new WinTrustData(wtfi);
                Guid guidAction = new Guid(WINTRUST_ACTION_GENERIC_VERIFY_V2);
                WinVerifyTrustResult result = WinVerifyTrust(INVALID_HANDLE_VALUE, guidAction, wtd);
                bool ret = (result == WinVerifyTrustResult.Success);
                wtfi.Dispose();
                wtd.Dispose();
                return ret;
            }
            private WinTrust() { }
        }
    }
}
