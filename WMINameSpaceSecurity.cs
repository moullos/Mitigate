////////////////////////////////////////////////////////////////////////////////////
// Adapted from https://www.codeproject.com/Articles/15848/WMI-Namespace-Security //
// Subject to the The Code Project Open License (CPOL) 1.02                       //
////////////////////////////////////////////////////////////////////////////////////

using System;
using System.Collections.Generic;
using System.Management;
using System.Runtime.InteropServices;

namespace Mitigate
{


    /// <summary>
    /// Provides methods and data to view WMI namespace security.
    /// </summary>
    sealed public class ViewNameSpaceSecurity : NameSpaceSecurity
    {
         bool m_bRecursive;

        public ViewNameSpaceSecurity(string name, bool recursive) : base(name)
        {
            m_bRecursive = recursive;
        }

        private void EnumNameSpaces(string sns, Dictionary<string, string> results)
        {
            try
            {
                // Retrieve namespaces
                string g = m_ms.Path.ToString() + "\\" + sns;
                ManagementClass mcNameSpace = new ManagementClass(g + ":__NameSpace");
                results[g] = ViewSecurityDescriptor(g);

                foreach (ManagementObject mo in mcNameSpace.GetInstances())
                {
                    string s = sns + "\\" + mo["Name"].ToString();
                    EnumNameSpaces(s, results);
                }
                // Alert garbage collector
                mcNameSpace.Dispose();
            }
            catch (System.Exception viewex)
            {
                throw new Exception("ViewNameSpaceSecurity.ViewNameSpaces Error: " + viewex.Message);
            }
        }

        public Dictionary<string, string> GetNameSpaceSDDL(string sComputer)
        {
            Dictionary<string, string> results = new Dictionary<string, string>();
            try
            {
                connectToComputer(sComputer);
            }
            catch (Exception ex)
            {
                throw new Exception("ViewNamespaceSecurity.ViewSecurity Error: " + ex.Message);
            }


            try
            {
                ManagementPath mp = new ManagementPath(m_sNameSpace + ":__NameSpace");
                ObjectGetOptions options = new ObjectGetOptions(null, new TimeSpan(0, 0, 0, 25), true);
                ManagementClass mcNameSpace = new ManagementClass(m_ms, mp, options);
                results[m_sNameSpace] = ViewSecurityDescriptor(m_ms.Path.ToString());

                if (m_bRecursive == true)
                {
                    foreach (ManagementObject mo in mcNameSpace.GetInstances())
                    {
                        string s = m_sNameSpace + "\\" + mo["Name"].ToString();
                        EnumNameSpaces(mo["Name"].ToString(), results);
                    }
                }
                // Alert garbage collector
                mcNameSpace.Dispose();
            }
            catch (System.Exception viewex)
            {
                throw new Exception("ViewNameSpaceSecurity.ViewNameSpaces Error: " + viewex.Message);
            }
            return results;
        }

        private string ViewSecurityDescriptor(string sNameSpace)
        {
            IntPtr pStringSD = IntPtr.Zero;             // ptr to string Security Descriptor
                                                        //IntPtr pSystemSD = IntPtr.Zero;			// ptr to system Security Descriptor
            int iStringSDSize = 0;                      // size of string Security Descriptor
                                                        //int iSystemSDSize = 0;					// size of system Security Descriptor
            string stringSD;                            // string representation of system Security Descriptor
            int iError = 0;                             // Win32 error
            bool bRes;                                  // Boolean result


            ManagementPath nsmp = new ManagementPath(sNameSpace + ":__SystemSecurity");
            ObjectGetOptions suboptions = new ObjectGetOptions(null, new TimeSpan(0, 0, 0, 25), true);
            ManagementClass systemSecurity = new ManagementClass(nsmp, suboptions);
            try
            {
                ManagementBaseObject outParams = systemSecurity.InvokeMethod("GetSD", null, null);
                if ((uint)outParams["ReturnValue"] != 0)
                {
                    throw new Exception("ViewNamespaceSecurity.ViewSecurity error, GetSD returns: " + outParams["ReturnValue"]);
                }

                // Convert SD from SECURITY_DESCRIPTOR structure format to a string we can view
                bRes = ConvertSecurityDescriptorToStringSecurityDescriptor((byte[])outParams["SD"], 1,
                    SECURITY_INFORMATION.DACL_SECURITY_INFORMATION |
                    SECURITY_INFORMATION.OWNER_SECURITY_INFORMATION |
                    SECURITY_INFORMATION.GROUP_SECURITY_INFORMATION |
                    SECURITY_INFORMATION.SACL_SECURITY_INFORMATION,
                    out pStringSD, out iStringSDSize);

                if (!bRes)
                {
                    iError = Marshal.GetLastWin32Error();
                    throw new Exception("ConvertSecurityDescriptorToStringSecurityDescriptor API Error: " + iError);
                }

                stringSD = Marshal.PtrToStringAuto(pStringSD);
                return stringSD;
            }
            catch (System.Exception vnssex)
            {
                throw new Exception("ViewNameSpaceSecurity.ViewSecurity Error: " + vnssex.Message);
            }
            finally
            {
                // Free unmanaged memory
                if (pStringSD != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(pStringSD);
                    pStringSD = IntPtr.Zero;
                }

                // Alert the garbage collector
                systemSecurity.Dispose();
            }
        }
    }
    public class NameSpaceSecurity
    {
        protected string m_sNameSpace;                  // namespace to target
        protected ManagementScope m_ms;                 // scope for management operations
        protected ConnectionOptions m_co;               // settings required for WMI connection


        public NameSpaceSecurity(string snamespace)
        {
            m_sNameSpace = snamespace;
        }

        protected void connectToComputer(string WsName)
        {
            m_co = new ConnectionOptions();
            string sConnection = ("\\\\" + WsName + "\\" + m_sNameSpace);

            try
            {
                m_ms = new ManagementScope(sConnection, m_co);
                m_ms.Connect();
            }
            catch (System.Exception e)
            {
                throw new Exception("Unable to connect to " + "\\\\" + WsName + ", Reason: " + e.Message);
            }
        }

        /*-----------------------------------------------------
		 Interop structures and functions
		-----------------------------------------------------*/

        [DllImport("Advapi32.dll", CharSet = CharSet.Auto, SetLastError = true, ExactSpelling = false)]
        protected static extern bool
            ConvertSecurityDescriptorToStringSecurityDescriptor(
            [In] byte[] SecurityDescriptor,
            [In] int RequestedStringSDRevision,
            [In] SECURITY_INFORMATION SecurityInformation,
            [Out] out IntPtr StringSecurityDescriptor,
            [Out] out int StringSecurityDescriptorLen
            );

        public enum SECURITY_INFORMATION : uint
        {
            OWNER_SECURITY_INFORMATION = 0x00000001,
            GROUP_SECURITY_INFORMATION = 0x00000002,
            DACL_SECURITY_INFORMATION = 0x00000004,
            SACL_SECURITY_INFORMATION = 0x00000008,
            PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000,
            PROTECTED_SACL_SECURITY_INFORMATION = 0x40000000,
            UNPROTECTED_DACL_SECURITY_INFORMATION = 0x20000000,
            UNPROTECTED_SACL_SECURITY_INFORMATION = 0x10000000
        };


    }
}
