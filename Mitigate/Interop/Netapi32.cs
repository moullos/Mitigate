using System;
using System.Runtime.InteropServices;

namespace Mitigate.Interop
{
    internal class Netapi32
    {
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


        [DllImport("Netapi32.dll")]
        public static extern int NetApiBufferFree(IntPtr Buffer);
        
        public static USER_MODALS_INFO_3 GetLockOutPolicy()
        {
            USER_MODALS_INFO_3 objUserModalsInfo3 = new USER_MODALS_INFO_3();
            IntPtr bufPtr;
            uint lngReturn = NetUserModalsGet(@"\\" + Environment.MachineName, 3, out bufPtr);
            if (lngReturn == 0)
            {
                objUserModalsInfo3 = (USER_MODALS_INFO_3)Marshal.PtrToStructure(bufPtr, typeof(USER_MODALS_INFO_3));
            }
            NetApiBufferFree(bufPtr);
            return objUserModalsInfo3;
        }
    }
}
