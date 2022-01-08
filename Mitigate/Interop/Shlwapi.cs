using System;
using System.Runtime.InteropServices;

namespace Mitigate.Interop
{
    class Shlwapi
    {
        public static bool DoesPathPatternMatch(string FilePath, string RulePath) 
        {
            return PathMatch.MatchPattern(FilePath, RulePath);
        }
        [Flags]
        public enum MatchPatternFlags : uint
        {
            Normal = 0x00000000,   // PMSF_NORMAL
            Multiple = 0x00000001,   // PMSF_MULTIPLE
            DontStripSpaces = 0x00010000    // PMSF_DONT_STRIP_SPACES
        }
        sealed class PathMatch
        {
            [DllImport("Shlwapi.dll", SetLastError = false)]
            static extern int PathMatchSpecExW([MarshalAs(UnmanagedType.LPWStr)] string file,
                                               [MarshalAs(UnmanagedType.LPWStr)] string spec,
                                               MatchPatternFlags flags);

            public static bool MatchPattern(string file, string spec, MatchPatternFlags flags = MatchPatternFlags.Normal)
            {
                if (String.IsNullOrEmpty(file))
                    return false;

                if (String.IsNullOrEmpty(spec))
                    return true;

                int result = PathMatchSpecExW(file, spec, flags);

                return (result == 0);
            }
        }
    }
}
