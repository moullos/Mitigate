using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;

namespace Mitigate
{
    class PrintUtils
    {

        /// <summary>
        /// Prints the MITIG&TE Banner
        /// </summary>
        public static void PrintBanner()
        {
            Console.WriteLine(@" 
 __  __ _____ _______ _____ _____     _______ ______ 
|  \/  |_   _|__   __|_   _/ ____| __|__   __|  ____|
| \  / | | |    | |    | || |  __ ( _ ) | |  | |__   
| |\/| | | |    | |    | || | |_ |/ _ \/\ |  |  __|  
| |  | |_| |_   | |   _| || |__| | (_>  < |  | |____ 
|_|  |_|_____|  |_|  |_____\_____|\___/\/_|  |______|

Machine Interrogation To Identify Gaps & Techniques for Execution");
        }

        public static void PrintTactic(string tactic)
        {
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Magenta;
            Console.Write("=====( ");
            Console.ForegroundColor = ConsoleColor.DarkGreen;
            Console.Write(tactic);
            Console.ForegroundColor = ConsoleColor.Magenta;
            var PadWidth = Math.Max(Console.WindowWidth - tactic.Length - 12, 1);
            Console.Write(" )".PadRight(PadWidth, '='));
            Console.WriteLine();
            Console.ResetColor();
        }

        public static void PrintLegend()
        {
            //[i] : Technique Testing Start
            //[*] : SubTechnique Testing Start
            //[?] : Test Information
            //[!] : Testing Error

            Console.WriteLine("    Legend:");

            Console.WriteLine();
            Console.Write("".PadRight(9));
            Console.Write("[");
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.Write("i");
            Console.ResetColor();
            Console.Write("]".PadRight(11));
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("Technique mitigation enumeration start");
            Console.ResetColor();

            Console.Write("".PadRight(9));
            Console.Write("[");
            Console.ForegroundColor = ConsoleColor.DarkYellow;
            Console.Write("*");
            Console.ResetColor();
            Console.Write("]".PadRight(11));
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("Subtechnique mitigation enumeration start");
            Console.ResetColor();

            Console.Write("".PadRight(9));
            Console.Write("[");
            Console.ForegroundColor = ConsoleColor.Blue;
            Console.Write("?");
            Console.ResetColor();
            Console.Write("]".PadRight(11));
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("Mitigation enumeration start");
            Console.ResetColor();

            Console.Write("".PadRight(9));
            Console.Write("[");
            Console.ForegroundColor = ConsoleColor.DarkRed;
            Console.Write("!");
            Console.ResetColor();
            Console.Write("]".PadRight(11));
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("Enumeration failed");
            Console.ResetColor();

            Console.Write("".PadRight(9));
            Console.ForegroundColor = ConsoleColor.DarkGreen;
            Console.Write("Yes".PadRight(13));
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("Mitigation was detected");
            Console.ResetColor();

            Console.Write("".PadRight(9));
            Console.ForegroundColor = ConsoleColor.Red;
            Console.Write("No".PadRight(13));
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("Mitigation was not detected");
            Console.ResetColor();

            Console.Write("".PadRight(9));
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write("Partially".PadRight(13));
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("Mitigation was partially detected");
            Console.ResetColor();

            Console.Write("".PadRight(9));
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write("NotAutomated".PadRight(13));
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("No automatic mitigation enumeration is possible");
            Console.ResetColor();

            Console.WriteLine();
        }

        public static void PrintUsage()
        {
            Console.WriteLine("Usage: Mitigate.exe OutFile");
            Console.WriteLine("       OutFile: The file name of the resulting JSON file. Can be imported into the ATT&CK Navigator for visualisation");
        }
        /// <summary>
        /// Prints the MITIG&TE initation message
        /// </summary>
        /// <param name="version">MITIG&TE's version</param>
        public static void PrintInit(string version)
        {
            Console.WriteLine(String.Format("Work in progress by moullos (github.com/moullos)", version));
            Console.WriteLine();
        }
        public static void PrintDict(Dictionary<string, double> dict)
        {
            foreach (KeyValuePair<string, double> kvp in dict)
            {
                Console.WriteLine("Key = {0}, Value = {1}", kvp.Key, kvp.Value);
            }
        }

        public static void PrintDict(Dictionary<string, string> dict)
        {
            foreach (KeyValuePair<string, string> kvp in dict)
            {
                Console.WriteLine("Key = {0}, Value = {1}", kvp.Key, kvp.Value);
            }
        }

        public static void PrintDict(Dictionary<string, bool> dict)
        {
            foreach (KeyValuePair<string, bool> kvp in dict)
            {
                Console.WriteLine("Key = {0}, Value = {1}", kvp.Key, kvp.Value);
            }
        }

        public static void PrintDict(Dictionary<string, Mitigation> dict)
        {
            foreach (KeyValuePair<string, Mitigation> kvp in dict)
            {
                Console.WriteLine("Key = {0}, Value = {1}", kvp.Key, kvp.Value);
            }
        }

        public static void PrintDict(List<Dictionary<string, string>> listdict)
        {
            if (listdict.Count > 0)
            {
                foreach (Dictionary<string, string> dict in listdict)
                {
                    PrintDict(dict);
                }
            }
        }

        public static void PrintWarning(string warning)
        {
            Console.Write("-> ");
            Console.WriteLine(warning);
        }

        public static void PrintError(string error)
        {
            Console.Write("-> ");
            Console.WriteLine(error);
        }

        public static void PrintTechniqueStart(string title, string id)
        {
            Console.WriteLine();
            Console.Write("[");
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.Write("i");
            Console.ResetColor();
            Console.Write("] ");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write(id.PadRight(9));
            Console.Write(" ");
            Console.ResetColor();
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.Write(title);
            Console.ResetColor();
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.ResetColor();
            Console.WriteLine();
        }
        public static void PrintSubTechniqueStart(string title, string id)
        {
            Console.Write("[");
            Console.ForegroundColor = ConsoleColor.DarkYellow;
            Console.Write("*", ConsoleColor.DarkYellow);
            Console.ResetColor();
            Console.Write("] ");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write(id.PadRight(9));
            Console.Write(" ");
            Console.ResetColor();
            Console.Write(title);
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.ResetColor();
            Console.WriteLine();
        }

        public static void ErrorPrint(string error)
        {
            Console.Write("".PadRight(14));
            Console.Write("[");
            Console.ForegroundColor = ConsoleColor.DarkRed;
            Console.Write("!");
            Console.ResetColor();
            Console.Write("] ");
            Console.Write("Failed: ");
            Console.Write(error.Trim());
            Console.WriteLine();
            Console.ResetColor();
        }

        public static void ExceptionPrint(string message)
        {
            if (Program.Arguments.Verbose == true)
            {
                Console.ForegroundColor = ConsoleColor.DarkGray;
                var value = String.Format("      [X] Exception: {0}", message);
                var PadWidth = Math.Max(Console.WindowWidth - 2, 1);
                Console.WriteLine(value.PadRight(PadWidth));
                Console.ResetColor();
            }
        }

        public static void PrintMitigationInfo(string message)
        {
            message = message.Trim();
            Console.Write("".PadRight(14));
            Console.Write("[");
            Console.ForegroundColor = ConsoleColor.Blue;
            Console.Write("?");
            Console.ResetColor();
            Console.Write("] ");
            var MaxSpace = Console.WindowWidth - 35;
            List<string> lines = WrapLines(message, MaxSpace).ToList();
            var lineCount = lines.Count();
            for (int count = 0; count < lineCount - 1; count++)
            {
                Console.WriteLine(lines[count]);
                Console.Write("".PadRight(18));
            }
            Console.Write(lines.Last());
            Console.ForegroundColor = ConsoleColor.DarkGray;
            var PadWidth = Math.Max(Console.WindowWidth - message.Length - 35, 1);
            Console.Write("".PadRight(PadWidth, '.'));
            Console.ResetColor();
        }

        public static void PrintMitigationMessage(string message)
        {
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write("".PadRight(18));
            Console.WriteLine(message.Trim());
            Console.ResetColor();
        }
        private static IEnumerable<string> WrapLines(string content, int maxSize)
        {
            if (content == null)
                throw new ArgumentNullException("str");
            if (maxSize < 1)
                throw new ArgumentException("'chunkSize' must be greater than 0.");

            for (int i = 0; i < content.Length; i += maxSize)
                yield return content.Substring(i, Math.Min(maxSize, content.Length - i));
        }

        public static void PrintSubInfo(string InfoTopic)
        {
            InfoTopic = InfoTopic.Trim();
            Console.Write("".PadRight(17));
            Console.Write("-> ");
            var MaxSpace = Console.WindowWidth - 37;
            List<string> lines = WrapLines(InfoTopic, MaxSpace).ToList();
            var lineCount = lines.Count();
            for (int count = 0; count < lineCount - 1; count++)
            {
                Console.WriteLine(lines[count]);
                Console.Write("".PadRight(20));
            }
            Console.Write(lines.Last());
            Console.ForegroundColor = ConsoleColor.DarkGray;
            var PadWidth = Math.Max(Console.WindowWidth - lines.Last().Length - 37, 1);
            Console.Write("".PadRight(PadWidth, '.'));
            Console.ResetColor();
        }

        public static void PrintMitigationResult(Mitigation result)
        {
            if (result == Mitigation.True)
            {
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write("".PadRight(9, '.'));
                Console.ForegroundColor = ConsoleColor.DarkGreen;
                Console.WriteLine("Yes");
                Console.ResetColor();
            }
            else if (result == Mitigation.False)
            {
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write("".PadRight(10, '.'));
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("No");
                Console.ResetColor();
            }
            else if (result == Mitigation.NA)
            {
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write("".PadRight(9, '.'));
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine("N/A");
                Console.ResetColor();
            }
            else if (result == Mitigation.TestFailed)
            {
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write("".PadRight(6, '.'));
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("Failed");
                Console.ResetColor();
            }
            else if (result == Mitigation.Partial)
            {
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write("".PadRight(3, '.'));
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("Partially");
                Console.ResetColor();
            }
            else if (result == Mitigation.CannotBeMeasured)
            {
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine("NotAutomated");
                Console.ResetColor();
            }
        }

        // https://stackoverflow.com/questions/13656846/how-to-programmatic-disable-c-sharp-console-applications-quick-edit-mode

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr GetStdHandle(int nStdHandle);

        [DllImport("kernel32.dll")]
        static extern bool GetConsoleMode(IntPtr hConsoleHandle, out uint lpMode);

        [DllImport("kernel32.dll")]
        static extern bool SetConsoleMode(IntPtr hConsoleHandle, uint dwMode);

        public static bool DisableConsoleQuickEdit()
        {

            const uint ENABLE_QUICK_EDIT = 0x0040;

            // STD_INPUT_HANDLE (DWORD): -10 is the standard input device.
            const int STD_INPUT_HANDLE = -10;
            IntPtr consoleHandle = GetStdHandle(STD_INPUT_HANDLE);

            // get current console mode
            uint consoleMode;
            if (!GetConsoleMode(consoleHandle, out consoleMode))
            {
                // ERROR: Unable to get console mode.
                return false;
            }

            // Clear the quick edit bit in the mode flags
            consoleMode &= ~ENABLE_QUICK_EDIT;

            // set the new mode
            if (!SetConsoleMode(consoleHandle, consoleMode))
            {
                // ERROR: Unable to set console mode
                return false;
            }
            else
            {
                return true;
            }
        }
    }
}

