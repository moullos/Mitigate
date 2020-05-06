using System;
using System.Collections.Generic;
using System.Net.NetworkInformation;
using System.Text;

namespace Mitigate
{
    class PrintUtils
    {
        public static void PrintBanner()
        {
            Console.WriteLine(@" 
 __  __ _____ _______ _____ _____     _______ ______ 
|  \/  |_   _|__   __|_   _/ ____| __|__   __|  ____|
| \  / | | |    | |    | || |  __ ( _ ) | |  | |__   
| |\/| | | |    | |    | || | |_ |/ _ \/\ |  |  __|  
| |  | |_| |_   | |   _| || |__| | (_>  < |  | |____ 
|_|  |_|_____|  |_|  |_____\_____|\___/\/_|  |______|
");
        }

        public static void PrintTactic(string tactic)
        {
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Magenta;
            Console.Write("=====( ");
            Console.ForegroundColor = ConsoleColor.DarkGreen;
            Console.Write(tactic);
            Console.ForegroundColor = ConsoleColor.Magenta;
            Console.Write(" )".PadRight(Console.WindowWidth - 7 - tactic.Length - 10, '='));
            Console.WriteLine();
            Console.ResetColor();
        }
        public static void PrintInit(string version)
        {
            Console.WriteLine(String.Format("MITIG&TE v{0} by Panos Moullotou", version));
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
        public static void PrintTechniqueStart(string title, string id)
        {
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
            Console.Write("".PadRight(Console.WindowWidth - 9 - 5 - title.Length - 10, '.'));
            Console.ResetColor();
            Console.WriteLine();
        }
        public static void PrintSubTechniqueStart(string combined)
        {
            string[] tokens = combined.Split(':');
            PrintSubTechniqueStart(tokens[0].Trim(), tokens[1].Trim());
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
            Console.Write("".PadRight(Console.WindowWidth - 9 - 5 - title.Length - 10, '.'));
            Console.ResetColor();
            Console.WriteLine();
        }

        public static void ErrorPrint(string error)
        {
            Console.Write("[");
            Console.ForegroundColor = ConsoleColor.DarkRed;
            Console.Write("!");
            Console.ResetColor();
            Console.Write("] ");
            Console.Write("".PadRight(10));
            Console.Write(error.Trim());
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("".PadRight(Console.WindowWidth - error.Trim().Length - 10 - 14, '.'));
            Console.ResetColor();
        }

        public static void ExceptionPrint(string message)
        {
            if (Program.verbose == true)
            {
                Console.ForegroundColor = ConsoleColor.DarkGray;
                var value = String.Format("      [X] Exception: {0}", message);
                Console.WriteLine(value.PadRight(Console.WindowWidth - 1));
                Console.ResetColor();
            }
        }

        public static void PrintInfo(string message)
        {
            Console.Write("".PadRight(14));
            Console.Write(message.Trim());
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write("".PadRight(Console.WindowWidth - message.Trim().Length - 10 - 15, '.'));
            Console.ResetColor();
        }

        public static void PrintResult(Mitigation result)
        {
            if (result == Mitigation.True)
            {
                Console.ForegroundColor = ConsoleColor.DarkGreen;
                Console.WriteLine("\u221a");
                Console.ResetColor();
            }
            else if (result == Mitigation.False)
            {
                Console.ForegroundColor = ConsoleColor.DarkRed;
                Console.WriteLine("X");
                Console.ResetColor();
            }
            else if (result == Mitigation.NoMitigationAvailable)
            {
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine(".");
                Console.ResetColor();
            }
            else if (result == Mitigation.Failed)
            {
                Console.ForegroundColor = ConsoleColor.DarkRed;
                Console.WriteLine("!");
                Console.ResetColor();
            }
        }

    }
}
