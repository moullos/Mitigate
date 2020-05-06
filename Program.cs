using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Policy;

namespace Mitigate
{
    class Program
    {
        // CLI ARGS TO BE
        public static bool verbose = false;
        public static bool ExportCoverage = true;
        public static string Outfile = "test.json";

        public static List<string> InterestingUsers;
        public static bool IsDomainJoined;
        public static string version;
        public static void Main(string[] args)
        {
            /////////////////////
            /// Initial setup ///
            /////////////////////
            AttackCTI ATTCK = new AttackCTI(@"C:\Users\Panayiotis\source\repos\Mitigate\enterprise-attack.json");
            Navigator navigator = new Navigator();
            version = "WIP";
            PrintUtils.PrintBanner();
            PrintUtils.PrintInit(version);

            Console.WriteLine("Collecting some machine information. This might take some time...");
            InterestingUsers = UserUtils.GetInterestingUsers();
            IsDomainJoined = SystemUtils.IsDomainJoined();

            Console.OutputEncoding = System.Text.Encoding.UTF8;

            /////////////////
            /// Main Loop ///
            /////////////////
            HashSet<string> TestedTechniques = new HashSet<string>();
            // For all tactics
            foreach (string tactic in ATTCK.GetAllTactics())
            {
                PrintUtils.PrintTactic(tactic);
                // For all techniques
                foreach (Technique technique in ATTCK.GetRootTechniquesByTactic(tactic))
                {
                    Console.WriteLine(technique.GetID() + ":" + technique.GetName());
                    // Check if the technique has been already tested 
                    if (TestedTechniques.Contains(technique.GetID()))
                    {
                        // If it has:
                        continue;
                    }
                    TestedTechniques.Add(technique.GetID());
                    var subtechniques = ATTCK.GetSubTechniquesByTechnique(technique);
                    // Does it have subtechniques?
                    if (subtechniques.Count() > 0)
                    {
                        // Subtechniques found. Handle them
                        Tests.Execute(technique, subtechniques, navigator);
                    }
                    else
                    {
                        // No subtechniques. Just handle root technique
                        Tests.Execute(technique, navigator);
                    }
                }
            }


            /*

            // INITIAL ACCESS TECHNIQUES
            PrintUtils.PrintTactic("Initial Access");

            PrintUtils.PrintTechniqueStart("Phishing", "T1566");
            navigator.AddTechnique("T1566", Tests.T1566_001(), Tests.T1566_002(), Tests.T1566_003());

            PrintUtils.PrintTechniqueStart("Valid Accounts", "T1078");
            navigator.AddTechnique("T1078", Tests.T1078_001(), Tests.T1078_002(), Tests.T1078_003());

            // EXECUTION TECHNIQUES
            PrintUtils.PrintTactic("Execution Techniques");

            PrintUtils.PrintTechniqueStart("Inter-Process Communication", "T1559");
            navigator.AddTechnique("T1559", Tests.T1559_001(), Tests.T1559_002());

            PrintUtils.PrintTechniqueStart("Command and Scripting Interpreter", "T1059");
            navigator.AddTechnique("T1059", 
                Tests.T1059_001(), 
                Tests.NotApplicableSubTechnique(),
                Tests.T1059_003(),
                Tests.NotApplicableSubTechnique(),
                Tests.T1059_005(),
                Tests.T1059_006()
                );

            PrintUtils.PrintTechniqueStart("Exploitation for Client Execution","T1203");
            navigator.AddTechnique("T1203", Tests.T1203());

            PrintUtils.PrintTechniqueStart("Native API", "T1106");
            navigator.AddTechnique("T1106", Tests.T1106());

            PrintUtils.PrintTechniqueStart("Scheduled Task/Job", "T1053");
            navigator.AddTechnique("T1053",
                Tests.NotApplicableSubTechnique(),
                Tests.T1053_002(),
                Tests.NotApplicableSubTechnique(),
                Tests.NotApplicableSubTechnique(),
                Tests.T1053_005()
                );

            PrintUtils.PrintTechniqueStart("BITS Jobs", "T1197");
            navigator.AddTechnique("T1197", Tests.T1197());

            PrintUtils.PrintTechniqueStart("Windows Management Instrumentation", "T1047");
            navigator.AddTechnique("T1047", Tests.T1047());

            PrintUtils.PrintTechniqueStart("Boot or Logon Autostart Execution", "T1547");
            navigator.AddTechnique("T1547",
                Tests.T1547_001(),
                Tests.T1547_002(),
                Tests.T1547_003(),
                Tests.T1547_004(),
                Tests.T1547_005(),
                Tests.NotApplicableSubTechnique(),
                Tests.NotApplicableSubTechnique(),
                Tests.T1547_008(),
                Tests.T1547_009(),
                Tests.T1547_010(),
                Tests.NotApplicableSubTechnique()
                );

            PrintUtils.PrintTechniqueStart("Boot or Logon Initialization Scripts", "T1037");
            navigator.AddTechnique("T1037",
                Tests.T1037_001(),
                Tests.NotApplicableSubTechnique(),
                Tests.T1037_003()
                );

            PrintUtils.PrintTechniqueStart("Browser Extensions", "T1176");
            navigator.AddTechnique("T1176", Tests.T1176());
            */

            navigator.ToJSON(Outfile);
            if (ExportCoverage)
                navigator.ExportCoverage("Coverage.json");
        }
    }
}

