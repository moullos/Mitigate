using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Runtime.CompilerServices;
using System.Security.Policy;

namespace Mitigate
{
    class Program
    {
        // CLI ARGS TO BE
        public static bool verbose = false;
        public static bool ExportCoverage = true;
        public static string Url = @"https://raw.githubusercontent.com/mitre/cti/subtechniques/enterprise-attack/enterprise-attack.json";

        public static List<string> InterestingUsers;
        public static bool IsDomainJoined;
        public static string version="WIP";
        public static void Main(string[] args)
        {


            /////////////////////
            /// Initial setup ///
            /////////////////////
            if (args.Length == 0)
            {
                PrintUtils.PrintUsage();
                System.Environment.Exit(1);
            }
            string Outfile = args[0];
            PrintUtils.PrintBanner();
            PrintUtils.PrintInit(version);
            AttackCTI ATTCK = new AttackCTI(Url);
            Navigator navigator = new Navigator();


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

            navigator.ToJSON(Outfile);
            if (ExportCoverage)
                navigator.ExportCoverage("Coverage.json");
        }
    }
}

