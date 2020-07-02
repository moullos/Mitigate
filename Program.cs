using System;
using System.Collections.Generic;
using System.DirectoryServices.AccountManagement;
using System.Linq;
using System.Text.RegularExpressions;

namespace Mitigate
{
    /*
     * TODO LIST:
     * - Make print error part of mitigation result
     */
    class Program
    {
   
        // Some static values and global vars
        public static string AttackUrl = @"https://raw.githubusercontent.com/mitre/cti/subtechniques/enterprise-attack/enterprise-attack.json";
        public static List<string> SIDsToCheck;
        public static bool IsDomainJoined;
        public static string version = "WIP";
        public static MitigateArgumentParser Arguments;
        public static UserPrincipal UserToCheck;

        public static void Main(string[] args)
        {


            /////////////////////
            /// Initial setup ///
            /////////////////////
            PrintUtils.DisableConsoleQuickEdit();
            Console.OutputEncoding = System.Text.Encoding.UTF8;

            // Arg Parsing
            try
            {
                Arguments = new MitigateArgumentParser(args);
            }
            catch (Exception ex)
            {
                PrintUtils.PrintError(ex.Message);
                MitigateArgumentParser.PrintUsage();
                Environment.Exit(1);
            }


            PrintUtils.PrintBanner();
            PrintUtils.PrintInit(version);
            PrintUtils.PrintLegend();
            IsDomainJoined = SystemUtils.IsDomainJoined();

            // Check if it's running as admin
            if (!UserUtils.IsItRunningAsAdmin())
            {
                PrintUtils.PrintWarning("Mitigate is not running as an administrator." +
                    " This might restrict its ability to perform the necessary checks");
            }

            // Pulling ATT&CK json from GitHub
            AttackCTI ATTCK = new AttackCTI(AttackUrl);
            Navigator navigator = new Navigator();

            // Getting some user info and deciding the user for least priv checks
            PrintUtils.PrintWarning("Collecting some machine information. This might take some time...");
            if (!string.IsNullOrEmpty(Arguments.Username))
            {
                try
                {
                    UserToCheck = UserUtils.GetUser(Arguments.Username);
                    SIDsToCheck = UserUtils.GetGroups(UserToCheck);
                }
                catch (Exception ex)
                {
                    PrintUtils.ErrorPrint(ex.Message);
                    Environment.Exit(1);
                }
            }
            else
            {
                try
                {
                    UserToCheck = UserUtils.GetLastLoggedInUser();
                    SIDsToCheck = UserUtils.GetGroups(UserToCheck);
                }
                catch (Exception ex)
                {
                    PrintUtils.ErrorPrint(ex.Message);
                    Environment.Exit(1);
                }
            }
            PrintUtils.PrintWarning($"Least privilege checks will be performed for user {UserToCheck.SamAccountName}");
            /////////////////
            /// Main Loop ///
            /////////////////
            
            // Keeping track on tested techniques to stop from testing twice
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
                        Tests.Execute(technique, subtechniques, navigator, ATTCK);
                    }
                    else
                    {
                        // No subtechniques. Just handle root technique
                        Tests.Execute(technique, navigator, ATTCK);
                    }
                }
            }

            // Exporting the file for the navigator
            navigator.ToJSON(Arguments.OutFile);
            if (Arguments.ExportCoverage)
                navigator.ExportCoverage("Coverage.json");
        }
    }
}

