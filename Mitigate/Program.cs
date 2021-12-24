using System;
using System.Collections.Generic;
using System.DirectoryServices.AccountManagement;
using System.Globalization;
using System.Linq;
using System.Reflection;
using System.Text.RegularExpressions;
using Mitigate.Enumerations;
using Mitigate.Utils;

namespace Mitigate
{
    class Program
    {

        // Some static values and global vars
        public static string AttackUrl = @"https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json";
        public static List<string> SIDsToCheck;
        public static bool IsDomainJoined;
        public static string version = "WIP";
        public static MitigateArguments Arguments;
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
                Arguments = new MitigateArguments(args);
            }
            catch (Exception ex)
            {
                PrintUtils.Error(ex.Message);
                MitigateArguments.PrintUsage();
                Environment.Exit(1);
            }

            PrintUtils.PrintBanner();
            PrintUtils.PrintInit(version);
            PrintUtils.PrintLegend();
            IsDomainJoined = SystemUtils.IsDomainJoined();

            // Collect all implemented enumeration classes
            var AllEnumerations = new List<Enumeration>();

            foreach (var type in Assembly.GetExecutingAssembly().GetTypes())
            {
                if (!type.IsSubclassOf(typeof(Enumeration)) || type.IsAbstract)
                    continue;
                var instance = (Enumeration)Activator.CreateInstance(type);
                AllEnumerations.Add(instance);
            }


            // Check for the GenerateDocumentation flag
            if (!string.IsNullOrEmpty(Arguments.GenerateDocumentation))
            {
                PrintUtils.Warning("The GenerateDocumentation argument was set. The program will just generated the documentation for enumerations and then exit");
                AttackCTI Attack = new AttackCTI(AttackUrl);
                var test = Attack.GetAllMitigationTypes();
                TextInfo textInfo = new CultureInfo("en-US", false).TextInfo;
                using (var tw = new System.IO.StreamWriter("asdfadsfsad"))
                {

                foreach (var item in test)
                {
                    tw.WriteLine("public const string " + Regex.Replace(textInfo.ToTitleCase(item), @"\s+", "").Replace("/", "").Replace("-", "") + " = " + "\"" + item + "\";");

                }
                }

                DocumentationGeneration.CreateEnumerationCoveragePerMitigationType(AllEnumerations, Attack, Arguments.GenerateDocumentation);
                Environment.Exit(0);
            }

            // Check for the GenerateTracker flag
            if (!string.IsNullOrEmpty(Arguments.GenerateTracker))
            {
                PrintUtils.Warning("The GenerateTracker argument was set.The program will just generated the documentation for enumerations and then exit");
                AttackCTI Attack = new AttackCTI(AttackUrl);
                TrackerGeneration.CreateTracker(AllEnumerations, Attack, Arguments.GenerateTracker);
                Environment.Exit(0);
            }

            // Instanciate the navigator object
            Navigator navigator = null;
            try
            {
                navigator = new Navigator();
            }
            catch (Exception ex)
            {
                PrintUtils.Error(ex.Message);
                Environment.Exit(1);
            }

            // Check if it's running as admin
            if (!UserUtils.IsItRunningAsAdmin())
            {
                PrintUtils.Warning("Mitigate is not running as an administrator." +
                    " This might restrict its ability to perform the necessary checks");
            }
            
            // Getting some user info and deciding the user for least priv checks
            PrintUtils.Warning("Collecting some machine information. This might take some time...");
            if (!string.IsNullOrEmpty(Arguments.Username))
            {
                try
                {
                    UserToCheck = UserUtils.GetUser(Arguments.Username);
                    SIDsToCheck = UserUtils.GetGroups(UserToCheck);
                }
                catch (Exception ex)
                {
                    PrintUtils.Error(ex.Message);
                    PrintUtils.Error(ex.StackTrace);
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
                    PrintUtils.Error(ex.Message);
                    Environment.Exit(1);
                }
            }
            PrintUtils.Warning($"Least privilege checks will be performed for user {UserToCheck.SamAccountName}");

            // Get all mitigation types in alphabetical order 
            var AllMitigationTypes = AllEnumerations.
                                        Select(o => o.MitigationType).
                                        Distinct().
                                        OrderBy(s => s);



            ///////////////
            // MAIN LOOP //
            ///////////////

            // Execute all enumerations for all mitigation types
            Context context = new Context(UserToCheck, SIDsToCheck, Arguments, SystemUtils.IsDomainJoined());
            foreach (var MitigationType in AllMitigationTypes)
            {
                PrintUtils.PrintTactic(MitigationType);
                var RelevantEnumerations = AllEnumerations.Where(o => o.MitigationType == MitigationType);
                foreach (var enumeration in RelevantEnumerations)
                {
                    enumeration.Execute(context);
                }
            }

            // Adding the enumeration results to the navigator
            navigator.IngestResults(AllEnumerations);

            // Exporting the navigator in the json format and outputing
            navigator.ToJSON(Arguments.OutFile);


            // Exporting the coverage file for the navigator if it was request in the arguments
            if (Arguments.ExportCoverage)
                navigator.ExportCoverage("Coverage.json");
        }
    }
}

