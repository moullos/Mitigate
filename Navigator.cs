using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Mitigate
{


    public static class ColorPalette
    {
        public static string NoMitigationsDetected = "#f4a261";
        public static string SomeMitigations = "#e9c46a";
        public static string AllMItigationDetected = "#2a9d8f";
        public static string White = "#ffffff";
        public static string NoMitigationsAvailable = "#009ACD";
        public static string Covered = "#9e9ac8";
        public static string Error = "#d62c08";

    }

    public class Layout
    {
        public string layout { get; set; }
        public bool showID { get; set; }
        public bool showName { get; set; }
    }

    public class Filters
    {
        public IList<string> stages { get; set; }
        public IList<string> platforms { get; set; }
    }

    public class Metadata
    {
        public Metadata(string name, string value)
        {
            this.name = name;
            this.value = value;
        }
        public string name { get; set; }
        public string value { get; set; }
    }
    /// <summary>
    /// Navigator Technique object matching the technique format expected by the ATT&CK navigator
    /// </summary>
    public class NTechnique
    {
        public string techniqueID { get; set; }
        public string color { get; set; }
        public bool enabled { get; set; }
        // public double score { get; set; }
        public IList<Metadata> metadata { get; set; }
        //Constructor for root techniques with subtechniques
        public NTechnique(string rootTechniqueID, List<string> subTechniquesColors)
        {
            this.techniqueID = rootTechniqueID;
            this.color = this.PopulateColor(subTechniquesColors);
            if (this.color == ColorPalette.NoMitigationsAvailable)
                this.enabled = Program.Arguments.ShowUnmitigatableTechnique;
            else
                this.enabled = true;
            this.metadata = new List<Metadata>();
        }
        // Constructor for sub techniques and root techniques for not subtechniques. 
        public NTechnique(string techniqueID, Dictionary<string, Mitigation> results)
        {
            this.techniqueID = techniqueID;
            this.color = this.PopulateColor(results);
            if (this.color == ColorPalette.NoMitigationsAvailable)
                this.enabled = Program.Arguments.ShowUnmitigatableTechnique;
            else
                this.enabled = true;
            this.PopulateMetadata(results);
        }
        /// <summary>
        /// Technique metadata contains the mitigation info gathered by the tool. This takes the MitigationInfo and populates the navigator technique metadata
        /// </summary>
        /// <param name="MitigationInfo">The mitigation info gather by the tool for a particular technique</param>
        private void PopulateMetadata(Dictionary<string, Mitigation> MitigationInfo)
        {
            this.metadata = new List<Metadata>();
            foreach (KeyValuePair<string, Mitigation> entry in MitigationInfo)
            {
                this.metadata.Add(new Metadata(entry.Key, entry.Value.ToString()));
            }
        }
        /// <summary>
        /// Method that sets the Color of a Technique in the navigator based on the info collected. 
        /// Applies to subtechniques or techniques with no subtechniques
        /// </summary>
        /// <param name="MitigationInfo">>The mitigation info gather by the tool for a particular technique</param>
        private string PopulateColor(Dictionary<string, Mitigation> MitigationInfo)
        {
            // Method that generated a score/color based on the results.
            List<Mitigation> MitigationResults = MitigationInfo.Values.ToList();

            if (MitigationResults.Count() == 0)
                return ColorPalette.White;

            if (MitigationResults.Count() == 1 && MitigationResults[0] == Mitigation.TestNotImplemented)
                return ColorPalette.White;

            // Check if the technique cannot be mitigated
            if (MitigationResults.Count() == 1 && MitigationResults[0] == Mitigation.NoMitigationAvailable)
                return ColorPalette.NoMitigationsAvailable;

            // if all mitigations are applied
            if (MitigationResults.All(o => o == Mitigation.True))
                return ColorPalette.AllMItigationDetected;

            // if at least some mitigations are applied
            if (MitigationResults.Contains(Mitigation.True) || MitigationResults.Contains(Mitigation.Partial))
                return ColorPalette.SomeMitigations;

            // Else no mitigations are applied or none where detected. 
            return ColorPalette.NoMitigationsDetected;
        }

        /// <summary>
        /// Method that sets the Color of a rootTechnique based on the colour of the subtechniques
        /// </summary>
        /// <param name="subTechniquesColors">List of the colours of the other subtechniques</param>
        private string PopulateColor(List<string> subTechniquesColors)
        {
            // If all subtehcniques are fully mitigated, then root technique is fully mitigated;
            if (subTechniquesColors.All(o => o == ColorPalette.AllMItigationDetected))
                return ColorPalette.AllMItigationDetected;
            // If all are not mitigated
            if (subTechniquesColors.All(o => o == ColorPalette.NoMitigationsDetected))
                return ColorPalette.NoMitigationsDetected;
            // If all cannot be mitigated
            if (subTechniquesColors.All(o => o == ColorPalette.NoMitigationsAvailable))
                return ColorPalette.NoMitigationsAvailable;
            // If no tests are defined or can't be mitigated
            if (subTechniquesColors.All(o => o == ColorPalette.NoMitigationsAvailable || o == ColorPalette.White))
                return ColorPalette.White;
            return ColorPalette.SomeMitigations;
        }
    }
    public class Legenditem
    {
        public Legenditem(string label, string color)
        {
            this.label = label;
            this.color = color;
        }
        public string label { get; set; }
        public string color { get; set; }
    }

    public class Gradient
    {
        public IList<string> colors { get; set; }
        public int minValue { get; set; }
        public int maxValue { get; set; }
    }

    public class Navigator
    {

        public string name { get; set; }
        public string version { get; set; }
        public string domain { get; set; }
        public string description { get; set; }
        public Filters filters = new Filters();
        public Layout layout = new Layout();
        public int sorting { get; set; }
        public IList<Legenditem> legendItems = new List<Legenditem>();
        public int viewMode { get; set; }
        public IList<NTechnique> techniques = new List<NTechnique>();
        public Gradient gradient = new Gradient();
        public IList<object> metadata = new List<object>();
        public bool showTacticRowBackground { get; set; }
        public string tacticRowBackground { get; set; }
        public bool selectTechniquesAcrossTactics { get; set; }
        public bool hideDisabled { get; set; }
        /// <summary>
        /// Navigator constructor setting up some required values
        /// </summary>
        public Navigator()
        {
            filters.stages = new List<string>();
            filters.platforms = new List<string>();
            name = "Output";
            version = "3.0";
            domain = "mitre-enterprise";
            description = "Output of the Mitig&te project";
            filters.stages.Add("act");
            filters.platforms.Add("Windows");
            sorting = 0;
            viewMode = 0;
            gradient.colors = new List<string>() { "#ffffff", "#4dd2fb", "#0c1b33" };
            showTacticRowBackground = false;
            tacticRowBackground = "#dddddd";
            selectTechniquesAcrossTactics = true;
            hideDisabled = true;
            layout.layout = "flat";
            this.CreateLegend();

        }
        public void CreateLegend()
        {
            var items = new Dictionary<string, string>
            {
                { "All mitigations were detected", ColorPalette.AllMItigationDetected },
                { "Some mitigations were detected", ColorPalette.SomeMitigations },
                { "No mitigation were detected", ColorPalette.NoMitigationsDetected },
                { "Technique can't be mitigated", ColorPalette.NoMitigationsAvailable }
            };
            foreach (var item in items)
            {
                legendItems.Add(new Legenditem(item.Key, item.Value));
            }
        }
        public void CreateCoverageLegend()
        {
            legendItems.Clear();
            var items = new Dictionary<string, string>
            {
                { "Some mitigation enumeration implemented", ColorPalette.Covered },
                { "Technique can't be mitigated", ColorPalette.NoMitigationsAvailable }
            };
            foreach (var item in items)
            {
                legendItems.Add(new Legenditem(item.Key, item.Value));
            }
        }
        /// <summary>
        /// Method that creates a JSON file containing the results that can be ingested for the ATT&CK navigator
        /// </summary>
        /// <param name="filename">Filename to export the JSON to</param>
        public void ToJSON(string filename)
        {
            string JSONresult = JsonConvert.SerializeObject(this);
            using (var tw = new StreamWriter(filename))
            {
                tw.WriteLine(JSONresult.ToString());
                tw.Close();
            }
        }
        /// <summary>
        /// Method that creates a JSON file summarizing the technique coverage of the tool. 
        /// </summary>
        /// <param name="filename">Filename to export the JSON to</param>
        public void ExportCoverage(string filename)
        {
            this.name = "Coverage";
            this.description = "Coverage of the MITIG&TE project";
            CreateCoverageLegend();
            foreach (NTechnique technique in this.techniques)
            {
                technique.metadata.Clear();
                //technique.score = 0;
                if (technique.color != ColorPalette.NoMitigationsAvailable && technique.color != ColorPalette.White)
                    technique.color = ColorPalette.Covered;
                
            }
            string JSONresult = JsonConvert.SerializeObject(this);
            using (var tw = new StreamWriter(filename))
            {
                tw.WriteLine(JSONresult.ToString());
                tw.Close();
            }
        }
        // Method for adding techniques with no subtecniques
        public void AddMitigationInfo(Technique technique, Dictionary<string, Mitigation> MitigationInfo)
        {
            // Creating a new navigation technique object for the technique
            NTechnique NavigatorTechnique = new NTechnique(technique.GetID(), MitigationInfo);
            // Adding the technique to the list of processed techniques
            this.techniques.Add(NavigatorTechnique);
        }
        // Method for adding technique with subtechniques
        public void AddMitigationInfo(Technique rootTechnique, List<string> subTechniqueIDs, List<Dictionary<string, Mitigation>> subTechniqueResults)
        {
            List<string> subTechniquesColors = new List<string>();
            // Adding subtechniques
            foreach (var item in subTechniqueIDs.Zip(subTechniqueResults, Tuple.Create))
            {
                var subTechniqueID = item.Item1;
                var MitigationInfo = item.Item2;
                NTechnique subTechnique = new NTechnique(subTechniqueID, MitigationInfo);
                this.techniques.Add(subTechnique);
                subTechniquesColors.Add(subTechnique.color);
            }
            // Adding root technique
            NTechnique NavigatorRootTechnique = new NTechnique(rootTechnique.GetID(), subTechniquesColors);
            this.techniques.Add(NavigatorRootTechnique);
        }
    }
}