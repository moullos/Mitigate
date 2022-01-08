using Mitigate.Enumerations;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Web.Script.Serialization;

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
        public bool showSubtechniques { get; set; }
        public IList<Metadata> metadata { get; set; }

        internal NTechnique(string techniqueID, List<Enumeration> techniqueEnumerations)
        {
            this.techniqueID = techniqueID;
            this.enabled = true;
            this.showSubtechniques = true;
            AddMetadata(techniqueEnumerations);
            AddColor(techniqueEnumerations);
        }

        internal void AddMetadata(IEnumerable<Enumeration> RelevantEnumerations)
        {
            if (RelevantEnumerations == null || !RelevantEnumerations.Any())
                throw new ArgumentNullException("AddMetadata called with no relevant enumerations");

            this.metadata = new List<Metadata>();

            // Sorting alphabetically using the MitigationType
            RelevantEnumerations = RelevantEnumerations.OrderBy(s => s.MitigationType);
            foreach (var enumeration in RelevantEnumerations)
            {
                var topLine = new Metadata("------------", " ");
                var Title = new Metadata("Mitigation Name", enumeration.Name);
                var MitigationType = new Metadata("Mitigation Type", enumeration.MitigationType);
                var Description = new Metadata("Description", enumeration.MitigationDescription);
                var Results = new Metadata("Findings", String.Join(",", enumeration.Results.Select(o => o.ToString())));

                this.metadata.Add(topLine);
                this.metadata.Add(Title);
                this.metadata.Add(MitigationType);
                this.metadata.Add(Description);
                this.metadata.Add(Results);
            }
        }
        internal void AddResults(Enumeration enumeration)
        {
            foreach (var result in enumeration.Results)
            {
                this.metadata.Add(new Metadata(result.Info, result.ToResultType().ToString()));
            }
        }

        private void AddColor(List<Enumeration> TechniqueEnumerations)
        {
            //var TechniqueResults = TechniqueEnumerations.Select(o => o.Results).ToList().Aggregate((i, j) => i.Union(j)).Select(o => o.ToResultType());

            var TechniqueResults = new List<ResultType>();
            foreach (var techniqueResults in TechniqueEnumerations.Select(o => o.Results))
            {
                TechniqueResults.AddRange(techniqueResults.Select(o=>o.ToResultType()));
            }
            if (!TechniqueResults.Any())
                throw new ArgumentException($"Add Color for Technique {this.techniqueID} failed. " +
                    $"Probably a bug. Do you want to try and fix it?");
            // if all mitigation are detected
            if (TechniqueResults.All(o => o == ResultType.True))
            {
                this.color = ColorPalette.AllMItigationDetected;
                return;
            }
            // if no mitigation where detected
            if (TechniqueResults.All(o => o == ResultType.False))
            {
                this.color = ColorPalette.NoMitigationsDetected;
                return;
            }
            if (TechniqueResults.All(o=> o == ResultType.NoMitigationAvailable))
            {
                this.color = ColorPalette.NoMitigationsAvailable;
                return;
            }
            if (TechniqueResults.All(o => o == ResultType.TestFailed))
            {
                this.color = ColorPalette.Error;
                return;
            }
            if (TechniqueResults.All(o => o == ResultType.CannotBeMeasured))
            {
                this.color = ColorPalette.White;
                return;
            }
            if (TechniqueResults.All(o => o == ResultType.TestNotImplemented))
            {
                this.color = ColorPalette.White;
                return;
            }
            if (TechniqueResults.Contains(ResultType.True) || TechniqueResults.Contains(ResultType.Partial))
            {
                this.color = ColorPalette.SomeMitigations;
                return;
            }
            else
            {
                this.color = ColorPalette.NoMitigationsDetected;
            }

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

    internal class Gradient
    {
        public IList<string> colors { get; set; }
        public int minValue { get; set; }
        public int maxValue { get; set; }
    }

    public class NavigatorVersion
    {
        public string attack { get;  private set; }
        public string navigator { get; private set; }
        public string layer { get; private set; }
        public NavigatorVersion(string attack, string navigator, string layer)
        {
            this.attack = attack;
            this.navigator = navigator;
            this.layer = layer;
        }

    } 
    /// <summary>
    /// Navigator options inline with the navigator layer file format definition v4.2
    /// https://github.com/mitre-attack/attack-navigator/blob/master/layers/LAYERFORMATv4_2.md
    /// </summary>
    public class Navigator
    {

        public string name { get; set; }
        public NavigatorVersion versions { get; set; }
        public string domain;
        public string description { get; set; }
        public Filters filters = new Filters();
        public Layout layout = new Layout();
        public int sorting { get; set; }
        public IList<Legenditem> legendItems = new List<Legenditem>();
        public int viewMode { get; set; }
        public IList<NTechnique> techniques = new List<NTechnique>();
        private Gradient gradient = new Gradient();
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
            versions = new NavigatorVersion("10", "4.5.1", "4.3");
            name = "Output";
            domain = "mitre-enterprise";
            description = "Output of the Mitig&te project";
            filters.stages.Add("act");
            filters.platforms.Add("Windows");
            sorting = 0;
            gradient.colors = new List<string>() { "#ffffff", "#4dd2fb", "#0c1b33" };
            showTacticRowBackground = false;
            tacticRowBackground = "#dddddd";
            selectTechniquesAcrossTactics = true;
            hideDisabled = true;
            layout.layout = "flat";
            layout.showName = true;
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
            var JSON = new JavaScriptSerializer();
            JSON.MaxJsonLength = int.MaxValue;
            string JSONresult = JSON.Serialize(this);
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
            var JSON = new JavaScriptSerializer();
            JSON.MaxJsonLength = int.MaxValue;
            string JSONresult = JSON.Serialize(this);
            using (var tw = new StreamWriter(filename))
            {
                tw.WriteLine(JSONresult.ToString());
                tw.Close();
            }
        }

        internal void IngestResults(IEnumerable<Enumeration> ExecutedEnumerations)
        {
            if (ExecutedEnumerations == null || !ExecutedEnumerations.Any())
                throw new ArgumentNullException();

            var AlltechniqueIds = ExecutedEnumerations.Select(o => o.Techniques).Aggregate((i, j) => i.Union(j).ToArray());

            foreach (var techniqueId in AlltechniqueIds)
            {
                // Create the technique object
                var RelevantEnumerations = ExecutedEnumerations.Where(o => o.Techniques.Contains(techniqueId)).ToList();
                var technique = new NTechnique(techniqueId, RelevantEnumerations);

                // Add to the list
                this.techniques.Add(technique);
            }
        }

    }
}