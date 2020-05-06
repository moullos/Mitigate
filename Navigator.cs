using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;

namespace Mitigate
{


    public static class ColorPallete
    {
        public static string Red = "#f4a261";
        public static string Amber = "#e9c46a";
        public static string Green = "#2a9d8f";
        public static string White = "#ffffff";
        public static string Blue = "#009ACD";
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

    public class NTechnique
    {
        public string techniqueID { get; set; }
        public string color { get; set; }
        public bool enabled { get; set; }
        public double score { get; set; }
        public IList<Metadata> metadata { get; set; }
        //Constructor for root techniques with subtechniques
        public NTechnique(string rootTechniqueID, List<double> subTechniqueScores)
        {
            this.techniqueID = rootTechniqueID;
            this.PopulateColor(subTechniqueScores);
            this.enabled = true;
            this.metadata = new List<Metadata>();
        }
        // Constructor for sub techniques and root techniques for not subtechniques. 
        public NTechnique(string techniqueID, Dictionary<string, Mitigation> results)
        {
            this.techniqueID = techniqueID;
            this.PopulateColor(results);
            this.enabled = true;
            this.PopulateMetadata(results);
        }
        private void PopulateMetadata(Dictionary<string, Mitigation> results)
        {
            this.metadata = new List<Metadata>();
            foreach (KeyValuePair<string, Mitigation> entry in results)
            {
                this.metadata.Add(new Metadata("-" + entry.Key, entry.Value.ToString()));
            }
        }
        private void PopulateColor(Dictionary<string, Mitigation> results)
        {
            // Method that generated a score/color based on the results.
            // Valid colors are Red, Amber, Green
            List<Mitigation> allResults = results.Values.ToList();
            allResults.RemoveAll(isNAorNotImplemented);
            // If all results are NA and not implemented
            if (allResults.Count == 0)
            {
                this.color = ColorPallete.White;
                return;
            }
            this.score = allResults.Average(x => (int)x);
            if (score == 2.0)
            {
                this.color = ColorPallete.Green;
            }
            else if (score == 0.0)
            {
                this.color = ColorPallete.Red;
            }
            else
            {
                this.color = ColorPallete.Amber;
            }

            bool isNAorNotImplemented(Mitigation r)
            {
                return (r == Mitigation.NA | r == Mitigation.TestNotImplemented);
            }
        }
        private void PopulateColor(List<double> subTechniquesScore)
        {
            this.score = subTechniquesScore.Average();
            if (score == 2.0)
            {
                this.color = ColorPallete.Green;
            }
            else if (score == 0.0)
            {
                this.color = ColorPallete.Red;
            }
            else
            {
                this.color = ColorPallete.Amber;
            }
        }
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
        public int sorting { get; set; }
        public int viewMode { get; set; }
        public IList<NTechnique> techniques = new List<NTechnique>();
        public Gradient gradient = new Gradient();
        public IList<object> metadata = new List<object>();
        public bool showTacticRowBackground { get; set; }
        public string tacticRowBackground { get; set; }
        public bool selectTechniquesAcrossTactics { get; set; }
        public bool hideDisabled { get; set; }
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
        }
        public void ToJSON(string filename)
        {
            string JSONresult = JsonConvert.SerializeObject(this);
            using (var tw = new StreamWriter(filename))
            {
                tw.WriteLine(JSONresult.ToString());
                tw.Close();
            }
        }
        public void ExportCoverage(string filename)
        {
            this.name = "Coverage";
            this.description = "Coverage of the MITIG&TE project";
            foreach (NTechnique technique in this.techniques)
            {
                technique.metadata.Clear();
                technique.score = 0;
                technique.color = ColorPallete.Blue;
            }
            string JSONresult = JsonConvert.SerializeObject(this);
            using (var tw = new StreamWriter(filename))
            {
                tw.WriteLine(JSONresult.ToString());
                tw.Close();
            }

        }
        // Method for adding techniques with no subtecniques
        public void AddResults(string techniqueID, Dictionary<string, Mitigation> results)
        {

            NTechnique technique = new NTechnique(techniqueID, results);
            this.techniques.Add(technique);
        }
        // Method for adding technique with subtechniques
        public void AddResults(string rootTechniqueID, List<string> subTechniqueIDs, List<Dictionary<string, Mitigation>> subTechniqueResults)
        {
            List<double> subTechniquesScores = new List<double>();
            // Adding subtechniques
            foreach (var item in subTechniqueIDs.Zip(subTechniqueResults, Tuple.Create))
            {
                var subTechniqueID = item.Item1;
                var results = item.Item2;
                NTechnique subTechnique = new NTechnique(subTechniqueID, results);
                this.techniques.Add(subTechnique);
                subTechniquesScores.Add(subTechnique.score);
            }
            // Adding root technique
            NTechnique rootTechnique = new NTechnique(rootTechniqueID, subTechniquesScores);
            this.techniques.Add(rootTechnique);
        }
    }
}
