using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Web.Script.Serialization;
using Mitigate.Utils;

namespace Mitigate
{
    public class AttackCTI
    {
        IEnumerable<StixObj> AllTechniques = null;
        IEnumerable<StixObj> WindowsTechniques = null;
        IEnumerable<StixObj> MitigationRelationships = null;
        IEnumerable<StixObj> Mitigations = null;

        public AttackCTI(string Url)
        {
            ServicePointManager.Expect100Continue = true;
            ServicePointManager.SecurityProtocol = (SecurityProtocolType)3072;
            CTIRoot AllAttack;
            string json;
            using (var w = new WebClient())
            {
                try
                {
                    // Need to find a way to switch to MITRE TAXII server instead of the json file
                    PrintUtils.Warning("Pulling latest ATT&CK matrix data from github.com/mitre/cti");
                    json = w.DownloadString(Url);
                }
                catch (Exception ex)
                {
                    PrintUtils.Debug(ex.StackTrace);
                    throw new Exception("Unable to obtain latest Mitre Att&CK information. Please ensure that the device is connected to the internet");
                }

                try
                {
                    var JSON = new JavaScriptSerializer();
                    JSON.MaxJsonLength = int.MaxValue;
                    AllAttack = JSON.Deserialize<CTIRoot>(json);
                }
                catch (Exception ex)
                {
                    PrintUtils.Debug(ex.StackTrace);
                    throw new Exception("ATT&CK Json deserialiazation failed");
                }
            }


            var items = AllAttack.objects;
            // Filtering all techniques
            AllTechniques = items.Where(o => o.type == "attack-pattern");
            // Getting all win techniques
            WindowsTechniques = items.Where(o => o.type == "attack-pattern"  && !o.revoked  && !o.x_mitre_deprecated && o.x_mitre_platforms.Contains("Windows"));
            // Getting all windows mitigations
            MitigationRelationships = items.Where(o => o.type == "relationship" && o.relationship_type == "mitigates");
            Mitigations = items.Where(o => o.type == "course-of-action");
            AllAttack = null;
            items = null;
        }

        public IEnumerable<string> GetAllTechniqueIDs()
        {   
            return WindowsTechniques.Select(o => o.external_references[0].external_id);
        }

        public IEnumerable<string> GetAllTactics()
        {
            return new string[] { "initial-access", "execution", "persistence", "privilege-escalation", "defense-evasion", "credential-access", "discovery", "lateral-movement", "collection", "command-and-control", "exfiltration", "impact" };
            // Dynamically doing this messes with the ordering of the tactics...
            HashSet<string> TacticNames = new HashSet<string>();
            foreach (StixObj t in WindowsTechniques)
                foreach (var phase in t.kill_chain_phases)
                {
                    TacticNames.Add(phase.phase_name);
                }
            return TacticNames.AsEnumerable();
        }

        public IEnumerable<string> GetAllMitigationTypes()
        {
            return Mitigations.Where(o => o.x_mitre_deprecated == false).Select(o => o.name);
        }

        public IEnumerable<StixObj> GetRootTechniquesByTactic(string Tactic)
        {
            return WindowsTechniques.Where(o => o.kill_chain_phases.Select(j => j.phase_name).Contains(Tactic) && o.x_mitre_is_subtechnique == false); ;
        }
        public IEnumerable<StixObj> GetSubTechniquesByTechnique(StixObj technique)
        {
            return WindowsTechniques.Where(o => o.GetID().StartsWith(technique.GetID() + "."));
        }


        private StixObj GetTechniqueStixObjFromStixId (string StixId)
        {
            var technique = AllTechniques.Where(o => o.id == StixId);
            if (technique.Count() != 1)
            {
                PrintUtils.Error($"Couldn't retrieve Technique Stix object from Stix Object ID:{StixId}. {technique.Count()} were retrieved instead of 1");
                throw new ArgumentException($"Couldn't retrieve Technique Stix object from Stix Object ID:{StixId}");
            }
            return technique.First();
        }


        public IEnumerable<string> GetAllTechniquesWithNoMitigation()
        {
            foreach (StixObj techniqueStixObj in AllTechniques)
            {
                if (techniqueStixObj.revoked == false && techniqueStixObj.x_mitre_deprecated == false && techniqueStixObj.x_mitre_platforms.Contains("Windows"))
                {
                    var Uses = MitigationRelationships.Where(o => o.target_ref == techniqueStixObj.id);
                    if (Uses.Count() == 0)
                    {
                        yield return GetTechniqueIdByStixObj(techniqueStixObj);
                    }
                }
            }
        }

        internal string GetTechniqueIdByStixObj(StixObj techniqueStixObj)
        {
            return techniqueStixObj.external_references[0].external_id;
        }
        public Dictionary<string, List<string>> GetTechniquesAddressedbyMitigationType(string mitigationType)
        {
            var MitigationDescriptionToTechnique = new Dictionary<string, List<string>>();
            var MitigationType = Mitigations.Where(o => o.name == mitigationType).First();
            var Uses = MitigationRelationships.Where(o => o.source_ref == MitigationType.id);
            foreach (var use in Uses)
            {
                var techniqueStixObj = GetTechniqueStixObjFromStixId(use.target_ref);
                var techniqueId = techniqueStixObj.external_references[0].external_id;
                if (techniqueStixObj.revoked == false && techniqueStixObj.x_mitre_deprecated == false && techniqueStixObj.x_mitre_platforms.Contains("Windows"))
                {
                    if (MitigationDescriptionToTechnique.ContainsKey(use.description))
                    {
                        MitigationDescriptionToTechnique[use.description].Add(techniqueId);
                    }
                    else
                    {
                        var TechniqueList = new List<string>();
                        TechniqueList.Add(techniqueId);
                        MitigationDescriptionToTechnique[use.description] = TechniqueList;
                    }
                }

            }
            return MitigationDescriptionToTechnique;
        }

        private IEnumerable<StixObj> GetTechniqueStixbyID(string[] techniqueIDs)
        {
            return WindowsTechniques.Where(o => techniqueIDs.Contains(o.external_references[0].external_id) && o.x_mitre_deprecated == false);

        }
        public string GetTechniqueMitigation(string[] techniqueIDs) 
        {
            var mitigationsStixIDs = Mitigations.Where(o => o.x_mitre_deprecated == false).Select(o => o.id);
            var techniques = GetTechniqueStixbyID(techniqueIDs);
            IEnumerable<StixObj> relevantMitigationRelationships = null;
            foreach (string mitigationStixId in mitigationsStixIDs)
            {
                foreach (StixObj technique in techniques)
                {
                    var target_ref = technique.id;
                    var source_ref = mitigationStixId;
                    relevantMitigationRelationships = MitigationRelationships.Where(o => o.target_ref == target_ref && o.source_ref == source_ref);
                }   
            }
            var test = relevantMitigationRelationships.GroupBy(o=>o.description);
            if (test.Count() != 1)
            {
                throw new Exception("Mapping failed");
            }
            return test.First().Key;

        }

        internal class CTIRoot
        {
            public string type { get; set; }
            public string id { get; set; }
            public string spec_version { get; set; }
            public StixObj[] objects { get; set; }
        }

    }
    public class StixObj
    {
        public string id { get; set; }
        public string name { get; set; }
        public External_References[] external_references { get; set; }
        public bool revoked { get; set; }
        public string type { get; set; }
        public DateTime modified { get; set; }
        public DateTime created { get; set; }
        public string[] object_marking_refs { get; set; }
        public string created_by_ref { get; set; }
        public string description { get; set; }
        public Kill_Chain_Phases[] kill_chain_phases { get; set; }
        public string[] x_mitre_platforms { get; set; }
        public string[] x_mitre_data_sources { get; set; }
        public string x_mitre_detection { get; set; }
        public string[] x_mitre_permissions_required { get; set; }
        public bool x_mitre_is_subtechnique { get; set; }
        public string x_mitre_version { get; set; }
        public string[] x_mitre_effective_permissions { get; set; }
        public string[] x_mitre_contributors { get; set; }
        public string[] x_mitre_defense_bypassed { get; set; }
        public string[] x_mitre_impact_type { get; set; }
        public string[] x_mitre_system_requirements { get; set; }
        public bool x_mitre_network_requirements { get; set; }
        public bool x_mitre_remote_support { get; set; }
        public bool x_mitre_deprecated { get; set; }
        public string source_ref { get; set; }
        public string relationship_type { get; set; }
        public string target_ref { get; set; }
        public string x_mitre_old_attack_id { get; set; }
        public string identity_class { get; set; }
        public string[] aliases { get; set; }
        public string[] labels { get; set; }
        public string[] x_mitre_aliases { get; set; }
        public string x_mitre_shortname { get; set; }
        public string[] tactic_refs { get; set; }
        public string definition_type { get; set; }
        public Definition definition { get; set; }
        public string GetID()
        {
            return this.external_references[0].external_id;
        }
        public string GetName()
        {
            return this.name;
        }
    }

    public class Definition
    {
        public string statement { get; set; }
    }

    public class External_References
    {
        public string source_name { get; set; }
        public string external_id { get; set; }
        public string url { get; set; }
        public string description { get; set; }
    }

    public class Kill_Chain_Phases
    {
        public string kill_chain_name { get; set; }

        public string phase_name { get; set; }
    }
}
