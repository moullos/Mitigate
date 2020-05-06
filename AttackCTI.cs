using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Policy;
using System.Text;

namespace Mitigate
{
    class AttackCTI
    {
        IEnumerable<Technique> WindowsTechniques = null;
        // Have this pull the file from online
        public AttackCTI(string ATTACKJSON)
        {
            using (StreamReader r = new StreamReader(ATTACKJSON))
            {
                string json = r.ReadToEnd();
                CTIRoot AllAttack = JsonConvert.DeserializeObject<CTIRoot>(json);
                Technique[] items = AllAttack.objects;
                // Filtering all techniques
                var AllTechniques = items.Where(o => o.type == "attack-pattern" && o.revoked == false);
                // Getting all win techniques
                WindowsTechniques = AllTechniques.Where(o => o.x_mitre_platforms.Contains("Windows"));
            }
        }
        public IEnumerable<string> GetAllTechniqueIDs()
        {
            return WindowsTechniques.Select(o => o.external_references[0].external_id);
        }
        public IEnumerable<string> GetAllTactics()
        {
            return new string[] { "initial-access", "execution", "persistence", "privilege-escalation", "defense-evasion", "credential-access", "discovery", "lateral-movement", "collection", "command-and-control", "exfiltration", "impact" };
            HashSet<string> TacticNames = new HashSet<string>();
            foreach (Technique t in WindowsTechniques)
                foreach (var phase in t.kill_chain_phases)
                {
                    TacticNames.Add(phase.phase_name);
                }
            return TacticNames.AsEnumerable();
        }
        public IEnumerable<Technique> GetRootTechniquesByTactic(string Tactic)
        {
            return WindowsTechniques.Where(o => o.kill_chain_phases.Select(j => j.phase_name).Contains(Tactic) && o.x_mitre_is_subtechnique == false); ;
        }
        public IEnumerable<Technique> GetSubTechniquesByTechnique(Technique technique)
        {
            return WindowsTechniques.Where(o => o.GetID().StartsWith(technique.GetID() + "."));
        }
        internal class CTIRoot
        {
            public string type { get; set; }
            public string id { get; set; }
            public string spec_version { get; set; }
            public Technique[] objects { get; set; }
        }

    }
    public class Technique
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
