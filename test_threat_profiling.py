import unittest
import pandas as pd
import os
from Threat_Profiling import load_json_files_from_directory, map_group_to_ttps, create_ttp_df, export_to_excel

class TestThreatProfile(unittest.TestCase):

    def setUp(self):
        # Sample data to mimic actual data from the MITRE repository
        self.intrusion_sets = [
            {"id": "intrusion-set--001", "type": "intrusion-set", "name": "APT29"},
            {"id": "intrusion-set--002", "type": "intrusion-set", "name": "FIN6"}
        ]
        self.attack_patterns = [
            {"id": "attack-pattern--001", "type": "attack-pattern", "name": "Spear Phishing", "external_references": [{"external_id": "T1193"}]},
            {"id": "attack-pattern--002", "type": "attack-pattern", "name": "PowerShell", "external_references": [{"external_id": "T1059.001"}]}
        ]
        self.relationships = [
            {"type": "relationship", "relationship_type": "uses", "source_ref": "intrusion-set--001", "target_ref": "attack-pattern--001"},
            {"type": "relationship", "relationship_type": "uses", "source_ref": "intrusion-set--001", "target_ref": "attack-pattern--002"},
            {"type": "relationship", "relationship_type": "uses", "source_ref": "intrusion-set--002", "target_ref": "attack-pattern--002"}
        ]
        self.user_specified_groups = ['APT29', 'FIN6']

    def test_map_group_to_ttps(self):
        group_to_ttps, all_ttps = map_group_to_ttps(self.intrusion_sets, self.attack_patterns, self.relationships)
        self.assertEqual(len(group_to_ttps), 2)
        self.assertIn('APT29', group_to_ttps)
        self.assertIn('FIN6', group_to_ttps)
        self.assertEqual(len(all_ttps), 2)

    def test_create_ttp_df(self):
        group_to_ttps, all_ttps = map_group_to_ttps(self.intrusion_sets, self.attack_patterns, self.relationships)
        ttp_df = create_ttp_df(all_ttps, group_to_ttps, self.user_specified_groups)
        
        # Check that the DataFrame is properly structured
        self.assertEqual(ttp_df.shape, (2, 4))  # 2 TTPs, 4 columns (TTP ID, 2 groups, TTP Frequency)
        self.assertEqual(list(ttp_df.columns), ['TTP ID', 'APT29', 'FIN6', 'TTP Frequency'])
        self.assertEqual(ttp_df.loc[ttp_df['TTP ID'] == 'T1193', 'APT29'].values[0], 'yes')
        self.assertEqual(ttp_df.loc[ttp_df['TTP ID'] == 'T1193', 'FIN6'].values[0], 'no')
        self.assertEqual(ttp_df.loc[ttp_df['TTP ID'] == 'T1193', 'TTP Frequency'].values[0], 1)

    def test_no_relationships(self):
        relationships = []
        group_to_ttps, all_ttps = map_group_to_ttps(self.intrusion_sets, self.attack_patterns, relationships)
        self.assertEqual(len(group_to_ttps), 0)
        self.assertEqual(len(all_ttps), 0)

    def test_no_intrusion_sets(self):
        intrusion_sets = []
        group_to_ttps, all_ttps = map_group_to_ttps(intrusion_sets, self.attack_patterns, self.relationships)
        self.assertEqual(len(group_to_ttps), 0)
        self.assertEqual(len(all_ttps), 0)

    def test_no_attack_patterns(self):
        attack_patterns = []
        group_to_ttps, all_ttps = map_group_to_ttps(self.intrusion_sets, attack_patterns, self.relationships)
        self.assertEqual(len(group_to_ttps), 0)
        self.assertEqual(len(all_ttps), 0)

    def test_empty_inputs(self):
        intrusion_sets = []
        attack_patterns = []
        relationships = []
        group_to_ttps, all_ttps = map_group_to_ttps(intrusion_sets, attack_patterns, relationships)
        self.assertEqual(len(group_to_ttps), 0)
        self.assertEqual(len(all_ttps), 0)

    def test_non_existent_group(self):
        non_existent_group = ['NonExistentGroup']
        group_to_ttps, all_ttps = map_group_to_ttps(self.intrusion_sets, self.attack_patterns, self.relationships)
        ttp_df = create_ttp_df(all_ttps, group_to_ttps, non_existent_group)
        
        self.assertEqual(ttp_df.shape, (2, 3))  # 2 TTPs, 3 columns (TTP ID, 1 group, TTP Frequency)
        self.assertEqual(list(ttp_df.columns), ['TTP ID', 'NonExistentGroup', 'TTP Frequency'])
        self.assertTrue(all(ttp_df['NonExistentGroup'] == 'no'))
        self.assertTrue(all(ttp_df['TTP Frequency'] == 0))

    def test_case_sensitivity(self):
        mixed_case_group = ['apt29']  # Lowercase group name
        group_to_ttps, all_ttps = map_group_to_ttps(self.intrusion_sets, self.attack_patterns, self.relationships)
        
        # Ensure group names are case-insensitive by making sure all are lowercase
        group_to_ttps = {group.lower(): ttps for group, ttps in group_to_ttps.items()}
        ttp_df = create_ttp_df(all_ttps, group_to_ttps, [group.lower() for group in mixed_case_group])
        
        self.assertEqual(ttp_df.shape, (2, 3))  # 2 TTPs, 3 columns (TTP ID, 1 group, TTP Frequency)
        self.assertEqual(list(ttp_df.columns), ['TTP ID', 'apt29', 'TTP Frequency'])
        self.assertEqual(ttp_df.loc[ttp_df['TTP ID'] == 'T1193', 'apt29'].values[0], 'yes')
        self.assertEqual(ttp_df.loc[ttp_df['TTP ID'] == 'T1193', 'TTP Frequency'].values[0], 1)

    def test_export_to_excel(self):
        group_to_ttps, all_ttps = map_group_to_ttps(self.intrusion_sets, self.attack_patterns, self.relationships)
        ttp_df = create_ttp_df(all_ttps, group_to_ttps, self.user_specified_groups)
        export_to_excel(ttp_df, filename='test_threat_profile.xlsx')
        
        # Verify the file was created and has content
        self.assertTrue(os.path.exists('test_threat_profile.xlsx'))
        loaded_df = pd.read_excel('test_threat_profile.xlsx', sheet_name='TTPs by Group')
        self.assertEqual(loaded_df.shape, ttp_df.shape)
        self.assertTrue(all(loaded_df.columns == ttp_df.columns))

if __name__ == '__main__':
    unittest.main()
