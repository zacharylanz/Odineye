import os
import json
import pandas as pd

# Helper function to load JSON files from a directory
def load_json_files_from_directory(directory_path):
    data = []
    for filename in os.listdir(directory_path):
        if filename.endswith('.json'):
            try:
                with open(os.path.join(directory_path, filename), 'r') as file:
                    file_data = json.load(file)
                    if 'objects' in file_data:
                        data.extend(file_data['objects'])
                    else:
                        print(f"Warning: 'objects' key not found in {filename}. Skipping this file.")
            except json.JSONDecodeError:
                print(f"Warning: {filename} is not a valid JSON file or is empty. Skipping this file.")
    return data

# Function to map relationships between intrusion sets and attack patterns
def map_group_to_ttps(intrusion_sets, attack_patterns, relationships):
    intrusion_set_dict = {item['id']: item for item in intrusion_sets if item['type'] == 'intrusion-set'}
    attack_pattern_dict = {item['id']: item for item in attack_patterns if item['type'] == 'attack-pattern'}

    group_to_ttps = {}
    all_ttps = set()

    for relationship in relationships:
        if (relationship['type'] == 'relationship' and 
            relationship['relationship_type'] == 'uses' and
            relationship['source_ref'] in intrusion_set_dict and
            relationship['target_ref'] in attack_pattern_dict):

            group_id = relationship['source_ref']
            ttp_id = relationship['target_ref']

            group_name = intrusion_set_dict[group_id]['name']
            ttp_external_id = attack_pattern_dict[ttp_id]['external_references'][0]['external_id']

            all_ttps.add(ttp_external_id)

            if group_name not in group_to_ttps:
                group_to_ttps[group_name] = []

            group_to_ttps[group_name].append(ttp_external_id)
    
    return group_to_ttps, sorted(all_ttps)

# Function to create the DataFrame with TTPs, group usage, and frequency
def create_ttp_df(all_ttps, group_to_ttps, user_specified_groups):
    ttp_df = pd.DataFrame(index=all_ttps)
    
    for group in user_specified_groups:
        ttp_df[group] = ttp_df.index.map(lambda ttp: 'yes' if ttp in group_to_ttps.get(group, []) else 'no')

    # Calculate the frequency of each TTP across the user-specified groups
    ttp_df['TTP Frequency'] = ttp_df.apply(lambda row: row[user_specified_groups].tolist().count('yes'), axis=1)

    ttp_df.reset_index(inplace=True)
    ttp_df.rename(columns={'index': 'TTP ID'}, inplace=True)
    
    return ttp_df

# Function to export the DataFrame to an Excel file
def export_to_excel(df, filename='threat_profile.xlsx'):
    if df.empty:
        print("No data to write to Excel.")
    else:
        with pd.ExcelWriter(filename, engine='openpyxl') as writer:
            df.to_excel(writer, index=False, sheet_name='TTPs by Group')
        print(f'Threat profile Excel file generated: {filename}')

# Main execution
if __name__ == "__main__":
    # Paths to the relevant folders in the cloned MITRE CTI repository
    intrusion_set_path = 'cti/enterprise-attack/intrusion-set'
    attack_pattern_path = 'cti/enterprise-attack/attack-pattern'
    relationship_path = 'cti/enterprise-attack/relationship'

    # Load the datasets
    intrusion_sets = load_json_files_from_directory(intrusion_set_path)
    attack_patterns = load_json_files_from_directory(attack_pattern_path)
    relationships = load_json_files_from_directory(relationship_path)

    # Example user-specified groups (Replace with actual user input)
    user_specified_groups = ['APT29', 'APT28', 'FIN6']

    # Map groups to their TTPs and get a list of all TTPs
    group_to_ttps, all_ttps = map_group_to_ttps(intrusion_sets, attack_patterns, relationships)

    # Create the DataFrame
    ttp_df = create_ttp_df(all_ttps, group_to_ttps, user_specified_groups)
    
    # Export the DataFrame to an Excel file
    export_to_excel(ttp_df)
