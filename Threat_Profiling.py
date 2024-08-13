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
    all_ttps = {}

    for relationship in relationships:
        if (relationship['type'] == 'relationship' and 
            relationship['relationship_type'] == 'uses' and
            relationship['source_ref'] in intrusion_set_dict and
            relationship['target_ref'] in attack_pattern_dict):

            group_id = relationship['source_ref']
            ttp_id = relationship['target_ref']

            group_name = intrusion_set_dict[group_id]['name']
            ttp_external_id = attack_pattern_dict[ttp_id]['external_references'][0]['external_id']
            ttp_name = attack_pattern_dict[ttp_id]['name']
            kill_chain_phases = ", ".join([phase['phase_name'] for phase in attack_pattern_dict[ttp_id].get('kill_chain_phases', [])])

            all_ttps[ttp_external_id] = {'name': ttp_name, 'kill_chain_phases': kill_chain_phases}

            if group_name not in group_to_ttps:
                group_to_ttps[group_name] = []

            group_to_ttps[group_name].append(ttp_external_id)
    
    return group_to_ttps, all_ttps

# Function to assign risk rating based on TTP frequency
def assign_risk_rating(frequency):
    if frequency >= 5:
        return "Critical"
    elif frequency >= 3:
        return "High"
    elif frequency >= 1:
        return "Medium"
    else:
        return "Low"

# Function to create the DataFrame with TTPs, group usage, frequency, and kill chain phases
def create_ttp_df(all_ttps, group_to_ttps, user_specified_groups):
    # Create the DataFrame with TTP IDs, names, and kill chain phases
    ttp_df = pd.DataFrame({
        'TTP ID': list(all_ttps.keys()), 
        'TTP Name': [details['name'] for details in all_ttps.values()],
        'Kill Chain Phases': [details['kill_chain_phases'] for details in all_ttps.values()]
    })
    
    for group in user_specified_groups:
        ttp_df[group] = ttp_df['TTP ID'].map(lambda ttp: 'yes' if ttp in group_to_ttps.get(group, []) else 'no')

    # Calculate the frequency of each TTP across the user-specified groups
    ttp_df['TTP Frequency'] = ttp_df[user_specified_groups].apply(lambda row: row.tolist().count('yes'), axis=1)

    # Assign risk ratings based on TTP frequency
    ttp_df['Risk Rating'] = ttp_df['TTP Frequency'].map(assign_risk_rating)

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
    intrusion_set_path = 'mitre_cti/enterprise-attack/intrusion-set'
    attack_pattern_path = 'mitre_cti/enterprise-attack/attack-pattern'
    relationship_path = 'mitre_cti/enterprise-attack/relationship'

    # Load the datasets
    intrusion_sets = load_json_files_from_directory(intrusion_set_path)
    attack_patterns = load_json_files_from_directory(attack_pattern_path)
    relationships = load_json_files_from_directory(relationship_path)

    # Create a dictionary of all available adversary group names (case-insensitive)
    available_groups = {item['name'].lower(): item['name'] for item in intrusion_sets if item['type'] == 'intrusion-set'}

    # Prompt user to input adversary groups
    user_input = input("Enter the names of the adversaries you want to include, separated by commas: ")
    user_specified_groups = [group.strip().lower() for group in user_input.split(",")]

    # Validate the user input against available groups
    valid_groups = []
    for group in user_specified_groups:
        if group in available_groups:
            valid_groups.append(available_groups[group])  # Use the correct casing from the dataset
        else:
            print(f"Warning: '{group}' is not found in the MITRE dataset and will be excluded.")

    # Check if there are valid groups left to process
    if not valid_groups:
        print("No valid adversary groups provided. Exiting.")
    else:
        # Map groups to their TTPs and get a list of all TTPs
        group_to_ttps, all_ttps = map_group_to_ttps(intrusion_sets, attack_patterns, relationships)

        # Create the DataFrame
        ttp_df = create_ttp_df(all_ttps, group_to_ttps, valid_groups)
        
        # Export the DataFrame to an Excel file
        export_to_excel(ttp_df)
