# combine_csv.py (Updated Version)
import os
import pandas as pd

# Path to the folder containing the daily CSV files
input_folder_path = './data/MachineLearningCVE'

# Path for the final, combined output file
output_file_path = './data/MachineLearningCVE.csv'

# Check if the input folder exists
if not os.path.isdir(input_folder_path):
    print(f"Error: Input folder not found at '{input_folder_path}'")
    exit()

# Get a list of all CSV files in the input folder
csv_files = [f for f in os.listdir(input_folder_path) if f.endswith('.csv')]

if not csv_files:
    print(f"Error: No CSV files found in '{input_folder_path}'")
    exit()

# Create a list to hold the dataframes
df_list = []

print(f"Found {len(csv_files)} files to merge.")

# Loop through the files and read them into pandas DataFrames
for file in csv_files:
    file_path = os.path.join(input_folder_path, file)
    print(f"Reading {file}...")
    try:
        df = pd.read_csv(file_path, encoding='latin1')
        df_list.append(df)
    except Exception as e:
        print(f"Could not read {file}. Error: {e}")

# Concatenate all the dataframes into a single one
if df_list:
    print("Merging all files...")
    combined_df = pd.concat(df_list, ignore_index=True)

    # Save the combined dataframe to a new CSV file
    print(f"Saving combined file to {output_file_path}...")
    combined_df.to_csv(output_file_path, index=False)
    print("✅ Done! The combined file has been created.")
else:
    print("No files were merged.")