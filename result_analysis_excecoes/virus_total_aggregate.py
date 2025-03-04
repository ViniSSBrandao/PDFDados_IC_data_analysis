import json
import csv
import os
from collections import OrderedDict

def process_virustotal_files(input_directory, output_csv):
    # Get all antivirus names from the first JSON file to ensure consistent ordering
    antivirus_names = []
    sample_file = None
    
    # Find first JSON file to get antivirus names
    for filename in os.listdir(input_directory):
        if filename.endswith('.json'):
            sample_file = os.path.join(input_directory, filename)
            break
    
    if sample_file:
        with open(sample_file, 'r') as f:
            data = json.load(f)
            antivirus_names = sorted(data['scans'].keys())
    
    # Prepare CSV headers
    headers = ['filename'] + antivirus_names
    
    # Open CSV file for writing
    with open(output_csv, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(headers)
        
        # Process each JSON file
        for filename in os.listdir(input_directory):
            if filename.endswith('.json'):
                filepath = os.path.join(input_directory, filename)
                
                try:
                    with open(filepath, 'r') as f:
                        data = json.load(f)
                        
                        # Get scan results for this file
                        scans = data.get('scans', {})
                        row = [filename]
                        
                        # Add result for each antivirus in order
                        for av in antivirus_names:
                            scan_result = scans.get(av, {}).get('result', None)
                            row.append(scan_result if scan_result else '')
                        
                        writer.writerow(row)
                        
                except json.JSONDecodeError:
                    print(f"Error decoding JSON file: {filename}")
                except Exception as e:
                    print(f"Error processing file {filename}: {str(e)}")

def main():
    # Configuration - adjust these paths as needed
    input_directory = './excecoes'  # Replace with your directory path
    output_csv = 'virus_total_analyses.csv'
    
    # Process the files
    print(f"Processing JSON files from {input_directory}")
    process_virustotal_files(input_directory, output_csv)
    print(f"CSV file created: {output_csv}")

if __name__ == "__main__":
    main()