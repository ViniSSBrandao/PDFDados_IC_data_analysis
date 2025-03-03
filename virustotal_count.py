import csv
import os
from collections import defaultdict

def generate_antivirus_result_counts_from_csv(input_csv, output_directory):
    # Create output directory if it doesn't exist
    os.makedirs(output_directory, exist_ok=True)
    
    # Dictionary to store results for each antivirus
    antivirus_results = defaultdict(lambda: defaultdict(int))
    
    # Read the input CSV
    try:
        with open(input_csv, 'r', encoding='utf-8') as csvfile:
            reader = csv.reader(csvfile)
            headers = next(reader)  # Get headers from first row
            antivirus_names = headers[1:]  # All columns except 'filename'
            
            row_count = 0
            # Process each row
            for row in reader:
                row_count += 1
                filename = row[0]  # First column is filename
                results = row[1:]  # Rest are antivirus results
                
                # Count results for each antivirus
                for av_name, result in zip(antivirus_names, results):
                    # Convert empty string to 'None' for consistency
                    result_str = 'None' if not result else result
                    antivirus_results[av_name][result_str] += 1
    
        # Generate CSV file for each antivirus
        for av_name, results in antivirus_results.items():
            output_file = os.path.join(output_directory, f"{av_name.lower().replace(' ', '_')}_results.csv")
            
            with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(['Result', 'Count'])
                
                # Sort results by count (descending) and then alphabetically
                sorted_results = sorted(results.items(), key=lambda x: (-x[1], x[0]))
                
                for result, count in sorted_results:
                    writer.writerow([result, count])
        
        print(f"Processed {row_count} files from {input_csv}")
        print(f"Generated {len(antivirus_results)} CSV files in {output_directory}")
        
    except FileNotFoundError:
        print(f"Error: Input CSV file not found: {input_csv}")
    except Exception as e:
        print(f"Error processing CSV file: {str(e)}")

def main():
    # Configuration - adjust these paths as needed
    input_csv = 'virus_total_analyses.csv'  # The CSV from the first script
    output_directory = 'antivirus_results'  # Directory where new CSV files will be created
    
    print(f"Processing CSV file: {input_csv}")
    generate_antivirus_result_counts_from_csv(input_csv, output_directory)
    print("Analysis complete")

if __name__ == "__main__":
    main()