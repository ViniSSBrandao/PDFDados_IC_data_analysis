import csv
import os
from collections import Counter

def categorize_samples(input_csv, output_csv):
    # Categories to track - Added 'Spam'
    categories = ['Phishing', 'Trojan', 'Spam', 'Multiple', 'Other', 'None']
    
    # Open output CSV file
    with open(output_csv, 'w', newline='', encoding='utf-8') as outfile:
        writer = csv.writer(outfile)
        writer.writerow(['Filename', 'Category', 'Phishing_Count', 'Trojan_Count', 'Spam_Count', 'Other_Count', 'None_Count'])
        
        # Read input CSV
        try:
            with open(input_csv, 'r', encoding='utf-8') as infile:
                reader = csv.reader(infile)
                headers = next(reader)  # Skip header row
                antivirus_names = headers[1:]  # All columns except filename
                
                sample_count = 0
                for row in reader:
                    sample_count += 1
                    filename = row[0]
                    results = row[1:]  # All antivirus results
                    
                    # Count detections - Added spam_count
                    phishing_count = 0
                    trojan_count = 0
                    spam_count = 0
                    other_count = 0
                    none_count = 0
                    
                    for result in results:
                        if not result or result == 'None':
                            none_count += 1
                            continue
                        
                        result_lower = result.lower()
                        if 'trojan' in result_lower:
                            trojan_count += 1
                        elif 'phish' in result_lower:
                            phishing_count += 1
                        elif 'spam' in result_lower:
                            spam_count += 1
                        elif 'phish' not in result_lower and 'trojan' not in result_lower and 'spam' not in result_lower:
                            other_count += 1
                    
                    total_detections = phishing_count + trojan_count + spam_count + other_count
                    
                    # Determine category
                    if total_detections == 0 and none_count > 0:
                        category = 'None'
                    elif total_detections == 0:
                        category = 'Other'  # Shouldn't happen with valid data
                    else:
                        # Calculate proportions (excluding None counts)
                        phishing_prop = phishing_count / total_detections if total_detections > 0 else 0
                        trojan_prop = trojan_count / total_detections if total_detections > 0 else 0
                        spam_prop = spam_count / total_detections if total_detections > 0 else 0
                        
                        # Check for Multiple category (adjusting for three categories)
                        if (0.4 <= phishing_prop + spam_prop<= 0.6) and (0.4 <= trojan_prop <= 0.6):
                            category = 'Multiple'
                        else:
                            # Most common category among non-None detections
                            counts = {
                                'Phishing': phishing_count,
                                'Trojan': trojan_count,
                                'Spam': spam_count,
                                'Other': other_count
                            }
                            category = max(counts, key=counts.get)
                            # If Other is tied with specific categories, prefer the specific category
                            if category == 'Other' and (phishing_count > 0 or trojan_count > 0 or spam_count > 0):
                                if phishing_count >= trojan_count and phishing_count >= spam_count:
                                    category = 'Phishing'
                                elif trojan_count >= spam_count:
                                    category = 'Trojan'
                                else:
                                    category = 'Spam'
                    
                    # Write result - Added spam_count to output
                    writer.writerow([filename, category, phishing_count, trojan_count, spam_count, other_count, none_count])
                    
            print(f"Processed {sample_count} samples from {input_csv}")
            print(f"Results written to {output_csv}")
            
        except FileNotFoundError:
            print(f"Error: Input CSV file not found: {input_csv}")
        except Exception as e:
            print(f"Error processing CSV file: {str(e)}")

def main():
    # Configuration - adjust these paths as needed
    input_csv = './result_analysis_excecoes/csvs/virus_total_analyses.csv'  # The CSV from the first script
    output_csv = 'sample_categories.csv'    # Output file name
    
    print(f"Processing CSV file: {input_csv}")
    categorize_samples(input_csv, output_csv)
    print("Categorization complete")

if __name__ == "__main__":
    main()