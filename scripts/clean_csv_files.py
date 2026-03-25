import os
import csv


def clean_csv_file(file_path, output_path, target_columns=6):
    """Clean a CSV file by ensuring consistent column counts and removing rows with missing labels."""
    with open(file_path, 'r') as infile, open(output_path, 'w', newline='') as outfile:
        reader = csv.reader(infile)
        writer = csv.writer(outfile)

        for row in reader:
            # Skip rows with missing labels (last column is empty)
            if len(row) < target_columns or not row[-1].strip():
                continue

            # Truncate or pad rows to match the target column count
            row = row[:target_columns] + [''] * (target_columns - len(row))
            writer.writerow(row)


def clean_csv_directory(input_dir, output_dir, target_columns=6):
    """Clean all CSV files in a directory."""
    os.makedirs(output_dir, exist_ok=True)

    for file_name in os.listdir(input_dir):
        if file_name.endswith('.csv'):
            input_path = os.path.join(input_dir, file_name)
            output_path = os.path.join(output_dir, file_name)
            clean_csv_file(input_path, output_path, target_columns)
            print(f"Cleaned {file_name} -> {output_path}")


if __name__ == "__main__":
    INPUT_DIR = "experiments/run_live_v2"
    OUTPUT_DIR = "experiments/run_live_v2_cleaned"

    clean_csv_directory(INPUT_DIR, OUTPUT_DIR)