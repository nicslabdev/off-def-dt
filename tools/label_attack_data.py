#!/usr/bin/env python3
"""
Label attack data based on simulation output.

Usage:
  python tools/label_attack_data.py --input-dir data/live_attacks --output-dir data/labeled_attacks
"""
import argparse
import os
import pandas as pd

def label_data(input_dir, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    for file in os.listdir(input_dir):
        if file.endswith('.csv'):
            input_path = os.path.join(input_dir, file)
            output_path = os.path.join(output_dir, file)

            # Load the data
            df = pd.read_csv(input_path)

            # Add a label column (example: label anomalies as 1, normal as 0)
            if 'attack' in file:
                df['label'] = 1
            else:
                df['label'] = 0

            # Save the labeled data
            df.to_csv(output_path, index=False)
            print(f'Labeled data saved to {output_path}')

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--input-dir', required=True, help='Directory with attack data')
    parser.add_argument('--output-dir', required=True, help='Directory to save labeled data')
    args = parser.parse_args()

    label_data(args.input_dir, args.output_dir)

if __name__ == '__main__':
    main()