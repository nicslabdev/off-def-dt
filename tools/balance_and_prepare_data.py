import pandas as pd
from sklearn.utils import resample

# File paths
attack_file = "data/labeled_attacks/attack_mqtt_replay.csv"
baseline_file = "data/labeled_attacks/baseline_replica.csv"
output_features = "data/features.csv"
output_labels = "data/labels.csv"

# Load datasets
attack_data = pd.read_csv(attack_file)
baseline_data = pd.read_csv(baseline_file)

# Oversample the smaller dataset
attack_data_upsampled = resample(
    attack_data,
    replace=True,  # Sample with replacement
    n_samples=len(baseline_data),  # Match the larger dataset
    random_state=42
)

# Combine datasets
combined_data = pd.concat([attack_data_upsampled, baseline_data])

# Shuffle the combined dataset
shuffled_data = combined_data.sample(frac=1, random_state=42).reset_index(drop=True)

# Split features and labels
features = shuffled_data.drop(columns=["label"])
labels = shuffled_data["label"]

# Save to CSV
features.to_csv(output_features, index=False)
labels.to_csv(output_labels, index=False, header=True)

print("Data balanced, combined, and saved to:")
print(f"Features: {output_features}")
print(f"Labels: {output_labels}")