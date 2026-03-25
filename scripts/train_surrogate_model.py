import os
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split

def load_training_data(data_dir):
    """Load training data for the surrogate model."""
    features = []
    labels = []
    for file in os.listdir(data_dir):
        if file.endswith('.csv'):
            file_path = os.path.join(data_dir, file)
            data = np.genfromtxt(file_path, delimiter=',', skip_header=1)
            if data.size == 0:  # Skip empty files
                print(f"Skipping empty file: {file_path}")
                continue
            if data.ndim == 1:  # Handle single-row files
                data = data.reshape(1, -1)
            # Remove rows with NaN labels
            valid_rows = ~np.isnan(data[:, -1])
            data = data[valid_rows]
            features.append(data[:, :-1])
            labels.append(data[:, -1])
    return np.vstack(features), np.hstack(labels)

def train_and_save_surrogate(data_dir, model_path, scaler_path):
    """Train a surrogate model and save it to disk."""
    features, labels = load_training_data(data_dir)
    X_train, X_test, y_train, y_test = train_test_split(features, labels, test_size=0.2, random_state=42)

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train_scaled, y_train)

    train_acc = model.score(X_train_scaled, y_train)
    test_acc = model.score(X_test_scaled, y_test)
    print(f"Training Accuracy: {train_acc:.4f}")
    print(f"Test Accuracy: {test_acc:.4f}")

    joblib.dump(model, model_path)
    joblib.dump(scaler, scaler_path)
    print(f"Model saved to {model_path}")
    print(f"Scaler saved to {scaler_path}")

if __name__ == "__main__":
    DATA_DIR = "experiments/run_live_v2_cleaned"
    MODEL_PATH = "ml/surrogate_model.joblib"
    SCALER_PATH = "ml/surrogate_scaler.joblib"

    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    train_and_save_surrogate(DATA_DIR, MODEL_PATH, SCALER_PATH)