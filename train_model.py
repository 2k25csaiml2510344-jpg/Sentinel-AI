import json
import os
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

# Project folders
os.makedirs("models", exist_ok=True)

# Real CIC-IDS2017 dataset path
DATA_PATH = os.path.join("MachineLearningCVE", "Tuesday-WorkingHours.pcap_ISCX.csv")
if not os.path.exists(DATA_PATH):
    DATA_PATH = os.path.join("dataset", "Tuesday-WorkingHours.pcap_ISCX.csv")

# Features used by Sentinel AI
FEATURES = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Packet Length Mean"
]

LABEL_COLUMN = "Label"

print("Loading CIC-IDS2017 dataset...")
print(f"Reading from: {DATA_PATH}")
data = pd.read_csv(
    DATA_PATH,
    sep=",",
    low_memory=False
)

# Clean column names (strip whitespace)
data.columns = data.columns.str.strip()

print("Dataset loaded successfully!")
print("Original shape:", data.shape)

# Check required columns
required_columns = FEATURES + [LABEL_COLUMN]

missing_columns = [
    column for column in required_columns
    if column not in data.columns
]

if missing_columns:
    raise ValueError(
        f"Missing columns in dataset: {missing_columns}"
    )

# Clean labels
data[LABEL_COLUMN] = data[LABEL_COLUMN].astype(str).str.strip()

# Remove invalid labels
data = data[
    data[LABEL_COLUMN].notna()
    & (data[LABEL_COLUMN] != "")
]

# Convert features to numeric
for column in FEATURES:
    data[column] = pd.to_numeric(
        data[column],
        errors="coerce"
    )

# Replace infinite values and drop invalid rows
data = data.replace([np.inf, -np.inf], np.nan)
data = data.dropna(subset=FEATURES + [LABEL_COLUMN])

# Binary classification:
# BENIGN = normal traffic
# ATTACK = all attack traffic (e.g. FTP-Patator, SSH-Patator)
data["Target"] = np.where(
    data[LABEL_COLUMN].str.upper() == "BENIGN",
    "BENIGN",
    "ATTACK"
)

# Prepare features and target
X = data[FEATURES]
y = data["Target"]

print("\nDataset cleaned!")
print("Total rows:", len(data))

print("\nClass distribution:")
print(y.value_counts())

# Encode target labels
encoder = LabelEncoder()
y_encoded = encoder.fit_transform(y)

# Train-test split (80% train, 20% test, stratified)
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y_encoded,
    test_size=0.2,
    random_state=42,
    stratify=y_encoded
)

print("\nTraining Random Forest model (this may take 15-20 seconds)...")

# Train model
model = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    class_weight="balanced",
    n_jobs=-1
)

model.fit(X_train, y_train)

# Evaluate model
predictions = model.predict(X_test)

accuracy = accuracy_score(
    y_test,
    predictions
)

print("\nModel Training Completed!")
print(f"Accuracy: {round(accuracy * 100, 2)}%")


print("\nClassification Report:")

report = classification_report(
    y_test,
    predictions,
    target_names=encoder.classes_,
    output_dict=True,
    zero_division=0
)

print(
    classification_report(
        y_test,
        predictions,
        target_names=encoder.classes_,
        zero_division=0
    )
)

# Save model performance metrics
performance = {
    "accuracy": float(accuracy),
    "classes": list(encoder.classes_),
    "classification_report": report
}

with open("models/model_performance.json", "w") as file:
    json.dump(performance, file, indent=4)

print("\nModel performance saved successfully!")


# Save trained model and artifacts
joblib.dump(
    model,
    os.path.join("models", "sentinel_model.pkl")
)

joblib.dump(
    encoder,
    os.path.join("models", "label_encoder.pkl")
)

joblib.dump(
    FEATURES,
    os.path.join("models", "feature_names.pkl")
)

print("\nReal CIC-IDS2017 model saved successfully in models/ directory!")
