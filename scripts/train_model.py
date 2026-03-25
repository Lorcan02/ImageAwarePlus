import sys
from pathlib import Path

# Add project root to Python path
ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(ROOT))

import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
import joblib

from modules.ml_features import extract_features
from modules.report import analyze_image


DATASET_PATH = ROOT / "dataset" / "images"
MODEL_PATH = ROOT / "models" / "phish_model.pkl"


def load_reports():

    rows = []
    labels = []

    for label in ["phish", "benign"]:

        folder = DATASET_PATH / label

        for image_file in folder.glob("*"):

            if image_file.suffix.lower() not in [".png", ".jpg", ".jpeg"]:
                continue

            print("Processing:", image_file.name)

            report = analyze_image(image_file)

            features = extract_features(report)

            rows.append(features)
            labels.append(1 if label == "phish" else 0)

    df = pd.DataFrame(rows)

    return df, labels


def train():

    X, y = load_reports()

    print("Loaded samples:", len(X))

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42
    )

    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=6,
        random_state=42,
    )

    model.fit(X_train, y_train)

    score = model.score(X_test, y_test)

    print("Model accuracy:", score)

    MODEL_PATH.parent.mkdir(exist_ok=True)

    joblib.dump(model, MODEL_PATH)

    print("Model saved:", MODEL_PATH)


if __name__ == "__main__":
    train()