import sys
from pathlib import Path

# Add project root to Python path
sys.path.append(str(Path(__file__).resolve().parents[1]))

from modules.evaluation import evaluate

if __name__ == "__main__":
    summary = evaluate(
        labels_csv="dataset/labels.csv",
        splits_csv="dataset/splits.csv",
        out_dir="outputs/eval",
        threshold=5.0,
        split="test",
    )
    print(summary)