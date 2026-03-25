import csv
from pathlib import Path

PREDICTIONS_FILE = Path("outputs/eval/predictions.csv")

def load_predictions():
    rows = []
    with open(PREDICTIONS_FILE, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for r in reader:
            rows.append({
                "y_true": int(r["y_true"]),
                "score": float(r["score"])
            })
    return rows


def compute_metrics(rows, threshold):
    tp = fp = tn = fn = 0

    for r in rows:
        pred = 1 if r["score"] >= threshold else 0
        true = r["y_true"]

        if pred == 1 and true == 1:
            tp += 1
        elif pred == 1 and true == 0:
            fp += 1
        elif pred == 0 and true == 0:
            tn += 1
        elif pred == 0 and true == 1:
            fn += 1

    precision = tp / (tp + fp) if (tp + fp) else 0
    recall = tp / (tp + fn) if (tp + fn) else 0
    accuracy = (tp + tn) / (tp + tn + fp + fn)
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) else 0

    return precision, recall, accuracy, f1


def run_sweep():
    rows = load_predictions()

    print("\nThreshold Sweep Results\n")
    print("Threshold | Precision | Recall | Accuracy | F1")
    print("-----------------------------------------------")

    for threshold in range(0, 81, 5):
        precision, recall, accuracy, f1 = compute_metrics(rows, threshold)

        print(
            f"{threshold:9} | "
            f"{precision:.2f}      | "
            f"{recall:.2f}   | "
            f"{accuracy:.2f}    | "
            f"{f1:.2f}"
        )


if __name__ == "__main__":
    run_sweep()