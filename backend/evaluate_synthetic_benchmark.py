import argparse
import csv
import hashlib
import json
from pathlib import Path
from typing import Any

import joblib
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)

from backend.train_model import LABELS, RISK_LEVEL_BY_LABEL

REQUIRED_COLUMNS = {
    "message",
    "label",
    "is_augmented",
    "template_id",
    "provenance",
}


def load_benchmark(path: Path, training_path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8-sig") as file:
        reader = csv.DictReader(file)
        missing = REQUIRED_COLUMNS - set(reader.fieldnames or ())
        if missing:
            raise ValueError(f"Benchmark is missing columns: {sorted(missing)}")
        rows = list(reader)
    if not rows:
        raise ValueError("Benchmark contains no rows.")

    with training_path.open(newline="", encoding="utf-8-sig") as file:
        training_rows = list(csv.DictReader(file))
    training_messages = {
        " ".join(row["message"].casefold().split())
        for row in training_rows
    }
    training_templates = {
        row.get("template_id", "")
        for row in training_rows
        if row.get("template_id")
    }

    benchmark_messages: set[str] = set()
    benchmark_templates: set[str] = set()
    for row_number, row in enumerate(rows, start=2):
        row["message"] = row["message"].strip()
        row["label"] = row["label"].strip().lower()
        if not row["message"] or row["label"] not in LABELS:
            raise ValueError(f"Invalid message or label on benchmark row {row_number}.")
        if row["provenance"] != "synthetic_holdout_example":
            raise ValueError(
                f"Benchmark row {row_number} is not labeled synthetic_holdout_example."
            )
        if row.get("split") != "synthetic_holdout":
            raise ValueError(f"Benchmark row {row_number} has an invalid split.")
        expected_risk = RISK_LEVEL_BY_LABEL[row["label"]]
        if row.get("risk_level", "").strip().lower() != expected_risk:
            raise ValueError(f"Benchmark row {row_number} has inconsistent risk_level.")

        normalized = " ".join(row["message"].casefold().split())
        template = row["template_id"].strip()
        if normalized in training_messages or normalized in benchmark_messages:
            raise ValueError("Benchmark messages must be unique and separate from training data.")
        if not template or template in training_templates or template in benchmark_templates:
            raise ValueError("Benchmark templates must be unique and separate from training data.")
        benchmark_messages.add(normalized)
        benchmark_templates.add(template)

    return rows


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Evaluate a frozen classifier on a separate synthetic benchmark."
    )
    parser.add_argument(
        "--model",
        type=Path,
        default=Path("backend/models/message_classifier.joblib"),
    )
    parser.add_argument(
        "--benchmark",
        type=Path,
        default=Path("data/synthetic_benchmark.csv"),
    )
    parser.add_argument(
        "--training-data",
        type=Path,
        default=Path("phishshield_dataset.csv"),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("backend/models/synthetic_benchmark_metrics.json"),
    )
    args = parser.parse_args()

    rows = load_benchmark(args.benchmark, args.training_data)
    model = joblib.load(args.model)
    messages = [row["message"] for row in rows]
    labels = [row["label"] for row in rows]
    predictions = model.predict(messages).tolist()
    probabilities = model.predict_proba(messages)
    class_indices = {label: index for index, label in enumerate(model.classes_)}
    legitimate_indices = [i for i, label in enumerate(labels) if label == "legitimate"]

    report: dict[str, Any] = {
        "kind": "synthetic_benchmark_not_real_world_evaluation",
        "rows": len(rows),
        "benchmark_sha256": hashlib.sha256(args.benchmark.read_bytes()).hexdigest(),
        "accuracy": accuracy_score(labels, predictions),
        "macro_f1": f1_score(
            labels,
            predictions,
            labels=list(LABELS),
            average="macro",
            zero_division=0,
        ),
        "macro_precision": precision_score(
            labels,
            predictions,
            labels=list(LABELS),
            average="macro",
            zero_division=0,
        ),
        "macro_recall": recall_score(
            labels,
            predictions,
            labels=list(LABELS),
            average="macro",
            zero_division=0,
        ),
        "legitimate_false_positive_rate": (
            sum(predictions[i] != "legitimate" for i in legitimate_indices)
            / len(legitimate_indices)
            if legitimate_indices
            else None
        ),
        "label_order": list(LABELS),
        "confusion_matrix": confusion_matrix(
            labels,
            predictions,
            labels=list(LABELS),
        ).tolist(),
        "per_class": classification_report(
            labels,
            predictions,
            labels=list(LABELS),
            output_dict=True,
            zero_division=0,
        ),
        "examples": [
            {
                "id": row.get("id", ""),
                "category": row.get("category", ""),
                "language": row.get("language", ""),
                "true_label": labels[index],
                "predicted_label": predictions[index],
                "predicted_probability": float(
                    probabilities[index][class_indices[predictions[index]]]
                ),
            }
            for index, row in enumerate(rows)
        ],
    }
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, allow_nan=False))
    print(f"\nSaved synthetic benchmark metrics: {output}")


if __name__ == "__main__":
    main()
