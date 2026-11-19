import argparse
import csv
import hashlib
import json
from pathlib import Path
import platform
from typing import Any

import joblib
import sklearn
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.pipeline import FeatureUnion, Pipeline

LABELS = ("legitimate", "suspicious", "phishing")
REQUIRED_COLUMNS = {"message", "label", "split", "is_augmented"}
RISK_LEVEL_BY_LABEL = {
    "legitimate": "low",
    "suspicious": "medium",
    "phishing": "high",
}


def build_pipeline(include_char_features: bool, class_weight: str | None) -> Pipeline:
    word_features = TfidfVectorizer(
        lowercase=True,
        strip_accents="unicode",
        ngram_range=(1, 2),
        min_df=1,
        sublinear_tf=True,
        max_features=30_000,
    )
    if include_char_features:
        features: Any = FeatureUnion(
            [
                ("word", word_features),
                (
                    "char",
                    TfidfVectorizer(
                        analyzer="char_wb",
                        lowercase=True,
                        ngram_range=(3, 5),
                        min_df=1,
                        sublinear_tf=True,
                        max_features=30_000,
                    ),
                ),
            ]
        )
    else:
        features = word_features

    return Pipeline(
        [
            ("features", features),
            (
                "classifier",
                LogisticRegression(
                    class_weight=class_weight,
                    max_iter=2_000,
                    random_state=42,
                    solver="lbfgs",
                ),
            ),
        ]
    )


def load_dataset(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8-sig") as file:
        reader = csv.DictReader(file)
        columns = set(reader.fieldnames or ())
        missing_columns = REQUIRED_COLUMNS - columns
        if missing_columns:
            raise ValueError(f"Dataset is missing required columns: {sorted(missing_columns)}")
        rows = list(reader)

    if not rows:
        raise ValueError("Dataset contains no rows.")

    for row_number, row in enumerate(rows, start=2):
        row["message"] = row["message"].strip()
        row["label"] = row["label"].strip().lower()
        row["split"] = row["split"].strip().lower()
        row["is_augmented"] = row["is_augmented"].strip()
        if not row["message"]:
            raise ValueError(f"Dataset row {row_number} has an empty message.")
        if row["label"] not in LABELS:
            raise ValueError(f"Dataset row {row_number} has an unknown label.")
        if row["split"] not in {"train", "val", "test"}:
            raise ValueError(f"Dataset row {row_number} has an invalid split.")
        if row["is_augmented"] not in {"0", "1"}:
            raise ValueError(f"Dataset row {row_number} has an invalid is_augmented value.")
        row.setdefault("provenance", "provided_dataset")
        if (
            row["provenance"] == "synthetic_training_example"
            and row["split"] != "train"
        ):
            raise ValueError(
                f"Dataset row {row_number} marks synthetic data outside the training split."
            )

    return rows


def audit_dataset(rows: list[dict[str, str]]) -> dict[str, Any]:
    split_names = ("train", "val", "test")
    split_label_counts = {
        split: {
            label: sum(row["split"] == split and row["label"] == label for row in rows)
            for label in LABELS
        }
        for split in split_names
    }

    template_splits: dict[str, set[str]] = {}
    normalized_message_splits: dict[str, set[str]] = {}
    split_message_counts: dict[tuple[str, str], int] = {}
    for row in rows:
        template_id = row.get("template_id", "").strip()
        if template_id:
            template_splits.setdefault(template_id, set()).add(row["split"])
        normalized_message = " ".join(row["message"].casefold().split())
        normalized_message_splits.setdefault(normalized_message, set()).add(row["split"])
        split_message_key = (row["split"], normalized_message)
        split_message_counts[split_message_key] = (
            split_message_counts.get(split_message_key, 0) + 1
        )

    template_leaks = sum(len(splits) > 1 for splits in template_splits.values())
    duplicate_message_leaks = sum(
        len(splits) > 1 for splits in normalized_message_splits.values()
    )
    within_split_duplicates = sum(count - 1 for count in split_message_counts.values())
    if template_leaks or duplicate_message_leaks or within_split_duplicates:
        raise ValueError(
            "Dataset duplicate/leakage detected. Keep exact messages unique within each split "
            "and message templates and exact messages disjoint across splits."
        )

    risk_level_mismatches = 0
    if rows and "risk_level" in rows[0]:
        risk_level_mismatches = sum(
            row.get("risk_level", "").strip().lower() != RISK_LEVEL_BY_LABEL[row["label"]]
            for row in rows
        )
        if risk_level_mismatches:
            raise ValueError(
                f"Dataset has {risk_level_mismatches} rows where risk_level conflicts with label."
            )

    normalized_messages = [
        " ".join(row["message"].casefold().split()) for row in rows
    ]
    return {
        "label_counts": {
            label: sum(row["label"] == label for row in rows)
            for label in LABELS
        },
        "split_label_counts": split_label_counts,
        "augmented_counts": {
            value: sum(row["is_augmented"] == value for row in rows)
            for value in ("0", "1")
        },
        "provenance_counts": _value_counts(rows, "provenance"),
        "language_counts": _value_counts(rows, "language"),
        "category_count": len({row.get("category", "") for row in rows if row.get("category")}),
        "template_count": len(template_splits),
        "template_split_leaks": template_leaks,
        "within_split_duplicate_rows": within_split_duplicates,
        "normalized_duplicate_rows": len(rows) - len(set(normalized_messages)),
        "duplicate_messages_crossing_splits": duplicate_message_leaks,
        "risk_level_label_mismatches": risk_level_mismatches,
    }


def _value_counts(rows: list[dict[str, str]], column: str) -> dict[str, int]:
    return {
        value: sum(row.get(column, "") == value for row in rows)
        for value in sorted({row.get(column, "") for row in rows})
        if value
    }


def metrics_for(
    model: Pipeline,
    messages: list[str],
    labels: list[str],
    augmented: list[str],
) -> dict[str, Any]:
    predictions = model.predict(messages).tolist()
    report = classification_report(
        labels,
        predictions,
        labels=list(LABELS),
        output_dict=True,
        zero_division=0,
    )
    legitimate_indices = [i for i, label in enumerate(labels) if label == "legitimate"]
    false_positives = sum(predictions[i] != "legitimate" for i in legitimate_indices)
    original_indices = [i for i, value in enumerate(augmented) if value == "0"]

    original_metrics: dict[str, Any] | None = None
    if original_indices:
        original_labels = [labels[i] for i in original_indices]
        original_predictions = [predictions[i] for i in original_indices]
        original_legitimate_indices = [
            i for i, label in enumerate(original_labels) if label == "legitimate"
        ]
        original_metrics = {
            "samples": len(original_indices),
            "accuracy": accuracy_score(original_labels, original_predictions),
            "macro_f1": f1_score(
                original_labels,
                original_predictions,
                labels=list(LABELS),
                average="macro",
                zero_division=0,
            ),
            "legitimate_false_positive_rate": (
                sum(
                    original_predictions[i] != "legitimate"
                    for i in original_legitimate_indices
                )
                / len(original_legitimate_indices)
                if original_legitimate_indices
                else None
            ),
        }

    return {
        "samples": len(labels),
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
            false_positives / len(legitimate_indices) if legitimate_indices else None
        ),
        "confusion_matrix_labels": list(LABELS),
        "confusion_matrix": confusion_matrix(
            labels,
            predictions,
            labels=list(LABELS),
        ).tolist(),
        "per_class": report,
        "non_augmented": original_metrics,
    }


def write_validation_misclassifications(
    model: Pipeline,
    rows: list[dict[str, str]],
    output_path: Path,
) -> int:
    messages = [row["message"] for row in rows]
    predictions = model.predict(messages).tolist()
    probabilities = model.predict_proba(messages)
    class_indices = {
        label: index for index, label in enumerate(model.classes_.tolist())
    }
    fieldnames = [
        "id",
        "category",
        "language",
        "is_augmented",
        "true_label",
        "predicted_label",
        "predicted_probability",
        "true_label_probability",
        "indicators",
        "message",
    ]

    output_path.parent.mkdir(parents=True, exist_ok=True)
    errors = 0
    with output_path.open("w", newline="", encoding="utf-8-sig") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        for row, prediction, row_probabilities in zip(rows, predictions, probabilities):
            if prediction == row["label"]:
                continue
            errors += 1
            writer.writerow(
                {
                    "id": row.get("id", ""),
                    "category": row.get("category", ""),
                    "language": row.get("language", ""),
                    "is_augmented": row["is_augmented"],
                    "true_label": row["label"],
                    "predicted_label": prediction,
                    "predicted_probability": (
                        f"{row_probabilities[class_indices[prediction]]:.4f}"
                    ),
                    "true_label_probability": (
                        f"{row_probabilities[class_indices[row['label']]]:.4f}"
                    ),
                    "indicators": row.get("indicators", ""),
                    "message": row["message"],
                }
            )
    return errors


def main() -> None:
    parser = argparse.ArgumentParser(description="Train and evaluate the message risk classifier.")
    parser.add_argument(
        "--dataset",
        type=Path,
        default=Path("phishshield_dataset.csv"),
    )
    parser.add_argument(
        "--model-output",
        type=Path,
        default=Path("backend/models/message_classifier.joblib"),
    )
    parser.add_argument(
        "--metrics-output",
        type=Path,
        default=Path("backend/models/metrics.json"),
    )
    parser.add_argument(
        "--review-output",
        type=Path,
        default=Path("backend/models/validation_misclassifications.csv"),
    )
    args = parser.parse_args()

    dataset_path = args.dataset.resolve()
    rows = load_dataset(dataset_path)
    dataset_audit = audit_dataset(rows)
    partitions = {
        split: [row for row in rows if row["split"] == split]
        for split in ("train", "val", "test")
    }
    if any(not partitions[split] for split in partitions):
        raise ValueError("Dataset must have non-empty train, val, and test splits.")

    train_rows = partitions["train"]
    val_rows = partitions["val"]
    test_rows = partitions["test"]

    candidates = [
        ("word_unweighted", False, None),
        ("word_balanced", False, "balanced"),
        ("word_char_unweighted", True, None),
        ("word_char_balanced", True, "balanced"),
    ]
    validation_results = []
    for name, include_char_features, class_weight in candidates:
        candidate = build_pipeline(include_char_features, class_weight)
        candidate.fit(
            [row["message"] for row in train_rows],
            [row["label"] for row in train_rows],
        )
        result = metrics_for(
            candidate,
            [row["message"] for row in val_rows],
            [row["label"] for row in val_rows],
            [row["is_augmented"] for row in val_rows],
        )
        validation_results.append(
            {
                "name": name,
                "include_char_features": include_char_features,
                "class_weight": class_weight,
                **result,
            }
        )

    selected = max(
        validation_results,
        key=lambda result: (
            result["macro_f1"],
            -(
                result["legitimate_false_positive_rate"]
                if result["legitimate_false_positive_rate"] is not None
                else 1
            ),
        ),
    )
    validation_review_model = build_pipeline(
        selected["include_char_features"],
        selected["class_weight"],
    )
    validation_review_model.fit(
        [row["message"] for row in train_rows],
        [row["label"] for row in train_rows],
    )
    review_output = args.review_output.resolve()
    validation_error_count = write_validation_misclassifications(
        validation_review_model,
        val_rows,
        review_output,
    )

    final_model = build_pipeline(
        selected["include_char_features"],
        selected["class_weight"],
    )
    training_rows = train_rows + val_rows
    final_model.fit(
        [row["message"] for row in training_rows],
        [row["label"] for row in training_rows],
    )
    test_metrics = metrics_for(
        final_model,
        [row["message"] for row in test_rows],
        [row["label"] for row in test_rows],
        [row["is_augmented"] for row in test_rows],
    )

    model_output = args.model_output.resolve()
    metrics_output = args.metrics_output.resolve()
    model_output.parent.mkdir(parents=True, exist_ok=True)
    metrics_output.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(final_model, model_output)

    dataset_hash = hashlib.sha256(dataset_path.read_bytes()).hexdigest()
    metrics = {
        "dataset": str(args.dataset),
        "dataset_sha256": dataset_hash,
        "rows": len(rows),
        "split_sizes": {split: len(partition) for split, partition in partitions.items()},
        "dataset_audit": dataset_audit,
        "training_environment": {
            "python": platform.python_version(),
            "scikit_learn": sklearn.__version__,
        },
        "label_order": list(LABELS),
        "selected_model": {
            "name": selected["name"],
            "include_char_features": selected["include_char_features"],
            "class_weight": selected["class_weight"],
        },
        "validation_candidates": validation_results,
        "validation_misclassification_count": validation_error_count,
        "test": test_metrics,
        "model_file": str(args.model_output),
    }
    metrics_output.write_text(
        json.dumps(metrics, indent=2, allow_nan=False) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(metrics, indent=2, allow_nan=False))
    print(f"\nSaved model: {model_output}")
    print(f"Saved metrics: {metrics_output}")
    print(
        f"Saved {validation_error_count} validation errors for review: "
        f"{review_output}"
    )


if __name__ == "__main__":
    main()
