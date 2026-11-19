import csv
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from backend.train_model import audit_dataset, load_dataset


def test_dataset_audit_accepts_unique_messages_in_disjoint_splits() -> None:
    rows = [
        {
            "id": "1",
            "message": "A message",
            "label": "legitimate",
            "risk_level": "Low",
            "split": "train",
            "is_augmented": "0",
            "template_id": "template-1",
            "language": "en",
            "category": "legit",
        },
        {
            "id": "2",
            "message": "A different message",
            "label": "phishing",
            "risk_level": "High",
            "split": "test",
            "is_augmented": "0",
            "template_id": "template-2",
            "language": "en",
            "category": "scam",
        },
    ]

    audit = audit_dataset(rows)

    assert audit["within_split_duplicate_rows"] == 0
    assert audit["template_split_leaks"] == 0
    assert audit["duplicate_messages_crossing_splits"] == 0


def test_dataset_audit_rejects_duplicate_messages_within_a_split() -> None:
    row = {
        "id": "1",
        "message": "Repeated message",
        "label": "legitimate",
        "risk_level": "Low",
        "split": "train",
        "is_augmented": "0",
        "template_id": "template-1",
        "language": "en",
        "category": "legit",
    }
    duplicate = {**row, "id": "2", "message": "  Repeated   message "}

    with pytest.raises(ValueError, match="duplicate/leakage"):
        audit_dataset([row, duplicate])


def test_dataset_audit_rejects_synthetic_examples_outside_training_split() -> None:
    rows = [
        {
            "id": "1",
            "message": "Synthetic example",
            "label": "legitimate",
            "risk_level": "Low",
            "split": "test",
            "is_augmented": "1",
            "template_id": "template-1",
            "provenance": "synthetic_training_example",
        }
    ]

    with pytest.raises(ValueError, match="outside the training split"):
        with TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "dataset.csv"
            with path.open("w", newline="", encoding="utf-8") as file:
                writer = csv.DictWriter(file, fieldnames=rows[0].keys())
                writer.writeheader()
                writer.writerows(rows)
            load_dataset(path)
