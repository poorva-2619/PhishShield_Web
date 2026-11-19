import csv
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from backend.evaluate_synthetic_benchmark import load_benchmark

TRAINING_FIELDS = (
    "message",
    "label",
    "split",
    "template_id",
    "provenance",
)
BENCHMARK_FIELDS = (
    "id",
    "message",
    "label",
    "risk_level",
    "category",
    "language",
    "is_augmented",
    "split",
    "template_id",
    "provenance",
)


def write_csv(path: Path, fieldnames: tuple[str, ...], rows: list[dict[str, str]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def test_load_benchmark_accepts_separate_synthetic_examples() -> None:
    with TemporaryDirectory() as temporary_directory:
        directory = Path(temporary_directory)
        training_path = directory / "training.csv"
        benchmark_path = directory / "benchmark.csv"
        write_csv(
            training_path,
            TRAINING_FIELDS,
            [
                {
                    "message": "A message in the training data",
                    "label": "legitimate",
                    "split": "train",
                    "template_id": "train-1",
                    "provenance": "provided_dataset",
                }
            ],
        )
        write_csv(
            benchmark_path,
            BENCHMARK_FIELDS,
            [
                {
                    "id": "SYN0002",
                    "message": "A different synthetic benchmark message",
                    "label": "phishing",
                    "risk_level": "High",
                    "category": "account_lure",
                    "language": "en",
                    "is_augmented": "1",
                    "split": "synthetic_holdout",
                    "template_id": "benchmark-1",
                    "provenance": "synthetic_holdout_example",
                }
            ],
        )

        rows = load_benchmark(benchmark_path, training_path)

    assert len(rows) == 1
    assert rows[0]["label"] == "phishing"


def test_load_benchmark_rejects_message_overlap_with_any_dataset_split() -> None:
    with TemporaryDirectory() as temporary_directory:
        directory = Path(temporary_directory)
        training_path = directory / "training.csv"
        benchmark_path = directory / "benchmark.csv"
        write_csv(
            training_path,
            TRAINING_FIELDS,
            [
                {
                    "message": "A message in the validation data",
                    "label": "legitimate",
                    "split": "val",
                    "template_id": "validation-1",
                    "provenance": "provided_dataset",
                }
            ],
        )
        write_csv(
            benchmark_path,
            BENCHMARK_FIELDS,
            [
                {
                    "id": "SYN0002",
                    "message": "  A   message in the validation data ",
                    "label": "legitimate",
                    "risk_level": "Low",
                    "category": "legit",
                    "language": "en",
                    "is_augmented": "1",
                    "split": "synthetic_holdout",
                    "template_id": "benchmark-1",
                    "provenance": "synthetic_holdout_example",
                }
            ],
        )

        with pytest.raises(ValueError, match="separate from training data"):
            load_benchmark(benchmark_path, training_path)


def test_load_benchmark_rejects_template_overlap_with_dataset() -> None:
    with TemporaryDirectory() as temporary_directory:
        directory = Path(temporary_directory)
        training_path = directory / "training.csv"
        benchmark_path = directory / "benchmark.csv"
        write_csv(
            training_path,
            TRAINING_FIELDS,
            [
                {
                    "message": "A message in the training data",
                    "label": "legitimate",
                    "split": "test",
                    "template_id": "shared-template",
                    "provenance": "provided_dataset",
                }
            ],
        )
        write_csv(
            benchmark_path,
            BENCHMARK_FIELDS,
            [
                {
                    "id": "SYN0002",
                    "message": "A different synthetic benchmark message",
                    "label": "phishing",
                    "risk_level": "High",
                    "category": "account_lure",
                    "language": "en",
                    "is_augmented": "1",
                    "split": "synthetic_holdout",
                    "template_id": "shared-template",
                    "provenance": "synthetic_holdout_example",
                }
            ],
        )

        with pytest.raises(ValueError, match="templates must be unique"):
            load_benchmark(benchmark_path, training_path)
