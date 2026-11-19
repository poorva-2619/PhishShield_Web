import csv
from pathlib import Path

TRAINING_EXAMPLES = (
    (
        "legitimate",
        "legit_telecom",
        "hinglish",
        "business",
        "Aapka mobile recharge Rs 299 ka successfully ho gaya hai. Plan 28 din tak valid hai.",
        "none",
    ),
    (
        "legitimate",
        "legit_telecom",
        "hi",
        "business",
        "आपका मोबाइल रिचार्ज सफल रहा। आपका प्लान अगले 28 दिनों तक चालू रहेगा।",
        "none",
    ),
    (
        "legitimate",
        "legit_telecom",
        "en",
        "business",
        "Your monthly broadband payment was received. The billing period ends on 30 November.",
        "none",
    ),
    (
        "legitimate",
        "legit_delivery",
        "hinglish",
        "business",
        "Aapka grocery order dispatch ho gaya hai. Delivery app mein expected time dekh sakte hain.",
        "none",
    ),
    (
        "legitimate",
        "legit_delivery",
        "hi",
        "business",
        "आपका पार्सल रिसेप्शन पर पहुँचा दिया गया है। यह संदेश केवल डिलीवरी की सूचना है।",
        "none",
    ),
    (
        "legitimate",
        "legit_family_chat",
        "hinglish",
        "saved_contact",
        "Main bazaar se sabzi le aunga. Tumhe ghar ke liye kuch aur chahiye?",
        "none",
    ),
    (
        "legitimate",
        "legit_family_chat",
        "hi",
        "saved_contact",
        "मैं स्टेशन पहुँच गया हूँ, ट्रेन दस मिनट में आएगी।",
        "none",
    ),
    (
        "legitimate",
        "legit_family_chat",
        "hinglish",
        "saved_contact",
        "Kal school meeting 4 baje hai. Main office se seedha wahan aaunga.",
        "none",
    ),
    (
        "suspicious",
        "mlm_pitch",
        "hinglish",
        "unknown",
        "Ghar baithe guaranteed income ke liye meri referral team join karo. Details DM karunga.",
        "unsolicited_contact;financial_promise;referral_request",
    ),
    (
        "suspicious",
        "investment_unverified",
        "hi",
        "unknown",
        "यह ऑनलाइन ग्रुप हर हफ्ते पक्के मुनाफे का दावा करता है। जुड़ने के लिए मुझे संदेश भेजें।",
        "unsolicited_contact;financial_promise;unverified_investment",
    ),
    (
        "suspicious",
        "survey_reward",
        "en",
        "unknown",
        "You have been selected for a free shopping voucher. Complete this survey to claim it.",
        "unsolicited_contact;unexpected_reward;survey_request",
    ),
    (
        "suspicious",
        "unknown_favour",
        "hinglish",
        "unknown",
        "Bhai urgent hai, mujhe paise bhej do aur abhi call mat karna. Baad mein samjhaunga.",
        "urgency;money_request;discourages_verification",
    ),
    (
        "phishing",
        "upi_scam",
        "hinglish",
        "unknown",
        "Aapke UPI account par rok lag jayegi. Is link par OTP daal kar turant verify karein: https://upi-check.example.com",
        "credential_request;urgency;account_threat;external_link",
    ),
    (
        "phishing",
        "bank_kyc_block",
        "hi",
        "unknown",
        "आपका बैंक खाता आज बंद हो जाएगा। खाते को चालू रखने के लिए अपना पासवर्ड और सुरक्षा कोड यहाँ दें: https://bank-help.example.com",
        "credential_request;urgency;account_threat;external_link",
    ),
    (
        "phishing",
        "parcel_fee_scam",
        "en",
        "unknown",
        "Your parcel is on hold. Pay a small redelivery fee and confirm your card details here: https://parcel-fee.example.com",
        "payment_request;card_details;delivery_lure;external_link",
    ),
)

BENCHMARK_EXAMPLES = (
    (
        "legitimate",
        "legit_telecom",
        "hinglish",
        "business",
        "Aapka data pack activate ho gaya hai aur 15 December tak valid hai.",
        "none",
    ),
    (
        "legitimate",
        "legit_telecom",
        "hi",
        "business",
        "आपके प्रीपेड नंबर पर नया प्लान सफलतापूर्वक शुरू हो गया है।",
        "none",
    ),
    (
        "legitimate",
        "legit_telecom",
        "en",
        "business",
        "We received your broadband bill payment. Your next bill is due on 5 December.",
        "none",
    ),
    (
        "legitimate",
        "legit_delivery",
        "hinglish",
        "business",
        "Aapka order pickup ke liye ready hai. Store counter par order number dikhana.",
        "none",
    ),
    (
        "legitimate",
        "legit_delivery",
        "hi",
        "business",
        "आपका रिटर्न पैकेज कुरियर ने ले लिया है। खरीदारी वाले ऐप में स्थिति देख सकते हैं।",
        "none",
    ),
    (
        "legitimate",
        "legit_family_chat",
        "hinglish",
        "saved_contact",
        "Chai bana dena, main aadhe ghante mein ghar pahunch raha hoon.",
        "none",
    ),
    (
        "legitimate",
        "legit_family_chat",
        "hi",
        "saved_contact",
        "आज दादी के घर dinner है, सब लोग सात बजे तक पहुँच जाना।",
        "none",
    ),
    (
        "legitimate",
        "legit_family_chat",
        "en",
        "saved_contact",
        "I left the book on your desk. Please bring it when you come over.",
        "none",
    ),
    (
        "suspicious",
        "mlm_pitch",
        "en",
        "unknown",
        "Recruit people to my earning circle and receive a bonus for each new member.",
        "unsolicited_contact;referral_request;financial_promise",
    ),
    (
        "suspicious",
        "investment_unverified",
        "hinglish",
        "unknown",
        "Is private trading group mein har hafte fixed profit ka claim hai. Join karne ke liye DM karo.",
        "unsolicited_contact;unverified_investment;financial_promise",
    ),
    (
        "suspicious",
        "survey_reward",
        "hi",
        "unknown",
        "आपको मुफ्त शॉपिंग कूपन मिल सकता है। पुरस्कार लेने से पहले यह सर्वे भरें।",
        "unsolicited_contact;unexpected_reward;survey_request",
    ),
    (
        "suspicious",
        "unknown_favour",
        "en",
        "unknown",
        "I need money urgently. Send it now and do not call me to check; I will explain later.",
        "urgency;money_request;discourages_verification",
    ),
    (
        "phishing",
        "account_takeover",
        "en",
        "unknown",
        "Unusual sign-in detected. Verify your password and security code now: https://account-check.example.com",
        "credential_request;urgency;account_lure;external_link",
    ),
    (
        "phishing",
        "utility_disconnection",
        "hi",
        "unknown",
        "आज बिजली काट दी जाएगी। सेवा जारी रखने के लिए तुरंत भुगतान करें: https://bill-help.example.com",
        "payment_request;urgency;service_threat;external_link",
    ),
    (
        "phishing",
        "upi_scam",
        "hinglish",
        "unknown",
        "Galti se paise bhejne ka dawa karke sender bolta hai ki turant UPI PIN share karo.",
        "upi_pin_request;money_lure;urgency",
    ),
)

FIELDNAMES = (
    "id",
    "message",
    "risk_level",
    "label",
    "category",
    "language",
    "sender_context",
    "has_url",
    "urls",
    "indicators",
    "is_augmented",
    "template_id",
    "split",
    "provenance",
)


def build_row(
    index: int,
    example: tuple[str, str, str, str, str, str],
    *,
    split: str,
    provenance: str,
) -> dict[str, str]:
    label, category, language, sender_context, message, indicators = example
    risk_level = {"legitimate": "Low", "suspicious": "Medium", "phishing": "High"}[label]
    return {
        "id": f"SYN{index:04d}",
        "message": message,
        "risk_level": risk_level,
        "label": label,
        "category": category,
        "language": language,
        "sender_context": sender_context,
        "has_url": "1" if "http" in message.lower() else "0",
        "urls": "",
        "indicators": indicators,
        "is_augmented": "1",
        "template_id": f"SYN{index:04d}",
        "split": split,
        "provenance": provenance,
    }


def write_rows(path: Path, rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8-sig") as file:
        writer = csv.DictWriter(file, fieldnames=FIELDNAMES, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    repository_root = Path(__file__).resolve().parents[1]
    dataset_path = repository_root / "phishshield_dataset.csv"
    benchmark_path = repository_root / "data" / "synthetic_benchmark.csv"
    with dataset_path.open(newline="", encoding="utf-8-sig") as file:
        reader = csv.DictReader(file)
        original_fieldnames = list(reader.fieldnames or [])
        existing_rows = list(reader)

    if "provenance" not in original_fieldnames:
        original_fieldnames.append("provenance")
    for row in existing_rows:
        row.setdefault("provenance", "provided_dataset")

    normalized_existing_messages = {
        " ".join(row["message"].casefold().split())
        for row in existing_rows
    }
    existing_training_by_message = {
        " ".join(row["message"].casefold().split()): row
        for row in existing_rows
        if row.get("provenance") == "synthetic_training_example"
        and row.get("split") == "train"
    }
    next_id = max(
        (
            int(row["id"][3:])
            for row in existing_rows
            if row.get("id", "").startswith("SYN") and row["id"][3:].isdigit()
        ),
        default=0,
    ) + 1
    new_training = []
    for example in TRAINING_EXAMPLES:
        label, category, _, _, message, _ = example
        normalized = " ".join(message.casefold().split())
        existing = existing_training_by_message.get(normalized)
        if existing:
            if existing.get("label") != label or existing.get("category") != category:
                raise ValueError("An existing synthetic training example has conflicting metadata.")
            continue
        if normalized in normalized_existing_messages:
            raise ValueError("A synthetic training message already exists in another dataset row.")
        row = build_row(
            next_id,
            example,
            split="train",
            provenance="synthetic_training_example",
        )
        new_training.append(row)
        normalized_existing_messages.add(normalized)
        next_id += 1

    all_dataset_rows = existing_rows + new_training
    dataset_messages = {
        " ".join(row["message"].casefold().split())
        for row in all_dataset_rows
    }
    dataset_templates = {
        row.get("template_id", "")
        for row in all_dataset_rows
        if row.get("template_id")
    }

    if benchmark_path.exists():
        with benchmark_path.open(newline="", encoding="utf-8-sig") as file:
            benchmark_rows = list(csv.DictReader(file))
        expected_messages = {
            " ".join(example[4].casefold().split()): example
            for example in BENCHMARK_EXAMPLES
        }
        benchmark_messages = set()
        benchmark_templates = set()
        for row in benchmark_rows:
            normalized = " ".join(row["message"].casefold().split())
            expected = expected_messages.get(normalized)
            if (
                expected is None
                or row.get("label") != expected[0]
                or row.get("category") != expected[1]
                or row.get("split") != "synthetic_holdout"
                or row.get("provenance") != "synthetic_holdout_example"
            ):
                raise ValueError("Existing synthetic benchmark does not match expected examples.")
            if normalized in dataset_messages or normalized in benchmark_messages:
                raise ValueError("Synthetic benchmark messages must be unique and separate from the dataset.")
            template = row.get("template_id", "").strip()
            if not template or template in dataset_templates or template in benchmark_templates:
                raise ValueError("Synthetic benchmark templates must be unique and separate from the dataset.")
            benchmark_messages.add(normalized)
            benchmark_templates.add(template)
        if benchmark_messages != set(expected_messages):
            raise ValueError("Existing synthetic benchmark is incomplete.")
    else:
        benchmark_start = max(
            (
                int(row["id"][3:])
                for row in all_dataset_rows
                if row.get("id", "").startswith("SYN") and row["id"][3:].isdigit()
            ),
            default=0,
        ) + 1
        benchmark_rows = [
            build_row(
                benchmark_start + offset,
                example,
                split="synthetic_holdout",
                provenance="synthetic_holdout_example",
            )
            for offset, example in enumerate(BENCHMARK_EXAMPLES)
        ]
        if any(
            " ".join(row["message"].casefold().split()) in dataset_messages
            for row in benchmark_rows
        ):
            raise ValueError("Synthetic benchmark messages must be separate from the dataset.")
        if any(row["template_id"] in dataset_templates for row in benchmark_rows):
            raise ValueError("Synthetic benchmark templates must be separate from the dataset.")

    if new_training:
        with dataset_path.open("w", newline="", encoding="utf-8-sig") as file:
            writer = csv.DictWriter(
                file,
                fieldnames=original_fieldnames,
                lineterminator="\n",
            )
            writer.writeheader()
            writer.writerows(all_dataset_rows)
    if not benchmark_path.exists():
        write_rows(benchmark_path, benchmark_rows)

    print(f"Added {len(new_training)} synthetic examples to the training split.")
    print(f"Verified {len(benchmark_rows)} separate synthetic benchmark examples.")
    print("No validation or existing test rows were changed.")


if __name__ == "__main__":
    main()
