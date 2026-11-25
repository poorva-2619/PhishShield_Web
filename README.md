# PhishShield Web

PhishShield Web is an explainable phishing detection project for browser-based
communication platforms.

## Backend MVP

The API accepts a user-submitted message from a supported web platform, checks
message language, and inspects URL structure locally. It returns a risk
category with explanations and suggested actions. It does not contact external
URL services, inspect destination pages, verify sender identity, or retain
request content or analysis results.

### Run locally

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
py -m pip install -e ".[test]"
py -m uvicorn backend.app.main:app --reload
```

The API is available at `http://127.0.0.1:8000`; its health check is
`GET /health`.

### Analyze a message

Send a `POST` to `/api/v1/analyze` with a JSON body:

```json
{
  "schemaVersion": 1,
  "platform": "whatsapp_web",
  "messageText": "Reply with your OTP to verify your account."
}
```

The supported `platform` values are `whatsapp_web`, `telegram_web`,
`gmail_web`, and `outlook_web`.

The response contains `riskLevel`, `reasons`, `suggestions`, and `limitations`.
Suggestions are matched to the detected warning signs; they recommend safer
ways to verify a request, but do not establish that a message or link is
malicious or safe. The local URL checks report the hostname and may flag
embedded credentials, IP-address hosts, punycode hostnames, or unencrypted
HTTP. They do not determine domain ownership, reputation, or whether the
destination is malicious; an unflagged host is not necessarily safe. Analysis
is heuristic. The endpoint does not log, persist, or echo message content,
URL paths, or query strings.

### Run tests

```powershell
py -m pytest
```

## Experimental message classifier

The labeled CSV can be used to train a three-class TF-IDF/logistic-regression
baseline (`legitimate`, `suspicious`, `phishing`):

```powershell
py -m backend.train_model --dataset phishshield_dataset.csv
```

Training selects between word and word-plus-character TF-IDF configurations
using only the validation split. It fits the selected pipeline on train plus
validation data, evaluates once on the held-out test split, and writes
`backend/models/message_classifier.joblib` and detailed metrics to
`backend/models/metrics.json`. It also writes
`backend/models/validation_misclassifications.csv` to review mistakes made on
the validation split. That report includes the message text, so it is excluded
from Git. The audit rejects duplicate messages within a split, checks
label/risk consistency, and prevents message templates or exact normalized
messages from crossing splits.

The dataset includes 59 clearly labeled `synthetic_training_example` rows,
all assigned to the training split. These examples broaden telecom, delivery,
family-chat, unsolicited-income-pitch, and phishing-pattern coverage. They are
synthetic, not independently verified real-world messages.

A separate set of 15 synthetic examples is available as a smoke-test
benchmark. It is not included in training or model selection:

```powershell
py -m backend.evaluate_synthetic_benchmark
```

The evaluator checks that benchmark messages and templates do not overlap any
row in the dataset, then writes
`backend/models/synthetic_benchmark_metrics.json`. The current smoke-test result
is 80% accuracy and 0.768 macro-F1 on 15 synthetic examples, with 1 of 8
synthetic legitimate examples flagged (12.5%). This small, authored benchmark
does not establish real-world performance.

### Adding reviewed examples

Use [the training template](./data/train_examples_template.csv) for new
training rows and [the independent-test template](./data/independent_test_examples_template.csv)
only for newly collected, independently labeled final-evaluation rows. Keep
the test template separate: do not use its examples to author training data,
choose model settings, or change detection rules. Add examples only after the
message and label have been reviewed; do not relabel an example solely
because the classifier disagrees.

Collect messages only with appropriate permission. Remove names, phone
numbers, email addresses, account identifiers, OTPs, and other personal data
before adding a row. Record whether each example is real or synthetic in
`provenance`, set `is_augmented` consistently, use a unique `template_id`,
and assign `split` to `train` or `test` according to the template being used.
The trainer rejects synthetic rows outside `train`, duplicate messages, and
template overlap between splits.

The trained artifact is experimental and is **not currently used by the live
analysis API**. The original CSV contained 75 exact duplicate messages within
its splits; these were removed while preserving labels and split assignment
and preferring non-augmented copies. The existing 176-message test split was
consulted during iterative development, so its reported metrics are retained
for reproducibility but should not be treated as an untouched final
evaluation. The model should not set user-facing risk levels until it is
evaluated on a larger, representative, independently collected dataset and
its false-positive rate is improved. The dataset remains English-heavy
(990 English, 103 Hinglish, and 14 Hindi messages), so performance for Hindi
is not established.

## Chrome extension MVP

The Manifest V3 extension analyzes only text explicitly selected by the user
on WhatsApp Web, Telegram Web, Gmail, or Outlook on the web. For Gmail and
Outlook, select the email text to review; for chat services, select one
message. It sends only that selection to the local backend after the user
clicks **Analyze selected message**. The extension does not scan messages or
run analysis in the background. JSON report export is initiated by the user
and downloaded locally; it includes the selected message or email text.

### Load the extension

1. Start the backend using the instructions above.
2. Open `chrome://extensions` and enable **Developer mode**.
3. Select **Load unpacked** and choose the repository's `extension` folder.
4. Open WhatsApp Web, Telegram Web, Gmail, or Outlook on the web. Select the
   text of one message or email, then open the PhishShield extension popup.
5. Click **Analyze selected message**. To retain a report, click **Download
   JSON report**.

The extension currently sends requests to `http://127.0.0.1:8000`. Keep the
backend local; production deployment requires configuring HTTPS and the
extension's allowed backend host.
