"""
Labeled Dataset Loader for Supervised WAF Training

Loads HTTP requests with attack type labels for supervised classification.

Dataset Format:
{
    "request": "GET /admin?id=1' OR '1'='1 HTTP/1.1...",
    "label": 1,  # Integer class ID
    "label_name": "SQL_INJECTION",
    "source": "CSIC2010" | "OWASP" | "synthetic",
    "metadata": {...}
}

Author: ISRO Cybersecurity Division
"""

import torch
from torch.utils.data import Dataset
from typing import List, Dict, Optional, Tuple
import json
import csv
from pathlib import Path
from collections import Counter
import numpy as np
from urllib.parse import urlparse

from model.classifier_model import CLASS_LABELS, LABEL_TO_CLASS
from parsing import AccessLogParser, RequestNormalizer
from tokenization import WAFTokenizer


class LabeledWAFDataset(Dataset):
    """
    Labeled dataset for supervised attack classification.

    Supports:
    - CSIC 2010 dataset
    - OWASP payloads
    - Custom labeled data
    - Synthetic attack generation
    """

    def __init__(
        self,
        data: List[Dict],
        tokenizer: WAFTokenizer,
        max_length: int = 128,
        normalize: bool = True
    ):
        """
        Initialize labeled dataset.

        Args:
            data: List of dictionaries with 'request' and 'label' keys
            tokenizer: WAFTokenizer instance
            max_length: Maximum sequence length
            normalize: Apply request normalization
        """
        self.data = data
        self.tokenizer = tokenizer
        self.max_length = max_length
        self.normalize = normalize

        # Initialize normalizer if needed
        if self.normalize:
            self.normalizer = RequestNormalizer()

        # Compute class weights for imbalanced datasets
        self.class_counts = self._compute_class_distribution()
        self.class_weights = self._compute_class_weights()

    def __len__(self) -> int:
        return len(self.data)

    def __getitem__(self, idx: int) -> Dict[str, torch.Tensor]:
        """
        Get a single item.

        Returns:
            Dictionary with input_ids, attention_mask, and labels
        """
        item = self.data[idx]

        # Parse and normalize request
        if self.normalize:
            try:
                parsed = AccessLogParser.parse_http_request(item['request'])
                self.normalizer.normalize(parsed)
                text = f"{parsed['method']} {parsed['path']} {parsed.get('query', '')} {parsed.get('body', '')}"
            except Exception:
                # If parsing fails, use raw request
                text = item['request']
        else:
            text = item['request']

        # Tokenize
        tokenized = self.tokenizer.tokenize(text, return_original=False)

        # Get label
        if isinstance(item['label'], str):
            label = LABEL_TO_CLASS.get(item['label'], 11)  # 11 = UNKNOWN_ATTACK
        else:
            label = item['label']

        return {
            "input_ids": tokenized.input_ids.squeeze(0),
            "attention_mask": tokenized.attention_mask,
            "labels": torch.tensor(label, dtype=torch.long)
        }

    def _compute_class_distribution(self) -> Dict[int, int]:
        """Compute class distribution"""
        labels = [
            item['label'] if isinstance(item['label'], int)
            else LABEL_TO_CLASS.get(item['label'], 11)
            for item in self.data
        ]
        return dict(Counter(labels))

    def _compute_class_weights(self) -> torch.Tensor:
        """
        Compute class weights for imbalanced dataset.

        Uses inverse frequency weighting.
        """
        total = sum(self.class_counts.values())
        num_classes = len(CLASS_LABELS)

        weights = torch.zeros(num_classes)
        for class_id in range(num_classes):
            count = self.class_counts.get(class_id, 1)
            weights[class_id] = total / (num_classes * count)

        return weights

    def get_statistics(self) -> Dict:
        """Get dataset statistics"""
        return {
            'total_samples': len(self.data),
            'num_classes': len(self.class_counts),
            'class_distribution': {
                CLASS_LABELS[k]: v
                for k, v in self.class_counts.items()
            },
            'class_weights': {
                CLASS_LABELS[i]: round(float(self.class_weights[i]), 4)
                for i in range(len(self.class_weights))
                if i in self.class_counts
            }
        }


def load_csic2010_dataset(
    dataset_path: str,
    tokenizer: WAFTokenizer,
    test_split: float = 0.2,
    val_split: float = 0.1
) -> Tuple[LabeledWAFDataset, LabeledWAFDataset, LabeledWAFDataset]:
    """
    Load CSIC 2010 HTTP dataset.

    Args:
        dataset_path: Path to CSIC2010 dataset directory
        tokenizer: WAFTokenizer instance
        test_split: Fraction for test set
        val_split: Fraction for validation set

    Returns:
        Tuple of (train_dataset, val_dataset, test_dataset)
    """
    dataset_path = Path(dataset_path)

    # Load normal traffic
    normal_file = dataset_path / "normalTrafficTraining.txt"
    anomalous_file = dataset_path / "anomalousTrafficTest.txt"

    data = []

    # Load benign requests
    if normal_file.exists():
        with open(normal_file, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            requests = content.split('\n\n')  # Requests separated by blank lines
            for req in requests:
                if req.strip():
                    data.append({
                        'request': req.strip(),
                        'label': 0,  # BENIGN
                        'label_name': 'BENIGN',
                        'source': 'CSIC2010'
                    })

    # Load attack requests
    if anomalous_file.exists():
        with open(anomalous_file, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            requests = content.split('\n\n')
            for req in requests:
                if req.strip():
                    # Auto-classify attack type based on patterns
                    attack_class = classify_attack_type(req)
                    data.append({
                        'request': req.strip(),
                        'label': attack_class,
                        'label_name': CLASS_LABELS[attack_class],
                        'source': 'CSIC2010'
                    })

    # Shuffle and split
    np.random.shuffle(data)

    total = len(data)
    test_size = int(total * test_split)
    val_size = int(total * val_split)
    train_size = total - test_size - val_size

    train_data = data[:train_size]
    val_data = data[train_size:train_size + val_size]
    test_data = data[train_size + val_size:]

    # Create datasets
    train_dataset = LabeledWAFDataset(train_data, tokenizer)
    val_dataset = LabeledWAFDataset(val_data, tokenizer)
    test_dataset = LabeledWAFDataset(test_data, tokenizer)

    return train_dataset, val_dataset, test_dataset


def load_json_dataset(
    json_path: str,
    tokenizer: WAFTokenizer,
    test_split: float = 0.2,
    val_split: float = 0.1
) -> Tuple[LabeledWAFDataset, LabeledWAFDataset, LabeledWAFDataset]:
    """
    Load dataset from JSON file.

    JSON Format:
    [
        {
            "request": "GET /path?param=value HTTP/1.1...",
            "label": 0 or "BENIGN",
            "label_name": "BENIGN",
            "metadata": {}
        },
        ...
    ]

    Args:
        json_path: Path to JSON dataset file
        tokenizer: WAFTokenizer instance
        test_split: Fraction for test set
        val_split: Fraction for validation set

    Returns:
        Tuple of (train_dataset, val_dataset, test_dataset)
    """
    with open(json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    # Shuffle
    np.random.shuffle(data)

    # Split
    total = len(data)
    test_size = int(total * test_split)
    val_size = int(total * val_split)
    train_size = total - test_size - val_size

    train_data = data[:train_size]
    val_data = data[train_size:train_size + val_size]
    test_data = data[train_size + val_size:]

    # Create datasets
    train_dataset = LabeledWAFDataset(train_data, tokenizer)
    val_dataset = LabeledWAFDataset(val_data, tokenizer)
    test_dataset = LabeledWAFDataset(test_data, tokenizer)

    return train_dataset, val_dataset, test_dataset


def load_csv_dataset(
    csv_path: str,
    tokenizer: WAFTokenizer,
    test_split: float = 0.2,
    val_split: float = 0.1
) -> Tuple[LabeledWAFDataset, LabeledWAFDataset, LabeledWAFDataset]:
    """
    Load dataset from CSV file.

    Expected columns:
    - method
    - path (preferred) or url
    - query (optional)
    - post_data (optional)
    - label (benign|malicious or class label)

    Args:
        csv_path: Path to CSV dataset file
        tokenizer: WAFTokenizer instance
        test_split: Fraction for test set
        val_split: Fraction for validation set

    Returns:
        Tuple of (train_dataset, val_dataset, test_dataset)
    """
    data: List[Dict] = []

    with open(csv_path, 'r', encoding='utf-8', errors='ignore', newline='') as f:
        reader = csv.DictReader(f)
        for row in reader:
            method = (row.get('method') or 'GET').strip().upper()
            path = (row.get('path') or '').strip()
            url = (row.get('url') or '').strip()
            query = (row.get('query') or '').strip()
            post_data = (row.get('post_data') or '').strip()
            raw_label = (row.get('label') or '').strip()

            if not path and url:
                try:
                    parsed_url = urlparse(url)
                    path = parsed_url.path or '/'
                    if not query:
                        query = parsed_url.query
                except Exception:
                    path = '/'

            if not path:
                path = '/'

            # Build canonical request string for parser/tokenizer pipeline.
            request_target = path + (f"?{query}" if query else "")
            request_line = f"{method} {request_target} HTTP/1.1"
            request_text = request_line + (f"\n\n{post_data}" if post_data else "")

            label_upper = raw_label.upper()
            if label_upper in LABEL_TO_CLASS:
                label_id = LABEL_TO_CLASS[label_upper]
            elif label_upper == 'BENIGN':
                label_id = 0
            elif label_upper == 'MALICIOUS':
                # Map generic malicious labels to a specific attack class.
                label_id = classify_attack_type(request_text)
                if label_id == 0:
                    label_id = 11  # UNKNOWN_ATTACK
            else:
                try:
                    parsed_int = int(raw_label)
                    label_id = parsed_int if 0 <= parsed_int < len(CLASS_LABELS) else 11
                except (TypeError, ValueError):
                    label_id = 11

            data.append({
                'request': request_text,
                'label': label_id,
                'label_name': CLASS_LABELS.get(label_id, 'UNKNOWN_ATTACK'),
                'source': 'CSV'
            })

    if not data:
        raise ValueError(f"No valid rows found in CSV dataset: {csv_path}")

    # Shuffle
    np.random.shuffle(data)

    # Split
    total = len(data)
    test_size = int(total * test_split)
    val_size = int(total * val_split)
    train_size = total - test_size - val_size

    train_data = data[:train_size]
    val_data = data[train_size:train_size + val_size]
    test_data = data[train_size + val_size:]

    # Create datasets
    train_dataset = LabeledWAFDataset(train_data, tokenizer)
    val_dataset = LabeledWAFDataset(val_data, tokenizer)
    test_dataset = LabeledWAFDataset(test_data, tokenizer)

    return train_dataset, val_dataset, test_dataset


def classify_attack_type(request_text: str) -> int:
    """
    Auto-classify attack type based on patterns.

    This is a heuristic classifier for labeling unlabeled data.
    Not perfect, but useful for initial labeling.

    Args:
        request_text: HTTP request text

    Returns:
        Attack class ID
    """
    text_lower = request_text.lower()

    # SQL Injection patterns
    sql_patterns = [
        "' or ", "\" or ", "union select", "select * from",
        "'; drop", "\"; drop", "1=1", "' and ",
        "sleep(", "benchmark(", "waitfor delay"
    ]
    if any(pattern in text_lower for pattern in sql_patterns):
        return 1  # SQL_INJECTION

    # XSS patterns
    xss_patterns = [
        "<script", "javascript:", "onerror=", "onload=",
        "alert(", "prompt(", "confirm(", "<img src=x"
    ]
    if any(pattern in text_lower for pattern in xss_patterns):
        return 2  # XSS

    # Path Traversal patterns
    path_patterns = [
        "../", "..\\", "etc/passwd", "windows/system",
        "%2e%2e", "....//", "....//"
    ]
    if any(pattern in text_lower for pattern in path_patterns):
        return 3  # PATH_TRAVERSAL

    # Command Injection patterns
    cmd_patterns = [
        "; cat ", "| cat ", "; ls ", "| ls ",
        "; whoami", "| whoami", "&& cat", "|| cat",
        "`cat ", "$(cat "
    ]
    if any(pattern in text_lower for pattern in cmd_patterns):
        return 4  # COMMAND_INJECTION

    # XXE patterns
    xxe_patterns = [
        "<!entity", "<!doctype", "system \"file:", "system \"http:"
    ]
    if any(pattern in text_lower for pattern in xxe_patterns):
        return 5  # XXE

    # SSRF patterns
    ssrf_patterns = [
        "localhost", "127.0.0.1", "169.254.169.254",
        "internal", "192.168.", "10.0."
    ]
    if any(pattern in text_lower for pattern in ssrf_patterns):
        return 6  # SSRF

    # LDAP Injection patterns
    ldap_patterns = [
        "ldap://", ")(", ")(&", ")|"
    ]
    if any(pattern in text_lower for pattern in ldap_patterns):
        return 7  # LDAP_INJECTION

    # File Inclusion patterns
    file_patterns = [
        "include(", "require(", "file://", "php://",
        "expect://", "zip://"
    ]
    if any(pattern in text_lower for pattern in file_patterns):
        return 8  # FILE_INCLUSION

    # Buffer Overflow patterns
    buffer_patterns = [
        "a" * 100,  # Long repeated characters
        "%x" * 10,  # Format string
        "\x00"  # Null byte
    ]
    if any(pattern in text_lower for pattern in buffer_patterns):
        return 10  # BUFFER_OVERFLOW

    # Default: UNKNOWN_ATTACK
    return 11


def generate_synthetic_attacks(
    num_samples: int = 1000,
    attack_types: Optional[List[int]] = None
) -> List[Dict]:
    """
    Generate synthetic attack samples for training.

    Args:
        num_samples: Number of samples to generate
        attack_types: List of attack class IDs to generate (None = all)

    Returns:
        List of synthetic attack dictionaries
    """
    if attack_types is None:
        attack_types = list(range(1, 12))  # All attack types except BENIGN

    synthetic_data = []

    # Attack templates
    templates = {
        1: [  # SQL_INJECTION
            "GET /login?username=admin' OR '1'='1&password=x HTTP/1.1",
            "POST /search?q=1' UNION SELECT NULL,username,password FROM users-- HTTP/1.1",
            "GET /product?id=1'; DROP TABLE products;-- HTTP/1.1"
        ],
        2: [  # XSS
            "GET /search?q=<script>alert('XSS')</script> HTTP/1.1",
            "POST /comment?text=<img src=x onerror=alert(1)> HTTP/1.1",
            "GET /page?name=<svg onload=alert('XSS')> HTTP/1.1"
        ],
        3: [  # PATH_TRAVERSAL
            "GET /download?file=../../../../etc/passwd HTTP/1.1",
            "GET /view?doc=..\\..\\..\\windows\\system.ini HTTP/1.1",
            "POST /read?path=%2e%2e%2f%2e%2e%2fetc%2fpasswd HTTP/1.1"
        ],
        4: [  # COMMAND_INJECTION
            "GET /ping?host=127.0.0.1; cat /etc/passwd HTTP/1.1",
            "POST /exec?cmd=whoami && cat /etc/shadow HTTP/1.1",
            "GET /run?cmd=`cat /etc/passwd` HTTP/1.1"
        ]
    }

    samples_per_type = num_samples // len(attack_types)

    for attack_class in attack_types:
        if attack_class in templates:
            base_templates = templates[attack_class]
            for i in range(samples_per_type):
                # Generate variations
                template = base_templates[i % len(base_templates)]
                synthetic_data.append({
                    'request': template,
                    'label': attack_class,
                    'label_name': CLASS_LABELS[attack_class],
                    'source': 'synthetic'
                })

    return synthetic_data


def create_balanced_dataset(
    datasets: List[List[Dict]],
    target_samples_per_class: int = 1000
) -> List[Dict]:
    """
    Create balanced dataset by sampling from multiple sources.

    Args:
        datasets: List of dataset lists
        target_samples_per_class: Target number of samples per class

    Returns:
        Balanced dataset
    """
    # Merge all datasets
    all_data = []
    for dataset in datasets:
        all_data.extend(dataset)

    # Group by class
    class_data = {}
    for item in all_data:
        label = item['label'] if isinstance(item['label'], int) else LABEL_TO_CLASS.get(item['label'], 11)
        if label not in class_data:
            class_data[label] = []
        class_data[label].append(item)

    # Balance classes
    balanced_data = []
    for class_id in class_data:
        samples = class_data[class_id]
        if len(samples) >= target_samples_per_class:
            # Undersample
            balanced_data.extend(np.random.choice(samples, target_samples_per_class, replace=False))
        else:
            # Oversample
            balanced_data.extend(samples)
            # Repeat samples to reach target
            remaining = target_samples_per_class - len(samples)
            balanced_data.extend(np.random.choice(samples, remaining, replace=True))

    np.random.shuffle(balanced_data)
    return balanced_data
