"""Systematic error analysis and false-positive/false-negative diagnosis.

Crucial for production security ML to avoid 'over-defensive collapse'
(blocking legitimate user queries) while maintaining near-zero false negatives.
"""
from __future__ import annotations

from typing import Dict, List


class ErrorAnalyzer:
    """Computes confusion matrices, precision/recall, and isolates high-loss failures."""

    @staticmethod
    def analyze_predictions(predictions: List[Dict[str, any]]) -> Dict[str, any]:
        """
        Input format for each prediction:
            {"text": str, "true_label": int (0 or 1), "pred_label": int (0 or 1), "confidence": float}
        """
        tp = 0  # True Positive (Caught threat)
        tn = 0  # True Negative (Allowed benign)
        fp = 0  # False Positive (Blocked benign - over-defensive)
        fn = 0  # False Negative (Missed threat - security failure!)

        false_positives: List[Dict] = []
        false_negatives: List[Dict] = []

        for p in predictions:
            true_y = p["true_label"]
            pred_y = p["pred_label"]

            if true_y == 1 and pred_y == 1:
                tp += 1
            elif true_y == 0 and pred_y == 0:
                tn += 1
            elif true_y == 0 and pred_y == 1:
                fp += 1
                false_positives.append(p)
            elif true_y == 1 and pred_y == 0:
                fn += 1
                false_negatives.append(p)

        total = len(predictions)
        accuracy = (tp + tn) / max(total, 1)
        precision = tp / max(tp + fp, 1)
        recall = tp / max(tp + fn, 1)
        f1 = 2 * (precision * recall) / max(precision + recall, 1e-12)
        fpr = fp / max(fp + tn, 1)

        return {
            "total_samples": total,
            "confusion_matrix": {
                "true_positives": tp,
                "true_negatives": tn,
                "false_positives": fp,
                "false_negatives": fn,
            },
            "metrics": {
                "accuracy": round(accuracy, 4),
                "precision": round(precision, 4),
                "recall": round(recall, 4),
                "f1_score": round(f1, 4),
                "false_positive_rate": round(fpr, 4),
            },
            "false_positives_sample": false_positives[:5],
            "false_negatives_sample": false_negatives[:5],
            "actionable_recommendations": [
                "If False Positives are elevated: re-calibrate classification threshold higher and add whitelist for technical debugging queries.",
                "If False Negatives occur: generate synthetic adversarial variations around missed payloads and retrain LoRA adapters."
            ]
        }
