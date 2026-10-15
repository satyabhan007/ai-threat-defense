import unittest
from ch02_transformer_finetuning.error_analysis import ErrorAnalyzer

class TestErrorAnalyzer(unittest.TestCase):
    def test_analyze_predictions(self):
        predictions = [
            {"text": "t1", "true_label": 1, "pred_label": 1, "confidence": 0.9},
            {"text": "t2", "true_label": 0, "pred_label": 0, "confidence": 0.1},
            {"text": "t3", "true_label": 0, "pred_label": 1, "confidence": 0.8},
            {"text": "t4", "true_label": 1, "pred_label": 0, "confidence": 0.2},
            {"text": "t5", "true_label": 1, "pred_label": 1, "confidence": 0.85},
            {"text": "t6", "true_label": 0, "pred_label": 1, "confidence": 0.7},
        ]

        result = ErrorAnalyzer.analyze_predictions(predictions)

        self.assertEqual(result["total_samples"], 6)
        self.assertEqual(result["confusion_matrix"]["true_positives"], 2)
        self.assertEqual(result["confusion_matrix"]["true_negatives"], 1)
        self.assertEqual(result["confusion_matrix"]["false_positives"], 2)
        self.assertEqual(result["confusion_matrix"]["false_negatives"], 1)

        metrics = result["metrics"]
        self.assertEqual(metrics["accuracy"], 0.5)
        self.assertEqual(metrics["precision"], 0.5)
        self.assertAlmostEqual(metrics["recall"], 2/3, places=4)

        self.assertEqual(len(result["false_positives_sample"]), 2)
        self.assertEqual(len(result["false_negatives_sample"]), 1)

if __name__ == "__main__":
    unittest.main()
