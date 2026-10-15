"""Unit tests for ONNX export."""
import unittest
import sys
import os
import tempfile
import shutil

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from ch04_onnx_serving.export_onnx import export_model_to_onnx, ONNXExportConfig


class TestExportONNX(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_export_happy_path(self):
        config = ONNXExportConfig(
            model_name="test_model",
            output_dir=self.test_dir
        )
        out_path = export_model_to_onnx(config)

        # Verify return path
        expected_path = os.path.join(self.test_dir, "test_model.onnx")
        self.assertEqual(out_path, expected_path)

        # Verify file creation
        self.assertTrue(os.path.exists(out_path))

        # Verify contents
        with open(out_path, "rb") as f:
            content = f.read()
        self.assertEqual(content, b"ONNX_V17_GRAPH_SPEC_AI_THREAT_DETECTOR\x00\x01\x02\x03")

    def test_export_nested_directory(self):
        nested_dir = os.path.join(self.test_dir, "deeply", "nested", "path")
        config = ONNXExportConfig(
            model_name="nested_model",
            output_dir=nested_dir
        )

        # Ensure it doesn't exist yet
        self.assertFalse(os.path.exists(nested_dir))

        out_path = export_model_to_onnx(config)

        self.assertTrue(os.path.exists(out_path))
        self.assertTrue(os.path.exists(nested_dir))

    def test_export_existing_directory(self):
        # Create directory first
        os.makedirs(self.test_dir, exist_ok=True)

        config = ONNXExportConfig(
            model_name="existing_dir_model",
            output_dir=self.test_dir
        )

        out_path = export_model_to_onnx(config)

        self.assertTrue(os.path.exists(out_path))


if __name__ == "__main__":
    unittest.main()
