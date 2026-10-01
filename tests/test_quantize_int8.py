import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from ch04_onnx_serving.quantize_int8 import INT8Quantizer

class TestINT8Quantizer(unittest.TestCase):
    def test_quantize_basic(self):
        """Test basic quantization without zero point shift."""
        weights = [1.0, -1.0, 0.5, -0.5, 0.0]
        scale = 0.5
        zero_point = 0
        expected = [2, -2, 1, -1, 0]

        result = INT8Quantizer.quantize(weights, scale, zero_point)
        self.assertEqual(result, expected)

    def test_quantize_with_zero_point(self):
        """Test quantization with a non-zero zero point."""
        weights = [1.0, 2.0, -1.0]
        scale = 0.1
        zero_point = 50
        expected = [60, 70, 40]

        result = INT8Quantizer.quantize(weights, scale, zero_point)
        self.assertEqual(result, expected)

    def test_quantize_clamping(self):
        """Test that values are correctly clamped between -128 and 127."""
        weights = [200.0, -200.0, 127.5, -128.5]
        scale = 1.0
        zero_point = 0
        expected = [127, -128, 127, -128]

        result = INT8Quantizer.quantize(weights, scale, zero_point)
        self.assertEqual(result, expected)

    def test_dequantize_basic(self):
        """Test basic dequantization."""
        quantized = [60, 70, 40]
        scale = 0.1
        zero_point = 50
        expected = [1.0, 2.0, -1.0]

        result = INT8Quantizer.dequantize(quantized, scale, zero_point)
        for r, e in zip(result, expected):
            self.assertAlmostEqual(r, e)

    def test_roundtrip(self):
        """Test full roundtrip quantization and dequantization preserves values within expected error."""
        weights = [-5.5, -2.1, 0.0, 1.2, 4.8, 9.9]
        min_v = min(weights)
        max_v = max(weights)
        scale, zp = INT8Quantizer.calculate_scale_and_zero_point(min_v, max_v)

        q = INT8Quantizer.quantize(weights, scale, zp)
        approx = INT8Quantizer.dequantize(q, scale, zp)

        for w, a in zip(weights, approx):
            # Error should be bounded by scale/2
            self.assertTrue(abs(w - a) <= (scale / 2) + 1e-5)

if __name__ == '__main__':
    unittest.main()
