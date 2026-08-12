import math
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from model_presets import (
    HARDENED_IDS_FEATURE_ORDER,
    HARDENED_IDS_LABELS,
    default_hardened_ids_model_path,
    normalize_feature_map,
)


class BaseModelAdapter:
    runtime = "disabled"

    def predict(self, features: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        return None

    def status(self) -> Dict[str, Any]:
        return {
            "runtime": self.runtime,
            "enabled": False,
            "error": "Model runtime disabled.",
            "feature_order": [],
            "labels": [],
        }


class OnnxModelAdapter(BaseModelAdapter):
    runtime = "onnx"

    def __init__(self) -> None:
        self.enabled = False
        self.error: Optional[str] = None
        self.session = None
        self.input_name = ""
        self.feature_order: List[str] = []
        self.labels: List[str] = []
        self.output_names: List[str] = []
        self.model_path = ""

        model_path = os.getenv("ONNX_MODEL_PATH", "").strip()
        if not model_path:
            bundled_model = default_hardened_ids_model_path()
            if bundled_model.exists():
                model_path = str(bundled_model)

        feature_order = [
            item.strip() for item in os.getenv("MODEL_FEATURE_ORDER", "").split(",") if item.strip()
        ] or list(HARDENED_IDS_FEATURE_ORDER)
        labels = [item.strip() for item in os.getenv("MODEL_LABELS", "").split(",") if item.strip()] or list(
            HARDENED_IDS_LABELS
        )

        if not model_path or not feature_order:
            self.error = "Missing ONNX_MODEL_PATH or MODEL_FEATURE_ORDER."
            return

        try:
            import numpy as np
            import onnxruntime as ort
        except ImportError:
            self.error = "onnxruntime and numpy must be installed for ONNX inference."
            return

        self.np = np
        self.ort = ort
        self.feature_order = feature_order
        self.labels = labels
        self.model_path = str(Path(model_path).resolve())

        try:
            self.session = ort.InferenceSession(model_path, providers=["CPUExecutionProvider"])
        except Exception as exc:
            self.error = f"Could not load ONNX model: {exc}"
            return

        self.input_name = self.session.get_inputs()[0].name
        self.output_names = [item.name for item in self.session.get_outputs()]
        self.enabled = True

    def _softmax(self, values: List[float]) -> List[float]:
        if not values:
            return []
        highest = max(values)
        exponentials = [math.exp(value - highest) for value in values]
        total = sum(exponentials) or 1.0
        return [item / total for item in exponentials]

    def predict(self, features: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not self.enabled or self.session is None:
            return None

        normalized_features = normalize_feature_map(features)
        vector = [[float(normalized_features.get(name, 0.0)) for name in self.feature_order]]
        input_tensor = self.np.asarray(vector, dtype=self.np.float32)
        outputs = self.session.run(None, {self.input_name: input_tensor})
        if not outputs:
            return None

        raw_output = outputs[0]
        raw_scores = self.np.ravel(raw_output).astype(float).tolist()
        if not raw_scores:
            return None

        if len(raw_scores) == 1:
            score = max(0.0, min(1.0, float(raw_scores[0])))
            if len(self.labels) >= 2:
                probabilities = [round(1.0 - score, 4), round(score, 4)]
            else:
                probabilities = [round(score, 4)]
        elif all(0.0 <= float(value) <= 1.0 for value in raw_scores):
            probabilities = [float(value) for value in raw_scores]
        else:
            probabilities = self._softmax([float(value) for value in raw_scores])

        predicted_index = max(range(len(probabilities)), key=probabilities.__getitem__)
        predicted_label = (
            self.labels[predicted_index]
            if predicted_index < len(self.labels)
            else f"class_{predicted_index}"
        )
        return {
            "attack_type": predicted_label,
            "confidence": round(float(probabilities[predicted_index]), 4),
            "runtime": self.runtime,
            "feature_order": self.feature_order,
        }

    def status(self) -> Dict[str, Any]:
        return {
            "runtime": self.runtime,
            "enabled": self.enabled,
            "error": self.error,
            "feature_order": self.feature_order,
            "labels": self.labels,
            "input_name": self.input_name,
            "output_names": self.output_names,
            "model_path": self.model_path,
        }


def build_model_adapter() -> BaseModelAdapter:
    runtime = os.getenv("MODEL_RUNTIME", "").strip().lower()
    if runtime == "onnx":
        return OnnxModelAdapter()
    return BaseModelAdapter()
