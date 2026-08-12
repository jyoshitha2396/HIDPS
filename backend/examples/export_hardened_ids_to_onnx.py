from __future__ import annotations

import argparse
import sys
from pathlib import Path

import torch

BACKEND_DIR = Path(__file__).resolve().parents[1]
ROOT_DIR = BACKEND_DIR.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from torch_models import create_hardened_ids_model


def export_checkpoint(checkpoint_path: Path, output_path: Path, opset: int = 18) -> None:
    model = create_hardened_ids_model()
    state_dict = torch.load(checkpoint_path, map_location="cpu", weights_only=False)
    model.load_state_dict(state_dict)
    model.eval()

    output_path.parent.mkdir(parents=True, exist_ok=True)
    dummy_input = torch.randn(1, 13, dtype=torch.float32)
    torch.onnx.export(
        model,
        dummy_input,
        output_path.as_posix(),
        export_params=True,
        external_data=False,
        opset_version=opset,
        do_constant_folding=True,
        input_names=["features"],
        output_names=["scores"],
        dynamic_axes={"features": {0: "batch_size"}, "scores": {0: "batch_size"}},
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Export hardened IDS checkpoint to ONNX.")
    parser.add_argument(
        "--checkpoint",
        default=str(ROOT_DIR / "hardened_ids_vfinal.pth"),
        help="Path to the .pth checkpoint file.",
    )
    parser.add_argument(
        "--output",
        default=str(BACKEND_DIR / "models" / "hardened_ids_vfinal.onnx"),
        help="Destination .onnx file path.",
    )
    parser.add_argument("--opset", type=int, default=18)
    args = parser.parse_args()

    checkpoint_path = Path(args.checkpoint).resolve()
    output_path = Path(args.output).resolve()
    export_checkpoint(checkpoint_path, output_path, opset=args.opset)
    print(f"Exported ONNX model to {output_path}")


if __name__ == "__main__":
    main()
