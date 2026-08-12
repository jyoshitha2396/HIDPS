import argparse
import importlib
from pathlib import Path
from typing import Any

import torch


def resolve_factory(factory_ref: str):
    if ":" not in factory_ref:
        raise ValueError("Factory reference must use module_path:callable_name format.")

    module_name, factory_name = factory_ref.split(":", 1)
    module = importlib.import_module(module_name)
    factory = getattr(module, factory_name, None)
    if factory is None or not callable(factory):
        raise ValueError(f"Could not load callable '{factory_name}' from '{module_name}'.")
    return factory


def load_checkpoint_state(checkpoint_path: Path, state_dict_key: str | None):
    checkpoint = torch.load(checkpoint_path, map_location="cpu")
    if state_dict_key:
        checkpoint = checkpoint[state_dict_key]
    elif isinstance(checkpoint, dict):
        for candidate in ("state_dict", "model_state_dict", "model"):
            if candidate in checkpoint and isinstance(checkpoint[candidate], dict):
                checkpoint = checkpoint[candidate]
                break
    return checkpoint


def main():
    parser = argparse.ArgumentParser(description="Export a PyTorch checkpoint to ONNX.")
    parser.add_argument("--checkpoint", required=True, help="Path to the .pth or .pt checkpoint file.")
    parser.add_argument("--output", required=True, help="Destination .onnx file path.")
    parser.add_argument(
        "--factory",
        required=True,
        help="Python reference to the model factory in module:callable format.",
    )
    parser.add_argument(
        "--input-shape",
        default="1,16",
        help="Dummy input shape as comma-separated integers. Example: 1,16",
    )
    parser.add_argument(
        "--state-dict-key",
        default="",
        help="Optional checkpoint key containing the state_dict, for example model_state_dict.",
    )
    parser.add_argument("--opset", type=int, default=18)
    args = parser.parse_args()

    checkpoint_path = Path(args.checkpoint)
    output_path = Path(args.output)
    input_shape = [int(item.strip()) for item in args.input_shape.split(",") if item.strip()]
    if not input_shape:
        raise ValueError("Input shape must contain at least one dimension.")

    factory = resolve_factory(args.factory)
    model = factory()
    state_dict = load_checkpoint_state(checkpoint_path, args.state_dict_key or None)
    if isinstance(state_dict, dict):
        model.load_state_dict(state_dict)
    else:
        raise ValueError("Checkpoint did not resolve to a state_dict dictionary.")

    model.eval()
    dummy_input = torch.randn(*input_shape, dtype=torch.float32)

    torch.onnx.export(
        model,
        dummy_input,
        output_path.as_posix(),
        export_params=True,
        opset_version=args.opset,
        do_constant_folding=True,
        input_names=["features"],
        output_names=["scores"],
        dynamic_axes={"features": {0: "batch_size"}, "scores": {0: "batch_size"}},
    )

    print(f"Exported ONNX model to {output_path}")


if __name__ == "__main__":
    main()
