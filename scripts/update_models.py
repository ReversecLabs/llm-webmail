"""Apply the reviewed model catalog without changing server authentication settings."""
import argparse
import json
import os
from pathlib import Path
import tempfile

import toml


def apply_model_catalog(config_path, catalog_path):
    config_path, catalog_path = Path(config_path), Path(catalog_path)
    config = toml.load(config_path)
    catalog = json.loads(catalog_path.read_text())
    models = catalog["models"]
    if not all(model.get("provider") == "openrouter" for model in models):
        raise ValueError("Chat models must use OpenRouter")
    names = [model.get("name", model.get("key")) for model in models]
    if len(names) != len(set(names)) or not all(names):
        raise ValueError("Model identifiers must be present and unique")
    enabled = {model.get("name", model.get("key")) for model in models if model.get("enabled")}
    if catalog.get("selected") not in enabled:
        raise ValueError("The default model must be enabled")
    config["llm"] = catalog
    with tempfile.NamedTemporaryFile("w", dir=config_path.parent, delete=False) as stream:
        temp_path = Path(stream.name)
        try:
            toml.dump(config, stream)
            stream.flush()
            os.chmod(temp_path, config_path.stat().st_mode & 0o777)
            os.replace(temp_path, config_path)
        finally:
            temp_path.unlink(missing_ok=True)
    return len(enabled)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    root = Path(__file__).resolve().parent.parent
    parser.add_argument("--config", type=Path, default=root / "config.toml")
    parser.add_argument("--catalog", type=Path, default=root / "model_catalog.json")
    args = parser.parse_args()
    count = apply_model_catalog(args.config, args.catalog)
    print(f"Updated model catalog: {count} enabled models; other server settings preserved.")
