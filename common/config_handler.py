import os
import json
from pathlib import Path
from dotenv import load_dotenv

class Config:
    """
    Handles configuration by merging config.json and .env variables.
    Priority: Environment Variables > config.json > Defaults
    """
    def __init__(self, config_path: str = None):
        # Load .env file if it exists
        load_dotenv()
        
        self.base_dir = Path(__file__).parent.parent
        if config_path is None:
            config_path = self.base_dir / "config.json"
        
        self._config_data = {}
        if os.path.exists(config_path):
            with open(config_path, "r") as f:
                self._config_data = json.load(f)

    def get(self, key: str, default=None):
        # 1. Check environment variables (prefixed with GHOSTNET_)
        env_key = f"GHOSTNET_{key.upper()}"
        env_val = os.getenv(env_key)
        if env_val is not None:
            return env_val
        
        # 2. Check config.json
        return self._config_data.get(key, default)

    @property
    def encryption_key(self) -> bytes:
        key = self.get("encryption_key")
        if not key:
            raise ValueError("Encryption key not found in config or environment")
        return key.encode()

    @property
    def domain(self) -> str:
        return self.get("domain", "ghost.net")

    @property
    def server_ip(self) -> str:
        return self.get("server_ip", "127.0.0.1")

    @property
    def server_port(self) -> int:
        return int(self.get("server_port", 53))

    @property
    def chunk_size(self) -> int:
        return int(self.get("chunk_size", 32))

    @property
    def delay_min(self) -> float:
        return float(self.get("delay_min", 0.1))

    @property
    def delay_max(self) -> float:
        return float(self.get("delay_max", 1.0))

# Global config instance
config = Config()
