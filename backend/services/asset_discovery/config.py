from pydantic_settings import BaseSettings


class AssetDiscoverySettings(BaseSettings):
    SCAN_INTERVAL_MINUTES: int = 60
    MAX_CONCURRENT_SCANS: int = 10
    DISCOVERY_TIMEOUT_SECONDS: int = 300
    NMAP_RATE: str = "1000"
    CLOUD_DISCOVERY_ENABLED: bool = True
    CONTAINER_DISCOVERY_ENABLED: bool = True
    ACTIVE_PROBE_INTERVAL: int = 300

    class Config:
        env_file = ".env"
        extra = "allow"


asset_settings = AssetDiscoverySettings()
