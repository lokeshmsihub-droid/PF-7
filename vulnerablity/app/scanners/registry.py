import logging
from typing import Dict, Any, List, Optional, Type
from app.scanners.base import ScannerAdapter, ScannerCapability

logger = logging.getLogger(__name__)

class ScannerRegistry:
    """
    Central registry for security scanner adapters.
    Manages lifecycle, initialization, health checks, and capability queries.
    """
    _adapters: Dict[str, Type[ScannerAdapter]] = {}
    _instances: Dict[str, ScannerAdapter] = {}

    @classmethod
    def register(cls, name: str, adapter_cls: Type[ScannerAdapter]) -> None:
        cls._adapters[name.lower()] = adapter_cls
        logger.info(f"Registered scanner adapter: {name.lower()}")

    @classmethod
    def get(cls, name: str, config: Optional[Dict[str, Any]] = None) -> ScannerAdapter:
        cls._ensure_defaults_registered()
        name_key = name.lower()
        if name_key not in cls._instances:
            if name_key not in cls._adapters:
                raise ValueError(f"Scanner '{name}' is not registered in ScannerRegistry. Available: {list(cls._adapters.keys())}")
            adapter = cls._adapters[name_key]()
            adapter.initialize(config)
            cls._instances[name_key] = adapter
        return cls._instances[name_key]

    @classmethod
    def list_available(cls) -> List[Dict[str, Any]]:
        cls._ensure_defaults_registered()
        results = []
        for name in list(cls._adapters.keys()):
            try:
                adapter = cls.get(name)
                is_valid = adapter.validate()
                cap = adapter.detect_capabilities()
                results.append({
                    "name": name,
                    "version": cap.version,
                    "available": is_valid,
                    "supported_languages": cap.supported_languages,
                    "scan_types": cap.scan_types,
                    "features": cap.features,
                })
            except Exception as e:
                results.append({
                    "name": name,
                    "available": False,
                    "error": str(e)
                })
        return results

    @classmethod
    def _ensure_defaults_registered(cls) -> None:
        if not cls._adapters:
            from app.scanners.semgrep.adapter import SemgrepAdapter
            from app.scanners.codeql.adapter import CodeQLAdapter
            from app.scanners.trivy.adapter import TrivyAdapter
            from app.scanners.osv.adapter import OSVAdapter

            cls.register("semgrep", SemgrepAdapter)
            cls.register("codeql", CodeQLAdapter)
            cls.register("trivy", TrivyAdapter)
            cls.register("osv", OSVAdapter)
            cls.register("osv-scanner", OSVAdapter)

    @classmethod
    def reset(cls) -> None:
        cls._instances.clear()
