import logging
import datetime
from typing import Dict, Any, Optional
from app.core.config import settings

logger = logging.getLogger(__name__)

class RawResultStorageService:
    """
    MongoDB storage service for unadulterated scanner outputs (SARIF, JSON, etc.)
    Preserves audit artifacts separately from relational metadata with strict tenant isolation.
    """

    def __init__(self, uri: Optional[str] = None, db_name: Optional[str] = None):
        self.uri = uri or settings.MONGODB_URI
        self.db_name = db_name or settings.MONGODB_DB
        self.enabled = settings.ENABLE_MONGODB_STORAGE
        self._client = None

    def _get_collection(self):
        if not self.enabled:
            return None
        try:
            import pymongo
            if not self._client:
                self._client = pymongo.MongoClient(self.uri, serverSelectionTimeoutMS=2000)
            db = self._client[self.db_name]
            return db["raw_scan_results"]
        except Exception as exc:
            logger.warning(f"MongoDB unavailable for raw result storage: {exc}")
            return None

    def store_raw_result(
        self,
        tenant_id: int,
        scan_id: str,
        repository_id: str,
        repository_name: str,
        scanner: str,
        scanner_version: str,
        output_format: str,
        raw_output: str,
        artifact_hash: str
    ) -> Optional[str]:
        """
        Stores the raw scan artifact document in MongoDB.
        Returns document location string if stored, or None.
        """
        collection = self._get_collection()
        if collection is None:
            return None

        doc = {
            "tenant_id": tenant_id,
            "scan_id": scan_id,
            "repository_id": repository_id,
            "repository_name": repository_name,
            "scanner": scanner,
            "scanner_version": scanner_version,
            "format": output_format,
            "artifact_hash": artifact_hash,
            "raw_result": raw_output,
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "raw_result_location": f"mongodb://{self.db_name}/raw_scan_results/{scan_id}"
        }

        try:
            collection.replace_one(
                {"tenant_id": tenant_id, "scan_id": scan_id, "scanner": scanner},
                doc,
                upsert=True
            )
            logger.info(f"Stored raw scanner result for ScanJob {scan_id} [{scanner}] in MongoDB.")
            return doc["raw_result_location"]
        except Exception as exc:
            logger.error(f"Failed to persist raw scan result to MongoDB: {exc}")
            return None

    def get_raw_result(self, tenant_id: int, scan_id: str, scanner: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """
        Retrieves raw scanner artifact with strict tenant isolation.
        """
        collection = self._get_collection()
        if collection is None:
            return None

        try:
            query = {"tenant_id": tenant_id, "scan_id": scan_id}
            if scanner:
                query["scanner"] = scanner
            doc = collection.find_one(query, {"_id": 0})
            return doc
        except Exception as exc:
            logger.error(f"Failed to query MongoDB raw result: {exc}")
            return None

    def list_raw_results(self, tenant_id: int, scan_id: str) -> List[Dict[str, Any]]:
        """
        Retrieves all raw scanner artifacts for a scan with strict tenant isolation.
        """
        collection = self._get_collection()
        if collection is None:
            return []

        try:
            cursor = collection.find(
                {"tenant_id": tenant_id, "scan_id": scan_id},
                {"_id": 0, "raw_result": 0}
            )
            return list(cursor)
        except Exception as exc:
            logger.error(f"Failed to list MongoDB raw results: {exc}")
            return []
