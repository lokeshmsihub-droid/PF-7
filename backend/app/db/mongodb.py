from pymongo import MongoClient
from app.core.config import settings

class MongoDBClient:
    """Helper client to manage connections to MongoDB raw events collections."""
    
    def __init__(self):
        self.url = settings.MONGODB_URL
        self.db_name = settings.MONGODB_DB_NAME
        self._client = None
        self._db = None

    def connect(self):
        """Establish connection to MongoDB."""
        if not self._client:
            self._client = MongoClient(self.url)
            self._db = self._client[self.db_name]

    def disconnect(self):
        """Close connection to MongoDB."""
        if self._client:
            self._client.close()
            self._client = None
            self._db = None

    @property
    def db(self):
        """Get the database instance."""
        if self._db is None:
            self.connect()
        return self._db

    @property
    def raw_events_collection(self):
        """Get the raw_events collection handler."""
        return self.db["raw_events"]
