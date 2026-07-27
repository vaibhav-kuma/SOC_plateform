from typing import Any, Optional, List
from elasticsearch import AsyncElasticsearch
from elasticsearch.exceptions import ConnectionError as ESConnectionError
from core.config import settings
import logging

logger = logging.getLogger("soc.elasticsearch")


class ElasticClient:
    def __init__(self):
        self.client: Optional[AsyncElasticsearch] = None

    async def start(self):
        http_auth = None
        if settings.ELASTICSEARCH_USERNAME and settings.ELASTICSEARCH_PASSWORD:
            http_auth = (settings.ELASTICSEARCH_USERNAME, settings.ELASTICSEARCH_PASSWORD)

        self.client = AsyncElasticsearch(
            hosts=settings.es_hosts,
            http_auth=http_auth,
            verify_certs=settings.ELASTICSEARCH_VERIFY_CERTS,
            sniffer_timeout=60,
            max_retries=settings.ELASTICSEARCH_MAX_RETRIES,
            retry_on_timeout=True,
            timeout=settings.ELASTICSEARCH_TIMEOUT,
        )
        if not await self.client.ping():
            raise ConnectionError("Cannot connect to Elasticsearch")

    async def stop(self):
        if self.client:
            try:
                await self.client.close()
            except Exception as e:
                logger.error(f"Error closing Elasticsearch connection: {e}")

    async def index(self, index: str, document: dict, doc_id: Optional[str] = None) -> dict:
        try:
            return await self.client.index(index=index, document=document, id=doc_id)
        except Exception as e:
            logger.error(f"Elasticsearch index failed: {e}")
            raise

    async def search(self, index: str, query: dict, size: int = 50) -> dict:
        try:
            return await self.client.search(index=index, body=query, size=size)
        except ESConnectionError as e:
            logger.error(f"Elasticsearch search failed: {e}")
            raise
        except Exception as e:
            logger.error(f"Elasticsearch search failed: {e}")
            raise

    async def get(self, index: str, doc_id: str) -> Optional[dict]:
        try:
            result = await self.client.get(index=index, id=doc_id)
            return result["_source"]
        except ESConnectionError as e:
            logger.error(f"Elasticsearch get failed: {e}")
            return None
        except Exception:
            return None

    async def count(self, index: str, query: Optional[dict] = None) -> int:
        try:
            result = await self.client.count(index=index, body=query)
            return result["count"]
        except ESConnectionError as e:
            logger.error(f"Elasticsearch count failed: {e}")
            raise
        except Exception as e:
            logger.error(f"Elasticsearch count failed: {e}")
            raise

    async def bulk_index(self, index: str, documents: List[dict]):
        if not documents:
            return
        actions = []
        for doc in documents:
            action = {"index": {"_index": index}}
            if "_id" in doc:
                action["index"]["_id"] = doc.pop("_id")
            actions.append(action)
            actions.append(doc)
        try:
            await self.client.bulk(operations=actions)
        except ESConnectionError as e:
            logger.error(f"Elasticsearch bulk index failed: {e}")
            raise
        except Exception as e:
            logger.error(f"Elasticsearch bulk index failed: {e}")
            raise

    async def create_index(self, index: str, mappings: dict, settings: Optional[dict] = None):
        exists = await self.client.indices.exists(index=index)
        if not exists:
            body = {"mappings": mappings}
            if settings:
                body["settings"] = settings
            try:
                await self.client.indices.create(index=index, body=body)
            except ESConnectionError as e:
                logger.error(f"Elasticsearch create_index failed: {e}")
                raise
            except Exception as e:
                logger.error(f"Elasticsearch create_index failed: {e}")
                raise

    async def delete_index(self, index: str):
        exists = await self.client.indices.exists(index=index)
        if exists:
            try:
                await self.client.indices.delete(index=index)
            except ESConnectionError as e:
                logger.error(f"Elasticsearch delete_index failed: {e}")
                raise
            except Exception as e:
                logger.error(f"Elasticsearch delete_index failed: {e}")
                raise

    async def search_after(
        self, index: str, query: dict, sort: list, pit_id: Optional[str] = None, size: int = 1000
    ) -> tuple:
        if not pit_id:
            pit = await self.client.open_point_in_time(index=index, keep_alive="5m")
            pit_id = pit["id"]
        query["size"] = size
        query["pit"] = {"id": pit_id, "keep_alive": "5m"}
        query["sort"] = sort
        try:
            result = await self.client.search(**query)
        except ESConnectionError as e:
            logger.error(f"Elasticsearch search_after failed: {e}")
            raise
        except Exception as e:
            logger.error(f"Elasticsearch search_after failed: {e}")
            raise
        return result, pit_id


elastic_client = ElasticClient()
