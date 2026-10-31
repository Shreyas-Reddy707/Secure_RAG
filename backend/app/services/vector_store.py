import uuid
from typing import List, Dict, Any
from qdrant_client import QdrantClient, models
from fastembed import TextEmbedding, SparseTextEmbedding
from app.config import settings

class HybridVectorStore:
    DENSE_MODEL_NAME = "BAAI/bge-small-en-v1.5"
    SPARSE_MODEL_NAME = "Qdrant/bm25"

    def __init__(self):
        self.collection_name = settings.QDRANT_COLLECTION
        try:
            self.client = QdrantClient(
                host=settings.QDRANT_HOST,
                port=settings.QDRANT_PORT,
                api_key=settings.QDRANT_API_KEY,
                timeout=10,
            )
            self.client.get_collections()
        except Exception:
            print("[VectorStore] Qdrant container unreachable, using local in-memory Qdrant instance.")
            self.client = QdrantClient(":memory:")

        self.dense_model = TextEmbedding(model_name=self.DENSE_MODEL_NAME)
        self.sparse_model = SparseTextEmbedding(model_name=self.SPARSE_MODEL_NAME)
        self._ensure_collection()

    def _ensure_collection(self):
        if not self.client.collection_exists(self.collection_name):
            self.client.create_collection(
                collection_name=self.collection_name,
                vectors_config={
                    "dense": models.VectorParams(size=384, distance=models.Distance.COSINE)
                },
                sparse_vectors_config={
                    "sparse": models.SparseVectorParams(modifier=models.Modifier.IDF)
                },
            )

    def reset_and_seed(self, records: List[Dict[str, Any]]):
        if self.client.collection_exists(self.collection_name):
            self.client.delete_collection(self.collection_name)
        self._ensure_collection()
        self.upsert_chunks(records)

    def upsert_chunks(self, records: List[Dict[str, Any]]):
        texts = [r["text"] for r in records]
        dense_vecs = list(self.dense_model.embed(texts))
        sparse_vecs = list(self.sparse_model.embed(texts))

        points = []
        for idx, rec in enumerate(records):
            point_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, rec["chunk_id"]))
            points.append(
                models.PointStruct(
                    id=point_id,
                    vector={
                        "dense": dense_vecs[idx].tolist(),
                        "sparse": models.SparseVector(
                            indices=sparse_vecs[idx].indices.tolist(),
                            values=sparse_vecs[idx].values.tolist(),
                        ),
                    },
                    payload=rec,
                )
            )
        self.client.upsert(collection_name=self.collection_name, points=points)

    def hybrid_search(self, query: str, top_k: int = 6) -> List[Dict[str, Any]]:
        dense_q = list(self.dense_model.embed([query]))[0].tolist()
        sparse_q = list(self.sparse_model.embed([query]))[0]

        results = self.client.query_points(
            collection_name=self.collection_name,
            prefetch=[
                models.Prefetch(query=dense_q, using="dense", limit=top_k * 2),
                models.Prefetch(
                    query=models.SparseVector(
                        indices=sparse_q.indices.tolist(),
                        values=sparse_q.values.tolist(),
                    ),
                    using="sparse",
                    limit=top_k * 2,
                ),
            ],
            query=models.FusionQuery(fusion=models.Fusion.RRF),
            limit=top_k,
            with_payload=True,
        )

        hits = []
        for pt in results.points:
            payload = dict(pt.payload or {})
            # Strip ground-truth evaluation label so pipeline agents never see it
            payload.pop("ground_truth_is_poisoned", None)
            payload["retrieval_score"] = round(float(pt.score or 0.0), 4)
            hits.append(payload)
        return hits

    def list_all_chunks(self) -> List[Dict[str, Any]]:
        records, _ = self.client.scroll(
            collection_name=self.collection_name,
            limit=500,
            with_payload=True,
            with_vectors=False,
        )
        return [dict(r.payload or {}) for r in records]

vector_store = HybridVectorStore()

