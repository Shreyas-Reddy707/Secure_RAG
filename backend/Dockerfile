FROM python:3.11-slim

WORKDIR /app

# 1. Install system build essentials required by ONNX/FastEmbed
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# 2. Configure Python and FastEmbed cache environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    FASTEMBED_CACHE_PATH=/app/.fastembed_cache

# 3. Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# 4. Pre-warm local FastEmbed Dense (BGE) & Sparse (BM25) models at build time
RUN python -c "from fastembed import TextEmbedding, SparseTextEmbedding; \
    TextEmbedding(model_name='BAAI/bge-small-en-v1.5', cache_dir='/app/.fastembed_cache'); \
    SparseTextEmbedding(model_name='Qdrant/bm25', cache_dir='/app/.fastembed_cache')"

# 5. Copy backend application source
COPY . .

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

