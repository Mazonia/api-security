"""RAG Pipeline & Vector Store Surface Audit Rule."""
import re
from typing import Dict, List, Any
from ..governance import get_governance_mapping

VECTOR_STORE_PATTERNS = {
    "Pinecone": re.compile(r'\b(?:pinecone|Pinecone|PineconeVectorStore)\b', re.I),
    "ChromaDB": re.compile(r'\b(?:chromadb|Chroma|ChromaVectorStore)\b', re.I),
    "Qdrant": re.compile(r'\b(?:qdrant_client|QdrantClient|QdrantVectorStore)\b', re.I),
    "Weaviate": re.compile(r'\b(?:weaviate|WeaviateVectorStore)\b', re.I),
    "Milvus": re.compile(r'\b(?:pymilvus|MilvusClient|Milvus)\b', re.I),
    "FAISS": re.compile(r'\b(?:faiss|FAISS)\b', re.I),
    "LanceDB": re.compile(r'\b(?:lancedb|LanceDBVectorStore)\b', re.I),
    "pgvector": re.compile(r'\b(?:pgvector|PGVector)\b', re.I),
    "Elasticsearch/OpenSearch": re.compile(r'\b(?:ElasticsearchStore|OpenSearchVectorSearch)\b', re.I),
    "Redis Vector": re.compile(r'\b(?:RedisVectorStore)\b', re.I),
    "Vespa": re.compile(r'\b(?:vespa_app|Vespa)\b', re.I)
}


class RagSecurityRule:
    def audit(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        findings = []

        # 1. Identify vector stores present
        detected_stores = []
        for store_name, pattern in VECTOR_STORE_PATTERNS.items():
            if pattern.search(content):
                detected_stores.append(store_name)

        if detected_stores:
            # Check for multi-tenant filter in similarity search
            sim_search_matches = list(re.finditer(r'(?:similarity_search|query|search|retrieve)\s*\([^\)]*\)', content, re.I))
            has_tenant_filter = bool(re.search(r'\b(?:filter\s*=|namespace\s*=|tenant_id|org_id|user_id|tenant)\b', content, re.I))

            for store in detected_stores:
                if sim_search_matches and not has_tenant_filter:
                    gov = get_governance_mapping("rag-cross-tenant-isolation-gap")
                    findings.append({
                        "rule_id": "rag-cross-tenant-isolation-gap",
                        "title": f"Vector Store ({store}) Query Lacks Tenant Isolation Filter",
                        "severity": "HIGH",
                        "file": file_path,
                        "line": content[:sim_search_matches[0].start()].count("\n") + 1,
                        "snippet": content[max(0, sim_search_matches[0].start()-30):sim_search_matches[0].end()+30].strip(),
                        "description": f"Vector search on {store} does not enforce metadata tenant/user isolation filters, risking cross-tenant data leakage.",
                        "governance": gov
                    })

            # Check for untrusted external ingestion
            if re.search(r'(?:RecursiveUrlLoader|WebBaseLoader|UnstructuredURLLoader|requests\.get|urllib\.request)\s*\(', content, re.I):
                gov = get_governance_mapping("rag-external-poisoning-surface")
                findings.append({
                    "rule_id": "rag-external-poisoning-surface",
                    "title": "RAG Ingestion from Untrusted External URL",
                    "severity": "MEDIUM",
                    "file": file_path,
                    "line": 1,
                    "snippet": "External URL loader feeds into RAG embedding store",
                    "description": "RAG pipeline ingests dynamic unverified web content directly into vector embeddings (Data Poisoning surface).",
                    "governance": gov
                })

        return findings
