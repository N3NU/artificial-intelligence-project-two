from pathlib import Path

from langchain_community.document_loaders import TextLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_ollama import OllamaEmbeddings
from langchain_community.vectorstores import Chroma

# -------------------------
# CONFIG
# -------------------------

DOCS_PATH = "./docs"
DB_PATH = "./chroma_db"
COLLECTION_NAME = "secure_rag"

# -------------------------
# LOAD DOCUMENTS
# -------------------------

all_docs = []

for file_path in Path(DOCS_PATH).glob("*.txt"):

    print(f"Loading: {file_path.name}")
    loader = TextLoader(str(file_path))
    docs = loader.load()
#    if "phishing" in str(file_path):
#        print(f"docs: {docs}")
    filename = file_path.name

    # -------------------------
    # DEFAULT METADATA
    # -------------------------

    metadata = {
        "source": filename,
        "trusted": True,
        "department": "general",
        "classification": "internal",
        "category": "general"
    }

    # -------------------------
    # DOCUMENT-SPECIFIC METADATA
    # -------------------------

    if "ransomware" in filename:
        metadata["category"] = "ransomware"
        metadata["department"] = "incident_response"

    elif "phishing" in filename:
        metadata["category"] = "phishing"
        metadata["department"] = "security_awareness"
    elif "password" in filename:
        metadata["category"] = "identity"
        metadata["department"] = "it_security"

    elif "ir_sop" in filename:
        metadata["category"] = "incident_response"
        metadata["department"] = "soc"

    elif "malicious" in filename:
        metadata["trusted"] = False
        metadata["classification"] = "untrusted"
        metadata["category"] = "prompt_injection"

    # -------------------------
    # APPLY METADATA
    # -------------------------

    for doc in docs:
        doc.metadata.update(metadata)
 #       if "phishing" in str(file_path):
 #           print(f"docs updated: {docs}")
    all_docs.extend(docs)

print(f"\nLoaded {len(all_docs)} documents")

# -------------------------
# CHUNKING
# -------------------------

splitter = RecursiveCharacterTextSplitter(
    chunk_size=500,
    chunk_overlap=100
)

chunks = splitter.split_documents(all_docs)

print(f"Created {len(chunks)} chunks")

# -------------------------
# EMBEDDINGS
# -------------------------

embeddings = OllamaEmbeddings(
    model="nomic-embed-text"
)

# -------------------------
# VECTOR DB
# -------------------------

db = Chroma.from_documents(
    documents=chunks,
    embedding=embeddings,
    persist_directory=DB_PATH,
    collection_name=COLLECTION_NAME
)

print("\nVector DB ingestion complete.")
print(f"\nchunk metadata:\n\n{chunks[0].metadata}\n\nchunk:\n\n{chunks[0]}")
