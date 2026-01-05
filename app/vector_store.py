from pathlib import Path

from langchain_core.documents import Document
from langchain_openai import OpenAIEmbeddings
from langchain_community.document_loaders import TextLoader, CSVLoader, PyPDFLoader
from langchain_community.vectorstores import FAISS
import json

# Path to documents
DOCS_PATH = Path("data/fraud_docs")

def load_vector_store() -> FAISS:
    embeddings = OpenAIEmbeddings()
    docs = []

    # ----------------------------
    # TXT Files
    # ----------------------------
    txt_path = DOCS_PATH / "txt"
    if txt_path.exists():
        for txt_file in txt_path.glob("*.txt"):
            try:
                docs.extend(TextLoader(str(txt_file)).load())
            except Exception as e:
                print(f"Error loading TXT file {txt_file}: {e}")

    # ----------------------------
    # CSV Files
    # ----------------------------
    csv_path = DOCS_PATH / "csv"
    if csv_path.exists():
        for csv_file in csv_path.glob("*.csv"):
            try:
                # CSVLoader already returns Document objects
                docs.extend(CSVLoader(str(csv_file)).load())
            except Exception as e:
                print(f"Error loading CSV file {csv_file}: {e}")

    # ----------------------------
    # PDF Files
    # ----------------------------
    pdf_path = DOCS_PATH / "pdf"
    if pdf_path.exists():
        for pdf_file in pdf_path.glob("*.pdf"):
            try:
                docs.extend(PyPDFLoader(str(pdf_file)).load())
            except Exception as e:
                print(f"Error loading PDF file {pdf_file}: {e}")

    # ----------------------------
    # JSON Files
    # ----------------------------
    json_path = DOCS_PATH / "json"
    if json_path.exists():
        for json_file in json_path.glob("*.json"):
            try:
                with open(json_file, "r") as f:
                    data = json.load(f)
                    for item in data:
                        # Wrap each JSON object into a Document
                        docs.append(Document(
                            page_content=json.dumps(item),
                            metadata={"source": str(json_file)}
                        ))
            except Exception as e:
                print(f"Error loading JSON file {json_file}: {e}")

    if not docs:
        raise ValueError("No documents found to build the vector store.")

    vector_store = FAISS.from_documents(docs, embeddings)
    print(f"Loaded {len(docs)} documents into the vector store.")
    return vector_store
