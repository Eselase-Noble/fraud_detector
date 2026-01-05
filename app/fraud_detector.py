from dotenv import load_dotenv
from langchain_classic.chains.retrieval_qa.base import RetrievalQA

from app.models import Transaction, FraudResult
from langchain_openai import ChatOpenAI
from app.vector_store import load_vector_store
from app.external import load_risk_data
import os

load_dotenv()
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
if not OPENAI_API_KEY:
    raise ValueError("OPENAI_API_KEY not set in environment!")

os.environ["OPENAI_API_KEY"] = OPENAI_API_KEY
llm = ChatOpenAI(model="gpt-4.1", temperature=0)
vector_store = load_vector_store()

def detect_fraud(txn: Transaction, history: list[Transaction]) -> FraudResult:
    risks = load_risk_data()

    signals = []
    score = 0.1

    # -------------------------
    # Deterministic risk rules
    # -------------------------
    if txn.amount > 1000:
        signals.append("High transaction amount")
        score += 0.4

    if history:
        last_location = history[0].location
        if txn.location and last_location and txn.location != last_location:
            signals.append("Location anomaly")
            score += 0.3

    for r in risks:
        if r["country"] == txn.location and r["risk_level"] == "high":
            signals.append("High-risk country")
            score += 0.3

    score = min(score, 1.0)
    decision = "BLOCK" if score > 0.7 else "REVIEW" if score > 0.4 else "ALLOW"

    # -------------------------
    # RAG Context
    # -------------------------
    history_context = [
        {
            "amount": h.amount,
            "location": h.location,
            "timestamp": h.timestamp.isoformat()
        }
        for h in history[:5]
    ]

    rag_prompt = f"""
You are a fraud detection expert.

Use ONLY retrieved knowledge from the fraud knowledge base.

### Transaction
{txn.model_dump()}

### User History
{history_context}

### Detected Risk Signals
{signals}

Explain the fraud risk and justify the decision.
"""

    # -------------------------
    # Retrieval QA (REAL RAG)
    # -------------------------
    retriever = vector_store.as_retriever(search_kwargs={"k": 5})

    qa_chain = RetrievalQA.from_chain_type(
        llm=llm,
        retriever=retriever,
        return_source_documents=False
    )

    rag_result = qa_chain.invoke(rag_prompt)

    # Depending on LC version
    reason = (
        rag_result["result"]
        if isinstance(rag_result, dict)
        else str(rag_result)
    )

    return FraudResult(
        transaction_id=txn.transaction_id,
        score=score,
        decision=decision,
        reason=reason,
        signals=signals
    )

