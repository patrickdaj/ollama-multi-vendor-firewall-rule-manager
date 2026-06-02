"""RAG chain using LangChain LCEL (compatible with langchain 0.3+ / 1.x).

The chain accepts {"input": str, "chat_history": list} and returns a str answer.
"""
from __future__ import annotations

from langchain_core.messages import AIMessage, BaseMessage, HumanMessage
from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_core.runnables import RunnableParallel
from langchain_ollama import ChatOllama

from src.config import settings
from src.rag.vectorstore import get_vectorstore

_SYSTEM_PROMPT = """\
You are an expert firewall policy analyst with deep knowledge of Palo Alto Networks \
(PAN-OS), Cisco ASA, Cisco FTD, and Fortinet FortiGate. You have access to a knowledge \
base of firewall rules, NAT rules, address objects, service objects, application objects, \
decryption policies, and threat feeds from multiple devices.

Use the retrieved context below to answer questions about firewall policies. When \
referencing rules or objects, always include the device name, vendor, and object name. \
If the context does not contain enough information to answer fully, say so — do not \
invent rule details.

Retrieved context:
{context}
"""

_PROMPT = ChatPromptTemplate.from_messages([
    ("system", _SYSTEM_PROMPT),
    MessagesPlaceholder("chat_history"),
    ("human", "{input}"),
])


def _llm() -> ChatOllama:
    return ChatOllama(
        base_url=settings.ollama_base_url,
        model=settings.ollama_chat_model,
        temperature=0.1,
    )


def get_retriever(k: int = 8):
    return get_vectorstore().as_retriever(search_kwargs={"k": k})


def _format_docs(docs) -> str:
    return "\n\n".join(d.page_content for d in docs)


def build_rag_chain():
    """Return a chain: {input, chat_history} → str answer."""
    retriever = get_retriever()
    llm = _llm()

    chain = (
        RunnableParallel(
            context=(lambda x: x["input"]) | retriever | _format_docs,
            input=lambda x: x["input"],
            chat_history=lambda x: x.get("chat_history", []),
        )
        | _PROMPT
        | llm
        | StrOutputParser()
    )
    return chain


def messages_to_history(messages: list[dict]) -> list[BaseMessage]:
    result: list[BaseMessage] = []
    for m in messages:
        if m["role"] == "user":
            result.append(HumanMessage(content=m["content"]))
        elif m["role"] == "assistant":
            result.append(AIMessage(content=m["content"]))
    return result
