"""RAG chain using LangChain LCEL (compatible with langchain 0.3+ / 1.x).

The chain accepts {"input": str, "chat_history": list} and returns a str answer.
"""
from __future__ import annotations

from langchain_core.messages import AIMessage, BaseMessage, HumanMessage
from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_core.runnables import RunnableParallel

from src.llm.factory import get_chat_llm
from src.rag.vectorstore import get_vectorstore

_SYSTEM_PROMPT = """\
You are an expert firewall policy analyst with deep knowledge of Palo Alto Networks \
(PAN-OS), Cisco ASA, Cisco FTD, and Fortinet FortiGate. You have access to a knowledge \
base of firewall rules, NAT rules, address objects, service objects, application objects, \
decryption policies, and threat feeds from multiple devices.

Use the retrieved context below to answer questions about firewall policies. \
If the context does not contain enough information to answer fully, say so — do not \
invent rule details.

**Formatting rules — follow these exactly:**
- Respond in markdown
- Use bullet points for lists; maximum 5 bullets
- Use a fenced code block for any CLI or config syntax
- Keep the total response under 12 lines — be direct and concise
- Do not add preamble, summaries, or closing remarks

**Linking rules — follow these exactly:**
When you reference a specific named object that appears in the retrieved context, \
render it as a markdown link so the user can jump directly to it in the UI. \
Use these URL patterns (replace DEVICE with the actual device name, NAME with the object name):
- Security rule:      [name](/policy?device=DEVICE&type=security_rule&search=NAME)
- NAT rule:           [name](/policy?device=DEVICE&type=nat_rule&search=NAME)
- Address object:     [name](/policy?device=DEVICE&type=address_object&search=NAME)
- Service object:     [name](/policy?device=DEVICE&type=service_object&search=NAME)
- Application:        [name](/policy?device=DEVICE&type=application&search=NAME)
- App group:          [name](/policy?device=DEVICE&type=app_group&search=NAME)
- URL category:       [name](/policy?device=DEVICE&type=url_category&search=NAME)
- Security profile:   [name](/policy?device=DEVICE&type=security_profile&search=NAME)
- Decryption rule:    [name](/policy?device=DEVICE&type=decryption_rule&search=NAME)
- EDL:                [name](/policy?device=DEVICE&type=edl&search=NAME)
- Zone:               [name](/policy?device=DEVICE&type=zone&search=NAME)
- Device (general):   [name](/policy?device=DEVICE)
Only link objects whose exact name and device you know from the retrieved context. \
Do not invent or guess links.

Retrieved context:
{context}
"""

_PROMPT = ChatPromptTemplate.from_messages([
    ("system", _SYSTEM_PROMPT),
    MessagesPlaceholder("chat_history"),
    ("human", "{input}"),
])


def _llm():
    return get_chat_llm()


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
