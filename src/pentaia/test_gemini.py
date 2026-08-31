from pentaia.llm import get_llm


llm = get_llm()

response = llm.invoke(
    "Reply with exactly: PentAiA Gemini connection successful"
)

print(response.text)