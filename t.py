from openai import OpenAI

client = OpenAI(api_key="")

resp = client.responses.create(
    model="gpt-4.1-mini",
    input="Say hello in one short sentence."
)

print(resp.output_text)
