"""Which current Claude models does this Bedrock account actually have access to?

Being listed by list_foundation_models does not imply access is granted — model
access is enabled per-model. Probe the data plane directly.
"""

import os

from dotenv import load_dotenv

load_dotenv()

REGION = os.environ.get("AWS_REGION") or "us-east-1"
KEY = os.environ.get("AMAZON_BEDROCK_API_KEY") or os.environ.get("AWS_BEARER_TOKEN_BEDROCK")
os.environ["AWS_BEARER_TOKEN_BEDROCK"] = KEY
os.environ.setdefault("AWS_REGION", REGION)

import boto3  # noqa: E402

rt = boto3.client("bedrock-runtime", region_name=REGION)

CANDIDATES = [
    "us.anthropic.claude-opus-5",
    "global.anthropic.claude-opus-5",
    "us.anthropic.claude-sonnet-5",
    "us.anthropic.claude-opus-4-8",
    "us.anthropic.claude-sonnet-4-6",
    "us.anthropic.claude-haiku-4-5-20251001-v1:0",
]

working: list[str] = []
print(f"region={REGION}\n" + "=" * 70)

for model_id in CANDIDATES:
    try:
        resp = rt.converse(
            modelId=model_id,
            messages=[{"role": "user", "content": [{"text": "Reply with exactly: OK"}]}],
            inferenceConfig={"maxTokens": 16},
        )
        text = resp["output"]["message"]["content"][0]["text"].strip()
        usage = resp.get("usage", {})
        print(f"  OK    {model_id}  -> {text!r}  (in={usage.get('inputTokens')} out={usage.get('outputTokens')})")
        working.append(model_id)
    except Exception as e:  # noqa: BLE001
        name = type(e).__name__
        msg = str(e).split(":", 2)[-1].strip()[:110]
        print(f"  FAIL  {model_id}  -> {name}: {msg}")

print("=" * 70)
print(f"\n{len(working)} working model(s):")
for m in working:
    print(f"  {m}")

# Does the Anthropic SDK's Mantle client work against a model we know is enabled?
if working:
    bare = working[0].split(".", 1)[1] if working[0].startswith(("us.", "global.")) else working[0]
    print(f"\n[Mantle] trying AnthropicBedrockMantle with '{bare}'")
    try:
        from anthropic import AnthropicBedrockMantle

        client = AnthropicBedrockMantle(aws_region=REGION)
        r = client.messages.create(
            model=bare,
            max_tokens=16,
            messages=[{"role": "user", "content": "Reply with exactly: OK"}],
        )
        print(f"    OK — {r.content[0].text!r}")
    except Exception as e:  # noqa: BLE001
        print(f"    FAILED — {type(e).__name__}: {str(e)[:220]}")
