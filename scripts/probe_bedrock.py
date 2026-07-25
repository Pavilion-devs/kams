"""Determine which Bedrock auth path works with the credentials in .env.

The .env carries AMAZON_BEDROCK_API_KEY (a Bedrock bearer token) rather than a
SigV4 access-key pair. Those are different auth mechanisms, so rather than guess
which client accepts it, try each path and report what actually works.
"""

import os
import sys

from dotenv import load_dotenv

load_dotenv()

REGION = os.environ.get("AWS_REGION") or "us-east-1"
KEY = os.environ.get("AMAZON_BEDROCK_API_KEY") or os.environ.get("AWS_BEARER_TOKEN_BEDROCK")

if not KEY:
    sys.exit("No AMAZON_BEDROCK_API_KEY / AWS_BEARER_TOKEN_BEDROCK found in environment")

# boto3 reads the bearer token from this specific variable.
os.environ["AWS_BEARER_TOKEN_BEDROCK"] = KEY
os.environ.setdefault("AWS_REGION", REGION)

print(f"region={REGION}  key={KEY[:6]}…{KEY[-4:]}  len={len(KEY)}")
print("=" * 70)


def path_a_list_models() -> list[str]:
    """Control plane: which Anthropic models does this account actually see?"""
    print("\n[A] boto3 bedrock.list_foundation_models (control plane)")
    try:
        import boto3

        bedrock = boto3.client("bedrock", region_name=REGION)
        resp = bedrock.list_foundation_models(byProvider="anthropic")
        ids = [m["modelId"] for m in resp.get("modelSummaries", [])]
        print(f"    OK — {len(ids)} Anthropic models visible")
        for i in ids:
            print(f"      {i}")
        return ids
    except Exception as e:  # noqa: BLE001 - probe: report, don't raise
        print(f"    FAILED — {type(e).__name__}: {str(e)[:200]}")
        return []


def path_a2_inference_profiles() -> list[str]:
    print("\n[A2] boto3 bedrock.list_inference_profiles")
    try:
        import boto3

        bedrock = boto3.client("bedrock", region_name=REGION)
        resp = bedrock.list_inference_profiles()
        ids = [
            p["inferenceProfileId"]
            for p in resp.get("inferenceProfileSummaries", [])
            if "anthropic" in p["inferenceProfileId"]
        ]
        print(f"    OK — {len(ids)} Anthropic inference profiles")
        for i in ids:
            print(f"      {i}")
        return ids
    except Exception as e:  # noqa: BLE001
        print(f"    FAILED — {type(e).__name__}: {str(e)[:200]}")
        return []


def path_b_converse(model_id: str) -> bool:
    """Data plane via boto3 Converse — the documented Bedrock-API-key path."""
    print(f"\n[B] boto3 bedrock-runtime.converse  model={model_id}")
    try:
        import boto3

        rt = boto3.client("bedrock-runtime", region_name=REGION)
        resp = rt.converse(
            modelId=model_id,
            messages=[{"role": "user", "content": [{"text": "Reply with exactly: OK"}]}],
            inferenceConfig={"maxTokens": 16},
        )
        text = resp["output"]["message"]["content"][0]["text"]
        print(f"    OK — model replied: {text!r}")
        return True
    except Exception as e:  # noqa: BLE001
        print(f"    FAILED — {type(e).__name__}: {str(e)[:250]}")
        return False


def path_c_mantle(model_id: str) -> bool:
    """Anthropic SDK Mantle client — the path we want for tool_runner + MCP helpers."""
    print(f"\n[C] AnthropicBedrockMantle  model={model_id}")
    try:
        from anthropic import AnthropicBedrockMantle

        client = AnthropicBedrockMantle(aws_region=REGION)
        resp = client.messages.create(
            model=model_id,
            max_tokens=16,
            messages=[{"role": "user", "content": "Reply with exactly: OK"}],
        )
        print(f"    OK — model replied: {resp.content[0].text!r}")
        return True
    except Exception as e:  # noqa: BLE001
        print(f"    FAILED — {type(e).__name__}: {str(e)[:250]}")
        return False


def path_c2_mantle_bearer(model_id: str) -> bool:
    """Mantle client with the bearer token passed explicitly as auth_token."""
    print(f"\n[C2] AnthropicBedrockMantle(auth_token=…)  model={model_id}")
    try:
        from anthropic import AnthropicBedrockMantle

        client = AnthropicBedrockMantle(aws_region=REGION, auth_token=KEY)
        resp = client.messages.create(
            model=model_id,
            max_tokens=16,
            messages=[{"role": "user", "content": "Reply with exactly: OK"}],
        )
        print(f"    OK — model replied: {resp.content[0].text!r}")
        return True
    except Exception as e:  # noqa: BLE001
        print(f"    FAILED — {type(e).__name__}: {str(e)[:250]}")
        return False


models = path_a_list_models()
profiles = path_a2_inference_profiles()

# Prefer a discovered profile/model; otherwise fall back to documented guesses.
candidates = [m for m in profiles if "claude" in m][:1]
candidates += [m for m in models if "claude" in m][:1]
if not candidates:
    candidates = ["us.anthropic.claude-sonnet-4-5-20250929-v1:0"]

print("\n" + "=" * 70)
print(f"probing data plane with: {candidates[0]}")
path_b_converse(candidates[0])
path_c_mantle("anthropic.claude-opus-5")
path_c2_mantle_bearer("anthropic.claude-opus-5")
