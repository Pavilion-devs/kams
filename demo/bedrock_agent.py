"""Real Bedrock agent demo: inference -> MCP rug pull -> SigNoz quarantine.

This is deliberately not a playback. It calls Amazon Bedrock Converse, lets the
model choose an MCP tool, sends that call through Kams, and feeds the policy
error back to the model so the agent can degrade safely.

Prerequisites:
  1. SigNoz Foundry is running and provisioned.
  2. .env contains AMAZON_BEDROCK_API_KEY.

Run:
    kams-demo-agent
    uv run python demo/bedrock_agent.py
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import pathlib
import sys
import tempfile
import time
import uuid
from typing import Any

import boto3
import httpx
from dotenv import load_dotenv
from opentelemetry.trace import SpanKind, Status, StatusCode

from kams.daemon.state import SharedState
from kams.detect.cost import ContextCostEstimator
from kams.protocol import mcp
from kams.telemetry import semconv as sc
from kams.telemetry import tracing

ROOT = pathlib.Path(__file__).resolve().parent.parent
MODEL_DEFAULT = "us.anthropic.claude-sonnet-4-6"
GREEN, RED, CYAN, DIM, BOLD, RESET = (
    "\033[32m", "\033[31m", "\033[36m", "\033[2m", "\033[1m", "\033[0m"
)


class MCPClient:
    """Small sequential stdio MCP client with SEP-414 propagation."""

    def __init__(self, command: list[str], *, env: dict[str, str]) -> None:
        self.command = command
        self.env = env
        self.proc: asyncio.subprocess.Process | None = None
        self._id = 0

    async def __aenter__(self) -> MCPClient:
        self.proc = await asyncio.create_subprocess_exec(
            *self.command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=ROOT,
            env=self.env,
            limit=32 * 1024 * 1024,
        )
        return self

    async def __aexit__(self, *_exc) -> None:
        if self.proc and self.proc.returncode is None:
            assert self.proc.stdin
            self.proc.stdin.close()
            try:
                await asyncio.wait_for(self.proc.wait(), timeout=10)
            except asyncio.TimeoutError:
                self.proc.kill()

    async def call(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        assert self.proc and self.proc.stdin and self.proc.stdout
        self._id += 1
        outbound = dict(params or {})
        traceparent, tracestate, baggage = tracing.traceparent_from_current()
        if traceparent:
            outbound = mcp.inject_trace_context(
                outbound, traceparent, tracestate, baggage
            )
        request = {
            "jsonrpc": "2.0",
            "id": self._id,
            "method": method,
            "params": outbound,
        }
        self.proc.stdin.write(json.dumps(request, separators=(",", ":")).encode() + b"\n")
        await self.proc.stdin.drain()
        line = await asyncio.wait_for(self.proc.stdout.readline(), timeout=30)
        if not line:
            stderr = await self.proc.stderr.read() if self.proc.stderr else b""
            raise RuntimeError(f"MCP shim exited without a response: {stderr.decode()[-800:]}")
        return json.loads(line)


def _shim_command(
    lock: pathlib.Path,
    state: pathlib.Path,
    server_name: str = "notes-mcp",
) -> list[str]:
    return [
        sys.executable,
        "-m",
        "kams.cli",
        "shim",
        "--server",
        server_name,
        "--lock",
        str(lock),
        "--state",
        str(state),
        "--no-reflex",
        "--no-forward",
        "--",
        sys.executable,
        "demo/rogue_mcp_server.py",
    ]


async def _mcp_session(
    lock: pathlib.Path,
    state: pathlib.Path,
    poison_flag: pathlib.Path,
    server_name: str = "notes-mcp",
) -> MCPClient:
    env = {**os.environ, "KAMS_DEMO_POISON_FLAG": str(poison_flag)}
    client = MCPClient(_shim_command(lock, state, server_name), env=env)
    await client.__aenter__()
    await client.call("initialize", {"protocolVersion": "2025-06-18"})
    return client


async def _pin(lock: pathlib.Path, server_name: str = "notes-mcp") -> None:
    proc = await asyncio.create_subprocess_exec(
        sys.executable,
        "-m",
        "kams.cli",
        "pin",
        server_name,
        "--lock",
        str(lock),
        cwd=ROOT,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()
    if proc.returncode:
        raise RuntimeError(f"pin failed: {stderr.decode()}")
    print(f"  {GREEN}✓{RESET} {stdout.decode().strip()}")


async def _start_daemon(state: pathlib.Path, port: int) -> asyncio.subprocess.Process:
    proc = await asyncio.create_subprocess_exec(
        sys.executable,
        "-m",
        "kams.cli",
        "daemon",
        "--state",
        str(state),
        "--port",
        str(port),
        "--no-judge",
        "--log-level",
        "info",
        cwd=ROOT,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=os.environ.copy(),
    )
    async with httpx.AsyncClient(timeout=1.0) as client:
        for _ in range(50):
            if proc.returncode is not None:
                stderr = await proc.stderr.read() if proc.stderr else b""
                raise RuntimeError(f"kamsd failed to start: {stderr.decode()[-800:]}")
            try:
                response = await client.get(f"http://127.0.0.1:{port}/")
                if response.status_code == 200:
                    return proc
            except httpx.HTTPError:
                pass
            await asyncio.sleep(0.1)
    proc.terminate()
    raise RuntimeError(f"kamsd did not become healthy on port {port}")


async def _start_signoz_proxy(
    lock: pathlib.Path,
    state: pathlib.Path,
    port: int,
) -> asyncio.subprocess.Process:
    proc = await asyncio.create_subprocess_exec(
        sys.executable,
        "-m",
        "kams.cli",
        "proxy",
        "--upstream",
        os.environ.get("SIGNOZ_MCP_UPSTREAM", "http://127.0.0.1:8000/mcp"),
        "--server",
        "signoz-mcp",
        "--port",
        str(port),
        "--lock",
        str(lock),
        "--state",
        str(state),
        "--no-reflex",
        "--no-forward",
        cwd=ROOT,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=os.environ.copy(),
    )
    async with httpx.AsyncClient(timeout=1.0) as client:
        for _ in range(50):
            if proc.returncode is not None:
                stderr = await proc.stderr.read() if proc.stderr else b""
                raise RuntimeError(f"SigNoz MCP proxy failed to start: {stderr.decode()[-800:]}")
            try:
                # Any HTTP response proves the listener is ready; MCP itself is
                # POST-based, so GET may intentionally return an error.
                await client.get(f"http://127.0.0.1:{port}/mcp")
                return proc
            except httpx.HTTPError:
                pass
            await asyncio.sleep(0.1)
    proc.terminate()
    raise RuntimeError(f"SigNoz MCP proxy did not become ready on port {port}")


async def _provision_through_kams(
    lock: pathlib.Path,
    state: pathlib.Path,
    port: int,
) -> None:
    proxy = await _start_signoz_proxy(lock, state, port)
    try:
        env = {
            **os.environ,
            "SIGNOZ_MCP_URL": f"http://127.0.0.1:{port}/mcp",
        }
        proc = await asyncio.create_subprocess_exec(
            sys.executable,
            "scripts/provision.py",
            cwd=ROOT,
            env=env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        if stdout:
            print(stdout.decode().rstrip())
        if proc.returncode:
            raise RuntimeError(f"SigNoz provisioning failed: {stderr.decode()[-1200:]}")
    finally:
        if proxy.returncode is None:
            proxy.terminate()
            try:
                await asyncio.wait_for(proxy.wait(), timeout=5)
            except asyncio.TimeoutError:
                proxy.kill()


async def _wait_for_signoz(
    state: pathlib.Path,
    timeout: float,
    server_name: str = "notes-mcp",
) -> Any:
    shared = SharedState(state)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for restriction in shared.active(force=True):
            if restriction.server == server_name and restriction.origin == "signoz":
                return restriction
        await asyncio.sleep(1)
    raise TimeoutError(
        "SigNoz did not install the quarantine before the timeout. "
        "Run scripts/provision.py and confirm the kams-webhook channel can reach port 8787."
    )


async def _wait_for_alert_ready(timeout: float) -> None:
    """Wait for the versioned rule to leave FIRING before generating an attack.

    SigNoz correctly suppresses duplicate notifications for an alert group that
    was already firing before the demo daemon came online. Waiting for recovery
    makes the next drift a real state transition rather than relying on stale
    Alertmanager state.
    """
    api_key = os.environ.get("SIGNOZ_API_KEY")
    if not api_key:
        raise RuntimeError("SIGNOZ_API_KEY is required to inspect alert readiness")
    url = os.environ.get("SIGNOZ_URL", "http://127.0.0.1:8080").rstrip("/")
    target = "Kams — MCP tool definition poisoned (CRITICAL)"
    deadline = time.monotonic() + timeout
    async with httpx.AsyncClient(
        timeout=5.0,
        headers={"SIGNOZ-API-KEY": api_key},
    ) as client:
        while time.monotonic() < deadline:
            response = await client.get(f"{url}/api/v2/rules", params={"limit": 100})
            response.raise_for_status()
            payload = response.json()
            rows = payload.get("data") if isinstance(payload, dict) else payload
            rule = next(
                (row for row in rows or [] if row.get("alert") == target),
                None,
            )
            if rule is None:
                raise RuntimeError("the versioned Kams alert is not provisioned")
            if str(rule.get("state", "")).lower() != "firing":
                return
            await asyncio.sleep(5)
    raise TimeoutError(
        "the Kams alert never recovered before the demo; stop emitting drift "
        "metrics and retry after the alert window clears"
    )


def _tool_config(tools: list[dict[str, Any]], *, force: str | None = None) -> dict[str, Any]:
    config: dict[str, Any] = {
        "tools": [
            {
                "toolSpec": {
                    "name": tool["name"],
                    "description": tool.get("description") or tool["name"],
                    "inputSchema": {"json": tool.get("inputSchema") or {"type": "object"}},
                }
            }
            for tool in tools
        ]
    }
    if force:
        config["toolChoice"] = {"tool": {"name": force}}
    return config


def _usage(response: dict[str, Any]) -> tuple[int, int]:
    usage = response.get("usage") or {}
    return int(usage.get("inputTokens") or 0), int(usage.get("outputTokens") or 0)


async def _converse(runtime, model: str, **kwargs) -> dict[str, Any]:
    return await asyncio.to_thread(runtime.converse, modelId=model, **kwargs)


async def run(args) -> int:
    load_dotenv(ROOT / ".env")
    token = os.environ.get("AMAZON_BEDROCK_API_KEY") or os.environ.get(
        "AWS_BEARER_TOKEN_BEDROCK"
    )
    if not token:
        raise SystemExit("AMAZON_BEDROCK_API_KEY is missing from .env")
    os.environ["AWS_BEARER_TOKEN_BEDROCK"] = token
    region = os.environ.get("AWS_REGION", "us-east-1")
    model = os.environ.get("KAMS_MODEL", args.model)

    tracing.setup(
        "kams-demo-agent",
        endpoint=args.otlp_endpoint,
        extra_resource={"gen_ai.agent.name": "kams-security-demo"},
    )
    tracer = tracing.tracer("kams.demo.agent")
    meter = tracing.meter("kams.demo.agent")
    cost_histogram = meter.create_histogram(
        sc.METRIC_CONTEXT_COST,
        unit="{token}",
        description="Provider-reconciled context tokens caused by MCP results",
    )
    estimator = ContextCostEstimator()
    conversation_id = uuid.uuid4().hex
    server_name = f"notes-mcp-{conversation_id[:8]}"
    runtime = boto3.client("bedrock-runtime", region_name=region)

    with tempfile.TemporaryDirectory(prefix="kams-bedrock-demo-") as tmp:
        work = pathlib.Path(tmp)
        lock = work / "kams.lock"
        state = work / "kams-state.json"
        poison_flag = work / "poisoned"
        if not args.skip_provision:
            print(f"\n{BOLD}0. Provision SigNoz through Kams' HTTP MCP proxy{RESET}")
            await _provision_through_kams(lock, state, args.proxy_port)
        daemon = await _start_daemon(state, args.daemon_port)
        try:
            with tracer.start_as_current_span(
                "invoke_agent kams-security-demo",
                kind=SpanKind.INTERNAL,
                attributes={
                    sc.GEN_AI_OPERATION_NAME: sc.OP_INVOKE_AGENT,
                    sc.GEN_AI_AGENT_NAME: "kams-security-demo",
                    sc.GEN_AI_CONVERSATION_ID: conversation_id,
                },
            ) as agent_span:
                print(f"\n{BOLD}{CYAN}Kams × Bedrock — real control-loop demo{RESET}")
                print(f"  {DIM}model={model}  conversation={conversation_id[:10]}…{RESET}")

                print(f"\n{BOLD}1. Establish and pin a clean MCP baseline{RESET}")
                clean = await _mcp_session(lock, state, poison_flag, server_name)
                try:
                    clean_list = await clean.call("tools/list")
                finally:
                    await clean.__aexit__(None, None, None)
                if "error" in clean_list:
                    raise RuntimeError(f"clean tools/list failed: {clean_list['error']}")
                await _pin(lock, server_name)

                print(f"  {DIM}waiting for a clean SigNoz alert state…{RESET}")
                await _wait_for_alert_ready(args.alert_ready_timeout)

                print(f"\n{BOLD}2. Same server rug-pulls its tool description{RESET}")
                poison_flag.touch()
                poisoned = await _mcp_session(lock, state, poison_flag, server_name)
                try:
                    poisoned_list = await poisoned.call("tools/list")
                finally:
                    await poisoned.__aexit__(None, None, None)
                tools = (poisoned_list.get("result") or {}).get("tools") or []
                if not tools:
                    raise RuntimeError("poisoned server returned no tools")
                print(f"  {RED}●{RESET} poisoned definition observed; metric exported to SigNoz")

                print(f"\n{BOLD}3. SigNoz alert closes the loop{RESET}")
                restriction = await _wait_for_signoz(
                    state, args.alert_timeout, server_name
                )
                agent_span.add_event(
                    "kams.signoz.quarantine",
                    {
                        sc.KAMS_RULE_NAME: restriction.rule,
                        sc.KAMS_ENFORCE_ORIGIN: restriction.origin,
                        sc.KAMS_SERVER_NAME: restriction.server,
                    },
                )
                print(
                    f"  {GREEN}✓{RESET} {restriction.rule} installed a "
                    f"{restriction.action} restriction via {restriction.origin}"
                )

                print(f"\n{BOLD}4. Bedrock agent selects the poisoned tool{RESET}")
                user_message = {
                    "role": "user",
                    "content": [{
                        "text": (
                            "Save the note 'buy milk' using save_note. "
                            "If policy blocks the tool, do not retry; continue safely "
                            "and explain that the note was not saved."
                        )
                    }],
                }
                with tracer.start_as_current_span(
                    f"chat {model}",
                    kind=SpanKind.CLIENT,
                    attributes={
                        sc.GEN_AI_OPERATION_NAME: sc.OP_CHAT,
                        sc.GEN_AI_PROVIDER_NAME: sc.PROVIDER_AWS_BEDROCK,
                        sc.GEN_AI_REQUEST_MODEL: model,
                        sc.GEN_AI_CONVERSATION_ID: conversation_id,
                    },
                ) as inference_span:
                    first = await _converse(
                        runtime,
                        model,
                        messages=[user_message],
                        system=[{
                            "text": (
                                "You are a safe demo agent. Use the requested MCP tool. "
                                "Never invent a successful tool result."
                            )
                        }],
                        toolConfig=_tool_config(tools, force="save_note"),
                        inferenceConfig={"maxTokens": 256, "temperature": 0},
                    )
                    first_in, first_out = _usage(first)
                    inference_span.set_attribute(sc.GEN_AI_USAGE_INPUT_TOKENS, first_in)
                    inference_span.set_attribute(sc.GEN_AI_USAGE_OUTPUT_TOKENS, first_out)
                    inference_span.set_attribute(
                        sc.GEN_AI_RESPONSE_MODEL,
                        first.get("metrics", {}).get("modelId", model),
                    )

                assistant_message = first["output"]["message"]
                tool_use = next(
                    (
                        block["toolUse"]
                        for block in assistant_message.get("content") or []
                        if "toolUse" in block
                    ),
                    None,
                )
                if not tool_use:
                    raise RuntimeError("Bedrock returned no toolUse block despite forced tool choice")
                print(
                    f"  {GREEN}✓{RESET} Bedrock selected {tool_use['name']} "
                    f"with provider-reported usage {first_in} in / {first_out} out"
                )

                blocked = await _mcp_session(lock, state, poison_flag, server_name)
                try:
                    with tracer.start_as_current_span(
                        f"execute_tool {tool_use['name']}",
                        kind=SpanKind.INTERNAL,
                        attributes={
                            sc.GEN_AI_OPERATION_NAME: sc.OP_EXECUTE_TOOL,
                            sc.GEN_AI_TOOL_NAME: tool_use["name"],
                            sc.GEN_AI_TOOL_CALL_ID: tool_use["toolUseId"],
                            sc.GEN_AI_CONVERSATION_ID: conversation_id,
                        },
                    ) as tool_span:
                        result = await blocked.call(
                            "tools/call",
                            {
                                "name": tool_use["name"],
                                "arguments": tool_use.get("input") or {},
                            },
                        )
                        if "error" not in result:
                            tool_span.set_status(
                                Status(StatusCode.ERROR, "quarantined call unexpectedly succeeded")
                            )
                            raise RuntimeError("quarantined tool unexpectedly reached the server")
                        tool_span.set_status(
                            Status(StatusCode.ERROR, result["error"]["message"][:200])
                        )
                finally:
                    await blocked.__aexit__(None, None, None)
                print(f"  {RED}BLOCKED{RESET} {result['error']['message']}")

                result_bytes = len(json.dumps(result, separators=(",", ":")).encode())
                estimated = estimator.estimate(server_name, tool_use["name"], result_bytes)
                estimator.record(conversation_id, estimated)
                cost_histogram.record(
                    estimated.tokens,
                    {
                        "server": estimated.server,
                        "tool": estimated.tool,
                        "estimated": "true",
                    },
                )

                print(f"\n{BOLD}5. Agent degrades safely; cost is reconciled{RESET}")
                messages = [
                    user_message,
                    assistant_message,
                    {
                        "role": "user",
                        "content": [{
                            "toolResult": {
                                "toolUseId": tool_use["toolUseId"],
                                "content": [{"json": result["error"]}],
                                "status": "error",
                            }
                        }],
                    },
                ]
                with tracer.start_as_current_span(
                    f"chat {model}",
                    kind=SpanKind.CLIENT,
                    attributes={
                        sc.GEN_AI_OPERATION_NAME: sc.OP_CHAT,
                        sc.GEN_AI_PROVIDER_NAME: sc.PROVIDER_AWS_BEDROCK,
                        sc.GEN_AI_REQUEST_MODEL: model,
                        sc.GEN_AI_CONVERSATION_ID: conversation_id,
                    },
                ) as final_span:
                    final = await _converse(
                        runtime,
                        model,
                        messages=messages,
                        system=[{
                            "text": (
                                "When Kams blocks a tool, do not retry it. "
                                "Tell the user what was not completed and continue safely."
                            )
                        }],
                        toolConfig=_tool_config(tools),
                        inferenceConfig={"maxTokens": 256, "temperature": 0},
                    )
                    final_in, final_out = _usage(final)
                    final_span.set_attribute(sc.GEN_AI_USAGE_INPUT_TOKENS, final_in)
                    final_span.set_attribute(sc.GEN_AI_USAGE_OUTPUT_TOKENS, final_out)

                measured_delta = max(1, final_in - first_in)
                measured = estimator.reconcile(conversation_id, measured_delta)
                for attribution in measured:
                    cost_histogram.record(
                        attribution.tokens,
                        {
                            "server": attribution.server,
                            "tool": attribution.tool,
                            "estimated": "false",
                        },
                    )
                text_blocks = [
                    block["text"]
                    for block in final["output"]["message"].get("content") or []
                    if "text" in block
                ]
                final_text = " ".join(text_blocks).strip()
                print(f"  {CYAN}Agent:{RESET} {final_text}")
                print(
                    f"  {DIM}context attribution: estimated={estimated.tokens} tokens, "
                    f"provider-reconciled={sum(a.tokens for a in measured)} tokens{RESET}"
                )
                print(
                    f"\n{GREEN}{BOLD}PASS{RESET} one trace now contains Bedrock inference, "
                    "MCP detection, SigNoz quarantine, blocked execution, and safe continuation."
                )
        finally:
            if daemon.returncode is None:
                daemon.terminate()
                try:
                    await asyncio.wait_for(daemon.wait(), timeout=5)
                except asyncio.TimeoutError:
                    daemon.kill()
            tracing.shutdown()
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", default=MODEL_DEFAULT)
    parser.add_argument(
        "--alert-timeout",
        type=float,
        default=300.0,
        help="wait for Foundry's alert evaluator, including its ingestion delay",
    )
    parser.add_argument("--alert-ready-timeout", type=float, default=180.0)
    parser.add_argument("--daemon-port", type=int, default=8787)
    parser.add_argument("--proxy-port", type=int, default=8900)
    parser.add_argument(
        "--skip-provision",
        action="store_true",
        help="use the dashboard, alert, and webhook channel already in SigNoz",
    )
    parser.add_argument("--otlp-endpoint", default=None)
    return asyncio.run(run(parser.parse_args()))


if __name__ == "__main__":
    raise SystemExit(main())
