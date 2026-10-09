"""The browser-use preset — first plugin of the KT Companion runtime.

Registers the `browser-task` action kind: run a natural-language browser task
via https://github.com/browser-use/browser-use, confined to the domains the
*user* configured on the KT action instance (the kind's scope schema) — or
unconfined when they named none.

Two execution paths, chosen at call time:
  * real — ``browser_use`` importable AND an LLM API key in the environment;
  * mock — otherwise: no browser, but the same scope enforcement, content
           shape, and signed usage receipt, so the protocol demo runs anywhere.
"""

from __future__ import annotations

import asyncio
import os
import re
import time

from keeptalking_plugin import CallContext, Plugin, config_field

DEFAULT_MODELS = {
    "anthropic": "claude-sonnet-5",
    "openai": "gpt-5.2",
    # Custom endpoints serve arbitrary model names — no sensible default.
    "openai-compatible": "",
}


def _mentioned_hosts(task: str) -> list[str]:
    return re.findall(r"(?:https?://)?([a-z0-9-]+(?:\.[a-z0-9-]+)+)", task.lower())


def _blocked_hosts(task: str, allowed: list[str] | None) -> list[str]:
    """Hosts named in the task that fall outside the instance's allowlist.
    An empty/None allowlist means *unrestricted* — nothing is blocked. The
    boundary is the grant itself: an instance is inert until the user grants it,
    and having granted "browse the web" they meant the web, not nothing. A
    narrower instance is expressed by listing domains."""
    mentioned = _mentioned_hosts(task)
    if not allowed:
        return []
    normalized = [a.lower().lstrip("*.") for a in allowed]
    return [
        host
        for host in mentioned
        if not any(host == a or host.endswith("." + a) for a in normalized)
    ]


def _normalize_base_url(raw: str) -> tuple[str, str | None]:
    """OpenAI-compatible clients append the route themselves, so this field
    wants the base (`…/v1`), not a full completions URL. Pasting the latter is
    the common mistake and yields 404s on `…/chat/completions/chat/completions`,
    so trim it and say so rather than failing obscurely."""
    url = raw.strip().rstrip("/")
    for suffix in ("/chat/completions", "/completions", "/responses"):
        if url.endswith(suffix):
            return (
                url[: -len(suffix)],
                f"trimmed '{suffix}' — this field takes the base URL",
            )
    return url, None


async def _run_real(
    task: str, allowed: list[str] | None, headless: bool, config: dict, base_url: str
) -> str:
    from browser_use import Agent  # heavyweight import, deferred to call time

    kwargs = {}
    try:
        from browser_use import BrowserSession

        kwargs["browser_session"] = BrowserSession(
            allowed_domains=allowed or None, headless=headless
        )
    except Exception:
        pass  # older/newer API shapes; the agent default still runs

    provider = config.get("llm_provider") or "anthropic"
    api_key = config.get("llm_api_key")
    model = config.get("llm_model") or DEFAULT_MODELS.get(provider, "")

    # `base_url` is what points this at OpenRouter, a gateway, or a local
    # OpenAI-compatible server; passed only when set so stock provider
    # defaults still apply.
    client_kwargs: dict = {"model": model}
    if api_key:
        client_kwargs["api_key"] = api_key
    if base_url:
        client_kwargs["base_url"] = base_url

    llm = None
    if provider == "anthropic":
        try:
            from browser_use import ChatAnthropic

            llm = ChatAnthropic(**client_kwargs)
        except Exception:
            pass
    if llm is None:
        try:
            from browser_use import ChatOpenAI

            llm = ChatOpenAI(**client_kwargs)
        except Exception as error:
            # An OpenAI-compatible endpoint is the whole point of base_url —
            # failing silently here would look like "mock for no reason".
            if base_url:
                raise RuntimeError(
                    f"could not build an OpenAI-compatible client for {base_url}: {error}"
                ) from error

    agent = Agent(task=task, llm=llm, **kwargs) if llm else Agent(task=task, **kwargs)
    history = await agent.run()
    final = getattr(history, "final_result", lambda: None)()
    return final or "browser task finished (no final result text)"


def make_plugin() -> Plugin:
    plugin = Plugin(
        name="BrowserUse",
        vendor="browser-use.demo",
        version="0.1.0",
        summary="Hand a browsing task to an AI agent",
        description="Describe what you need done on the web and a browser-use "
        "agent carries it out in Chrome on this Mac. Each action you add in "
        "KeepTalking can be limited to a list of domains, and every run comes "
        "back with a signed usage receipt.\n\nReal runs need an LLM provider "
        "and API key below; until then the plugin answers with a mock run that "
        "says what it would have done.",
        symbol="globe",
        tint="#2F7CF6",
        category="Web",
        homepage="https://github.com/browser-use/browser-use",
        meters=[
            ("browser.seconds", "second", "Wall-clock seconds of browser agent time"),
        ],
        # Installed into this plugin's own venv by the Companion. No browser
        # download step: browser-use 0.13 drives the machine's own Chrome over
        # CDP (`browser-harness --doctor` diagnoses that side).
        requires=["browser-use"],
        config=[
            config_field(
                "llm_provider", label="LLM provider", type="choice",
                choices=["anthropic", "openai", "openai-compatible"],
                default="anthropic",
                description="Which provider drives the browser agent; "
                "'openai-compatible' means set an endpoint below",
            ),
            config_field(
                "llm_api_key", label="LLM API key", type="secret",
                env="ANTHROPIC_API_KEY",
                description="Stored in the plugin's state dir (0600); env var works too",
            ),
            config_field(
                "llm_base_url", label="Endpoint URL", type="string",
                env="OPENAI_BASE_URL",
                description="Base URL for OpenRouter, a gateway, or a local "
                "OpenAI-compatible server. Blank uses the provider's own endpoint",
            ),
            config_field(
                "llm_model", label="Model", type="string",
                description="Blank uses the provider default "
                "(required for openai-compatible)",
            ),
            config_field(
                "force_mock", label="Force mock runs", type="bool", default=False,
                description="Never launch a real browser, even when configured",
            ),
        ],
    )

    @plugin.kind(
        "browser-task",
        description="Run a natural-language browser task with browser-use, "
        "confined to this instance's allowed domains",
        input_schema={
            "type": "object",
            "properties": {
                "task": {
                    "type": "string",
                    "description": "What the browser agent should accomplish",
                }
            },
            "required": ["task"],
        },
        scope_schema={
            "allowedDomains": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Domains this instance may visit; empty allows any",
            },
            "headless": {"type": "boolean", "description": "Run the browser headless"},
        },
        # Empty allowlist ⇒ unrestricted, so a default instance can browse; the
        # user narrows it by naming domains.
        default_scope={"allowedDomains": [], "headless": True},
    )
    async def browser_task(args: dict, ctx: CallContext):
        task = args.get("task", "").strip()
        if not task:
            return "missing required argument: task", True

        scope = ctx.scope or {}
        allowed = scope.get("allowedDomains")
        headless = bool(scope.get("headless", True))
        started = time.monotonic()

        # Instance-scope enforcement happens HERE, plugin-side, in addition to
        # the host gating the call — the dual-enforcement contract. An empty
        # allowlist is not a scope of nothing; it is no domain restriction.
        blocked = _blocked_hosts(task, allowed)
        if blocked:
            ctx.report_usage("browser.seconds", 0)
            return (
                f"refused: task names host(s) outside this instance's scope: "
                f"{', '.join(sorted(set(blocked)))} (allowed: {', '.join(allowed)})",
                True,
            )

        config = ctx.config
        force_mock = bool(config.get("force_mock")) or bool(os.environ.get("KT_DEMO_MOCK"))
        provider = config.get("llm_provider") or "anthropic"
        base_url, url_note = _normalize_base_url(config.get("llm_base_url") or "")

        # A custom endpoint is only half a configuration without a model name,
        # and stock providers are only reachable with a key.
        if provider == "openai-compatible" and not base_url and not force_mock:
            ctx.report_usage("browser.seconds", 0)
            return "provider 'openai-compatible' needs an Endpoint URL in the plugin config", True

        # Decide what *blocks* a real run before attempting one, so the mock
        # always reports the true reason. A catch-all "else" here previously
        # claimed "no model configured" for every fallback — including a
        # missing browser-use install, which is the opposite of helpful.
        if force_mock:
            mock_reason = "forced mock"
        elif not config.get("llm_api_key"):
            mock_reason = "no LLM API key configured"
        elif provider == "openai-compatible" and not config.get("llm_model"):
            mock_reason = "no model configured for the custom endpoint"
        else:
            mock_reason = None

        if mock_reason is None:
            try:
                result = await _run_real(task, allowed, headless, config, base_url)
                ctx.report_usage("browser.seconds", int(time.monotonic() - started) + 1)
                return result
            except ImportError:
                mock_reason = (
                    "browser-use is not installed — use Install in the KT Companion "
                    "menu (or: companion.py --provision BrowserUse)"
                )
            except Exception as error:
                ctx.report_usage("browser.seconds", int(time.monotonic() - started) + 1)
                return f"browser-use run failed: {error}", True

        await asyncio.sleep(1)  # stand-in for the browser session
        model = config.get("llm_model") or DEFAULT_MODELS.get(provider) or "unset"
        scope_note = (
            f"within allowed domains {allowed}" if allowed else "with no domain restriction"
        )
        ctx.report_usage("browser.seconds", int(time.monotonic() - started) + 1)
        return (
            f"[mock] {mock_reason} (provider={provider}, model={model}, "
            f"endpoint={base_url or 'provider default'}"
            f"{'; ' + url_note if url_note else ''}). Would run "
            f"headless={headless} {scope_note}: {task!r}"
        )

    return plugin
