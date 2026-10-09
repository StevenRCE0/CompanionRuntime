"""MarkItDown — built-in document→Markdown converter plugin.

Registers the `markitdown-convert` action kind: convert one staged document
(PDF, Office, HTML, EPUB, images with OCR, audio with transcription — whatever
https://github.com/microsoft/markitdown supports) into clean Markdown, written
to the call's `markdown` output slot and harvested by the host.

First consumer of the KTPP v1.1 resources + ACT surface
(DESIGN_PLUGIN_RESOURCES_ACT.md):
  * the source arrives as a handle-addressed resource stream — never a path;
  * the result leaves ONLY through the host-allocated write slot;
  * the optional AI polish pass borrows the HOST's ACT connector via
    ``ctx.act`` (per-catalog consent, off by default) and degrades to the raw
    conversion on :class:`ActDenied`;
  * progress narrates through ``ctx.elucidate``.

Two execution paths, chosen at call time (the browser-use convention):
  * real — ``markitdown`` importable in this plugin's venv;
  * mock — otherwise: same scope enforcement, slot write, and receipt shape,
           so the protocol path demos anywhere; the slot gets a stub note.
"""

from __future__ import annotations

from pathlib import PurePosixPath

from keeptalking_plugin import (
    ActDenied,
    CallContext,
    Plugin,
    Resource,
    ResourceError,
    file_in,
    file_out,
)

# Inlining the converted draft into the polish prompt is capped by the host's
# per-request ACT attachment budget (256 KiB); stay under it.
POLISH_BYTE_CAP = 200_000


def _extension(name: str) -> str:
    return PurePosixPath(name.lower()).suffix  # ".pdf" | "" when none


def _scope_violation(source: Resource, scope: dict | None) -> str | None:
    scope = scope or {}
    allowed = [
        ext.lower() if ext.startswith(".") else f".{ext.lower()}"
        for ext in scope.get("allowedExtensions") or []
    ]
    extension = _extension(source.name)
    if allowed and extension not in allowed:
        return (
            f"source extension {extension or '(none)'!r} is outside this "
            f"instance's allowed extensions {allowed}"
        )
    max_bytes = scope.get("maxSourceBytes")
    size = source.byte_count
    if isinstance(max_bytes, int) and max_bytes > 0 and size and size > max_bytes:
        return f"source is {size} bytes; this instance accepts at most {max_bytes}"
    return None


def make_plugin() -> Plugin:
    plugin = Plugin(
        name="MarkItDown",
        vendor="keeptalking",
        version="0.1.0",
        summary="Turn documents into clean Markdown",
        description="Converts PDFs, Office files, HTML, EPUB, images (with OCR) "
        "and audio (with transcription) into Markdown using Microsoft's "
        "MarkItDown. The document arrives from KeepTalking and the Markdown goes "
        "straight back as a new file.\n\nAn optional AI cleanup pass tidies "
        "headings, tables and lists with KeepTalking's own model, only when you "
        "allow AI for this plugin in KeepTalking.",
        symbol="doc.text",
        tint="#F2762E",
        category="Documents",
        homepage="https://github.com/microsoft/markitdown",
        meters=[("convert.bytes", "byte", "Bytes of source material converted")],
        requires=["markitdown[all]"],
    )

    @plugin.kind(
        "markitdown-convert",
        display_name="Convert to Markdown",
        description="Convert a document (PDF, Office, HTML, EPUB, images with OCR, "
        "audio with transcription…) into clean Markdown",
        input_schema={
            "type": "object",
            "properties": {
                "polish": {
                    "type": "boolean",
                    "description": "Run an AI cleanup pass over the converted "
                    "Markdown (needs the catalog's AI toggle in KeepTalking; "
                    "silently skipped when unavailable)",
                },
                "instructions": {
                    "type": "string",
                    "description": "Optional guidance for conversion/cleanup emphasis",
                },
            },
        },
        scope_schema={
            "allowedExtensions": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Source extensions this instance accepts; "
                "empty allows all supported formats",
            },
            "maxSourceBytes": {
                "type": "integer",
                "description": "Largest source file this instance accepts",
            },
            "aiPolish": {
                "type": "boolean",
                "description": "Permit the AI cleanup pass on this instance",
            },
        },
        default_scope={
            "allowedExtensions": [],
            "maxSourceBytes": 52_428_800,
            "aiPolish": True,
        },
        objects=[
            file_in("source", "Document to convert"),
            file_out("markdown", "Converted Markdown document"),
        ],
        capabilities=["act"],
    )
    async def convert(args: dict, ctx: CallContext):
        try:
            source = ctx.resources.input("source")
        except ResourceError as error:
            return (
                f"markitdown-convert could not resolve its SOURCE: {error}. "
                "Pass the document's handle in input_handles (a context "
                "attachment handle, or stage a local file with kt_send_file).",
                True,
            )
        try:
            slot = ctx.resources.output("markdown")
        except ResourceError as error:
            return (
                f"markitdown-convert could not resolve its OUTPUT slot: {error}. "
                "Request outputs=[{name: \"markdown\", persistence: …}] on the call.",
                True,
            )
        if violation := _scope_violation(source, ctx.scope):
            return f"Denied by instance scope: {violation}", True

        ctx.elucidate(f"Converting {source.name}")
        markdown, mock_reason = None, None
        try:
            from markitdown import MarkItDown  # heavy import stays in-handler

            try:
                from markitdown import StreamInfo

                stream_info = StreamInfo(
                    extension=_extension(source.name) or None,
                    filename=source.name,
                )
            except ImportError:
                stream_info = None
            with source.open("rb") as stream:
                result = (
                    MarkItDown().convert_stream(stream, stream_info=stream_info)
                    if stream_info is not None
                    else MarkItDown().convert_stream(stream)
                )
            markdown = result.text_content or ""
        except ImportError:
            mock_reason = (
                "markitdown is not installed — use Install in the KT Companion "
                "menu (or: companion.py --provision MarkItDown)"
            )
        except Exception as error:
            return f"conversion failed: {error}", True
        ctx.report_usage("convert.bytes", source.byte_count or 0)

        if markdown is None:
            markdown = (
                f"[mock] {mock_reason}\n\nWould convert \"{source.name}\" "
                f"({source.byte_count or 'unknown'} bytes) to Markdown."
            )
        slot.write_text(markdown)

        polished = False
        if (
            mock_reason is None
            and args.get("polish")
            and (ctx.scope or {}).get("aiPolish", True)
        ):
            if len(markdown.encode("utf-8")) > POLISH_BYTE_CAP:
                ctx.elucidate("Skipping AI polish — conversion exceeds the polish size cap")
            else:
                ctx.elucidate("Polishing converted Markdown with AI")
                emphasis = (args.get("instructions") or "").strip()
                try:
                    # The draft already sits in the write slot; hand the model
                    # its HANDLE and let the host inject the content.
                    act = await ctx.act(
                        "The attached resource is machine-converted Markdown. "
                        "Clean it up: fix heading levels, repair broken tables "
                        "and lists, drop conversion artifacts. Preserve ALL "
                        "content; change structure only. Reply with ONLY the "
                        "cleaned Markdown."
                        + (f"\nEmphasis: {emphasis}" if emphasis else ""),
                        attachments=[slot.handle],
                    )
                    if act.text.strip():
                        slot.write_text(act.text)
                        polished = True
                except ActDenied as denial:
                    ctx.elucidate(f"AI polish unavailable ({denial}) — keeping raw conversion")

        note = " (AI-polished)" if polished else ""
        return (
            f"Converted {source.name} → Markdown "
            f"({len(markdown)} chars{note}); result in the `markdown` output."
        )

    return plugin


if __name__ == "__main__":
    make_plugin().run()
