def build_login_plain(ctx: dict[str, Any]) -> tuple[bytes, dict[str, Any]]:
    launcher_version = str(ctx.get("a6") or _resolve_launcher_version(ctx))
    online_res_version = str(ctx.get("a7") or _resolve_online_res_version(ctx))
    branch_tag = str(ctx.get("a14") or _resolve_branch_tag(ctx, launcher_version))
    a13_value = str(ctx.get("a13") or "")

    a1_value, a2_value, a1a2_source = _resolve_login_a1_a2(ctx)
    public_key_bytes = _resolve_client_public_key_bytes(ctx)

    if "a9" in ctx:
        a9_pay_platform = _to_int(ctx.get("a9"), 3)
    else:
        a9_pay_platform = _to_int(ctx.get("platform_id"), 3)

    if "a10" in ctx:
        a10_area = _to_int(ctx.get("a10"), 0)
    else:
        a10_area = _to_int(ctx.get("area"), 0)

    a11_env = _to_int(ctx.get("env"), 2)
    a12_value = _to_int(ctx.get("a12"), _to_int(ctx.get("pay_platform"), 2))
    a5_value = _to_int(ctx.get("a5"), 0)
    force_emit_a10 = bool(ctx.get("force_emit_a10"))
    force_emit_a12 = bool(ctx.get("force_emit_a12"))
    force_emit_a5 = bool(ctx.get("force_emit_a5"))

    if "a21" in ctx:
        channel_id = _to_int(ctx.get("a21"), default=1)
    else:
        channel_id = _to_int(
            (ctx.get("u8_token_by_channel_token") or {}).get("channelMasterId"),
            default=1,
        )

    if "a22" in ctx:
        sub_channel = _to_int(ctx.get("a22"), default=1)
    else:
        sub_channel = _to_int(
            (
                ctx.get("config", {})
                .get("launcher_version", {})
                .get("pkg", {})
                .get("sub_channel")
            ),
            default=1,
        )

    a4_value = _to_int(ctx.get("a4"), 0)
    client_language = _to_int(ctx.get("client_language"), 0)

    device_fields = _resolve_device_fields(ctx, online_res_version)
    disable_device_info = bool(ctx.get("disable_device_info"))
    device_payload = b"" if disable_device_info else _build_device_info_payload(device_fields)