"""Create local development configuration without overwriting existing credentials."""

import argparse
import json
import secrets
from pathlib import Path

from dotenv import dotenv_values


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bot-dir", type=Path, required=True)
    parser.add_argument("--group-openid", default="")
    args = parser.parse_args()
    backend_env = Path(".env")
    bot_config = args.bot_dir / ".env.prod"
    bot_values = dotenv_values(bot_config) if bot_config.exists() else {}
    try:
        bots = json.loads(bot_values.get("QQ_BOTS") or bot_values.get("qq_bots") or "[]")
        app_id = str(bots[0]["id"]) if bots else "UNCONFIGURED"
    except (ValueError, KeyError, TypeError):
        app_id = "UNCONFIGURED"
    if backend_env.exists():
        parser.error(
            "Backend .env already exists; update configuration manually to avoid changing credentials"
        )
    # Quote all generated values as JSON-compatible dotenv strings; do not print secrets.
    token = secrets.token_urlsafe(32)
    backend = {
        "NOMI_PUBLIC_URL": "http://127.0.0.1:8000",
        "NOMI_DATA_DIR": "./data",
        "NOMI_BOT_TOKEN": token,
        "NOMI_BOT_APP_ID": app_id,
        "NOMI_GROUP_OPENID": args.group_openid or "UNCONFIGURED",
        "NOMI_GROUP_LABEL": "服务器指定群",
    }
    backend_env.write_text(
        "\n".join(f"{k}={json.dumps(v, ensure_ascii=False)}" for k, v in backend.items()) + "\n",
        encoding="utf-8",
    )
    plugin_env = args.bot_dir / ".env"
    existing = dotenv_values(plugin_env) if plugin_env.exists() else {}
    keys = {"NOMI_AUTH_BASE_URL", "NOMI_BOT_API_TOKEN", "NOMI_ALLOWED_GROUP_OPENID", "NOMI_BOT_APP_ID"}
    if keys & set(existing) or keys & set(bot_values):
        backend_env.unlink()
        parser.error("Bot already has Nomi configuration; no existing configuration was overwritten")
    plugin = {
        "NOMI_AUTH_BASE_URL": backend["NOMI_PUBLIC_URL"],
        "NOMI_BOT_API_TOKEN": token,
        "NOMI_ALLOWED_GROUP_OPENID": args.group_openid,
        "NOMI_BOT_APP_ID": app_id,
        "NOMI_DISCOVERY": "true" if not args.group_openid else "false",
    }
    with plugin_env.open("a", encoding="utf-8") as output:
        output.write("\n# Local Nomi auth configuration; platform credentials remain in .env.prod.\n")
        for key, value in plugin.items():
            output.write(f"{key}={json.dumps(value, ensure_ascii=False)}\n")
        if not any(k.lower() == "command_start" for k in {**existing, **bot_values}):
            output.write('COMMAND_START=["", "/"]\n')
    print("Local backend and bot configuration created; no credentials were printed.")
    if not args.group_openid:
        print("Registration disabled until both configurations receive the real group OpenID.")


if __name__ == "__main__":
    main()
