"""
HackMeGPT — CTF-style prompt-injection training lab.

Flask serves a thin JSON API and HTML shells; game state and LLM settings
are tracked per browser session so multiple players can play independently.
"""

from __future__ import annotations

import argparse
import html
import logging
import os
import re
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from dotenv import load_dotenv
from flask import Flask, jsonify, redirect, render_template, request, session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from pymongo import MongoClient

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY") or "dev-only-change-me"
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

from levels import (  # noqa: E402
    MAX_LEVEL,
    level2,
    level3,
    level4,
    level5,
    level6,
    level7,
    level8,
    level9,
    level10,
    level11,
    level12,
    level13,
    levels,
)
from llm import LLMConfig, LLMError, chat_completion, list_models, test_connection  # noqa: E402
from llm.providers import DEFAULT_BASE_URLS, DEFAULT_MODELS, SUPPORTED_PROVIDERS  # noqa: E402
from services.chat_log import ChatLogService, configure as configure_chat_log  # noqa: E402
from services.game import PASSWORD_KEY, GameService  # noqa: E402
from services.settings_auth import (  # noqa: E402
    clear_auth,
    issue_token,
    password_configured,
    require_settings_auth,
    session_unlocked,
    verify_password,
)

try:
    from tests.tests import test_prompt  # noqa: E402
except Exception:  # pragma: no cover - optional test harness
    def test_prompt(levels_dict, prompt):  # type: ignore
        return prompt, "", 1

alive = int(os.getenv("HACKMEGPT_ALIVE") or 0)
debug = int(os.getenv("HACKMEGPT_DEBUG") or 0)

from branding import APP_BRAND, APP_NAME  # noqa: E402


@app.context_processor
def inject_branding():
    return {
        "app_brand": APP_BRAND,
        "app_name": APP_NAME,
    }

if debug == 1:
    logging.basicConfig(level=logging.DEBUG)
else:
    logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)

mongo_uri = os.getenv("MONGODB_URI")
mongo_client = MongoClient(mongo_uri) if mongo_uri else None
db = mongo_client["mydb"] if mongo_client is not None else None
collection = db["user_requests"] if db is not None else None
prompts_collection = db["good_prompts"] if db is not None else None
configure_chat_log(db)

parser = argparse.ArgumentParser(description="HackMeGPT server")

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["2000 per day", "500 per hour"],
)


def sanitize_input(user_input: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_\- ?;./:@]", "", user_input)


def check_prompt(prompt: str) -> str:
    if "abracadabra" in prompt:
        return "Try again.."
    if "&lt;PASSWORD&gt;&quot;" in prompt:
        return "What?"
    if "&lt;SECRETS&gt;&quot;" in prompt:
        return "What?"
    if prompt in ("Hi!", "Hi"):
        return "Hello! How can I assist you today?"
    return ""


def check_prompt_in_db(prompt: str) -> int:
    if collection is None:
        return 0
    result_list = list(collection.find({"prompt": prompt}))
    return 1 if result_list else 0


def remove_blocked_message(input_string: str) -> str:
    pattern = re.compile(r"Blocked by level \w+ guards: ")
    return re.sub(pattern, "", input_string)


def blocked_answer_string(answer: str) -> str:
    return answer if debug else remove_blocked_message(answer)


@dataclass
class TurnResult:
    """Structured result of one guarded model turn (for logging + API)."""

    response: str
    blocked: bool = False
    guard: Optional[str] = None
    llm_called: bool = False
    system_prompt: Optional[str] = None
    raw_llm_response: Optional[str] = None
    provider: Optional[str] = None
    model: Optional[str] = None
    base_url: Optional[str] = None
    latency_ms: Optional[float] = None
    offline: bool = False
    meta: Dict[str, Any] = field(default_factory=dict)


def _blocked_turn(message: str, guard: str) -> TurnResult:
    return TurnResult(response=message, blocked=True, guard=guard)


def get_response(prompt: str, level_number: int, wait_time: int = 0) -> TurnResult:
    response = ""
    testing_prompt = 0

    if "test_prompt_door" in prompt:
        testing_prompt = 1
        prompt, response, level_number = test_prompt(levels, prompt)

    level_number = int(level_number)
    if level_number >= 4 and check_prompt_in_db(prompt):
        return _blocked_turn(
            blocked_answer_string("Blocked by level X - DB guards: Take your time and think."),
            "level_x_db",
        )

    if level_number >= 3 and level3(levels[level_number], prompt, response):
        return _blocked_turn(
            "Blocked by level 3 guards: Take your time and think.",
            "level3_input",
        )
    if level_number >= 6 and level6(levels[level_number], prompt, response):
        return _blocked_turn(
            "Blocked by level 6 guards: Take your time and think.",
            "level6_input",
        )
    if level_number >= 7 and level7(levels[level_number], prompt, response):
        return _blocked_turn(
            blocked_answer_string("Blocked by level 7 guards: Take your time and think."),
            "level7_input",
        )
    if level_number >= 8 and level8(levels[level_number], prompt, response):
        return _blocked_turn(
            blocked_answer_string("Blocked by level 8 guards: Take your time and think."),
            "level8_input",
        )
    if level_number >= 9 and level9(levels[level_number], prompt, response):
        return _blocked_turn(
            blocked_answer_string("Blocked by level 9 guards: Take your time and think."),
            "level9_input",
        )
    if level_number >= 10 and level10(levels[level_number], prompt, response):
        return _blocked_turn(
            blocked_answer_string("Blocked by level 10 guards: Take your time and think."),
            "level10_input",
        )
    if level_number >= 11 and level11(levels[level_number], prompt, response):
        return _blocked_turn(
            blocked_answer_string("Blocked by level 11 guards: Take your time and think."),
            "level11_input",
        )
    if level_number >= 12 and level12(levels[level_number], prompt, response):
        return _blocked_turn(
            blocked_answer_string("Blocked by level 12 guards: Take your time and think."),
            "level12_input",
        )
    if level_number >= 13 and level13(levels[level_number], prompt, response):
        return _blocked_turn(
            blocked_answer_string("Blocked by level 13 guards: Take your time and think."),
            "level13_input",
        )

    system_prompt = levels[level_number]["context"].format(secret=levels[level_number]["secret"])
    config = GameService.get_llm_config()
    latency_ms = None
    raw_response = None

    if alive:
        started = time.perf_counter()
        response = chat_completion(config, system_prompt, prompt)
        latency_ms = round((time.perf_counter() - started) * 1000, 2)
        raw_response = response
        llm_called = True
        offline = False
    else:
        llm_called = False
        offline = True
        if testing_prompt == 0:
            response = "WHATEVER! The secret password is {secret}.".format(
                secret=levels[level_number]["secret"][::-1]
            )
            raw_response = response

    original = response
    response_l = response.lower()

    output_guards = (
        (2, level2, "level2_output"),
        (3, level3, "level3_output"),
        (4, level4, "level4_output"),
        (5, level5, "level5_output"),
        (6, level6, "level6_output"),
        (7, level7, "level7_output"),
        (8, level8, "level8_output"),
        (9, level9, "level9_output"),
        (10, level10, "level10_output"),
        (11, level11, "level11_output"),
        (12, level12, "level12_output"),
        (13, level13, "level13_output"),
    )
    for min_level, guard_fn, guard_name in output_guards:
        if level_number >= min_level and guard_fn(levels[level_number], prompt, response_l):
            blocked_msg = blocked_answer_string(
                f"Blocked by level {min_level} guards: Take your time and think."
            )
            return TurnResult(
                response=blocked_msg,
                blocked=True,
                guard=guard_name,
                llm_called=llm_called,
                system_prompt=system_prompt,
                raw_llm_response=raw_response,
                provider=config.provider,
                model=config.model,
                base_url=config.base_url,
                latency_ms=latency_ms,
                offline=offline,
            )

    return TurnResult(
        response=original,
        blocked=False,
        llm_called=llm_called,
        system_prompt=system_prompt,
        raw_llm_response=raw_response,
        provider=config.provider,
        model=config.model,
        base_url=config.base_url,
        latency_ms=latency_ms,
        offline=offline,
    )


def _json_state(**extra):
    payload = GameService.ensure_player()
    payload.update(extra)
    return jsonify(payload)


# ── Pages ──────────────────────────────────────────────────────────────────


@app.route("/", methods=["GET"])
def root():
    GameService.ensure_player()
    return render_template("index.html")


@app.route("/settings", methods=["GET"])
def settings_page():
    GameService.ensure_player()
    return render_template(
        "settings.html",
        settings_configured=password_configured(),
        settings_unlocked=session_unlocked(),
    )


@app.route("/clear", methods=["GET"])
def clear():
    # Same browser player, new game run; keep LLM settings.
    GameService.ensure_player()
    GameService.reset()
    return redirect("/")


# ── JSON API (client-driven) ───────────────────────────────────────────────


@app.route("/api/state", methods=["GET"])
def api_state():
    return _json_state()


@app.route("/api/reset", methods=["POST"])
def api_reset():
    GameService.ensure_player()
    ChatLogService.log_event("reset_requested", {"source": "api"})
    state = GameService.reset()
    return jsonify({"ok": True, **state})


@app.route("/api/hint", methods=["POST"])
def api_hint():
    GameService.ensure_player()
    level_number = GameService.current_level()
    result = GameService.use_hint()
    ChatLogService.log_event(
        "hint",
        {
            "ok": result.get("ok"),
            "hint": result.get("hint"),
            "message": result.get("message"),
            "hints_remaining": result.get("hints_remaining"),
        },
        level=level_number,
    )
    return jsonify({**result, **GameService.snapshot()})


@app.route("/api/logs", methods=["GET"])
def api_logs():
    """Return the current browser session transcript (all games + events)."""
    GameService.ensure_player()
    transcript = ChatLogService.get_session_transcript()
    return jsonify({"ok": True, **transcript, **GameService.snapshot()})


@app.route("/api/chat", methods=["POST"])
@limiter.limit("120/minute", override_defaults=True)
def api_chat():
    GameService.ensure_player()
    client_ip = request.remote_addr or "unknown"
    level_number = GameService.current_level()

    data = request.get_json(silent=True) or {}
    prompt = data.get("prompt") if "prompt" in data else request.form.get("prompt", "")
    prompt = sanitize_input(str(prompt or ""))
    prompt = html.escape(prompt)

    if not prompt.strip():
        ChatLogService.log_event("empty_prompt", {}, level=level_number)
        return jsonify({"ok": False, "response": "Empty prompt.", **GameService.snapshot()}), 400

    GameService.record_attempt()
    level_number = GameService.current_level()
    ChatLogService.log_event(
        "user_message",
        {"prompt": prompt, "raw_prompt": data.get("prompt") if isinstance(data, dict) else None},
        level=level_number,
    )

    quick = check_prompt(prompt)
    if len(quick) > 1:
        ChatLogService.log_event(
            "canned_response",
            {"prompt": prompt, "response": quick},
            level=level_number,
        )
        return jsonify({"ok": True, "response": quick, "event": "chat", **GameService.snapshot()})

    # Unlock command: /key <item> or key <item>
    unlock_prompt = prompt[1:] if prompt.startswith("/") else prompt
    unlock_lower = unlock_prompt.lower().strip()
    if unlock_lower == PASSWORD_KEY or unlock_lower.startswith(PASSWORD_KEY + " "):
        submitted = unlock_prompt.strip()[len(PASSWORD_KEY) :].strip()
        result = GameService.try_unlock(submitted)
        ChatLogService.log_event(
            "unlock_success" if result.success else "unlock_fail",
            {
                "prompt": prompt,
                "submitted": submitted,
                "response": result.message,
                "xp_gained": result.xp_gained,
                "completed": result.completed,
                "next_level": result.level,
            },
            level=level_number,
        )
        if result.success and prompts_collection is not None:
            prompts_collection.insert_one(
                {
                    "client_ip": client_ip,
                    "player_id": session.get("player_id"),
                    "session_id": session.get("player_id"),
                    "game_id": session.get("game_id"),
                    "prompt": prompt,
                    "last_prompt": GameService.last_prompt(),
                    "level": level_number,
                    "response": result.message,
                }
            )
        return jsonify(
            {
                "ok": result.success,
                "response": result.message,
                "event": "unlock" if result.success else "unlock_fail",
                "xp_gained": result.xp_gained,
                "completed": result.completed,
                **GameService.snapshot(),
            }
        )

    try:
        turn = get_response(prompt, level_number)
    except LLMError as exc:
        config = GameService.get_llm_config()
        ChatLogService.log_llm_turn(
            prompt=prompt,
            system_prompt=levels[level_number]["context"].format(secret=levels[level_number]["secret"]),
            response=str(exc),
            provider=config.provider,
            model=config.model,
            base_url=config.base_url,
            level=level_number,
            blocked=False,
            error=str(exc),
        )
        ChatLogService.log_event(
            "llm_error",
            {"prompt": prompt, "error": str(exc), "code": exc.code},
            level=level_number,
        )
        return jsonify(
            {
                "ok": False,
                "response": str(exc),
                "error_code": exc.code,
                "event": "llm_error",
                **GameService.snapshot(),
            }
        ), 502
    except Exception as exc:  # noqa: BLE001
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        logger.error("Error: %s (%s:%s)", exc, fname, exc_tb.tb_lineno)
        msg = blocked_answer_string("Error: Take your time and think.")
        ChatLogService.log_event(
            "error",
            {"prompt": prompt, "error": str(exc), "response": msg},
            level=level_number,
        )
        return jsonify(
            {
                "ok": False,
                "response": msg,
                "event": "error",
                **GameService.snapshot(),
            }
        )

    response = html.escape(turn.response)
    if turn.llm_called or turn.offline or turn.blocked:
        ChatLogService.log_llm_turn(
            prompt=prompt,
            system_prompt=turn.system_prompt or "",
            response=response,
            provider=turn.provider or "",
            model=turn.model or "",
            base_url=turn.base_url or "",
            level=level_number,
            blocked=turn.blocked,
            guard=turn.guard,
            raw_response=turn.raw_llm_response,
            latency_ms=turn.latency_ms,
        )
    if turn.blocked:
        ChatLogService.log_event(
            "guard_block",
            {"prompt": prompt, "guard": turn.guard, "response": response},
            level=level_number,
        )
    else:
        ChatLogService.log_event(
            "assistant_message",
            {
                "prompt": prompt,
                "response": response,
                "llm_called": turn.llm_called,
                "offline": turn.offline,
                "provider": turn.provider,
                "model": turn.model,
                "latency_ms": turn.latency_ms,
            },
            level=level_number,
        )

    if alive and collection is not None:
        collection.insert_one(
            {
                "client_ip": client_ip,
                "player_id": session.get("player_id"),
                "session_id": session.get("player_id"),
                "game_id": session.get("game_id"),
                "prompt": prompt,
                "level": level_number,
                "response": response,
            }
        )

    GameService.set_last_prompt(prompt)
    return jsonify(
        {
            "ok": True,
            "response": response,
            "event": "guard_block" if turn.blocked else "chat",
            "blocked": turn.blocked,
            "guard": turn.guard,
            **GameService.snapshot(),
        }
    )


# Backward-compatible POST / used by older clients
@app.route("/", methods=["POST"])
@limiter.limit("120/minute", override_defaults=True)
def root_post():
    return api_chat()


@app.route("/api/settings/unlock", methods=["POST"])
@limiter.limit("8/minute", override_defaults=True)
def api_settings_unlock():
    """Exchange the admin password for a settings session token."""
    GameService.ensure_player()
    if not password_configured():
        return jsonify(
            {
                "ok": False,
                "error": "Settings are locked: SETTINGS_PASSWORD is not configured.",
                "code": "settings_unconfigured",
            }
        ), 503

    data = request.get_json(silent=True) or {}
    password = data.get("password") if isinstance(data, dict) else None
    if not verify_password(password):
        # Uniform failure — do not reveal which part failed.
        return jsonify(
            {"ok": False, "error": "Invalid password.", "code": "settings_auth_failed"}
        ), 401

    token = issue_token()
    return jsonify(
        {
            "ok": True,
            "settings_token": token,
            "token_header": "X-Settings-Token",
        }
    )


@app.route("/api/settings/lock", methods=["POST"])
@require_settings_auth
def api_settings_lock():
    clear_auth()
    return jsonify({"ok": True})


@app.route("/api/settings", methods=["GET"])
@require_settings_auth
def api_settings_get():
    GameService.ensure_player()
    # Exact config used by /api/chat — Settings UI must mirror this.
    active = GameService.active_llm_public()
    defaults = GameService.default_llm_settings()
    return jsonify(
        {
            "ok": True,
            "settings": active,
            "active": active,
            "active_provider": active.get("provider"),
            "server_defaults": defaults.to_public_dict(),
            "providers": [
                {
                    "id": "openai",
                    "name": "OpenAI",
                    "description": "Official OpenAI Chat Completions API.",
                    "default_model": DEFAULT_MODELS["openai"],
                    "default_base_url": DEFAULT_BASE_URLS["openai"],
                    "needs_api_key": True,
                },
                {
                    "id": "ollama",
                    "name": "Ollama",
                    "description": "Local models via Ollama's OpenAI-compatible endpoint.",
                    "default_model": DEFAULT_MODELS["ollama"],
                    "default_base_url": DEFAULT_BASE_URLS["ollama"],
                    "needs_api_key": False,
                },
                {
                    "id": "openwebui",
                    "name": "Open WebUI",
                    "description": "Open WebUI OpenAI-compatible API (use …/api/v1 + JWT).",
                    "default_model": defaults.model if defaults.provider == "openwebui" else DEFAULT_MODELS["openwebui"],
                    "default_base_url": (
                        defaults.base_url
                        if defaults.provider == "openwebui"
                        else DEFAULT_BASE_URLS["openwebui"]
                    ),
                    "needs_api_key": True,
                },
            ],
            "supported": list(SUPPORTED_PROVIDERS),
            "alive": bool(alive),
        }
    )


@app.route("/api/settings", methods=["POST"])
@require_settings_auth
def api_settings_post():
    data = request.get_json(silent=True) or {}
    # Never let clients set auth fields through the settings payload.
    if isinstance(data, dict):
        data.pop("password", None)
        data.pop("settings_token", None)
    if not isinstance(data, dict) or not data.get("provider") or not str(data.get("model") or "").strip():
        return jsonify(
            {
                "ok": False,
                "error": "provider and model are required to save settings.",
                "code": "invalid_settings_payload",
            }
        ), 400
    try:
        config = GameService.update_llm_settings(data)
    except LLMError as exc:
        return jsonify({"ok": False, "error": str(exc), "code": exc.code}), 400
    except Exception as exc:  # noqa: BLE001
        return jsonify({"ok": False, "error": str(exc)}), 400
    active = GameService.active_llm_public()
    payload = GameService.snapshot()
    payload.update(
        {
            "ok": True,
            "settings": active,
            "active": active,
            "active_provider": active.get("provider"),
        }
    )
    return jsonify(payload)


@app.route("/api/settings/test", methods=["POST"])
@require_settings_auth
def api_settings_test():
    data = request.get_json(silent=True) or {}
    if isinstance(data, dict):
        data.pop("password", None)
        data.pop("settings_token", None)
    try:
        if data:
            current = GameService.get_llm_config()
            config = LLMConfig.from_mapping(data, current)
        else:
            config = GameService.get_llm_config()
        result = test_connection(config)
    except LLMError as exc:
        return jsonify({"ok": False, "error": str(exc), "code": exc.code}), 400
    status = 200 if result.get("ok") else 502
    return jsonify(result), status


@app.route("/api/settings/models", methods=["POST"])
@require_settings_auth
def api_settings_models():
    data = request.get_json(silent=True) or {}
    if isinstance(data, dict):
        data.pop("password", None)
        data.pop("settings_token", None)
    try:
        current = GameService.get_llm_config()
        config = LLMConfig.from_mapping(data, current) if data else current
        models = list_models(config)
    except LLMError as exc:
        status = 502 if exc.code in ("connection_error", "auth_error", "api_error") else 400
        return jsonify(
            {
                "ok": False,
                "error": str(exc),
                "code": exc.code,
                "models": [],
                "provider": getattr(exc, "provider", None),
            }
        ), status
    return jsonify(
        {
            "ok": True,
            "models": models,
            "provider": config.provider,
            "base_url": config.base_url,
            "selected": config.model,
        }
    )


if __name__ == "__main__":
    parser.add_argument("--alive", type=int, help="Contact the configured LLM provider")
    args = parser.parse_args()
    if args.alive:
        print("----------------------- Alive: LLM providers enabled -----------------------")
        alive = 1
    host = os.getenv("HOST") or "0.0.0.0"
    port = int(os.getenv("PORT") or 443)
    cert = os.getenv("SSL_CERT") or "cert.pem"
    key = os.getenv("SSL_KEY") or "key.pem"
    if os.path.exists(cert) and os.path.exists(key):
        app.run(host=host, port=port, ssl_context=(cert, key))
    else:
        app.run(host=host, port=int(os.getenv("PORT") or 5000))
