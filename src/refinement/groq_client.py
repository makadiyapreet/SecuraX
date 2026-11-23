"""
groq_client.py — Phase 4: Groq API Client Wrapper for Code Refinement.

Wraps the Groq chat-completions API with:
  - Model selection from config (config/refinement.yaml or env GROQ_MODEL)
  - Strict low temperature for reproducibility
  - Retries with exponential backoff + jitter for HTTP 429 and 5xx
  - Client-side rate limiting adhering to Groq free-tier boundaries
  - Persistent on-disk response cache (data/cache/groq/)
  - Telemetry logging of token usage and latency (logs/groq_calls.jsonl)
  - Offline/rate-limit fallback when API key is missing or quota is exhausted

SECURITY:
  The API key is read ONLY from GROQ_API_KEY environment variable.
  Never log, print, or commit the API key.
"""

import os
import sys
import time
import json
import random
import hashlib
import logging
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple
from collections import deque

import yaml
from dotenv import load_dotenv

# Project root resolution
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

# Load .env file automatically
load_dotenv(PROJECT_ROOT / ".env")

logger = logging.getLogger("groq_client")
if not logger.handlers:
    logger.setLevel(logging.INFO)
    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] [GroqClient] %(message)s"))
    logger.addHandler(ch)

DEFAULT_CONFIG_PATH = PROJECT_ROOT / "config" / "refinement.yaml"


def load_refinement_config(config_path: Optional[Path] = None) -> Dict[str, Any]:
    """Load refinement configuration from YAML."""
    path = Path(config_path) if config_path else DEFAULT_CONFIG_PATH
    if not path.is_file():
        # Fallback default configuration
        return {
            "models": {
                "default": "llama-3.3-70b-versatile",
                "alternate": "llama-3.1-8b-instant",
            },
            "generation": {
                "temperature": 0.1,
                "max_tokens": 800,
                "timeout_seconds": 30.0,
                "top_p": 0.95,
            },
            "resilience": {
                "max_retries": 5,
                "backoff_base": 2.0,
                "backoff_max": 60.0,
                "jitter": True,
            },
            "rate_limits": {
                "requests_per_minute": 30,
                "requests_per_day": 1000,
                "tokens_per_minute": 12000,
                "min_request_interval_seconds": 2.0,
            },
            "cache": {
                "enabled": True,
                "cache_dir": "data/cache/groq",
            },
            "telemetry": {
                "log_file": "logs/groq_calls.jsonl",
                "debug": False,
            },
        }
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


class ClientRateLimiter:
    """Client-side rate limiter for Groq free-tier constraints."""

    def __init__(self, requests_per_minute: int = 30, min_interval: float = 2.0, requests_per_day: int = 1000):
        self.rpm = requests_per_minute
        self.min_interval = min_interval
        self.rpd = requests_per_day
        self._timestamps: deque = deque()
        self._last_request_time: float = 0.0
        self._daily_count: int = 0
        self._daily_reset_time: float = time.time() + 86400

    def wait_if_needed(self) -> None:
        """Enforce rate limits before sending a request."""
        now = time.time()

        # Reset daily counter if 24 hours passed
        if now >= self._daily_reset_time:
            self._daily_count = 0
            self._daily_reset_time = now + 86400

        if self._daily_count >= self.rpd:
            raise RuntimeError(
                f"Client-side daily rate limit reached ({self.rpd} requests/day). "
                "Halting further requests until reset."
            )

        # Enforce minimum interval between consecutive requests
        elapsed_since_last = now - self._last_request_time
        if elapsed_since_last < self.min_interval:
            sleep_time = self.min_interval - elapsed_since_last
            time.sleep(sleep_time)

        # Enforce rolling 1-minute window
        now = time.time()
        while self._timestamps and now - self._timestamps[0] > 60.0:
            self._timestamps.popleft()

        if len(self._timestamps) >= self.rpm:
            sleep_needed = 60.0 - (now - self._timestamps[0]) + 0.1
            if sleep_needed > 0:
                logger.info(f"Rate limiter: RPM ceiling reached ({self.rpm}). Pausing {sleep_needed:.2f}s...")
                time.sleep(sleep_needed)

        now = time.time()
        self._timestamps.append(now)
        self._last_request_time = now
        self._daily_count += 1


class ResponseCache:
    """On-disk JSON cache keyed by hash(model + prompt + params)."""

    def __init__(self, cache_dir: Path):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _hash_key(self, model: str, system_prompt: str, user_prompt: str, temperature: float, max_tokens: int) -> str:
        key_str = f"{model}|{temperature:.2f}|{max_tokens}|{system_prompt.strip()}|{user_prompt.strip()}"
        return hashlib.sha256(key_str.encode("utf-8")).hexdigest()

    def get(self, model: str, system_prompt: str, user_prompt: str, temperature: float, max_tokens: int) -> Optional[Dict[str, Any]]:
        key = self._hash_key(model, system_prompt, user_prompt, temperature, max_tokens)
        cache_file = self.cache_dir / f"{key}.json"
        if cache_file.is_file():
            try:
                with open(cache_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"Error reading cache file {cache_file}: {e}")
        return None

    def put(self, model: str, system_prompt: str, user_prompt: str, temperature: float, max_tokens: int, data: Dict[str, Any]) -> None:
        key = self._hash_key(model, system_prompt, user_prompt, temperature, max_tokens)
        cache_file = self.cache_dir / f"{key}.json"
        try:
            with open(cache_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.warning(f"Error writing cache file {cache_file}: {e}")


def is_quota_or_rate_limit_error(err: Exception) -> bool:
    """Detect if exception is caused by rate limit, token ceiling, or credit/quota exhaustion."""
    try:
        from groq import RateLimitError
        if isinstance(err, RateLimitError):
            return True
    except ImportError:
        pass

    err_str = (str(err) + " " + getattr(err, "message", "")).lower()
    quota_signatures = [
        "rate_limit", "rate limit", "ratelimit", "429",
        "quota", "credit", "balance", "insufficient",
        "tokens per minute", "tpm", "itpm", "otpm", "rpd", "rpm",
        "limit exceeded", "resource has been exhausted",
        "billing", "payment", "402", "403", "413"
    ]
    return any(sig in err_str for sig in quota_signatures)


class GroqRefinementClient:
    """
    Robust Groq API client with rate limiting, retries, caching, and offline fallback.
    """

    def __init__(
        self,
        config_path: Optional[Path] = None,
        model_name: Optional[str] = None,
        api_key: Optional[str] = None,
    ):
        self.config = load_refinement_config(config_path)

        # Secrets resolution: collect all configured API keys (primary + fallback)
        # Supports GROQ_API_KEY, GROQ_API_KEY_FALLBACK, GROQ_API_KEY_2, GROQ_API_KEY_3,
        # or a comma-separated list in GROQ_API_KEYS
        candidate_keys = []
        if api_key is not None:
            # Explicit key provided (used for testing fallback or direct injection)
            if api_key.strip():
                candidate_keys.append(api_key.strip())
        else:
            # Check comma-separated list
            env_keys = os.getenv("GROQ_API_KEYS", "")
            if env_keys:
                for k in env_keys.split(","):
                    if k.strip():
                        candidate_keys.append(k.strip())

            # Check individual environment variables
            for var in [
                "GROQ_API_KEY",
                "GROQ_API_KEY_FALLBACK",
                "GROQ_API_KEY_2",
                "GROQ_API_KEY_3",
                "GROQ_FALLBACK_API_KEY",
            ]:
                val = os.getenv(var, "").strip()
                if val and val != "your_key_here" and val not in candidate_keys:
                    candidate_keys.append(val)

        # Deduplicate while preserving priority order
        seen = set()
        self.api_keys: List[str] = []
        for k in candidate_keys:
            if k and k != "your_key_here" and k not in seen:
                seen.add(k)
                self.api_keys.append(k)

        self.current_key_idx = 0
        self.is_available = len(self.api_keys) > 0
        self.unavailable_reason: Optional[str] = None

        if not self.is_available:
            self.unavailable_reason = (
                "GROQ_API_KEY is not set. Please set GROQ_API_KEY in your .env file or environment. "
                "See .env.example for instructions."
            )
            logger.warning(self.unavailable_reason)
        else:
            if len(self.api_keys) > 1:
                logger.info(f"GroqClient initialized with {len(self.api_keys)} API keys in active failover pool.")

        # Model selection: parameter > environment variable > config default
        self.model = model_name or os.getenv("GROQ_MODEL") or self.config["models"]["default"]
        self.alternate_model = self.config["models"].get("alternate", "openai/gpt-oss-120b")

        # Hyperparameters
        gen = self.config.get("generation", {})
        self.temperature = float(gen.get("temperature", 0.1))
        self.max_tokens = int(gen.get("max_tokens", 800))
        self.timeout = float(gen.get("timeout_seconds", 30.0))

        # Resilience & retries
        res = self.config.get("resilience", {})
        self.max_retries = int(res.get("max_retries", 5))
        self.backoff_base = float(res.get("backoff_base", 2.0))
        self.backoff_max = float(res.get("backoff_max", 60.0))
        self.use_jitter = bool(res.get("jitter", True))

        # Rate limiter setup
        rl = self.config.get("rate_limits", {})
        self.rate_limiter = ClientRateLimiter(
            requests_per_minute=int(rl.get("requests_per_minute", 30)),
            min_interval=float(rl.get("min_request_interval_seconds", 2.0)),
            requests_per_day=int(rl.get("requests_per_day", 1000)),
        )

        # Response cache setup
        cache_cfg = self.config.get("cache", {})
        self.cache_enabled = bool(cache_cfg.get("enabled", True))
        cache_dir = PROJECT_ROOT / cache_cfg.get("cache_dir", "data/cache/groq")
        self.cache = ResponseCache(cache_dir)

        # Telemetry
        telem = self.config.get("telemetry", {})
        self.log_file = PROJECT_ROOT / telem.get("log_file", "logs/groq_calls.jsonl")
        self.debug = bool(telem.get("debug", False))
        self.log_file.parent.mkdir(parents=True, exist_ok=True)

        # Groq client instantiation
        self._groq_client = self._init_active_client()

    def _init_active_client(self):
        """Instantiate Groq client for current active key."""
        if not self.is_available or not self.api_keys:
            return None
        try:
            from groq import Groq
            active_key = self.api_keys[self.current_key_idx]
            return Groq(api_key=active_key, timeout=self.timeout)
        except Exception as e:
            self.is_available = False
            self.unavailable_reason = f"Failed to initialize Groq client: {e}"
            logger.error(self.unavailable_reason)
            return None

    def _rotate_to_next_key(self, reason: str = "") -> bool:
        """
        Switch to the next fallback API key in pool if available.
        Returns True if rotated to another valid key, False if only 1 key is configured.
        """
        if len(self.api_keys) <= 1:
            return False

        old_idx = self.current_key_idx
        self.current_key_idx = (self.current_key_idx + 1) % len(self.api_keys)

        logger.warning(
            f"⚡ Groq API Failover: Key #{old_idx + 1} exhausted ({reason}). "
            f"Automatically transferring request to Fallback Key #{self.current_key_idx + 1} "
            f"({self.current_key_idx + 1}/{len(self.api_keys)} in pool)..."
        )
        self._groq_client = self._init_active_client()
        return True

    def list_available_models(self) -> List[str]:
        """Fetch list of active models directly from Groq API endpoint."""
        if not self.is_available or self._groq_client is None:
            return [self.model, self.alternate_model]
        try:
            models_page = self._groq_client.models.list()
            return [m.id for m in models_page.data]
        except Exception as e:
            logger.warning(f"Could not list models from Groq: {e}")
            return [self.model, self.alternate_model]

    def _log_telemetry(self, record: Dict[str, Any]) -> None:
        """Append call metrics to logs/groq_calls.jsonl without logging secrets."""
        try:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(record, ensure_ascii=False) + "\n")
        except Exception as e:
            logger.warning(f"Failed to append telemetry log: {e}")

    def complete(
        self,
        user_prompt: str,
        system_prompt: str = "You are an expert security engineer and code repair assistant.",
        model: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Execute chat completion with caching, rate limiting, and fallback.

        Returns structured dict:
          {
            "content": str or None,
            "raw_response": str or None,
            "status": "success" | "cached" | "refinement_unavailable" | "rate_limited" | "error",
            "usage": {"prompt_tokens": int, "completion_tokens": int, "total_tokens": int},
            "latency_seconds": float,
            "cached": bool,
            "model": str,
            "error_message": Optional[str]
          }
        """
        target_model = model or self.model
        temp = self.temperature if temperature is None else temperature
        tokens = min(self.max_tokens if max_tokens is None else max_tokens, 800)

        # Check Offline / Unavailability Fallback first
        if not self.is_available or self._groq_client is None:
            return {
                "content": None,
                "raw_response": None,
                "status": "refinement_unavailable",
                "reason": self.unavailable_reason or "Groq API service unavailable (no valid keys configured)",
                "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
                "latency_seconds": 0.0,
                "cached": False,
                "model": target_model,
                "error_message": self.unavailable_reason,
            }

        # Check Cache
        if self.cache_enabled:
            cached = self.cache.get(target_model, system_prompt, user_prompt, temp, tokens)
            if cached:
                cached["cached"] = True
                cached["status"] = "cached"
                if self.debug:
                    logger.info(f"Cache hit for prompt hash on {target_model}")
                return cached

        # Apply client-side rate limits
        try:
            self.rate_limiter.wait_if_needed()
        except RuntimeError as rle:
            return {
                "content": None,
                "raw_response": None,
                "status": "refinement_unavailable",
                "reason": str(rle),
                "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
                "latency_seconds": 0.0,
                "cached": False,
                "model": target_model,
                "error_message": str(rle),
            }

        # API Call with Exponential Backoff + Multi-Key Failover
        from groq import RateLimitError, InternalServerError, APIConnectionError, APITimeoutError, AuthenticationError

        retries = 0
        keys_failed_count = 0
        max_keys = len(self.api_keys)
        last_error = None

        while retries <= self.max_retries:
            start_time = time.time()
            try:
                response = self._groq_client.chat.completions.create(
                    model=target_model,
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ],
                    temperature=temp,
                    max_tokens=tokens,
                )
                latency = time.time() - start_time

                content = response.choices[0].message.content or ""
                usage = {
                    "prompt_tokens": getattr(response.usage, "prompt_tokens", 0),
                    "completion_tokens": getattr(response.usage, "completion_tokens", 0),
                    "total_tokens": getattr(response.usage, "total_tokens", 0),
                }

                result = {
                    "content": content,
                    "raw_response": content,
                    "status": "success",
                    "usage": usage,
                    "latency_seconds": latency,
                    "cached": False,
                    "model": target_model,
                    "error_message": None,
                }

                # Store in cache
                if self.cache_enabled:
                    self.cache.put(target_model, system_prompt, user_prompt, temp, tokens, result)

                # Log telemetry
                telem_entry = {
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "model": target_model,
                    "latency_seconds": round(latency, 3),
                    "prompt_tokens": usage["prompt_tokens"],
                    "completion_tokens": usage["completion_tokens"],
                    "total_tokens": usage["total_tokens"],
                    "status": "success",
                }
                if self.debug:
                    telem_entry["user_prompt_head"] = user_prompt[:150]
                self._log_telemetry(telem_entry)

                return result

            except AuthenticationError as auth_err:
                last_error = auth_err
                if keys_failed_count < max_keys - 1 and self._rotate_to_next_key(reason=f"Authentication failed: {auth_err}"):
                    keys_failed_count += 1
                    logger.info(f"Retrying request immediately with Fallback API key #{self.current_key_idx + 1}...")
                    continue

                self.is_available = False
                self.unavailable_reason = f"Authentication error across all configured API keys ({auth_err})"
                logger.error(self.unavailable_reason)
                return {
                    "content": None,
                    "raw_response": None,
                    "status": "refinement_unavailable",
                    "reason": self.unavailable_reason,
                    "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
                    "latency_seconds": time.time() - start_time,
                    "cached": False,
                    "model": target_model,
                    "error_message": str(auth_err),
                }

            except Exception as err:
                last_error = err

                # Automatic failover: if rate limit, credits exhausted, or quota ceiling hit
                if is_quota_or_rate_limit_error(err):
                    if keys_failed_count < max_keys - 1 and self._rotate_to_next_key(reason=f"Credits/Quota/RateLimit ({err})"):
                        keys_failed_count += 1
                        logger.info(f"Retrying request immediately with Fallback API key #{self.current_key_idx + 1}...")
                        continue

                    # If all fallback keys exhausted or only single key, perform exponential backoff
                    retries += 1
                    if retries > self.max_retries:
                        break

                    retry_after = None
                    if hasattr(err, "response") and err.response is not None:
                        headers = getattr(err.response, "headers", {})
                        retry_after_hdr = headers.get("retry-after")
                        if retry_after_hdr:
                            try:
                                retry_after = float(retry_after_hdr)
                            except ValueError:
                                pass

                    if retry_after is not None:
                        wait_time = min(retry_after, self.backoff_max)
                    else:
                        backoff = self.backoff_base * (2 ** (retries - 1))
                        jitter = random.uniform(0.1, 0.5) if self.use_jitter else 0.0
                        wait_time = min(backoff + jitter, self.backoff_max)

                    logger.warning(
                        f"Groq API Quota/RateLimit ({err}). All failover keys busy/exhausted. "
                        f"Retry {retries}/{self.max_retries} in {wait_time:.2f}s..."
                    )
                    time.sleep(wait_time)
                    continue

                # Server / Network temporary errors (5xx, timeouts, connection drop)
                if isinstance(err, (InternalServerError, APIConnectionError, APITimeoutError)):
                    retries += 1
                    if retries > self.max_retries:
                        break

                    retry_after = None
                    if hasattr(err, "response") and err.response is not None:
                        headers = getattr(err.response, "headers", {})
                        retry_after_hdr = headers.get("retry-after")
                        if retry_after_hdr:
                            try:
                                retry_after = float(retry_after_hdr)
                            except ValueError:
                                pass

                    if retry_after is not None:
                        wait_time = min(retry_after, self.backoff_max)
                    else:
                        backoff = self.backoff_base * (2 ** (retries - 1))
                        jitter = random.uniform(0.1, 0.5) if self.use_jitter else 0.0
                        wait_time = min(backoff + jitter, self.backoff_max)

                    logger.warning(
                        f"Groq API {err.__class__.__name__} ({err}). "
                        f"Retry {retries}/{self.max_retries} in {wait_time:.2f}s..."
                    )
                    time.sleep(wait_time)
                    continue

                # Any other unexpected exception
                logger.error(f"Non-retryable Groq API error: {err}")
                break

        # If retries exhausted or fatal error
        error_msg = f"Groq API call failed after {retries} retries: {last_error}"
        logger.error(error_msg)

        telem_entry = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "model": target_model,
            "status": "error",
            "error_type": last_error.__class__.__name__ if last_error else "Unknown",
            "retries": retries,
        }
        self._log_telemetry(telem_entry)

        return {
            "content": None,
            "raw_response": None,
            "status": "refinement_unavailable",
            "reason": error_msg,
            "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
            "latency_seconds": 0.0,
            "cached": False,
            "model": target_model,
            "error_message": error_msg,
        }
