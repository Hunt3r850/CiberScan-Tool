"""Escaneo concurrente de rutas web basado en diccionarios."""

import concurrent.futures
import datetime
import json
import logging
import time
from urllib.parse import quote, urljoin, urlsplit

import requests

from .result import ScanResult


class DirectoryScanner:
    def __init__(self, wordlist_manager, log_level=logging.INFO):
        self.wordlist_manager = wordlist_manager
        self.delay = 0.0
        self.timeout = 10
        self.follow_redirects = False
        self.user_agent = "CiberScan-Tool/2.0"
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(log_level)

    def set_delay(self, delay):
        self.delay = max(0.0, float(delay))

    def set_timeout(self, timeout):
        if float(timeout) <= 0:
            raise ValueError("El timeout debe ser mayor que cero")
        self.timeout = float(timeout)

    def set_follow_redirects(self, follow_redirects):
        self.follow_redirects = bool(follow_redirects)

    @staticmethod
    def _validate_base_url(base_url):
        parsed = urlsplit(base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("La URL base debe usar http o https e incluir un host")

    def scan_url(self, base_url, path):
        self._validate_base_url(base_url)
        safe_path = "/".join(quote(segment, safe="-._~%") for segment in str(path).split("/"))
        target_url = urljoin(base_url.rstrip("/") + "/", safe_path.lstrip("/"))
        if self.delay:
            time.sleep(self.delay)
        try:
            response = requests.get(
                target_url,
                headers={"User-Agent": self.user_agent},
                timeout=self.timeout,
                allow_redirects=self.follow_redirects,
            )
        except requests.RequestException as exc:
            self.logger.warning("No se pudo consultar %s: %s", target_url, exc)
            return None

        elapsed = response.elapsed.total_seconds() if getattr(response, "elapsed", None) else None
        result = ScanResult(
            target_url,
            response.status_code,
            response.headers.get("Content-Type"),
            len(response.content),
            elapsed,
        )
        sensitive_names = {"admin", "backup", "config", "database", "debug", "private", "secret"}
        first_segment = str(path).strip("/").split("/", 1)[0].split(".", 1)[0].lower()
        if response.status_code in {200, 204, 401, 403} and first_segment in sensitive_names:
            result.mark_interesting("Ruta potencialmente sensible")
        return result

    @staticmethod
    def _candidate_paths(words, extensions):
        suffixes = [""] if not extensions else list(extensions)
        seen = set()
        for word in words:
            word = str(word).strip().strip("/")
            if not word:
                continue
            for extension in suffixes:
                extension = str(extension).strip()
                if extension and not extension.startswith("."):
                    extension = "." + extension
                candidate = word + extension
                if candidate not in seen:
                    seen.add(candidate)
                    yield candidate

    def scan_with_wordlist(self, base_url, words, extensions=None, threads=10):
        self._validate_base_url(base_url)
        if not words:
            return []
        workers = max(1, min(int(threads), 100))
        candidates = list(self._candidate_paths(words, extensions))
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            results = list(executor.map(lambda item: self.scan_url(base_url, item), candidates))
        return [result for result in results if result is not None]

    def scan_site(self, base_url, wordlist_name="common.txt", method="native", extensions=None, threads=10):
        if method != "native":
            raise ValueError("Solo el metodo nativo esta disponible en esta instalacion")
        words = self.wordlist_manager.load_wordlist(wordlist_name)
        if words is None:
            return []
        return self.scan_with_wordlist(base_url, words, extensions=extensions, threads=threads)

    def scan(self, url, extensions=None, threads=10):
        return self.scan_site(url, extensions=extensions, threads=threads)

    def save_results(self, results, path):
        try:
            with open(path, "w", encoding="utf-8") as output:
                json.dump([result.to_dict() for result in results], output, ensure_ascii=False, indent=2)
            return True
        except (OSError, TypeError) as exc:
            self.logger.error("No se pudieron guardar los resultados: %s", exc)
            return False

    def load_results(self, path):
        try:
            with open(path, encoding="utf-8") as source:
                data = json.load(source)
        except (OSError, json.JSONDecodeError) as exc:
            self.logger.error("No se pudieron cargar los resultados: %s", exc)
            return []

        results = []
        for item in data:
            result = ScanResult(
                item["url"], item["status_code"], item.get("content_type"),
                item.get("content_length"), item.get("response_time"),
            )
            result.notes = item.get("notes", [])
            result.interesting = item.get("interesting", False)
            if item.get("discovery_time"):
                result.discovery_time = datetime.datetime.fromisoformat(item["discovery_time"])
            results.append(result)
        return results
