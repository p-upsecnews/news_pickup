"""HTTP取得の共通処理"""
import json
import ssl
import time
import urllib.request

USER_AGENT = "news-pickup/0.1 (+security news digest)"


def _ssl_context():
    # Windows の証明書ストアに期限切れ証明書が残っていると検証に失敗するため、
    # certifi があればそちらのCAバンドルを使う（検証自体は無効化しない）
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        return ssl.create_default_context()


_CTX = _ssl_context()


def fetch(url, timeout=60, retries=2, wait=5):
    """URLの本文をbytesで返す。一時的な失敗は数回リトライする"""
    last_err = None
    for attempt in range(retries + 1):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=timeout, context=_CTX) as r:
                return r.read()
        except Exception as e:  # 取得失敗は呼び出し側でまとめて記録する
            last_err = e
            if attempt < retries:
                time.sleep(wait)
    raise last_err


def fetch_json(url, **kwargs):
    return json.loads(fetch(url, **kwargs).decode("utf-8"))
