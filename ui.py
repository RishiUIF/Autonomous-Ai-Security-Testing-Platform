#!/usr/bin/env python
"""Start the local web UI:  python ui.py   (then open http://127.0.0.1:8000)"""
import argparse
import threading
import webbrowser

import uvicorn


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--port", type=int, default=8000)
    p.add_argument("--no-browser", action="store_true")
    a = p.parse_args()
    url = f"http://127.0.0.1:{a.port}"
    if not a.no_browser:
        threading.Timer(1.2, lambda: webbrowser.open(url)).start()
    print(f"Red/Blue lab UI running at {url}  (Ctrl+C to stop)")
    uvicorn.run("redblue.ui.app:app", host="127.0.0.1", port=a.port, log_level="warning")


if __name__ == "__main__":
    main()

# python run.py --target shopco --model ollama_chat/llama3.1:8b --concurrency 1 --rounds 2 --attacks-per-category 1 --no-llm-judge