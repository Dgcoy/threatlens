import os
import sys
from pathlib import Path

os.environ.setdefault("APP_PIN", "123456")
os.environ.setdefault("SESSION_SECRET", "test-secret")

API_DIR = Path(__file__).resolve().parent.parent
REPO_ROOT = API_DIR.parent
for p in (str(API_DIR), str(REPO_ROOT)):
    if p not in sys.path:
        sys.path.insert(0, p)
