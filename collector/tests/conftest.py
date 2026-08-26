import sys
from pathlib import Path

# collector code imports sibling modules; shared/ lives at repo root
COLLECTOR_DIR = Path(__file__).resolve().parent.parent
REPO_ROOT = COLLECTOR_DIR.parent
for p in (str(COLLECTOR_DIR), str(REPO_ROOT)):
    if p not in sys.path:
        sys.path.insert(0, p)
