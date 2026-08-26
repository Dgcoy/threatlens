import sys
from pathlib import Path

INTEL_DIR = Path(__file__).resolve().parent.parent
REPO_ROOT = INTEL_DIR.parent
for p in (str(INTEL_DIR), str(REPO_ROOT)):
    if p not in sys.path:
        sys.path.insert(0, p)
