"""Expose disposable native-test failures through GitHub check annotations."""
from pathlib import Path
import sys


path = Path(sys.argv[1])
if path.is_file():
    tail = path.read_text(errors="replace")[-5000:]
    tail = tail.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    print("::error title=Native HAProxy qualification::" + tail)
