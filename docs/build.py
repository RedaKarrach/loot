"""Build docs/index.html from the template and real loot output.

    python docs/build.py <folder with *.txt outputs>

The folder is produced by running loot on the planted demo home (see demo/plant.py).
Each <!--OUT:name--> placeholder in index.template.html is replaced by name.txt.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

here = Path(__file__).parent
template = (here / "index.template.html").read_text(encoding="utf-8")
outs = Path(sys.argv[1])


def fill(match: re.Match[str]) -> str:
    name = match.group(1)
    text = (outs / f"{name}.txt").read_text(encoding="utf-8")
    text = "\n".join(line.rstrip() for line in text.splitlines()).strip("\n")
    return "\n" + text.replace("</script", "<\\/script") + "\n"


html = re.sub(r"<!--OUT:([a-z-]+)-->", fill, template)
(here / "index.html").write_text(html, encoding="utf-8")
print(f"wrote {here / 'index.html'} ({len(html)} bytes)")
