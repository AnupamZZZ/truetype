# Double-click this file (Windows) to open TrueType. You can also drag a file onto its icon.
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))
from truetype.gui import main

main()
