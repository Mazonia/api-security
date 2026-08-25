#!/usr/bin/env python3
"""Global CLI Entry Point for MazAPI Security Platform."""
import os
import sys

# Ensure api-security-project directory is in sys.path
root_dir = os.path.dirname(os.path.abspath(__file__))
project_dir = os.path.join(root_dir, "api-security-project")

if project_dir not in sys.path:
    sys.path.insert(0, project_dir)

if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from cli import main

if __name__ == "__main__":
    main()
