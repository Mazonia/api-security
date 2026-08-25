"""Setup script to install mazapi CLI globally."""
from setuptools import setup, find_packages

setup(
    name="mazapi",
    version="2.5.0",
    description="MazAPI Enterprise API & AI Security Intelligence Platform CLI",
    author="Team One — UMaT Ghana",
    py_modules=["cli_entry"],
    packages=find_packages(where="api-security-project"),
    package_dir={"": "api-security-project"},
    install_requires=[
        "rich>=13.0.0",
        "httpx>=0.24.0",
        "scikit-learn>=1.2.0",
        "numpy>=1.23.0",
        "aiosqlite>=0.19.0",
        "pyyaml>=6.0",
    ],
    entry_points={
        "console_scripts": [
            "mazapi = cli_entry:main",
        ],
    },
    python_requires=">=3.9",
)
