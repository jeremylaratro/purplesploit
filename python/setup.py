#!/usr/bin/env python3
"""
PurpleSploit Python Package
Hybrid pentesting framework - Python components
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="purplesploit",
    version="2.0.0",
    author="PurpleSploit Team",
    author_email="purplesploit@example.com",
    description="Hybrid pentesting framework - Python advanced features",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/jeremylaratro/purplesploit",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    install_requires=[
        "fastapi>=0.104.0",
        "uvicorn[standard]>=0.24.0",
        "sqlalchemy>=2.0.0",
        "pydantic>=2.0.0",
        "python-multipart>=0.0.6",
        "jinja2>=3.1.0",
        "aiofiles>=23.0.0",
        "httpx>=0.25.0",
        "rich>=13.0.0",
        "textual>=0.40.0",
        "pandas>=2.0.0",
        "matplotlib>=3.7.0",
        "seaborn>=0.12.0",
        "weasyprint>=60.0",
        "python-docx>=1.0.0",
        "openpyxl>=3.1.0",
        "cryptography>=41.0.0",
        "pyyaml>=6.0",
        "click>=8.1.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-asyncio>=0.21.0",
            "pytest-cov>=4.1.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.5.0",
            "isort>=5.12.0",
        ],
        "ai": [
            "openai>=1.0.0",
            "anthropic>=0.7.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "purplesploit-api=purplesploit.api.server:main",
            "purplesploit-web=purplesploit.web.dashboard:main",
            "purplesploit-pro=purplesploit.tui.app:main",
            "purplesploit-report=purplesploit.reporting.cli:main",
        ],
    },
    include_package_data=True,
    package_data={
        "purplesploit.web": ["templates/*.html", "static/*"],
        "purplesploit.reporting": ["templates/*.html", "templates/*.jinja2"],
    },
)
