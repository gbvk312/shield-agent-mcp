from setuptools import setup, find_packages

setup(
    name="shield-agent-mcp",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "click",
        "rich",
        "google-generativeai",
        "pydantic",
        "python-dotenv",
        "gitpython",
    ],
    extras_require={
        "mcp": ["mcp>=1.0.0"],
    },
    entry_points={
        "console_scripts": [
            "shield-agent=shield_agent.cli:main",
        ],
    },
    author="gbvk",
    description="A Hybrid-AI Security & Quality Sentinel for the MCP Era",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/gbvk/shield-agent-mcp",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.9",
)
