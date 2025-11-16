"""Setup configuration for HackwithAI."""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="hackwithai",
    version="0.1.0",
    author="HackwithAI Contributors",
    description="Local LLM-powered security reconnaissance tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/reconai",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.11",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "reconai=reconai.cli:app",
        ],
    },
    include_package_data=True,
    package_data={
        "reconai": [
            "web/templates/*.html",
            "web/static/*",
        ],
    },
)
