from setuptools import setup, find_packages

# Read the contents of the README file
with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="DopeShell",
    version="2.0.0",
    author="Abhishek Sharma, Manaswi Sharma",
    author_email="170mailmea@gmail.com",
    description="A Python library for creating secure reverse shells with session management and encryption.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/anonymous300502/DopeShellPyPi",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security",
    ],
    python_requires='>=3.7',
    install_requires=[
        "cryptography>=39.0.0",
    ],
    entry_points={
        "console_scripts": [
            "dopeshell-server=DopeShell.server:main",
            "dopeshell-client=DopeShell.client:main",
        ],
    },
)