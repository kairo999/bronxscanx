from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="bronxscanx",
    version="6.0.0",
    author="BRONX_ULTRA",
    author_email="bronx@example.com",
    description="BRONX Multi-Scanner - Domain, Port, CDN, Tunable, Subdomain scanner for Termux",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/BRONX-ULTRA/bronxscanx",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
    ],
    python_requires=">=3.7",
    install_requires=[
        "rich>=10.0.0",
        "httpx>=0.23.0",
        "dnspython>=2.0.0",
        "urllib3>=1.26.0",
        "ipaddress>=1.0.23",
    ],
    entry_points={
        "console_scripts": [
            "bronxscanx = bronxscanx.__main__:main",
        ],
    },
)
