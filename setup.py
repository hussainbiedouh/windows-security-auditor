from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    install_requires = [line.strip() for line in fh.readlines() if line.strip() and not line.startswith("#")]

setup(
    name="windows-security-auditor",
    version="0.1.0",
    author="OSP Project",
    author_email="osp-project@example.com",
    description="A CLI tool to scan Windows systems for security misconfigurations and vulnerabilities",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/your-username/windows-security-auditor",
    py_modules=["security_auditor"],
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Security Professionals",
        "Environment :: Console",
        "License :: OSI Approved :: MIT License",
        "Operating System :: Microsoft :: Windows",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Topic :: Security",
        "Topic :: System :: Systems Administration",
    ],
    python_requires=">=3.8",
    install_requires=install_requires,
    entry_points={
        "console_scripts": [
            "security-auditor=security_auditor:main",
        ],
    },
)