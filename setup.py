from setuptools import setup


setup(
    name="RedirXploit",
    version="1.0.0",
    description="Open Redirect Vulnerability Scanner",
    long_description="RedirXploit is a tool designed to scan URLs for open redirect vulnerabilities.",
    long_description_content_type="text/markdown",
    author="Angix Black",
    url="https://github.com/AngixBlack/RedirXploit",  
    py_modules=["redirXploit"],
    install_requires=[
        "argparse",
        "requests",
        "rich",
    ],
    entry_points={
        "console_scripts": [
            "redirx=redirXploit:main",  
            "RedirXploit=redirXploit:main",  
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
    ],
    python_requires=">=3.6",
)
