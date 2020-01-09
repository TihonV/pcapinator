from setuptools import setup, find_packages
from pathlib import Path


PACKAGE_NAME = "pcapinator"
REPO_URL = "https://github.com/mspicer/pcapinator"

VERSION = Path('VERSION').read_text().splitlines()[0]

_, DESCRIPTION, DESCRIPTION_LONG = Path('README.md').read_text().splitlines()


setup(
    name=PACKAGE_NAME,
    version=VERSION,
    author="Mike Spicer",
    description=DESCRIPTION,
    long_description=DESCRIPTION_LONG,
    long_description_content_type="text/markdown",
    url=REPO_URL,
    packages=find_packages(exclude=['tests']),
    install_requires=[
        "python-dateutil>=2.8.0,<3.0",
        "pandas>=0.25.0,<1.0",
    ],
    include_package_data=True,
    classifiers=[
        "Environment :: Console",
        "License :: OSI Approved :: MIT License",
        "Operating System :: MacOS",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3 :: Only",
        "Topic :: System :: Networking",
        "Topic :: Utilities",
    ],
    python_requires='>=3.6, <4.0',
)

