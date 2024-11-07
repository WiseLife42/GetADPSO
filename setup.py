from setuptools import setup, find_packages

def parse_requirements():
    with open('requirements.txt') as f:
        return f.read().splitlines()

setup(
    name="GetADPSO",
    version="0.2",
    description="A Python package to retrieve msDS-ResultantPSO and msDS-PSOApplied attributes from Active Directory.",
    author="WiseLife",
    author_email="",
    url="https://github.com/WiseLife42/GetADPSO",
    packages=find_packages(),
    install_requires=parse_requirements(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
    entry_points={
        'console_scripts': [
            'getadpso=getadpso.getadpso:main',
        ],
    },
)
