from setuptools import setup

setup(
    name="oralyzer",
    version="1.0.0",
    description="Open redirect and CRLF injection scanner",
    py_modules=["oralyzer"],
    packages=["core"],
    package_data={"core": ["payloads.txt"]},
    entry_points={"console_scripts": ["oralyzer=oralyzer:main"]},
    install_requires=["requests", "beautifulsoup4"],
)
