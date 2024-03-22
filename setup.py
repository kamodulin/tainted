from setuptools import find_namespace_packages, setup

setup(
    name="tainted",
    version="0.0.1",
    packages=find_namespace_packages(include=["tainted*"]),
    install_requires=["astor >= 0.8.1"],
    extras_require={
        "dev": ["black", "isort", "pytest", "pytest-cov"],
    },
)
