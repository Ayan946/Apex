from setuptools import setup

setup(
    name="apex",
    version="1.0",
    py_modules=["main"],
    packages=["apex"],
    install_requires=["requests", "pyjwt"],
    entry_points={"console_scripts": ["apex=main:main"]},
)
