from setuptools import setup

setup(
    name="remoteKrbRelayx",
    version="1.0",
    description="A tool for coercing and relaying Kerberos authentication over DCOM and RPC.",
    author="Ole Fredrik Borgundvåg Berg (@olefredrikberg)",
    packages=["remotekrbrelayx", "remotekrbrelayx.krbrelayx", "remotekrbrelayx.krbrelayx.lib", "remotekrbrelayx.krbrelayx.lib.utils", "remotekrbrelayx.krbrelayx.lib.clients"],
    install_requires=[
        "setuptools==80.9.0",
        "impacket @ git+https://github.com/sploutchy/impacket.git@potato",
        "pyOpenSSL==24.0.0"
    ],
    scripts=["remoteKrbRelayx.py"],
)