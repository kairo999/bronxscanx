from setuptools import setup, find_packages
setup(name="bronxscan", version="8.0.0", author="BRONX_ULTRA", packages=find_packages(), install_requires=["rich","httpx","urllib3","ipaddress"], entry_points={"console_scripts": ["bronxscan = bronxscan.core:main"]})
