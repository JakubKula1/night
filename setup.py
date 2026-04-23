from setuptools import setup, find_packages

setup(
    name='night',
    version='0.1.0',
    packages=find_packages(include=['night', 'night.*']),
    install_requires=['click', 'crossplane', 'rich'],
    entry_points={
        'console_scripts': [
            'night = night.cli:cli',
        ],
    },
)