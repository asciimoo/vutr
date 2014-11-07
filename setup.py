from setuptools import setup, find_packages

import vutr

install_requires = ('requests',
                    'click')

setup(
    name='vutr',
    version=vutr.__version__,
    description='CVE Tracker',
    license=vutr.__licence__,
    author_email='asciimoo@gmail.com',
    packages=find_packages(),
    install_requires=install_requires,
    entry_points={
        'console_scripts': [
            'vutr = vutr.__main__:cli',
        ],
    })
