#!/usr/bin/env python3

import os
from pathlib import Path
from setuptools import setup

ROOT_DIR = Path(os.path.join(os.path.dirname(__file__)))
PACKAGE_VERSION = f'{0}.{1}.{0}'


def readme():
    with open(ROOT_DIR.joinpath('README.md'), 'r', encoding='utf-8') as f:
        return f.read()


if __name__ == '__main__':
    setup(
        name='scapy-gptp',
        version=PACKAGE_VERSION,
        packages=["gptp"],
        install_requires=['setuptools', 'scapy[basic]'],
        # url='https://www.esrlabs.com',
        author='Christoph Weinsheimer',
        author_email='christoph.weinsheimer@esrlabs.com',
        description='scapy layer definition and tools for GPTP (IEEE 802.1as)',
        long_description=readme(),
        long_description_content_type='text/markdown',
        classifiers=[
            'Programming Language :: Python :: 3.7',
        ],
        python_requires='>=3.7',
        keywords=['esrlabs', 'gptp', 'scapy'],
        # project_urls={
        #     'Source': 'https://gerrit.int.esrlabs.com/#/admin/projects/tools/homebrew/t32',
        # },
    )
