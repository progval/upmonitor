#!/usr/bin/env python3

from distutils.core import setup

setup(name='upmonitor',
      version='1.0',
      description='Decentralized monitoring.',
      author='Valentin Lorentz',
      author_email='progval@progval.net',
      url='https://github.com/ProgVal/upmonitor',
      packages=['upmonitor', 'upmonitor.plugins'],
      scripts=['upmonitor-node.py'],
     )
