#!/usr/bin/env python3

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

load = unittest.defaultTestLoader.loadTestsFromModule

suites = []
dirname = os.path.dirname(__file__)
sys.path.append(dirname)
filenames = os.listdir(dirname)
for filename in filenames:
    if filename.startswith('test_') and filename.endswith('.py'):
        name = filename[:-3]
        plugin = __import__(name)
        suites.append(load(plugin))

if __name__ == '__main__':
    suite = unittest.TestSuite(suites)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    if result.wasSuccessful():
        sys.exit(0)
    else:
        sys.exit(1)
