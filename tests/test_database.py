import unittest

from upmonitor.database import Database

class TestDatabase(unittest.TestCase):
    def testBasics(self):
        database = Database(['One', 'Two', 'Three'])
        self.assertEqual(database.to_dict(), {
            'One': {'Two': {}, 'Three': {}},
            'Two': {'One': {}, 'Three': {}},
            'Three': {'One': {}, 'Two': {}}
            })

        database['One']['Two'].update_one(10, 'foo', 'bar')
        self.assertEqual(database.to_dict(), {
            'One': {'Two': {'foo': (10, 'bar')}, 'Three': {}},
            'Two': {'One': {}, 'Three': {}},
            'Three': {'One': {}, 'Two': {}}
            })
        self.assertRaises(AssertionError,  database['One']['Two'].update_one,
                9, 'foo', 'baz')
        self.assertEqual(database.to_dict(), {
            'One': {'Two': {'foo': (10, 'bar')}, 'Three': {}},
            'Two': {'One': {}, 'Three': {}},
            'Three': {'One': {}, 'Two': {}}
            })
        database['One']['Two'].update_one(11, 'foo', 'qux')
        self.assertEqual(database.to_dict(), {
            'One': {'Two': {'foo': (11, 'qux')}, 'Three': {}},
            'Two': {'One': {}, 'Three': {}},
            'Three': {'One': {}, 'Two': {}}
            })

    def testNetworkUpdate(self):
        database = Database(['One', 'Two', 'Three'])
        self.assertEqual(database.to_dict(), {
            'One': {'Two': {}, 'Three': {}},
            'Two': {'One': {}, 'Three': {}},
            'Three': {'One': {}, 'Two': {}}
            })

        database['One']['Two'].update_one(10, 'foo', 'bar')

        self.assertEqual(
            database.update_from_dict({'Two': {'One': {'baz': (5, 'qux')}}}),
            ({'Two': {'One': {'baz': None}}},
             {'Two': {'One': {'baz': (5, 'qux')}}})
            )
        self.assertEqual(
            database.update_from_dict({'Two': {'One': {'baz': (6, 'quux')}}}),
            ({'Two': {'One': {'baz': (5, 'qux')}}},
             {'Two': {'One': {'baz': (6, 'quux')}}})
            )
        self.assertEqual(
            database.update_from_dict({'Two': {'One': {'baz': (4, 'corge')}}}),
            ({}, {})
            )
