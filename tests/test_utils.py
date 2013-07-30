import unittest

from upmonitor import utils
from upmonitor.database import Database

class TestNetworkGraph(unittest.TestCase):
    def testBasics(self):
        hostnames = ['One', 'Two', 'Three', 'Four', 'Five', 'Six']
        database = Database(hostnames)
        for host1 in hostnames:
            for host2 in hostnames:
                if host1 != host2:
                    database[host1][host2].update_one(0, 'connected', False)
        database['One']['Two'].update_one(5, 'connected', True)
        database['Two']['One'].update_one(5, 'connected', True)
        database['Two']['Three'].update_one(5, 'connected', True)
        database['Three']['Two'].update_one(5, 'connected', True)
        database['Three']['One'].update_one(5, 'connected', True)
        database['One']['Three'].update_one(5, 'connected', True)
        database['One']['Four'].update_one(5, 'connected', True)
        database['Four']['One'].update_one(5, 'connected', True)
        database['Five']['Six'].update_one(5, 'connected', True)
        database['Six']['Five'].update_one(5, 'connected', True)

        #          One---Four      Five
        #          / \              |
        #         /   \             |
        #        /     \            |
        #       Two---Three        Six

        graph = utils.NetworkGraph(database)
        self.assertEqual(graph.get_reachable('One'),
            set(['One', 'Two', 'Three', 'Four']))
        self.assertEqual(graph.get_reachable('Four'),
            set(['One', 'Two', 'Three', 'Four']))
        self.assertEqual(graph.get_reachable('Five'),
            set(['Five', 'Six']))

        self.assertEqual(graph.get_routes('One', 'Two'),
            set([('One', 'Two'), ('One', 'Three', 'Two')]))
        self.assertEqual(graph.get_routes('One', 'Four'),
            set([('One', 'Four')]))
        self.assertEqual(graph.get_routes('Two', 'Four'),
            set([('Two', 'One', 'Four'), ('Two', 'Three', 'One', 'Four')]))
        self.assertEqual(graph.get_routes('Five', 'Six'),
            set([('Five', 'Six')]))
