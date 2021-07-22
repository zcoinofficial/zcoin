#!/usr/bin/env python3
from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import ElysiumTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_message,
    bitcoind_processes,
    connect_nodes_bi,
    start_node,
)
import time

class ElysiumSendSpendTest(ElysiumTestFramework):
    def run_test(self):
        super().run_test()

        lelantus_starting_block = 1000
        remaining = lelantus_starting_block - self.nodes[0].getblockcount()
        while remaining > 0:
            # Generate in blocks of 10 so we don't run into timeout issues.
            self.nodes[0].generatetoaddress(min(10, remaining), self.addrs[0])
            remaining -= 10

        self.sync_all()

        assert_equal(lelantus_starting_block, self.nodes[0].getblockcount())

        # non-lelantus
        self.nodes[0].elysium_sendissuancefixed(self.addrs[0], 1, 1, 0, 'main', \
            'indivisible', 'non-lelantus', '', '', '1000000')
        self.nodes[0].generate(1)

        non_lelantus_property = 3

        addr = self.nodes[1].getnewaddress()
        self.nodes[0].elysium_send(self.addrs[0], addr, non_lelantus_property, '100')
        self.nodes[0].generate(1)

        self.sync_all()

        assert_raises_message(
            JSONRPCException,
            'Property has not enabled Lelantus',
            self.nodes[1].elysium_sendlelantusspend, self.addrs[1], non_lelantus_property, "10"
        )

        self.nodes[0].elysium_sendissuancefixed(self.addrs[0], 1, 1, 0, 'main', \
            'indivisible', 'foo', '', '', '1000000', 1)
        self.nodes[0].generate(1)

        lelantus_property = 4

        addr = self.nodes[1].getnewaddress()
        self.nodes[0].elysium_send(self.addrs[0], addr, lelantus_property, '100')

        self.nodes[0].generate(1)
        self.sync_all()

        # spend without any mint
        assert_raises_message(
            JSONRPCException,
            'Insufficient funds',
            self.nodes[1].elysium_sendlelantusspend, self.addrs[1], lelantus_property, '100'
        )

        # have lelantus mint but have no elysium mint
        testing_node = self.nodes[1] # fresh node
        addr = testing_node.getnewaddress()
        self.nodes[0].sendtoaddress(addr, '100')
        self.nodes[0].generate(1)
        self.sync_all()

        testing_node.mintlelantus(2)
        self.nodes[0].generate(2)
        self.sync_all()

        assert_raises_message(
            JSONRPCException,
            'Insufficient funds',
            testing_node.elysium_sendlelantusspend, self.addrs[1], lelantus_property, '100'
        )

        # have elysium mint have no lelantus mint to spend
        testing_node = self.nodes[2] # fresh node
        addr = testing_node.getnewaddress()
        for _ in range(0, 10):
            self.nodes[0].sendtoaddress(addr, '1')
        self.nodes[0].elysium_send(self.addrs[0], addr, lelantus_property, '100')
        self.nodes[0].generate(2)
        self.sync_all()

        testing_node.elysium_sendlelantusmint(addr, lelantus_property, '10')
        testing_node.elysium_sendlelantusmint(addr, lelantus_property, '10')
        testing_node.generate(1)
        self.sync_all()
        time.sleep(1)

        assert_raises_message(
            JSONRPCException,
            'Error no lelantus mints to pay as transaction fee',
            self.nodes[2].elysium_sendlelantusspend, self.addrs[0], lelantus_property, '10'
        )

        # met all requirements
        for _ in range(0, 10):
            testing_node.mintlelantus(1)

        testing_node.generate(2)
        self.sync_all()

        receiver = self.nodes[0].getnewaddress()

        testing_node.elysium_sendlelantusspend(receiver, lelantus_property, '1')
        testing_node.elysium_sendlelantusspend(receiver, lelantus_property, '1')

        testing_node.generate(1)
        self.sync_all()

        assert_equal('2', self.nodes[0].elysium_getbalance(receiver, lelantus_property)['balance'])

        assert_raises_message(
            JSONRPCException,
            'Insufficient funds',
            testing_node.elysium_sendlelantusspend, receiver, lelantus_property, '19'
        )

        testing_node.elysium_sendlelantusspend(receiver, lelantus_property, '16')

        testing_node.generate(2)
        self.sync_all()
        assert_equal('18', self.nodes[0].elysium_getbalance(receiver, lelantus_property)['balance'])

        expected_num_mints = len(testing_node.elysium_listlelantusmints(lelantus_property, True))
        assert(expected_num_mints > 0)

        # encrypt wallet
        passphrase = '1234'
        testing_node.encryptwallet(passphrase)

        bitcoind_processes[2].wait()
        testing_node = self.nodes[2] = start_node(2, self.options.tmpdir, ['-elysium'])

        connect_nodes_bi(self.nodes, 0, 2)
        connect_nodes_bi(self.nodes, 1, 2)
        connect_nodes_bi(self.nodes, 2, 3)

        # mint still there
        mints = testing_node.elysium_listlelantusmints(lelantus_property, True)
        assert_equal(expected_num_mints, len(mints))

        assert_raises_message(
            JSONRPCException,
            'Unable to retrieve generated key for mint seed. Is the wallet locked?',
            testing_node.elysium_sendlelantusspend, receiver, lelantus_property, '2'
        )

        testing_node.walletpassphrase(passphrase, 2)
        testing_node.elysium_sendlelantusspend(receiver, lelantus_property, '2')

        testing_node.generate(2)
        time.sleep(2)

        assert_equal('20', self.nodes[0].elysium_getbalance(receiver, lelantus_property)['balance'])

        # try to mint on encrypted wallet
        time.sleep(2)
        assert_raises_message(
            JSONRPCException,
            'Wallet locked, unable to create transaction!',
            testing_node.elysium_sendlelantusmint, addr, lelantus_property, '10'
        )

        mints = testing_node.elysium_listlelantusmints(lelantus_property, True)
        assert_equal(0, len(mints))

        testing_node.walletpassphrase(passphrase, 2)
        testing_node.elysium_sendlelantusmint(addr, lelantus_property, '10')
        testing_node.elysium_sendlelantusmint(addr, lelantus_property, '10')

        testing_node.generate(2)
        self.sync_all()

        mints = testing_node.elysium_listlelantusmints(lelantus_property, True)
        assert_equal(2, len(mints))

        time.sleep(2)
        assert_raises_message(
            JSONRPCException,
            'Unable to retrieve generated key for mint seed. Is the wallet locked?',
            testing_node.elysium_sendlelantusspend, receiver, lelantus_property, '15'
        )

        testing_node.walletpassphrase(passphrase, 2)
        testing_node.elysium_sendlelantusspend(receiver, lelantus_property, '15')
        testing_node.generate(2)
        self.sync_all()

        assert_equal('35', self.nodes[0].elysium_getbalance(receiver, lelantus_property)['balance'])

        # try to spend on divisible asset
        self.nodes[0].elysium_sendissuancefixed(self.addrs[0], 1, 2, 0, 'main', \
            'divisible', 'foo', '', '', '1000000', 1)
        self.nodes[0].generate(1)

        lelantus_property_2 = 5

        self.nodes[0].elysium_send(self.addrs[0], addr, lelantus_property_2, '100000')
        self.nodes[0].generate(1)
        self.sync_all()

        testing_node.walletpassphrase(passphrase, 10)

        testing_node.elysium_sendlelantusmint(addr, lelantus_property_2, '5002')

        testing_node.elysium_sendlelantusmint(addr, lelantus_property_2, '4010.5')
        testing_node.elysium_sendlelantusmint(addr, lelantus_property_2, '4010.5')
        testing_node.generate(2)
        self.sync_all()

        testing_node.elysium_sendlelantusspend(receiver, lelantus_property_2, '5002')
        testing_node.generate(1)
        self.sync_all()

        assert_equal(5002, float(testing_node.elysium_getbalance(receiver, lelantus_property_2)['balance']))
        testing_node.elysium_sendlelantusspend(receiver, lelantus_property_2, '15.5')
        testing_node.generate(1)
        self.sync_all()

        assert_equal('5017.5', testing_node.elysium_getbalance(receiver, lelantus_property_2)['balance'].rstrip('0'))

if __name__ == '__main__':
    ElysiumSendSpendTest().main()
