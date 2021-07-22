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

class ElysiumSendLelantusMintTest(ElysiumTestFramework):
    def run_test(self):
        super().run_test()

        lelantus_starting_block = 1000
        remaining = lelantus_starting_block - self.nodes[0].getblockcount()
        while remaining > 0:
            # Generate in blocks of 10 so we don't run into timeout issues.
            self.nodes[0].generatetoaddress(min(10, remaining), self.addrs[0])
            remaining -= 10

        # create non-lelantus
        self.nodes[0].elysium_sendissuancefixed(
            self.addrs[0], 1, 1, 0, '', '', 'Non-lelantus', '', '', '1000000'
        )
        self.nodes[0].generate(1)
        non_lelantus_property = 3

        # create lelantus
        self.nodes[0].elysium_sendissuancefixed(
            self.addrs[0], 1, 1, 0, '', '', 'Lelantus', '', '', '1000000', 1
        )

        self.nodes[0].generate(1)
        lelantus_property = 4

        # create one more divisible
        self.nodes[0].elysium_sendissuancefixed(
            self.addrs[0], 1, 2, 0, '', '', 'Lelantus2', '', '', '1000000.00000', 1
        )

        self.nodes[0].generate(1)
        lelantus_property_2 = 5

        # non-lelantus
        addr = self.nodes[0].getnewaddress()
        self.nodes[0].elysium_send(self.addrs[0], addr, non_lelantus_property, "100")
        self.nodes[0].sendtoaddress(addr, 100)
        self.nodes[0].generate(1)

        assert_raises_message(
            JSONRPCException,
            'Property has not enabled Lelantus',
            self.nodes[0].elysium_sendlelantusmint, addr, non_lelantus_property, "10"
        )

        assert_equal("100", self.nodes[0].elysium_getbalance(addr, non_lelantus_property)['balance'])

        # lelantus
        # mint without firo and token
        addr = self.nodes[0].getnewaddress()
        assert_raises_message(
            JSONRPCException,
            'Sender has insufficient balance',
            self.nodes[0].elysium_sendlelantusmint, addr, lelantus_property, "10"
        )

        # mint without firo then fail
        addr = self.nodes[0].getnewaddress()
        self.nodes[0].elysium_send(self.addrs[0], addr, lelantus_property, "100")
        self.nodes[0].generate(1)

        assert_raises_message(
            JSONRPCException,
            'Error choosing inputs for the send transaction',
            self.nodes[0].elysium_sendlelantusmint, addr, lelantus_property, "10"
        )

        assert_equal("100", self.nodes[0].elysium_getbalance(addr, lelantus_property)['balance'])
        assert_equal(0, len(self.nodes[0].elysium_listpendinglelantusmints()))

        # mint without token then fail
        addr = self.nodes[0].getnewaddress()
        self.nodes[0].sendtoaddress(addr, 100)
        self.nodes[0].generate(1)

        assert_raises_message(
            JSONRPCException,
            'Sender has insufficient balance',
            self.nodes[0].elysium_sendlelantusmint, addr, lelantus_property, "10"
        )

        assert_equal("0", self.nodes[0].elysium_getbalance(addr, lelantus_property)['balance'])
        assert_equal(0, len(self.nodes[0].elysium_listpendinglelantusmints()))

        # success to mint should be shown on pending
        addr = self.nodes[0].getnewaddress()

        self.nodes[0].elysium_send(self.addrs[0], addr, lelantus_property, "100")
        for _ in range(0, 100):
            self.nodes[0].sendtoaddress(addr, 1)
        self.nodes[0].generate(10)

        self.nodes[0].elysium_sendlelantusmint(addr, lelantus_property, "10")
        self.nodes[0].elysium_sendlelantusmint(addr, lelantus_property, "11")

        assert_equal(2, len(self.nodes[0].elysium_listpendinglelantusmints()))
        assert_equal("79", self.nodes[0].elysium_getbalance(addr, lelantus_property)['balance'])

        self.nodes[0].generate(2)
        assert_equal(0, len(self.nodes[0].elysium_listpendinglelantusmints()))
        assert_equal(2, len(self.nodes[0].elysium_listlelantusmints()))

        # mint other asset
        addr2 = self.nodes[0].getnewaddress()
        self.nodes[0].elysium_send(self.addrs[0], addr2, lelantus_property_2, "100")

        for _ in range(0, 100):
            self.nodes[0].sendtoaddress(addr2, 1)
        self.nodes[0].generate(1)

        self.nodes[0].elysium_sendlelantusmint(addr2, lelantus_property_2, "10.10")
        self.nodes[0].elysium_sendlelantusmint(addr2, lelantus_property_2, "10.20")

        assert_equal(2, len(self.nodes[0].elysium_listpendinglelantusmints()))
        assert_equal("79.7", self.nodes[0].elysium_getbalance(addr2, lelantus_property_2)['balance'].rstrip('0'))

        self.nodes[0].generate(2)
        assert_equal(0, len(self.nodes[0].elysium_listpendinglelantusmints()))
        assert_equal(4, len(self.nodes[0].elysium_listlelantusmints()))

        mints = self.nodes[0].elysium_listlelantusmints()
        prop_mints = [m for m in mints if m['propertyid'] == lelantus_property]
        prop_mints_amount = [m['value'] for m in prop_mints]
        prop_mints_amount.sort()
        assert_equal(['10', '11'], prop_mints_amount)

        prop2_mints = [m for m in mints if m['propertyid'] == lelantus_property_2]
        prop2_mints_amount = [m['value'].rstrip('0') for m in prop2_mints]
        prop2_mints_amount.sort()
        assert_equal(['10.1', '10.2'], prop2_mints_amount)

        # lock wallet mints should still there
        passphrase = '1234'
        self.nodes[0].encryptwallet(passphrase)

        bitcoind_processes[0].wait()
        self.nodes[0] = start_node(0, self.options.tmpdir, ['-elysium'])

        assert_equal(0, len(self.nodes[0].elysium_listpendinglelantusmints()))
        assert_equal(4, len(self.nodes[0].elysium_listlelantusmints()))

        assert_raises_message(
            JSONRPCException,
            'Wallet locked, unable to create transaction!',
            self.nodes[0].elysium_sendlelantusmint, addr, lelantus_property, "5"
        )

        assert_raises_message(
            JSONRPCException,
            'Wallet locked, unable to create transaction!',
            self.nodes[0].elysium_sendlelantusmint, addr2, lelantus_property_2, "5"
        )
        self.nodes[0].walletpassphrase(passphrase, 20)

        self.nodes[0].sendtoaddress(addr, 1)
        self.nodes[0].generate(1)

        self.nodes[0].elysium_sendlelantusmint(addr, lelantus_property, "5")
        self.nodes[0].elysium_sendlelantusmint(addr, lelantus_property, "6")

        self.nodes[0].elysium_sendlelantusmint(addr2, lelantus_property_2, "5.1")
        self.nodes[0].elysium_sendlelantusmint(addr2, lelantus_property_2, "5.2")

        assert_equal(4, len(self.nodes[0].elysium_listpendinglelantusmints()))

        self.nodes[0].generate(10)
        mints = self.nodes[0].elysium_listlelantusmints()
        assert_equal(8, len(mints))

        assert_equal("68", self.nodes[0].elysium_getbalance(addr, lelantus_property)['balance'])
        assert_equal("69.4", self.nodes[0].elysium_getbalance(addr2, lelantus_property_2)['balance'].rstrip('0'))

        prop_mints = [m for m in mints if m['propertyid'] == lelantus_property]
        prop_mints_amount = [m['value'] for m in prop_mints]
        prop_mints_amount.sort()
        assert_equal(['10', '11', '5', '6'], prop_mints_amount)

        prop2_mints = [m for m in mints if m['propertyid'] == lelantus_property_2]
        prop2_mints_amount = [m['value'].rstrip('0') for m in prop2_mints]
        prop2_mints_amount.sort()
        assert_equal(['10.1', '10.2', '5.1', '5.2'], prop2_mints_amount)

if __name__ == '__main__':
    ElysiumSendLelantusMintTest().main()