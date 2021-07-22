#!/usr/bin/env python3
from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import ElysiumTestFramework
from test_framework.util import (
    assert_equal,
    connect_nodes_bi,
    start_node,
    stop_node,
    sync_blocks,
    assert_raises_message,
    bitcoind_processes)

import os
from shutil import rmtree

class ElysiumRecoverLelantusMintTest(ElysiumTestFramework):
    def get_datadir(self, node):
        return os.path.join(self.options.tmpdir, f"node{node}", "regtest")

    def get_walletfile(self, node):
        datadir = self.get_datadir(node)
        return os.path.join(datadir, "wallet.dat")

    def load_wallet_content(self, node):
        with open(self.get_walletfile(node), mode='rb') as f:
            return f.read()

    def clear_datadir(self, node):
        datadir = self.get_datadir(node)
        rmtree(datadir)
        os.mkdir(datadir)

    def connect_to_other(self, node):
        for i in range(len(self.nodes)):
            if i != node:
                connect_nodes_bi(self.nodes, node, i)

    def run_test(self):
        super().run_test()

        # Initialize node 0 with a mnemonic

        mnemonic = 'produce sign mass upper inner atom carbon return drip usual fringe toward enable cause load team lamp outdoor nest curious brass cover smart snack'

        stop_node(self.nodes[0], 0)
        self.clear_datadir(0)

        self.nodes[0] = start_node(0, self.options.tmpdir, ['-elysium', '-usemnemonic=1', f'-mnemonic={mnemonic}'])
        connect_nodes_bi(self.nodes, 0, 1)
        connect_nodes_bi(self.nodes, 0, 2)

        sync_blocks(self.nodes)

        addr = self.nodes[0].getnewaddress()

        remaining = 1000 - self.nodes[0].getblockcount()
        while remaining > 0:
            # Generate in blocks of 10 so we don't run into timeout issues.
            self.nodes[0].generatetoaddress(min(10, remaining), addr)
            remaining -= 10

        self.nodes[0].elysium_sendissuancefixed(addr, 1, 1, 0, '', '', 'Lelantus', '', '', '1000000', 1)
        self.nodes[0].generate(1)

        lelantus_property = 3

        self.nodes[0].elysium_sendlelantusmint(addr, lelantus_property, "100000")
        self.nodes[0].elysium_sendlelantusmint(addr, lelantus_property, "10")
        self.nodes[0].mintlelantus(2)
        self.nodes[0].mintlelantus(2)
        self.nodes[0].generate(2)

        for i in range(1, 30):
            self.nodes[0].elysium_sendlelantusspend(addr, lelantus_property, f'{i}')
            self.nodes[0].generate(2)

        expected_mints = self.nodes[0].elysium_listlelantusmints()
        assert_equal(100000 + 10 - sum(range(1, 30)), sum((int(m['value']) for m in expected_mints)))

        # Delete the old node and create a new one with the same mnemonic.

        stop_node(self.nodes[0], 0)
        self.clear_datadir(0)

        self.nodes[0] = start_node(0, self.options.tmpdir, ['-elysium', '-usemnemonic=1', f'-mnemonic={mnemonic}'])
        connect_nodes_bi(self.nodes, 0, 1)
        connect_nodes_bi(self.nodes, 0, 2)

        sync_blocks(self.nodes, timeout=1000)

        # Encrypt the wallet so we can test the behaviour of elysium_recoverlelantusmints with a passphrase.

        passphrase = 'abc123'
        self.nodes[0].encryptwallet(passphrase)
        bitcoind_processes[0].wait()

        self.nodes[0] = start_node(0, self.options.tmpdir, ['-elysium'])
        connect_nodes_bi(self.nodes, 0, 1)
        connect_nodes_bi(self.nodes, 0, 2)

        assert_raises_message(
            JSONRPCException,
            'Error: require passphrase to unlock wallet',
            self.nodes[0].elysium_recoverlelantusmints
        )

        assert_raises_message(
            JSONRPCException,
            'Error: The wallet passphrase entered was incorrect.',
            self.nodes[0].elysium_recoverlelantusmints, 'wrong passphrase'
        )

        self.nodes[0].elysium_recoverlelantusmints(passphrase)

        mints = self.nodes[0].elysium_listlelantusmints(lelantus_property)
        assert_equal([m['value'] for m in expected_mints].sort(), [m['value'] for m in mints].sort())

if __name__ == '__main__':
    ElysiumRecoverLelantusMintTest().main()