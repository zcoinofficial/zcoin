#!/usr/bin/env python3
import os
from shutil import rmtree
from test_framework.test_framework import ElysiumTestFramework
from test_framework.util import (
    assert_equal,
    connect_nodes_bi,
    start_node,
    stop_node,
    sync_blocks)

class ElysiumWalletRecoveryTest(ElysiumTestFramework):
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
        # stop node and read wallet.dat
        stop_node(self.nodes[0], 0)
        fresh_wallet_content = self.load_wallet_content(0)

        self.nodes[0] = start_node(0, self.options.tmpdir, ["-elysium"])
        self.connect_to_other(0)

        super().run_test()

        # generate lelantus property
        owner = self.addrs[0]

        lelantus_start_block = 1000
        remaining = lelantus_start_block - self.nodes[0].getblockcount()
        while remaining > 0:
            # Generate in blocks of 10 so we don't run into timeout issues.
            self.nodes[0].generatetoaddress(min(10, remaining), owner)
            remaining -= 10

        self.nodes[0].elysium_sendissuancefixed(owner, 1, 1, 0, '', '', 'Test Lelantus', '', '', '6', 1)

        self.nodes[0].generate(1)
        prop = 3

        self.nodes[0].elysium_sendlelantusmint(owner, prop, '3')
        self.nodes[0].elysium_sendlelantusmint(owner, prop, '3')

        for _ in range(10):
            self.nodes[0].mintlelantus(1)

        self.nodes[0].generate(2)

        self.nodes[0].elysium_sendlelantusspend(owner, prop, '2')
        self.nodes[0].generate(2)

        sync_blocks(self.nodes)

        expected_num_mints = len(self.nodes[0].elysium_listlelantusmints())

        # stop, clear state and restore fresh wallet
        stop_node(self.nodes[0], 0)
        self.clear_datadir(0)

        walletfile = self.get_walletfile(0)
        with open(walletfile, 'wb+') as wf:
            wf.write(fresh_wallet_content)

        # start and sync
        self.nodes[0] = start_node(0, self.options.tmpdir, ["-elysium"])
        self.connect_to_other(0)

        sync_blocks(self.nodes, timeout=1000)
        self.nodes[0].elysium_recoverlelantusmints()

        # verify state
        unspents = self.nodes[0].elysium_listlelantusmints()
        assert_equal(expected_num_mints, len(unspents))
        assert_equal('2', self.nodes[0].elysium_getbalance(owner, prop)['balance'])

if __name__ == '__main__':
    ElysiumWalletRecoveryTest().main()
