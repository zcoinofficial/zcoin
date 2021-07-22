#!/usr/bin/env python3
import os
from shutil import rmtree
from test_framework.test_framework import ElysiumTestFramework
from test_framework.util import (
    assert_equal,
    start_nodes,
    sync_blocks)

# This test ensures that a new serial number will be used when one with the same one is already on the blockchain. This
# is needed to (mostly) ensure user funds are safe when using multiple wallets. (Simultaneous transactions will still
# cause issues, however.)
class ElysiumMultipleWalletsTest(ElysiumTestFramework):
    def setup_nodes(self):
        mnemonic = 'produce sign mass upper inner atom carbon return drip usual fringe toward enable cause load team lamp outdoor nest curious brass cover smart snack'
        return start_nodes(self.num_nodes, self.options.tmpdir, [['-elysium', '-debug=1', '-usemnemonic=1', f'-mnemonic=${mnemonic}'] for _ in range(self.num_nodes)])

    def run_test(self):
        super().run_test()

        owner = self.addrs[0]
        receiver = self.addrs[1]

        lelantus_start_block = 1000
        remaining = lelantus_start_block - self.nodes[0].getblockcount()
        while remaining > 0:
            # Generate in blocks of 10 so we don't run into timeout issues.
            self.nodes[0].generatetoaddress(min(10, remaining), owner)
            remaining -= 10

        sync_blocks(self.nodes, timeout=1000)

        self.nodes[0].elysium_sendissuancefixed(owner, 1, 1, 0, '', '', 'Test Lelantus', '', '', '1000', 1)
        self.nodes[0].generate(1)

        prop = 3

        sync_blocks(self.nodes)

        addrs = [n.getnewaddress() for n in self.nodes]

        for i in range(len(self.nodes)):
            self.nodes[0].sendtoaddress(addrs[i], 1)
            self.nodes[0].elysium_send(owner, addrs[i], prop, '2')

        self.nodes[0].generate(1)
        sync_blocks(self.nodes)

        for i in range(len(self.nodes)):
            self.nodes[i].mintlelantus(1)
            self.nodes[i].elysium_sendlelantusmint(addrs[i], prop, '1')
            self.nodes[i].generate(1)
            sync_blocks(self.nodes)

        self.nodes[0].generate(1)
        sync_blocks(self.nodes)

        for i in range(len(self.nodes)):
            self.nodes[i].elysium_sendlelantusspend(receiver, prop, '1')
            self.nodes[i].generate(1)
            sync_blocks(self.nodes)

        # Assert that all the funds have successfully reached their destination.
        assert_equal(len(self.nodes), int(self.nodes[0].elysium_getbalance(receiver, prop)['balance']))


if __name__ == '__main__':
    ElysiumMultipleWalletsTest().main()
