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

# 0 for soft disabled, 1 for soft enabled, 2 for hard disabled, 3 for hard enabled
LELANTUS_STATUS = 'lelantusstatus'
SOFT_DISABLED = 0
SOFT_ENABLED = 1
HARD_DISABLED = 2
HARD_ENABLED = 3

STATUS_MAP = {
    SOFT_DISABLED : 'SoftDisabled',
    SOFT_ENABLED : 'SoftEnabled',
    HARD_DISABLED : 'HardDisabled',
    HARD_ENABLED : 'HardEnabled',
}

def status_str(status):
    if status not in STATUS_MAP:
        return 'Unknown'

    return STATUS_MAP[status]

class ElysiumLelantusStatusTest(ElysiumTestFramework):
    def new_property(self, name = 'default', status = None):
        before_properties = set([p['propertyid'] for p in self.nodes[0].elysium_listproperties()])

        args = [self.addrs[0], 1, 1, 0, '', '', 'Pre-lelantus', '', '', '1000000']
        if status is not None:
            args.append(status)

        self.nodes[0].elysium_sendissuancefixed(*args)
        self.nodes[0].generate(1)

        after_properties = set([p['propertyid'] for p in self.nodes[0].elysium_listproperties()])
        diff = after_properties - before_properties

        if len(diff) != 1:
            raise Exception(f'Expect just one new property but got {len(diff)}')

        return list(diff)[0]


    def verify_property(self, property, expected):
        sp = self.nodes[0].elysium_getproperty(property)

        for k in expected:
            if k not in sp:
                raise Exception(f'There is no {k} in property data {sp}')
            assert_equal(expected[k], sp[k])

    def update_status(self, property, status, expected_error = None, submit = True, addr = None):
        if addr is None:
            addr = self.addrs[0]

        args = [addr, property, status]

        if expected_error is None:
            return self.nodes[0].elysium_sendchangelelantusstatus(self.addrs[0], property, status)
        else:
            assert_raises_message(JSONRPCException, expected_error, self.nodes[0].elysium_sendchangelelantusstatus, *args)

    def update_many_times(self, statuses, start = None, expected_error = None):
        p = self.new_property(status = start)
        if start is not None:
            self.verify_property(p, {LELANTUS_STATUS: status_str(start)})

        last = None
        if expected_error is not None:
            last = statuses[len(statuses) - 1]
            statuses = statuses[:len(statuses) - 1]

        for s in statuses:
            self.update_status(p, s)
            self.nodes[0].generate(1)
            self.verify_property(p, {LELANTUS_STATUS: status_str(s)})

        if last is not None:
            self.update_status(p, last, expected_error = expected_error)

    def run_test(self):
        super().run_test()

        addr = self.addrs[0]
        node = self.nodes[0]

        remaining = 200 - self.nodes[0].getblockcount()
        while remaining > 0:
            # Generate in blocks of 10 so we don't run into timeout issues.
            self.nodes[0].generatetoaddress(min(10, remaining), addr)
            remaining -= 10

        pre_lelantus = self.new_property()

        self.verify_property(pre_lelantus, {LELANTUS_STATUS: status_str(SOFT_DISABLED)})
        self.update_status(pre_lelantus, SOFT_DISABLED, expected_error='Lelantus feature is not activated yet')

        lelantus_start_block = 1000
        remaining = lelantus_start_block - self.nodes[0].getblockcount()
        while remaining > 0:
            # Generate in blocks of 10 so we don't run into timeout issues.
            self.nodes[0].generatetoaddress(min(10, remaining), addr)
            remaining -= 10

        # update after lelantus activation, should work
        lelantus1 = self.new_property()
        self.verify_property(lelantus1, {LELANTUS_STATUS: status_str(SOFT_DISABLED)})

        self.update_status(lelantus1, SOFT_ENABLED)
        node.generate(1)

        self.verify_property(lelantus1, {LELANTUS_STATUS: status_str(SOFT_ENABLED)})

        # verify status can be changed from soft to other but can not be changed from hard (on rpc level)
        self.update_many_times([SOFT_DISABLED, SOFT_ENABLED, SOFT_DISABLED, HARD_DISABLED, SOFT_DISABLED], \
            expected_error='The property is not allowed to update lelantus status')

        self.update_many_times([SOFT_DISABLED, SOFT_ENABLED, SOFT_DISABLED, HARD_ENABLED, SOFT_DISABLED], \
            expected_error='The property is not allowed to update lelantus status')

        self.update_many_times([SOFT_DISABLED], start=HARD_ENABLED, \
            expected_error='The property is not allowed to update lelantus status')

        self.update_many_times([SOFT_DISABLED], start=HARD_DISABLED, \
            expected_error='The property is not allowed to update lelantus status')

        # verify on consensus level
        property = self.new_property()
        tx = self.update_status(property, SOFT_ENABLED)
        raw = node.getrawtransaction(tx)
        node.clearmempool()

        self.update_status(property, HARD_ENABLED)
        node.generate(1)
        self.verify_property(property, {LELANTUS_STATUS: status_str(HARD_ENABLED)})

        node.sendrawtransaction(raw)
        node.generate(1)
        self.verify_property(property, {LELANTUS_STATUS: status_str(HARD_ENABLED)})

        # verify the transaction is on chain
        detail = node.getrawtransaction(tx, True)
        assert('height' in detail)

if __name__ == '__main__':
    ElysiumLelantusStatusTest().main()