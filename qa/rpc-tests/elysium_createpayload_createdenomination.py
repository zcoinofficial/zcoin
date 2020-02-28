#!/usr/bin/env python3
from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import ElysiumTestFramework
from test_framework.util import assert_equal, assert_raises_message

class ElysiumCreatePayloadCreateDenominationTest(ElysiumTestFramework):
    def run_test(self):
        super().run_test()
        super().generate_until_sigma_activated(self.nodes[0])

        existed_denom = "1"

        sigma_propid = super().create_default_property("Sigma", self.nodes[0], self.addrs[0], sigma = True, amount = "1000000")
        self.nodes[0].elysium_sendcreatedenomination(self.addrs[0], sigma_propid, existed_denom)
        self.nodes[0].generate(10)

        nonsigma_propid = super().create_default_property("Non Sigma", self.nodes[0], self.addrs[0], sigma = False, amount = "1000000")

        # create payload for non-sigma property should throw
        assert_raises_message(
            JSONRPCException,
            'Property has not enabled Sigma',
            self.nodes[0].elysium_createpayload_createdenomination, nonsigma_propid, "1"
        )

        # create payload for non-exist property should throw
        assert_raises_message(
            JSONRPCException,
            'Property identifier does not exist',
            self.nodes[0].elysium_createpayload_createdenomination, 99, "1"
        )

        # create payload with duplicated denom should throw
        assert_raises_message(
            JSONRPCException,
            'already exists',
            self.nodes[0].elysium_createpayload_createdenomination, sigma_propid, existed_denom
        )

        # success create payload
        payload = self.nodes[0].elysium_createpayload_createdenomination(sigma_propid, "2")
        hex_prop = "%08x" % sigma_propid
        raw = f"00000401{hex_prop}0000000000000002"

        assert_equal(raw, payload)

if __name__ == '__main__':
    ElysiumCreatePayloadCreateDenominationTest().main()
