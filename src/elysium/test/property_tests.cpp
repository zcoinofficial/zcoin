#include "../property.h"

#include <boost/test/unit_test.hpp>

#include <limits>
#include <type_traits>

namespace elysium {

BOOST_AUTO_TEST_SUITE(elysium_property_tests)

/*BOOST_AUTO_TEST_CASE(sigma_status_is_enabled_flag)
{
    typedef std::underlying_type<SigmaStatus>::type SigmaStatusBaseType;

    auto i = std::numeric_limits<SigmaStatusBaseType>::min();

    do {
        auto flag = static_cast<SigmaStatus>(i);
        auto res = IsEnabledFlag(flag);

        switch (flag) {
        case SigmaStatus::SoftEnabled:
        case SigmaStatus::HardEnabled:
            BOOST_CHECK_EQUAL(res, true);
            break;
        default:
            BOOST_CHECK_EQUAL(res, false);
        }
    } while (i++ == std::numeric_limits<SigmaStatusBaseType>::max());
}*/

BOOST_AUTO_TEST_SUITE_END()

}
