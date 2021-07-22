#include "params.h"
#include "chainparams.h"
#include <iostream>
namespace lelantus {

    CCriticalSection Params::cs_instance;
    std::unique_ptr<Params> Params::instance;
#ifdef ENABLE_ELYSIUM
    std::unique_ptr<Params> Params::elysium_instance;
#endif

Params const* Params::get_default() {
    if (instance) {
        return instance.get();
    } else {
        LOCK(cs_instance);
        if (instance) {
            return instance.get();
        }

        //fixing generator G;
        GroupElement g;
        if (!(::Params().GetConsensus().IsTestnet())) {
            unsigned char buff[32] = {0};
            GroupElement base;
            base.set_base_g();
            base.normalSha256(buff);
            g.generate(buff);
        }
        else
            g = GroupElement("9216064434961179932092223867844635691966339998754536116709681652691785432045",
                             "33986433546870000256104618635743654523665060392313886665479090285075695067131");


        //fixing n and m; N = n^m = 65,536
        int n = 16;
        int m = 4;

        //fixing bulletproof params
        int n_rangeProof = 64;
        int max_m_rangeProof = 16;

        instance.reset(new Params(g, n, m, n_rangeProof, max_m_rangeProof, ::Params().GetConsensus().nMaxValueLelantusMint));
        return instance.get();
    }
}

#ifdef ENABLE_ELYSIUM
Params const* Params::get_elysium() {
    if (elysium_instance) {
        return elysium_instance.get();
    } else {
        LOCK(cs_instance); // it's fine to reuse the lock from get_default
        if (elysium_instance) {
            return elysium_instance.get();
        }

        //fixing generator G;
        GroupElement g;
        if (!(::Params().GetConsensus().IsTestnet())) {
            unsigned char buff[32] = {0};
            GroupElement base;
            base.set_base_g();
            base.normalSha256(buff);
            g.generate(buff);
        }
        else
            g = GroupElement("9216064434961179932092223867844635691966339998754536116709681652691785432045",
                             "33986433546870000256104618635743654523665060392313886665479090285075695067131");


        //fixing n and m; N = n^m = 65,536
        int n = 16;
        int m = 4;

        //fixing bulletproof params
        int n_rangeProof = 64;
        int max_m_rangeProof = 16;

        elysium_instance.reset(new Params(g, n, m, n_rangeProof, max_m_rangeProof, INT64_MAX));
        return elysium_instance.get();
    }
}
#endif // ENABLE_ELYSIUM

Params::Params(const GroupElement& g_, int n_sigma_, int m_sigma_, int n_rangeProof_, int max_m_rangeProof_, int64_t n_max_value_mint):
    g(g_),
    n_sigma(n_sigma_),
    m_sigma(m_sigma_),
    n_rangeProof(n_rangeProof_),
    max_m_rangeProof(max_m_rangeProof_)
{

    //creating generators for sigma
    this->h_sigma.resize(n_sigma * m_sigma);
    unsigned char buff0[32] = {0};
    g.normalSha256(buff0);
    h_sigma[0].generate(buff0);
    for (int i = 1; i < n_sigma * m_sigma; ++i)
    {
        unsigned char buff[32] = {0};
        h_sigma[i - 1].normalSha256(buff);
        h_sigma[i].generate(buff);
    }

    //creating generators for bulletproofs
    g_rangeProof.resize(n_rangeProof * max_m_rangeProof);
    h_rangeProof.resize(n_rangeProof * max_m_rangeProof);
    g_rangeProof[0].generate(buff0);
    unsigned char buff1[32] = {0};
    g_rangeProof[0].normalSha256(buff1);
    h_rangeProof[0].generate(buff1);
    for (int i = 1; i < n_rangeProof * max_m_rangeProof; ++i)
    {
        unsigned char buff[32] = {0};
        h_rangeProof[i-1].normalSha256(buff);
        g_rangeProof[i].generate(buff);
        unsigned char buff2[32] = {0};
        g_rangeProof[i].normalSha256(buff2);
        h_rangeProof[i].generate(buff2);
    }

    limit_range = Scalar(uint64_t(2)).exponent(get_bulletproofs_n()) - n_max_value_mint;
    h1_limit_range = get_h1() * limit_range;
}

const GroupElement& Params::get_g() const {
    return g;
}

const GroupElement& Params::get_h0() const {
    return h_sigma[0];
}

const GroupElement& Params::get_h1() const {
    return h_sigma[1];
}

const std::vector<GroupElement>& Params::get_sigma_h() const {
    return h_sigma;
}

const std::vector<GroupElement>& Params::get_bulletproofs_g() const {
    return g_rangeProof;
}
const std::vector<GroupElement>& Params::get_bulletproofs_h() const {
    return h_rangeProof;
}

int Params::get_sigma_n() const {
    return n_sigma;
}

int Params::get_sigma_m() const {
    return m_sigma;
}

int Params::get_bulletproofs_n() const {
    return n_rangeProof;
}

int Params::get_bulletproofs_max_m() const {
    return max_m_rangeProof;
}

const Scalar& Params::get_limit_range() const {
    return limit_range;
}

const GroupElement& Params::get_h1_limit_range() const {
    return h1_limit_range;
}

} //namespace lelantus
