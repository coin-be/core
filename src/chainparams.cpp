// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "consensus/merkle.h"

#include "tinyformat.h"
#include "util.h"
#include "utilstrencodings.h"

#include <assert.h>

#include <boost/assign/list_of.hpp>

#include "chainparamsseeds.h"
#include "arith_uint256.h"

using namespace std;

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    // Genesis block

    // MainNet:

    //CBlock(hash=000001faef25dec4fbcf906e6242621df2c183bf232f263d0ba5b101911e4563, ver=1, hashPrevBlock=0000000000000000000000000000000000000000000000000000000000000000, hashMerkleRoot=12630d16a97f24b287c8c2594dda5fb98c9e6c70fc61d44191931ea2aa08dc90, nTime=1621478713, nBits=1e0fffff, nNonce=3188481, vtx=1, vchBlockSig=)
    //  Coinbase(hash=12630d16a9, nTime=1621478713, ver=1, vin.size=1, vout.size=1, nLockTime=0)
    //    CTxIn(COutPoint(0000000000, 4294967295), coinbase 00012a24323020466562203230313420426974636f696e2041544d7320636f6d6520746f20555341)
    //    CTxOut(empty)
    //  vMerkleTree: 12630d16a9

    // TestNet:

    //CBlock(hash=0000724595fb3b9609d441cbfb9577615c292abf07d996d3edabc48de843642d, ver=1, hashPrevBlock=0000000000000000000000000000000000000000000000000000000000000000, hashMerkleRoot=12630d16a97f24b287c8c2594dda5fb98c9e6c70fc61d44191931ea2aa08dc90, nTime=1621478713, nBits=1f00ffff, nNonce=30544, vtx=1, vchBlockSig=)
    //  Coinbase(hash=12630d16a9, nTime=1621478713, ver=1, vin.size=1, vout.size=1, nLockTime=0)
    //    CTxIn(COutPoint(0000000000, 4294967295), coinbase 00012a24323020466562203230313420426974636f696e2041544d7320636f6d6520746f20555341)
    //    CTxOut(empty)
    //  vMerkleTree: 12630d16a9

    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.nTime = nTime;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 0 << CScriptNum(42) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(txNew);
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "20 05 21";
    const CScript genesisOutputScript = CScript() << ParseHex("0451254161f306ff390a273516b8f6b4a9cc20c73df59e38ec6d8d6e2c8462afab3f0cdc913c6951cf887cfbb09f63383b90b2f7165ab9dd5f60de73ff1e767ab2") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */

class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        consensus.nMaxReorganizationDepth = 500;
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 1000;
        consensus.powLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.posLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.posLimitV2 = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nTargetTimespan =  10 * 60;
        consensus.nTargetSpacingV1 = 5 * 60;
        consensus.nTargetSpacing = 5 * 60;
        consensus.BIP34Height = -1;
        consensus.BIP34Hash = uint256();
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.fPoSNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 2; // 95% of 2
        consensus.nMinerConfirmationWindow = 2; // nTargetTimespan / nTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        /*
        Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 999999999999ULL; // never
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 0; // out of time
        */

        consensus.nProtocolV1RetargetingFixedTime = 1621478713;
        consensus.nProtocolV2Time = 1621478714;
        consensus.nProtocolV3Time = 1621478715;
        consensus.nLastPOWBlock = 1000000;
        consensus.nStakeTimestampMask = 0xf; // 15
        consensus.nCoinbaseMaturity = 20;
        consensus.nStakeMinAge = 8 * 60 * 60; // 8 hours

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000000000000100001");

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xe2;
        pchMessageStart[1] = 0x95;
        pchMessageStart[2] = 0x67;
        pchMessageStart[3] = 0x02;
        nDefaultPort = 35812;
        nPruneAfterHeight = 100000;

        genesis = CreateGenesisBlock(1621478713, 3188481, 0x1e0fffff, 1, 0);
        consensus.hashGenesisBlock = genesis.GetHash();
        // calculate main genesis block
        //consensus.hashGenesisBlock = uint256S("0x00");
        if (true && (genesis.GetHash() != consensus.hashGenesisBlock)) {
		std::cout << std::string("Calculating main genesis block...\n");
            arith_uint256 hashTarget = arith_uint256().SetCompact(genesis.nBits);
            uint256 hash;
            genesis.nNonce = 0;
            while (UintToArith256(genesis.GetHash()) > hashTarget)
            {
                ++genesis.nNonce;
                if (genesis.nNonce == 0)
                {
                    ++genesis.nTime;
                }
            }
            std::cout << "Genesis block found!\n";
            std::cout << "nonce: " << genesis.nNonce << "\n";
            std::cout << "time: " << genesis.nTime << "\n";
            std::cout << "blockhash: " << genesis.GetHash().ToString().c_str() << "\n";
            std::cout << "merklehash: " << genesis.hashMerkleRoot.ToString().c_str() << "\n";
        }
        assert(consensus.hashGenesisBlock == uint256S("0x000002bccc32338b564453d13d5959308b587c2dfa2e14c8c74dc18958a1be5b"));
        assert(genesis.hashMerkleRoot == uint256S("0x72160d70b4a4d1994693b8e00fafdbc6ec66aced2d99c6943619a5e70d0bde59"));

        vSeeds.push_back(CDNSSeedData("179.185.69.86", "179.185.69.86"));

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,29);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,28);
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1,156);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x88)(0xB2)(0x1E).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x88)(0xAD)(0xE4).convert_to_container<std::vector<unsigned char> >();
        cashaddrPrefix = "coinbe";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = false;

        checkpointData = (CCheckpointData) {
                    boost::assign::map_list_of
                    (0, uint256S("0x000002bccc32338b564453d13d5959308b587c2dfa2e14c8c74dc18958a1be5b")),
                    1621478713, // * UNIX timestamp of last checkpoint block
                    0,    // * total number of transactions between genesis and last checkpoint
                                //   (the tx=... number in the SetBestChain debug.log lines)
                    0      // * estimated number of transactions per day after checkpoint
        };
    }
};
static CMainParams mainParams;

/**
 * Testnet
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        consensus.nMaxReorganizationDepth = 500;
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 1000;
        consensus.powLimit = uint256S("0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.posLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.posLimitV2 = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nTargetTimespan =  10 * 60;
        consensus.nTargetSpacingV1 = 5 * 60;
        consensus.nTargetSpacing = 5 * 60;
        consensus.BIP34Height = -1;
        consensus.BIP34Hash = uint256();
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.fPoSNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
        consensus.nMinerConfirmationWindow = 2; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        consensus.nProtocolV1RetargetingFixedTime = 1621478713;
        consensus.nProtocolV2Time = 1621478714;
        consensus.nProtocolV3Time = 1621478715;
        consensus.nLastPOWBlock = 0x7fffffff;
        consensus.nStakeTimestampMask = 0xf;
        consensus.nCoinbaseMaturity = 10;
        consensus.nStakeMinAge = 8 * 60 * 60;

        pchMessageStart[0] = 0x7f;
        pchMessageStart[1] = 0x90;
        pchMessageStart[2] = 0xfb;
        pchMessageStart[3] = 0x67;
        nDefaultPort = 45812;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0000000000000000000000000000000000000000000000000000000000100001");

        /*
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 999999999999ULL; // never
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 0; // out of time
        */

        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(1621478713, 30544, 0x1f00ffff, 1, 0);
        consensus.hashGenesisBlock = genesis.GetHash();
        // calculate testnet genesis block
        //consensus.hashGenesisBlock = uint256S("0x00");
        if (true && (genesis.GetHash() != consensus.hashGenesisBlock)) {
		std::cout << std::string("Calculating testnet genesis block...\n");
            arith_uint256 hashTarget = arith_uint256().SetCompact(genesis.nBits);
            uint256 hash;
            genesis.nNonce = 0;
            while (UintToArith256(genesis.GetHash()) > hashTarget)
            {
                ++genesis.nNonce;
                if (genesis.nNonce == 0)
                {
                    ++genesis.nTime;
                }
            }
            std::cout << "Genesis block found!\n";
            std::cout << "nonce: " << genesis.nNonce << "\n";
            std::cout << "time: " << genesis.nTime << "\n";
            std::cout << "blockhash: " << genesis.GetHash().ToString().c_str() << "\n";
            std::cout << "merklehash: " << genesis.hashMerkleRoot.ToString().c_str() << "\n";
        }
        assert(consensus.hashGenesisBlock == uint256S("0x00002adbe0d15b1a083a7d3b1d7c17f6d516f4536dfdf88601609c3befb2465d"));
        assert(genesis.hashMerkleRoot == uint256S("0x72160d70b4a4d1994693b8e00fafdbc6ec66aced2d99c6943619a5e70d0bde59"));

        vFixedSeeds.clear();
        vSeeds.clear();

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,26);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,25);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();
        cashaddrPrefix = "cnbetest";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = true;

        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
            ( 0, uint256S("0x00002adbe0d15b1a083a7d3b1d7c17f6d516f4536dfdf88601609c3befb2465d")),
            1621478713,
            0,
            0
        };

    }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        consensus.nMaxReorganizationDepth = 50;
        consensus.nMajorityEnforceBlockUpgrade = 51;
        consensus.nMajorityRejectBlockOutdated = 75;
        consensus.nMajorityWindow = 100;
        consensus.powLimit = uint256S("0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.posLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.posLimitV2 = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nTargetTimespan =  10 * 60;
        consensus.nTargetSpacingV1 = 64;
        consensus.nTargetSpacing = 5 * 60;
        consensus.BIP34Height = -1; // BIP34 has not necessarily activated on regtest
        consensus.BIP34Hash = uint256();
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.fPoSNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 108;// 75% for regtest
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        /*
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 999999999999ULL; // never
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 0; // out of time
        */

        consensus.nProtocolV1RetargetingFixedTime = 1621478713;
        consensus.nProtocolV2Time = 1621478714;
        consensus.nProtocolV3Time = 1621478715;
        consensus.nLastPOWBlock = 1000;
        consensus.nStakeTimestampMask = 0xf;
        consensus.nCoinbaseMaturity = 10;
        consensus.nStakeMinAge = 1 * 60 * 60;

        pchMessageStart[0] = 0xe2;
        pchMessageStart[1] = 0x95;
        pchMessageStart[2] = 0x67;
        pchMessageStart[3] = 0x06;
        nDefaultPort = 35714;
        nPruneAfterHeight = 100000;

        genesis = CreateGenesisBlock(1621478713, 30544, 0x1f00ffff, 1, 0);
        consensus.hashGenesisBlock = genesis.GetHash();
        // calculate testnet genesis block
        //consensus.hashGenesisBlock = uint256S("0x00");
        if (true && (genesis.GetHash() != consensus.hashGenesisBlock)) {
		std::cout << std::string("Calculating testnet genesis block...\n");
            arith_uint256 hashTarget = arith_uint256().SetCompact(genesis.nBits);
            uint256 hash;
            genesis.nNonce = 0;
            while (UintToArith256(genesis.GetHash()) > hashTarget)
            {
                ++genesis.nNonce;
                if (genesis.nNonce == 0)
                {
                    ++genesis.nTime;
                }
            }
            std::cout << "Genesis block found!\n";
            std::cout << "nonce: " << genesis.nNonce << "\n";
            std::cout << "time: " << genesis.nTime << "\n";
            std::cout << "blockhash: " << genesis.GetHash().ToString().c_str() << "\n";
            std::cout << "merklehash: " << genesis.hashMerkleRoot.ToString().c_str() << "\n";
        }
        assert(consensus.hashGenesisBlock == uint256S("0x00002adbe0d15b1a083a7d3b1d7c17f6d516f4536dfdf88601609c3befb2465d"));
        assert(genesis.hashMerkleRoot == uint256S("0x72160d70b4a4d1994693b8e00fafdbc6ec66aced2d99c6943619a5e70d0bde59"));

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,26);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,25);
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1,153);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x88)(0xB2)(0x1E).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x88)(0xAD)(0xE4).convert_to_container<std::vector<unsigned char> >();
        cashaddrPrefix = "cnbereg";

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;
        fTestnetToBeDeprecatedFieldRPC = false;

    }

    void UpdateBIP9Parameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
    {
        consensus.vDeployments[d].nStartTime = nStartTime;
        consensus.vDeployments[d].nTimeout = nTimeout;
    }
};
static CRegTestParams regTestParams;

static CChainParams *pCurrentParams = 0;

const CChainParams &Params() {
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams& Params(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
            return mainParams;
    else if (chain == CBaseChainParams::TESTNET)
            return testNetParams;
    else if (chain == CBaseChainParams::REGTEST)
            return regTestParams;
    else
        throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    pCurrentParams = &Params(network);
}

void UpdateRegtestBIP9Parameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    regTestParams.UpdateBIP9Parameters(d, nStartTime, nTimeout);
}
