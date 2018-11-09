	// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "pow.h"

#include "arith_uint256.h"
#include "chain.h"
#include "chainparams.h"
#include "crypto/equihash.h"
#include "primitives/block.h"
#include "streams.h"
#include "uint256.h"
#include "util.h"


const CBlockIndex* GetLastBlockIndex(const CBlockIndex* pindex, bool fProofOfStake, const Consensus::Params& params)
{
    while (pindex && pindex->pprev && (pindex->IsProofOfStake() != fProofOfStake))
    {
    	if(fProofOfStake)
    	{
    		if(pindex->nHeight <=params.LTEHeight+ params.LTEPremineWindow)
				return NULL;
    	}
        pindex = pindex->pprev;
    }
    return pindex;
}



unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    assert(pindexLast != nullptr);
    int nHeight = pindexLast->nHeight + 1;
    bool postfork = nHeight >= params.LTEHeight;
    unsigned int nProofOfWorkLimit = UintToArith256(params.powLimit).GetCompact();
    
    // Genesis block
    if (pindexLast == NULL)
        return nProofOfWorkLimit;
    
    if (postfork == false) {
        return BitcoinGetNextWorkRequired(pindexLast, pblock, params);
    }
    else if (postfork && (nHeight < (params.LTEHeight + params.LTEPremineWindow))) {
        return nProofOfWorkLimit;
    }
    else if (postfork && (nHeight < (params.LTEHeight + params.LTEPremineWindow + params.nPowAveragingWindow))){
        return UintToArith256(params.powLimitStart).GetCompact();
    }
	if(pblock->IsProofOfStake() && nHeight >(params.LTEHeight + params.LTEPremineWindow + params.nPowAveragingWindow))
	{
	  return PosGetNextTargetRequired(pindexLast,pblock,params);
	}
    const CBlockIndex* pindexFirst = pindexLast;
    arith_uint256 bnTot {0};
    for (int i = 0; pindexFirst && i < params.nPowAveragingWindow; ) {
		if(pindexFirst->IsProofOfStake())
		{
			pindexFirst = pindexFirst->pprev;
			continue;
		}
        arith_uint256 bnTmp;
        bnTmp.SetCompact(pindexFirst->nBits);
        bnTot += bnTmp;
        pindexFirst = pindexFirst->pprev;
		++i;
    }
    
    if (pindexFirst == NULL)
        return nProofOfWorkLimit;
    
    arith_uint256 bnAvg {bnTot / params.nPowAveragingWindow};
    

    return CalculateNextWorkRequired(bnAvg, pindexLast->GetMedianTimePast(), pindexFirst->GetMedianTimePast(), params);
}
unsigned int PosGetNextTargetRequired(const CBlockIndex* pindexLast,  const CBlockHeader *pblock, const Consensus::Params& params)
{
	bool fProofOfStake = pblock->IsProofOfStake();
	assert(fProofOfStake == true);
    unsigned int bnTargetLimitnBits = UintToArith256(params.posLimit).GetCompact() ;

	// for two mistake POS blocks 
	// block height 1358191 (5ccd2a2789273b9334fffe6b8cadf5b858ce95fc598fcf31e7ee86e460b29e65)
	// and block height 1358194 (25d25978d7f5a62441af14b76cf2a454c849f1d7f9c447f86cb29c40fe1f9ad9)
	if (pblock->GetHash() == uint256S("5ccd2a2789273b9334fffe6b8cadf5b858ce95fc598fcf31e7ee86e460b29e65") ||
		pblock->GetHash() == uint256S("25d25978d7f5a62441af14b76cf2a454c849f1d7f9c447f86cb29c40fe1f9ad9"))
		return 0x1e0fffff;

	
    if (pindexLast == NULL )
        //return bnTargetLimit.GetCompact(); // genesis block
        return bnTargetLimitnBits;

    const CBlockIndex* pindexPrev = GetLastBlockIndex(pindexLast, fProofOfStake,params);
	if(pindexPrev == NULL)
		return bnTargetLimitnBits;
    else
    {
        if(pindexPrev->nHeight >= params.LTEHeight && pindexPrev->nHeight < params.LTEFork1Height)
	    {
    	    if(pblock->nHeight >= params.LTEFork1Height)
        	    return bnTargetLimitnBits;
        }
    }
    
    if (pindexPrev->pprev == NULL)
        //return bnTargetLimit.GetCompact(); // first block
        return bnTargetLimitnBits;
    const CBlockIndex* pindexPrevPrev = GetLastBlockIndex(pindexPrev->pprev, fProofOfStake,params);
	if(pindexPrevPrev == NULL)
		return bnTargetLimitnBits;
    if (pindexPrevPrev->pprev == NULL)
        //return bnTargetLimit.GetCompact(); // second block
        return bnTargetLimitnBits;
    

    int64_t nTargetSpacing = params.nPowTargetSpacing;
    int64_t nActualSpacing = pindexPrev->GetBlockTime() - pindexPrevPrev->GetBlockTime();

 
    if (nActualSpacing > nTargetSpacing * 10)
        nActualSpacing = nTargetSpacing * 10;

    // ppcoin: target change every block
    // ppcoin: retarget with exponential moving toward target spacing
    arith_uint256 bnNew;
    bnNew.SetCompact(pindexPrev->nBits);
    int64_t nInterval = 20;
    bnNew *= ((nInterval - 1) * nTargetSpacing + nActualSpacing + nActualSpacing);
    bnNew /= ((nInterval + 1) * nTargetSpacing);

	arith_uint256 bnTargetLimit;
	bnTargetLimit.SetCompact(bnTargetLimitnBits);

    if (bnNew <= 0 || bnNew > bnTargetLimit)
        bnNew = bnTargetLimit;

    return bnNew.GetCompact();
}


// Depricated for Bitcoin Gold
unsigned int BitcoinGetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    assert(pindexLast != nullptr);
    unsigned int nProofOfWorkLimit = UintToArith256(params.powLimit).GetCompact();

    // Only change once per difficulty adjustment interval
    if ((pindexLast->nHeight+1) % params.DifficultyAdjustmentInterval() != 0)
    {
        if (params.fPowAllowMinDifficultyBlocks)
        {
            // Special difficulty rule for testnet:
            // If the new block's timestamp is more than 2* 10 minutes
            // then allow mining of a min-difficulty block.
            if (pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nPowTargetSpacing*2)
                return nProofOfWorkLimit;
            else
            {
                // Return the last non-special-min-difficulty-rules-block
                const CBlockIndex* pindex = pindexLast;
                while (pindex->pprev && pindex->nHeight % params.DifficultyAdjustmentInterval() != 0 && pindex->nBits == nProofOfWorkLimit)
                    pindex = pindex->pprev;
                return pindex->nBits;
            }
        }
        return pindexLast->nBits;
    }

    // Go back by what we want to be 14 days worth of blocks
    // Litecoin: This fixes an issue where a 51% attack can change difficulty at will.
    // Go back the full period unless it's the first retarget after genesis. Code courtesy of Art Forz
    int blockstogoback = params.DifficultyAdjustmentInterval()-1;
    if ((pindexLast->nHeight+1) != params.DifficultyAdjustmentInterval())
        blockstogoback = params.DifficultyAdjustmentInterval();

    // Go back by what we want to be 14 days worth of blocks
    const CBlockIndex* pindexFirst = pindexLast;
    for (int i = 0; pindexFirst && i < blockstogoback; i++)
        pindexFirst = pindexFirst->pprev;

    assert(pindexFirst);
    return BitcoinCalculateNextWorkRequired(pindexLast, pindexFirst->GetBlockTime(), params);
}

// Depricated for Bitcoin Gold
unsigned int BitcoinCalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params& params)
{
    if (params.fPowNoRetargeting)
        return pindexLast->nBits;

    // Limit adjustment step
    int64_t nActualTimespan = pindexLast->GetBlockTime() - nFirstBlockTime;
    if (nActualTimespan < params.nPowTargetTimespan/4)
        nActualTimespan = params.nPowTargetTimespan/4;
    if (nActualTimespan > params.nPowTargetTimespan*4)
        nActualTimespan = params.nPowTargetTimespan*4;

    // Retarget
    arith_uint256 bnNew;
    arith_uint256 bnOld;
    bnNew.SetCompact(pindexLast->nBits);
    bnOld = bnNew;
    // Litecoin: intermediate uint256 can overflow by 1 bit
    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);
    bool fShift = bnNew.bits() > bnPowLimit.bits() - 1;
    if (fShift)
        bnNew >>= 1;
    bnNew *= nActualTimespan;
    bnNew /= params.nPowTargetTimespan;
    if (fShift)
        bnNew <<= 1;

    if (bnNew > bnPowLimit)
        bnNew = bnPowLimit;

    return bnNew.GetCompact();
}

unsigned int CalculateNextWorkRequired(arith_uint256 bnAvg, int64_t nLastBlockTime, int64_t nFirstBlockTime, const Consensus::Params& params)
{
    
    // Limit adjustment
    int64_t nActualTimespan = nLastBlockTime - nFirstBlockTime;
    nActualTimespan = params.AveragingWindowTimespan() + (nActualTimespan - params.AveragingWindowTimespan())/4;
    
    if (nActualTimespan < params.MinActualTimespan())
        nActualTimespan = params.MinActualTimespan();
    if (nActualTimespan > params.MaxActualTimespan())
        nActualTimespan = params.MaxActualTimespan();

    // Retarget
    const arith_uint256 bnPowLimit = UintToArith256(params.powLimitStart);
    arith_uint256 bnNew {bnAvg};
    bnNew /= params.AveragingWindowTimespan();
    bnNew *= nActualTimespan;
    
    if (bnNew > bnPowLimit)
        bnNew = bnPowLimit;

    return bnNew.GetCompact();
}

bool CheckProofOfWork(uint256 hash, unsigned int nBits, bool postfork, const Consensus::Params& params)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(params.PowLimit(postfork)))
        return false;

    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget)
        return false;

    return true;
}


bool CheckEquihashSolution(const CBlockHeader *pblock, const CChainParams& params)
{
    unsigned int n = params.EquihashN();
    unsigned int k = params.EquihashK();

    // Hash state
    crypto_generichash_blake2b_state state;
    EhInitialiseState(n, k, state);

    // I = the block header minus nonce and solution.
    CEquihashInput I{*pblock};
    // I||V
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << I;
    ss << pblock->nNonce;

    // H(I||V||...
    crypto_generichash_blake2b_update(&state, (unsigned char*)&ss[0], ss.size());

    bool isValid;
    EhIsValidSolution(n, k, state, pblock->nSolution, isValid);
    if (!isValid)
        return error("CheckEquihashSolution(): invalid solution");

    return true;
}

