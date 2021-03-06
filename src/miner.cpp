// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "miner.h"

#include "amount.h"
#include "chain.h"
#include "chainparams.h"
#include "coins.h"
#include "consensus/consensus.h"
#include "consensus/tx_verify.h"
#include "consensus/merkle.h"
#include "consensus/validation.h"
#include "hash.h"
#include "crypto/scrypt.h"
#include "validation.h"
#include "net.h"
#include "policy/feerate.h"
#include "policy/policy.h"
#include "pow.h"
#include "txdb.h"
#include "primitives/transaction.h"
#include "script/standard.h"
#include "timedata.h"
#include "txmempool.h"
#include "util.h"
#include "wallet/wallet.h"
#include "utilmoneystr.h"
#include "validationinterface.h"

#include <algorithm>
#include <queue>
#include <utility>

//////////////////////////////////////////////////////////////////////////////
//
// BitcoinMiner
//

//
// Unconfirmed transactions in the memory pool often depend on other
// transactions in the memory pool. When we select transactions from the
// pool, we select by highest fee rate of a transaction combined with all
// its ancestors.

uint64_t nLastBlockTx = 0;
uint64_t nLastBlockSize = 0;
uint64_t nLastBlockWeight = 0;

extern CAmount nMinimumInputValue;
extern CAmount nReserveBalance;
extern int nStakeMinConfirmations;

posState posstate;


static bool CheckKernel(CBlock* pblock, const COutPoint& prevout, CAmount amount);
//static bool CheckKernel(CBlock* pblock, const COutPoint& prevout, CAmount amount, int32_t utxoDepth);

int64_t UpdateTime(CBlockHeader* pblock, const Consensus::Params& consensusParams, const CBlockIndex* pindexPrev)
{
    int64_t nOldTime = pblock->nTime;
    int64_t nNewTime = std::max(pindexPrev->GetMedianTimePast()+1, GetAdjustedTime());

    if (nOldTime < nNewTime)
        pblock->nTime = nNewTime;

    // Updating time can change work required on testnet:
    if (consensusParams.fPowAllowMinDifficultyBlocks)
        pblock->nBits = GetNextWorkRequired(pindexPrev, pblock, consensusParams);

    return nNewTime - nOldTime;
}

BlockAssembler::Options::Options() {
    blockMinFeeRate = CFeeRate(DEFAULT_BLOCK_MIN_TX_FEE);
    nBlockMaxWeight = DEFAULT_BLOCK_MAX_WEIGHT;
    nBlockMaxSize = DEFAULT_BLOCK_MAX_SIZE;
}

BlockAssembler::BlockAssembler(const CChainParams& params, const Options& options) : chainparams(params)
{
    blockMinFeeRate = options.blockMinFeeRate;
    // Limit weight to between 4K and MAX_BLOCK_WEIGHT-4K for sanity:
    nBlockMaxWeight = std::max<size_t>(4000, std::min<size_t>(MAX_BLOCK_WEIGHT - 4000, options.nBlockMaxWeight));
    // Limit size to between 1K and MAX_BLOCK_SERIALIZED_SIZE-1K for sanity:
    nBlockMaxSize = std::max<size_t>(1000, std::min<size_t>(MAX_BLOCK_SERIALIZED_SIZE - 1000, options.nBlockMaxSize));
    // Whether we need to account for byte usage (in addition to weight usage)
    fNeedSizeAccounting = (nBlockMaxSize < MAX_BLOCK_SERIALIZED_SIZE - 1000);
}

static BlockAssembler::Options DefaultOptions(const CChainParams& params)
{
    // Block resource limits
    // If neither -blockmaxsize or -blockmaxweight is given, limit to DEFAULT_BLOCK_MAX_*
    // If only one is given, only restrict the specified resource.
    // If both are given, restrict both.
    BlockAssembler::Options options;
    options.nBlockMaxWeight = DEFAULT_BLOCK_MAX_WEIGHT;
    options.nBlockMaxSize = DEFAULT_BLOCK_MAX_SIZE;
    bool fWeightSet = false;
    if (gArgs.IsArgSet("-blockmaxweight")) {
        options.nBlockMaxWeight = gArgs.GetArg("-blockmaxweight", DEFAULT_BLOCK_MAX_WEIGHT);
        options.nBlockMaxSize = MAX_BLOCK_SERIALIZED_SIZE;
        fWeightSet = true;
    }
    if (gArgs.IsArgSet("-blockmaxsize")) {
        options.nBlockMaxSize = gArgs.GetArg("-blockmaxsize", DEFAULT_BLOCK_MAX_SIZE);
        if (!fWeightSet) {
            options.nBlockMaxWeight = options.nBlockMaxSize * WITNESS_SCALE_FACTOR;
        }
    }
    if (gArgs.IsArgSet("-blockmintxfee")) {
        CAmount n = 0;
        ParseMoney(gArgs.GetArg("-blockmintxfee", ""), n);
        options.blockMinFeeRate = CFeeRate(n);
    } else {
        options.blockMinFeeRate = CFeeRate(DEFAULT_BLOCK_MIN_TX_FEE);
    }
    return options;
}

BlockAssembler::BlockAssembler(const CChainParams& params) : BlockAssembler(params, DefaultOptions(params)) {}

void BlockAssembler::resetBlock()
{
    inBlock.clear();

    // Reserve space for coinbase tx
    nBlockSize = 1000;
    nBlockWeight = 4000;
    nBlockSigOpsCost = 400;
    fIncludeWitness = false;

    // These counters do not include coinbase tx
    nBlockTx = 0;
    nFees = 0;
}

std::unique_ptr<CBlockTemplate> BlockAssembler::CreateNewBlock(const CScript& scriptPubKeyIn, bool fMineWitnessTx)
{
    int64_t nTimeStart = GetTimeMicros();

    resetBlock();

    pblocktemplate.reset(new CBlockTemplate());

    if(!pblocktemplate.get())
        return nullptr;
    pblock = &pblocktemplate->block; // pointer for convenience

    // Add dummy coinbase tx as first transaction
    pblock->vtx.emplace_back();
    pblocktemplate->vTxFees.push_back(-1); // updated at end
    pblocktemplate->vTxSigOpsCost.push_back(-1); // updated at end

    LOCK2(cs_main, mempool.cs);
    CBlockIndex* pindexPrev = chainActive.Tip();
    nHeight = pindexPrev->nHeight + 1;

    pblock->nVersion = ComputeBlockVersion(pindexPrev, chainparams.GetConsensus(), MINING_TYPE_POW);
    // -regtest only: allow overriding block.nVersion with
    // -blockversion=N to test forking scenarios
    if (chainparams.MineBlocksOnDemand())
        pblock->nVersion = gArgs.GetArg("-blockversion", pblock->nVersion);

    pblock->nTime = GetAdjustedTime();
    const int64_t nMedianTimePast = pindexPrev->GetMedianTimePast();

    nLockTimeCutoff = (STANDARD_LOCKTIME_VERIFY_FLAGS & LOCKTIME_MEDIAN_TIME_PAST)
                       ? nMedianTimePast
                       : pblock->GetBlockTime();

    // Decide whether to include witness transactions
    // This is only needed in case the witness softfork activation is reverted
    // (which would require a very deep reorganization) or when
    // -promiscuousmempoolflags is used.
    // TODO: replace this with a call to main to assess validity of a mempool
    // transaction (which in most cases can be a no-op).
    fIncludeWitness = IsWitnessEnabled(pindexPrev, chainparams.GetConsensus()) && fMineWitnessTx;

    int nPackagesSelected = 0;
    int nDescendantsUpdated = 0;
    addPackageTxs(nPackagesSelected, nDescendantsUpdated);

    int64_t nTime1 = GetTimeMicros();

    nLastBlockTx = nBlockTx;
    nLastBlockSize = nBlockSize;
    nLastBlockWeight = nBlockWeight;

    // Create coinbase transaction.
    CMutableTransaction coinbaseTx;
    coinbaseTx.vin.resize(1);
    coinbaseTx.vin[0].prevout.SetNull();
    coinbaseTx.vout.resize(1);
    coinbaseTx.vout[0].scriptPubKey = scriptPubKeyIn;
    coinbaseTx.vout[0].nValue = nFees + GetBlockSubsidy(nHeight, chainparams.GetConsensus());
    coinbaseTx.vin[0].scriptSig = CScript() << nHeight << OP_0;
    pblock->vtx[0] = MakeTransactionRef(std::move(coinbaseTx));
    pblocktemplate->vchCoinbaseCommitment = GenerateCoinbaseCommitment(*pblock, pindexPrev, chainparams.GetConsensus());
    pblocktemplate->vTxFees[0] = -nFees;

    int ser_flags = (nHeight >= Params().GetConsensus().LTEHeight) ? SERIALIZE_BLOCK_LEGACY : 0;
    uint64_t nSerializeSize = GetSerializeSize(*pblock, SER_NETWORK, PROTOCOL_VERSION|ser_flags);
    LogPrintf("CreateNewBlock(): total size: %u block weight: %u txs: %u fees: %ld sigops %d\n", nSerializeSize, GetBlockWeight(*pblock), nBlockTx, nFees, nBlockSigOpsCost);

    arith_uint256 nonce;
    if (nHeight >= chainparams.GetConsensus().LTEHeight) {
        // Randomise nonce for new block foramt.
        nonce = UintToArith256(GetRandHash());
        // Clear the top and bottom 16 bits (for local use as thread flags and counters)
        nonce <<= 32;
        nonce >>= 16;
    }

    // Fill in header
    pblock->hashPrevBlock  = pindexPrev->GetBlockHash();
    pblock->nHeight        = pindexPrev->nHeight + 1;
    memset(pblock->nReserved, 0, sizeof(pblock->nReserved));
    UpdateTime(pblock, chainparams.GetConsensus(), pindexPrev);
    pblock->nBits          = GetNextWorkRequired(pindexPrev, pblock, chainparams.GetConsensus());
    pblock->nNonce         = ArithToUint256(nonce);
    pblock->nSolution.clear();
    pblocktemplate->vTxSigOpsCost[0] = WITNESS_SCALE_FACTOR * GetLegacySigOpCount(*pblock->vtx[0]);

    CValidationState state;
    if (!TestBlockValidity(state, chainparams, *pblock, pindexPrev, false, false)) {
        throw std::runtime_error(strprintf("%s: TestBlockValidity failed: %s", __func__, FormatStateMessage(state)));
    }
    int64_t nTime2 = GetTimeMicros();

    LogPrint(BCLog::BENCH, "CreateNewBlock() packages: %.2fms (%d packages, %d updated descendants), validity: %.2fms (total %.2fms)\n", 0.001 * (nTime1 - nTimeStart), nPackagesSelected, nDescendantsUpdated, 0.001 * (nTime2 - nTime1), 0.001 * (nTime2 - nTimeStart));

    return std::move(pblocktemplate);
}


std::unique_ptr<CBlockTemplate> BlockAssembler::CreateNewBlockPos(CWalletRef& pwallet, bool fMineWitnessTx)
{
    //int64_t nTimeStart = GetTimeMicros();

    resetBlock();

    pblocktemplate.reset(new CBlockTemplate());

    if(!pblocktemplate.get())
        return nullptr;
    pblock = &pblocktemplate->block; // pointer for convenience

    // Add dummy coinbase tx as first transaction
    pblock->vtx.emplace_back();
    pblocktemplate->vTxFees.push_back(-1); // updated at end
    pblocktemplate->vTxSigOpsCost.push_back(-1); // updated at end
    pblocktemplate->vTxSigOpsCost.push_back(-1);

    LOCK2(cs_main, mempool.cs);

    if (!EnsureWalletIsAvailable(pwallet, true))
        return nullptr;

    if(chainActive.Height()+1 <(Params().GetConsensus().LTEHeight+Params().GetConsensus().LTEPremineWindow+Params().GetConsensus().nPowAveragingWindow))
    	return nullptr;

    //std::shared_ptr<CReserveScript> coinbase_script;
    //pwallet->GetScriptForMining(coinbase_script);

    // If the keypool is exhausted, no script is returned at all.  Catch this.
    //if (!coinbase_script)
    //    return nullptr;	

    CBlockIndex* pindexPrev = chainActive.Tip();
    nHeight = pindexPrev->nHeight + 1;

    pblock->nVersion = ComputeBlockVersion(pindexPrev, chainparams.GetConsensus(), MINING_TYPE_POS);
    // -regtest only: allow overriding block.nVersion with
    // -blockversion=N to test forking scenarios
    if (chainparams.MineBlocksOnDemand())
        pblock->nVersion = gArgs.GetArg("-blockversion", pblock->nVersion);

    pblock->nTime = GetAdjustedTime();
    const int64_t nMedianTimePast = pindexPrev->GetMedianTimePast();

    nLockTimeCutoff = (STANDARD_LOCKTIME_VERIFY_FLAGS & LOCKTIME_MEDIAN_TIME_PAST)
                       ? nMedianTimePast
                       : pblock->GetBlockTime();

    // Decide whether to include witness transactions
    // This is only needed in case the witness softfork activation is reverted
    // (which would require a very deep reorganization) or when
    // -promiscuousmempoolflags is used.
    // TODO: replace this with a call to main to assess validity of a mempool
    // transaction (which in most cases can be a no-op).
    fIncludeWitness = IsWitnessEnabled(pindexPrev, chainparams.GetConsensus()) && fMineWitnessTx;

    //int64_t nTime1 = GetTimeMicros();

    nLastBlockTx = nBlockTx;
    nLastBlockSize = nBlockSize;
    nLastBlockWeight = nBlockWeight;

	/*
    // Create coinbase transaction.
    CMutableTransaction coinbaseTx;
    coinbaseTx.vin.resize(1);
    coinbaseTx.vin[0].prevout.SetNull();
    coinbaseTx.vout.resize(1);
	// reward to pos miner 1 coin 
    coinbaseTx.vout[0].nValue = nFees + GetBlockSubsidy(nHeight, chainparams.GetConsensus());
    coinbaseTx.vin[0].scriptSig = CScript() << nHeight << OP_0;
	// specify vout scriptpubkey of coinbase transaction (the first transaction)
	coinbaseTx.vout[0].scriptPubKey =  coinbase_script->reserveScript;
	
    pblock->vtx[0] = MakeTransactionRef(std::move(coinbaseTx));
    */
    
    pblocktemplate->vTxFees[0] = -nFees;

    //int ser_flags = (nHeight >= Params().GetConsensus().LTEHeight) ? SERIALIZE_BLOCK_LEGACY : 0;
    //uint64_t nSerializeSize = GetSerializeSize(*pblock, SER_NETWORK, PROTOCOL_VERSION|ser_flags);
    //LogPrintf("CreateNewBlockPos(): total size: %u block weight: %u txs: %u fees: %ld sigops %d\n", nSerializeSize, GetBlockWeight(*pblock), nBlockTx, nFees, nBlockSigOpsCost);

    // Fill in header
    pblock->hashPrevBlock  = pindexPrev->GetBlockHash();
    pblock->nHeight        = pindexPrev->nHeight + 1;
    UpdateTime(pblock, chainparams.GetConsensus(), pindexPrev);
    pblock->nBits          = GetNextWorkRequired(pindexPrev, pblock, chainparams.GetConsensus());
	arith_uint256 nonce(0);
    pblock->nNonce         = ArithToUint256(nonce);
    pblock->nSolution.clear();
    

    
    //int64_t nTime2 = GetTimeMicros();

    //LogPrint(BCLog::BENCH, "CreateNewBlockPOS() packages: %.2fms (%d packages, %d updated descendants), validity: %.2fms (total %.2fms)\n", 0.001 * (nTime1 - nTimeStart), nPackagesSelected, nDescendantsUpdated, 0.001 * (nTime2 - nTime1), 0.001 * (nTime2 - nTimeStart));

	// ExtraNonce
	/*
    int nExtraNonce = 1;
    CMutableTransaction txCoinbase(*pblock->vtx[0]);
    txCoinbase.vin[0].scriptSig = (CScript() << pblock->nHeight  << CScriptNum(nExtraNonce)) + COINBASE_FLAGS;
    assert(txCoinbase.vin[0].scriptSig.size() <= 100);

    pblock->vtx[0] = MakeTransactionRef(std::move(txCoinbase));
    */

	// Create coin stake
	CTransaction txCoinStake;
	txCoinStake.vin.clear();
	txCoinStake.vout.clear();
	// Mark coin stake transaction
    CScript scriptEmpty;
    scriptEmpty.clear();
    //txCoinStake.vout.push_back(CTxOut(0, scriptEmpty));
    posstate.numOfUtxo = 0;
    posstate.sumOfutxo = 0;

	// Choose coins to use
    CAmount nBalance = pwallet->GetBalance();
    if (nBalance <= nReserveBalance) {
    	//LogPrintf("CreateNewBlockPos(): nBalance not enough for POS, less than nReserveBalance\n");
        return nullptr;
    }

    std::set<std::pair<const CWalletTx*,unsigned int> > setCoins;
    int64_t nValueIn = 0;

    // Select coins with suitable depth
    if (!pwallet->SelectCoinsForStaking(nBalance - nReserveBalance, setCoins, nValueIn))
        return nullptr;
        
    posstate.numOfUtxo = setCoins.size();
    posstate.sumOfutxo = nValueIn;

    if (setCoins.empty())
        return nullptr;

	int64_t nCredit = 0;
	bool fKernelFound = false;
	CScript scriptPubKeyKernel;
	COutPoint prevoutFound;

	for (const auto& pcoin: setCoins) {
		COutPoint prevoutStake = COutPoint(pcoin.first->GetHash(), pcoin.second);

		Coin coinStake;
		if (!pcoinsTip->GetCoin(prevoutStake, coinStake)) {
			//return nullptr;
			continue;
		}	

		//CTxOut vout = pcoin.first->tx->vout[pcoin.second];
		//int nDepth = pcoin.first->GetDepthInMainChain();

		//if (CheckKernel(pblock, prevoutStake, vout.nValue, nDepth)) {
		if (CheckKernel(pblock, prevoutStake, coinStake.out.nValue)) {
            // Found a kernel
            LogPrintf("CreateCoinStake : kernel found\n");
            // Set prevoutFound
			prevoutFound = prevoutStake;
            std::vector<std::vector<unsigned char> > vSolutions;
            txnouttype whichType;
            CScript scriptPubKeyOut;
			//scriptPubKeyKernel = vout.scriptPubKey;
            scriptPubKeyKernel = coinStake.out.scriptPubKey;
            if (!Solver(scriptPubKeyKernel, whichType, vSolutions))  {
                LogPrintf("CreateNewBlockPos(): failed to parse kernel\n");
                break;
            }
            LogPrintf("CreateNewBlockPos(): parsed kernel type=%d\n", whichType);
            if (whichType != TX_PUBKEYHASH) {
                LogPrintf("CreateNewBlockPos(): no support for kernel type=%d\n", whichType);
                break;  
            }
            if (whichType == TX_PUBKEYHASH) {
				// use the same script pubkey
                scriptPubKeyOut = scriptPubKeyKernel;
            }

			// push empty vin
            txCoinStake.vin.push_back(CTxIn(prevoutStake));
            nCredit += coinStake.out.nValue;
            //nCredit += vout.nValue;
			// push empty vout
			CTxOut empty_txout = CTxOut();
			empty_txout.SetEmpty();
			txCoinStake.vout.push_back(empty_txout);
            txCoinStake.vout.push_back(CTxOut(nCredit, scriptPubKeyOut));

            LogPrintf("CreateNewBlockPos(): added kernel type=%d\n", whichType);
            fKernelFound = true;
            break;
        }
	}

	if (!fKernelFound)
		return nullptr;

    if (nCredit == 0 || nCredit > nBalance - nReserveBalance)
        return nullptr;
	txCoinStake.hash = txCoinStake.ComputeHash();

    // Create coinbase transaction.
    CMutableTransaction coinbaseTx;
    coinbaseTx.vin.resize(1);
    coinbaseTx.vin[0].prevout.SetNull();
    coinbaseTx.vout.resize(1);
	// reward to pos miner 1 coin 
    coinbaseTx.vout[0].nValue = nFees + GetBlockSubsidy(nHeight, chainparams.GetConsensus());
    coinbaseTx.vin[0].scriptSig = CScript() << nHeight << OP_0;
	// specify vout scriptpubkey of coinbase transaction (the first transaction)
	coinbaseTx.vout[0].scriptPubKey =  scriptPubKeyKernel;
    pblock->vtx[0] = MakeTransactionRef(std::move(coinbaseTx));

	// nExtraNonce
    int nExtraNonce = 1;
    CMutableTransaction txCoinbase(*pblock->vtx[0]);
    txCoinbase.vin[0].scriptSig = (CScript() << pblock->nHeight  << CScriptNum(nExtraNonce)) + COINBASE_FLAGS;
    assert(txCoinbase.vin[0].scriptSig.size() <= 100);
    pblock->vtx[0] = MakeTransactionRef(std::move(txCoinbase));

    int nPackagesSelected = 0;
    int nDescendantsUpdated = 0;
    addPackageTxs(nPackagesSelected, nDescendantsUpdated, prevoutFound);

	// insert CoinStake
	pblock->vtx.insert(pblock->vtx.begin() + 1, MakeTransactionRef(std::move(txCoinStake)));
    
	pblocktemplate->vTxSigOpsCost[0] = WITNESS_SCALE_FACTOR * GetLegacySigOpCount(*pblock->vtx[0]);
	pblocktemplate->vTxSigOpsCost[1] = WITNESS_SCALE_FACTOR * GetLegacySigOpCount(*pblock->vtx[1]);
	pblocktemplate->vchCoinbaseCommitment = GenerateCoinbaseCommitment(*pblock, pindexPrev, chainparams.GetConsensus());
	
	pblock->hashMerkleRoot = BlockMerkleRoot(*pblock);
	
	CValidationState state;
	if (!TestBlockValidity(state, chainparams, *pblock, pindexPrev, false, false)) {
		throw std::runtime_error(strprintf("%s: TestBlockValidity failed: %s", __func__, FormatStateMessage(state)));
	}

    return std::move(pblocktemplate);
}


void BlockAssembler::onlyUnconfirmed(CTxMemPool::setEntries& testSet)
{
    for (CTxMemPool::setEntries::iterator iit = testSet.begin(); iit != testSet.end(); ) {
        // Only test txs not already in the block
        if (inBlock.count(*iit)) {
            testSet.erase(iit++);
        }
        else {
            iit++;
        }
    }
}

bool BlockAssembler::TestPackage(uint64_t packageSize, int64_t packageSigOpsCost)
{
    // TODO: switch to weight-based accounting for packages instead of vsize-based accounting.
    if (nBlockWeight + WITNESS_SCALE_FACTOR * packageSize >= nBlockMaxWeight)
        return false;
    if (nBlockSigOpsCost + packageSigOpsCost >= MAX_BLOCK_SIGOPS_COST)
        return false;
    return true;
}

// Perform transaction-level checks before adding to block:
// - transaction finality (locktime)
// - premature witness (in case segwit transactions are added to mempool before
//   segwit activation)
// - serialized size (in case -blockmaxsize is in use)
bool BlockAssembler::TestPackageTransactions(const CTxMemPool::setEntries& package)
{
    uint64_t nPotentialBlockSize = nBlockSize; // only used with fNeedSizeAccounting
    for (const CTxMemPool::txiter it : package) {
        CValidationState state;
        if (!ContextualCheckTransaction(it->GetTx(), state,
                                        chainparams.GetConsensus(), nHeight,
                                        nLockTimeCutoff))
            return false;
        if (!fIncludeWitness && it->GetTx().HasWitness())
            return false;
        if (fNeedSizeAccounting) {
            uint64_t nTxSize = ::GetSerializeSize(it->GetTx(), SER_NETWORK, PROTOCOL_VERSION);
            if (nPotentialBlockSize + nTxSize >= nBlockMaxSize) {
                return false;
            }
            nPotentialBlockSize += nTxSize;
        }
    }
    return true;
}

void BlockAssembler::AddToBlock(CTxMemPool::txiter iter)
{
    pblock->vtx.emplace_back(iter->GetSharedTx());
    pblocktemplate->vTxFees.push_back(iter->GetFee());
    pblocktemplate->vTxSigOpsCost.push_back(iter->GetSigOpCost());
    if (fNeedSizeAccounting) {
        nBlockSize += ::GetSerializeSize(iter->GetTx(), SER_NETWORK, PROTOCOL_VERSION);
    }
    nBlockWeight += iter->GetTxWeight();
    ++nBlockTx;
    nBlockSigOpsCost += iter->GetSigOpCost();
    nFees += iter->GetFee();
    inBlock.insert(iter);

    bool fPrintPriority = gArgs.GetBoolArg("-printpriority", DEFAULT_PRINTPRIORITY);
    if (fPrintPriority) {
        LogPrintf("fee %s txid %s\n",
                  CFeeRate(iter->GetModifiedFee(), iter->GetTxSize()).ToString(),
                  iter->GetTx().GetHash().ToString());
    }
}

int BlockAssembler::UpdatePackagesForAdded(const CTxMemPool::setEntries& alreadyAdded,
        indexed_modified_transaction_set &mapModifiedTx)
{
    int nDescendantsUpdated = 0;
    for (const CTxMemPool::txiter it : alreadyAdded) {
        CTxMemPool::setEntries descendants;
        mempool.CalculateDescendants(it, descendants);
        // Insert all descendants (not yet in block) into the modified set
        for (CTxMemPool::txiter desc : descendants) {
            if (alreadyAdded.count(desc))
                continue;
            ++nDescendantsUpdated;
            modtxiter mit = mapModifiedTx.find(desc);
            if (mit == mapModifiedTx.end()) {
                CTxMemPoolModifiedEntry modEntry(desc);
                modEntry.nSizeWithAncestors -= it->GetTxSize();
                modEntry.nModFeesWithAncestors -= it->GetModifiedFee();
                modEntry.nSigOpCostWithAncestors -= it->GetSigOpCost();
                mapModifiedTx.insert(modEntry);
            } else {
                mapModifiedTx.modify(mit, update_for_parent_inclusion(it));
            }
        }
    }
    return nDescendantsUpdated;
}

// Skip entries in mapTx that are already in a block or are present
// in mapModifiedTx (which implies that the mapTx ancestor state is
// stale due to ancestor inclusion in the block)
// Also skip transactions that we've already failed to add. This can happen if
// we consider a transaction in mapModifiedTx and it fails: we can then
// potentially consider it again while walking mapTx.  It's currently
// guaranteed to fail again, but as a belt-and-suspenders check we put it in
// failedTx and avoid re-evaluation, since the re-evaluation would be using
// cached size/sigops/fee values that are not actually correct.
bool BlockAssembler::SkipMapTxEntry(CTxMemPool::txiter it, indexed_modified_transaction_set &mapModifiedTx, CTxMemPool::setEntries &failedTx)
{
    assert (it != mempool.mapTx.end());
    return mapModifiedTx.count(it) || inBlock.count(it) || failedTx.count(it);
}

void BlockAssembler::SortForBlock(const CTxMemPool::setEntries& package, CTxMemPool::txiter entry, std::vector<CTxMemPool::txiter>& sortedEntries)
{
    // Sort package by ancestor count
    // If a transaction A depends on transaction B, then A's ancestor count
    // must be greater than B's.  So this is sufficient to validly order the
    // transactions for block inclusion.
    sortedEntries.clear();
    sortedEntries.insert(sortedEntries.begin(), package.begin(), package.end());
    std::sort(sortedEntries.begin(), sortedEntries.end(), CompareTxIterByAncestorCount());
}

// This transaction selection algorithm orders the mempool based
// on feerate of a transaction including all unconfirmed ancestors.
// Since we don't remove transactions from the mempool as we select them
// for block inclusion, we need an alternate method of updating the feerate
// of a transaction with its not-yet-selected ancestors as we go.
// This is accomplished by walking the in-mempool descendants of selected
// transactions and storing a temporary modified state in mapModifiedTxs.
// Each time through the loop, we compare the best transaction in
// mapModifiedTxs with the next transaction in the mempool to decide what
// transaction package to work on next.
void BlockAssembler::addPackageTxs(int &nPackagesSelected, int &nDescendantsUpdated, const COutPoint& outpointPos)
{
    // mapModifiedTx will store sorted packages after they are modified
    // because some of their txs are already in the block
    indexed_modified_transaction_set mapModifiedTx;
    // Keep track of entries that failed inclusion, to avoid duplicate work
    CTxMemPool::setEntries failedTx;

    // Start by adding all descendants of previously added txs to mapModifiedTx
    // and modifying them for their already included ancestors
    UpdatePackagesForAdded(inBlock, mapModifiedTx);

    CTxMemPool::indexed_transaction_set::index<ancestor_score>::type::iterator mi = mempool.mapTx.get<ancestor_score>().begin();
    CTxMemPool::txiter iter;

    // Limit the number of attempts to add transactions to the block when it is
    // close to full; this is just a simple heuristic to finish quickly if the
    // mempool has a lot of entries.
    const int64_t MAX_CONSECUTIVE_FAILURES = 1000;
    int64_t nConsecutiveFailed = 0;

    while (mi != mempool.mapTx.get<ancestor_score>().end() || !mapModifiedTx.empty())
    {
        // First try to find a new transaction in mapTx to evaluate.
        if (mi != mempool.mapTx.get<ancestor_score>().end() &&
                SkipMapTxEntry(mempool.mapTx.project<0>(mi), mapModifiedTx, failedTx)) {
            ++mi;
            continue;
        }

        // Now that mi is not stale, determine which transaction to evaluate:
        // the next entry from mapTx, or the best from mapModifiedTx?
        bool fUsingModified = false;

        modtxscoreiter modit = mapModifiedTx.get<ancestor_score>().begin();
        if (mi == mempool.mapTx.get<ancestor_score>().end()) {
            // We're out of entries in mapTx; use the entry from mapModifiedTx
            iter = modit->iter;
            fUsingModified = true;
        } else {
            // Try to compare the mapTx entry to the mapModifiedTx entry
            iter = mempool.mapTx.project<0>(mi);
            if (modit != mapModifiedTx.get<ancestor_score>().end() &&
                    CompareModifiedEntry()(*modit, CTxMemPoolModifiedEntry(iter))) {
                // The best entry in mapModifiedTx has higher score
                // than the one from mapTx.
                // Switch which transaction (package) to consider
                iter = modit->iter;
                fUsingModified = true;
            } else {
                // Either no entry in mapModifiedTx, or it's worse than mapTx.
                // Increment mi for the next loop iteration.
                ++mi;
            }
        }

        // We skip mapTx entries that are inBlock, and mapModifiedTx shouldn't
        // contain anything that is inBlock.
        assert(!inBlock.count(iter));

        uint64_t packageSize = iter->GetSizeWithAncestors();
        CAmount packageFees = iter->GetModFeesWithAncestors();
        int64_t packageSigOpsCost = iter->GetSigOpCostWithAncestors();
        if (fUsingModified) {
            packageSize = modit->nSizeWithAncestors;
            packageFees = modit->nModFeesWithAncestors;
            packageSigOpsCost = modit->nSigOpCostWithAncestors;
        }

        if (packageFees < blockMinFeeRate.GetFee(packageSize)) {
            // Everything else we might consider has a lower fee rate
            return;
        }

        if (!TestPackage(packageSize, packageSigOpsCost)) {
            if (fUsingModified) {
                // Since we always look at the best entry in mapModifiedTx,
                // we must erase failed entries so that we can consider the
                // next best entry on the next loop iteration
                mapModifiedTx.get<ancestor_score>().erase(modit);
                failedTx.insert(iter);
            }

            ++nConsecutiveFailed;

            if (nConsecutiveFailed > MAX_CONSECUTIVE_FAILURES && nBlockWeight >
                    nBlockMaxWeight - 4000) {
                // Give up if we're close to full and haven't succeeded in a while
                break;
            }
            continue;
        }

        CTxMemPool::setEntries ancestors;
        uint64_t nNoLimit = std::numeric_limits<uint64_t>::max();
        std::string dummy;
        mempool.CalculateMemPoolAncestors(*iter, ancestors, nNoLimit, nNoLimit, nNoLimit, nNoLimit, dummy, false);

        onlyUnconfirmed(ancestors);
        ancestors.insert(iter);

        // Test if all tx's are Final
        if (!TestPackageTransactions(ancestors)) {
            if (fUsingModified) {
                mapModifiedTx.get<ancestor_score>().erase(modit);
                failedTx.insert(iter);
            }
            continue;
        }

        // This transaction will make it in; reset the failed counter.
        nConsecutiveFailed = 0;

        // Package can be added. Sort the entries in a valid order.
        std::vector<CTxMemPool::txiter> sortedEntries;
        SortForBlock(ancestors, iter, sortedEntries);

        for (size_t i=0; i<sortedEntries.size(); ++i) {
            const CTransaction& tx = sortedEntries[i]->GetTx();

			// check UTXO spent by pos mining
			bool spentByPos = false;
			if (outpointPos.n != uint32_t(-1)) 
			{
				for (const auto& vin : tx.vin) 
				{
					if (vin.prevout == outpointPos) 
					{
						spentByPos = true;
						break;
					}
				}
				
				if (spentByPos)
					continue;
			}
            AddToBlock(sortedEntries[i]);
            // Erase from the modified set, if present
            mapModifiedTx.erase(sortedEntries[i]);
        }

        ++nPackagesSelected;

        // Update transactions that depend on each of these
        nDescendantsUpdated += UpdatePackagesForAdded(ancestors, mapModifiedTx);
    }
}

void IncrementExtraNonce(CBlock* pblock, const CBlockIndex* pindexPrev, unsigned int& nExtraNonce)
{
    // Update nExtraNonce
    static uint256 hashPrevBlock;
    if (hashPrevBlock != pblock->hashPrevBlock)
    {
        nExtraNonce = 0;
        hashPrevBlock = pblock->hashPrevBlock;
    }
    ++nExtraNonce;
    unsigned int nHeight = pindexPrev->nHeight+1; // Height first in coinbase required for block.version=2
    CMutableTransaction txCoinbase(*pblock->vtx[0]);
    txCoinbase.vin[0].scriptSig = (CScript() << nHeight << CScriptNum(nExtraNonce)) + COINBASE_FLAGS;
    assert(txCoinbase.vin[0].scriptSig.size() <= 100);

    pblock->vtx[0] = MakeTransactionRef(std::move(txCoinbase));
    pblock->hashMerkleRoot = BlockMerkleRoot(*pblock);

}

bool CheckKernel(CBlock* pblock, const COutPoint& prevout, CAmount amount)
{
	Coin coinStake;
	if (!pcoinsTip->GetCoin(prevout, coinStake))
		return false;	

	int utxoHeight = coinStake.nHeight;
	
	if (utxoHeight > pblock->nHeight - nStakeMinConfirmations)
		return false;
		
    posstate.ifPos = 2;

    return CheckProofOfStake(pblock, prevout, amount, pblock->nHeight-utxoHeight);
}


/*
bool CheckKernel(CBlock* pblock, const COutPoint& prevout, CAmount amount, int32_t utxoDepth)
{	
	if (utxoDepth < nStakeMinConfirmations)
		return false;

    return CheckProofOfStake(pblock, prevout, amount);
}
*/

/*
bool CheckProofOfStake(CBlock* pblock, const COutPoint& prevout,  CAmount amount)
{
    // Base target
    arith_uint256 bnTarget;
    arith_uint256 bnTargetOld;
    bnTarget.SetCompact(pblock->nBits);

	// set MAX weight 10000.00000000
	if (amount > 10000 * COIN)
		amount = 10000 * COIN;

    // Weighted target
    bnTargetOld = bnTarget;
    bnTarget *= amount;
    if(bnTarget < bnTargetOld)
        return true;
    uint256 targetProofOfStake = ArithToUint256(bnTarget);

	uint256 targetOld = ArithToUint256(bnTargetOld);
	LogPrintf("CheckProofOfStake amount: %lld\n", amount);
	LogPrintf("CheckProofOfStake bnTargetOld: %s\n", targetOld.ToString().c_str());
	LogPrintf("CheckProofOfStake bnTarget: %s\n", targetProofOfStake.ToString().c_str());

    // Calculate hash
    CDataStream ss(SER_GETHASH, 0);
	ss << pblock->nHeight << prevout.hash << prevout.n;
	uint256	hashProofOfStake = Hash(ss.begin(), ss.end());

	LogPrintf("CheckProofOfStake hashProofOfStake: %s\n", hashProofOfStake.ToString().c_str());

    if (UintToArith256(hashProofOfStake) > bnTarget)
        return false;

	return true;
}
*/


bool CheckProofOfStake(CBlock* pblock, const COutPoint& prevout,  CAmount amount, int coinAge)
{
    // Base target
    arith_uint256 bnTarget;
    bnTarget.SetCompact(pblock->nBits);
    uint256 targetProofOfStake = ArithToUint256(bnTarget);

    // Calculate hash
    CDataStream ss(SER_GETHASH, 0);
	ss << pblock->nHeight << prevout.hash << prevout.n;
	uint256	hashProofOfStake = Hash(ss.begin(), ss.end());

	arith_uint256 bnHashPos = UintToArith256(hashProofOfStake);
	bnHashPos /= amount;
	bnHashPos /= coinAge;

	uint256 hashProofOfStakeWeight = ArithToUint256(bnHashPos);
	//LogPrintf("CheckProofOfStake amount: %lld\n", amount);
	//LogPrintf("CheckProofOfStake coinAge: %d\n", coinAge);
	//LogPrintf("CheckProofOfStake bnTarget: %s\n", targetProofOfStake.ToString().c_str());
	//LogPrintf("CheckProofOfStake hashProofOfStake: %s\n", hashProofOfStake.ToString().c_str());
	//LogPrintf("CheckProofOfStake hashProofOfStakeWeight: %s\n", hashProofOfStakeWeight.ToString().c_str());

    if (bnHashPos > bnTarget)
        return false;

	return true;
}


bool CheckStake(CBlock* pblock)
{
    uint256 proofHash;
	uint256 hashTarget;
    uint256 hashBlock = pblock->GetHash();

    if(!pblock->IsProofOfStake())
        return error("CheckStake() : %s is not a proof-of-stake block", hashBlock.GetHex());

	if (pblock->nHeight < Params().GetConsensus().LTEHeight + Params().GetConsensus().LTEPremineWindow + Params().GetConsensus().nPowAveragingWindow)
		return error("CheckStake(): pos not allow at the current block height");

    // verify hash target and signature of coinstake tx
	// Check coin stake transaction
    if (!pblock->vtx[1]->IsCoinStake())
        return error("CheckStake() : called on non-coinstake %s", pblock->vtx[1]->GetHash().ToString());

	Coin coinStake;
	{
	    LOCK2(cs_main,mempool.cs);
	    if (!pcoinsTip->GetCoin(pblock->vtx[1]->vin[0].prevout, coinStake))
		    return error("CheckStake() : can not get coinstake coin");
    }

	// Check stake min confirmations
	if (coinStake.nHeight > pblock->nHeight - nStakeMinConfirmations)
		return error("CheckStake() : utxo can not reach stake min confirmations");

	if (!CheckProofOfStake(pblock, pblock->vtx[1]->vin[0].prevout, coinStake.out.nValue, pblock->nHeight-coinStake.nHeight))
		return error("CheckStake() CheckProofOfStake");

	// Check pos authority
	CScript coinStakeFrom = coinStake.out.scriptPubKey;
	CScript coinStakeTo = pblock->vtx[1]->vout[1].scriptPubKey;
	
    txnouttype whichTypeFrom, whichTypeTo;
	std::vector<CTxDestination> txDestFromVec, txDestToVec;
	int nRequiredFrom, nRequiredTo;
	if (!ExtractDestinations(coinStakeFrom, whichTypeFrom, txDestFromVec, nRequiredFrom))
		return error("CheckStake() : ExtractDestinations coinStakeFrom ");

	if (!ExtractDestinations(coinStakeTo, whichTypeTo, txDestToVec, nRequiredTo))
		return error("CheckStake() : ExtractDestinations coinStakeTo ");

	if (whichTypeFrom != TX_PUBKEYHASH)
		return error("CheckStake() : whichTypeFrom ");

	if (whichTypeTo != TX_PUBKEYHASH)
		return error("CheckStake() : whichTypeTo ");

	if (coinStakeFrom != coinStakeTo)
		return error("CheckStake() : coinStakeFrom != coinStakeTo");

	// Check stake value
	CAmount nValueFrom = coinStake.out.nValue;
	CAmount nValueTo = pblock->vtx[1]->vout[1].nValue;
	if (nValueFrom != nValueTo)
		return error("CheckStake() : nValueFrom != nValueTo ");

    //// debug print
    LogPrintf("CheckStake() : new proof-of-stake block found  \n  hash: %s \nproofhash: %s  \ntarget: %s\n", hashBlock.GetHex(), proofHash.GetHex(), hashTarget.GetHex());
    LogPrintf("%s\n", pblock->ToString());
    LogPrintf("out %s\n", FormatMoney(pblock->vtx[1]->GetValueOut()));

    return true;
}





