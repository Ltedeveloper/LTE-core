// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "primitives/block.h"

#include "hash.h"
#include "tinyformat.h"
#include "utilstrencodings.h"
#include "chainparams.h"
#include "consensus/params.h"
#include "crypto/common.h"
#include "crypto/scrypt.h"

uint256 CBlockHeader::GetHash(const Consensus::Params& params) const
{
   /* int version;
    if (nHeight>= params.newcoinHeight) {
        version = PROTOCOL_VERSION| SERIALIZE_BLOCK_LEGACY;
    } else {
        version = PROTOCOL_VERSION ;
    }
    CHashWriter writer(SER_GETHASH, version);
    ::Serialize(writer, *this);
    return writer.GetHash();*/
    return SerializeHash(*this);
}

uint256 CBlockHeader::GetHash() const
{
    const Consensus::Params& consensusParams = Params().GetConsensus();
    return GetHash(consensusParams);
}

uint256 CBlockHeader::GetPoWHash() const
{
    uint256 thash;
    uint8_t temp_data[80];
    memcpy(temp_data,&this->nVersion,4);
    memcpy(temp_data+4,&this->hashPrevBlock,32);
    memcpy(temp_data+36,&this->hashMerkleRoot,32);
    memcpy(temp_data+68,&this->nTime,4);
    memcpy(temp_data+72,&this->nBits,4);
    uint32_t legacy_nonce = (uint32_t)nNonce.GetUint64(0);
    memcpy(temp_data+76,&legacy_nonce,4);
	
	
    scrypt_1024_1_1_256(BEGIN(temp_data), BEGIN(thash));
    return thash;
}

std::string CBlock::ToString() const
{
    std::stringstream s;
    s << strprintf("CBlock(hash=%s, ver=0x%08x, hashPrevBlock=%s, hashMerkleRoot=%s, nHeight=%u,nTime=%u, nBits=%08x, nNonce=%s, vtx=%u)\n",
        GetHash().ToString(),
        nVersion,
        hashPrevBlock.ToString(),
        hashMerkleRoot.ToString(),
        nHeight, nTime, nBits, nNonce.GetHex(),
        vtx.size());
    for (const auto& tx : vtx) {
        s << "  " << tx->ToString() << "\n";
    }
    return s.str();
}
