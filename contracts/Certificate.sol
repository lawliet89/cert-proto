pragma solidity ^0.4.17;

import "zeppelin-solidity/contracts/ownership/HasNoEther.sol";


contract Certificate is HasNoEther {
    /// A batch certificate issue
    struct Batch {
        bytes32 merkleRoot;
        /// Block number of issue
        uint blockNumber;
    }

    /// A recovation
    ///
    /// See https://www.imsglobal.org/sites/default/files/Badges/OBv2p0/index.html#RevocationList
    /// for the details needed
    /// We can
    ///
    /// XXX: Presumably when revoking, we have to check the Batch batch that the certificate was
    /// part of (including the merkle tree), and then check that the revocation sender is actually
    /// the issuer of the certificate in question.
    struct Revocation {
        // Hash of the certificate being revoked
        bytes32 hash;
        // Merkle root of the batch
        bytes32 batchMerkleRoot;
        /// Block number of revocation
        uint blockNumber;
        uint revocationReason;
    }

    /// An Issuer
    struct Issuer {
        Batch[] batches;
        Revocation[] revocations;

        /// Mapping from merkel root to index in batches list
        /// Danger: an unissued merkle root hash will always point to zero, so we better check
        mapping(bytes32 => uint) merkleToBatch;

        /// Mapping from revoked hash to index in revocation list
        mapping(bytes32 => uint) hashToRevocationIndex;
    }

    /// Mapping of issuer to their batches
    mapping(address => Issuer) issuers;

    /// Retrieve the issue struct and also verifies it actually has been issued
    function getBatch(address _issuer, bytes32 merkleRoot) internal view returns(Batch storage _issue) {
        Issuer storage issuer = issuers[_issuer];
        uint index = issuer.merkleToBatch[merkleRoot];
        require(issuer.batches.length > index);
        _issue = issuer.batches[index];
        require(_issue.merkleRoot == merkleRoot);
        return _issue;
    }

    function isBatchIssued(address _issuer, bytes32 merkleRoot) internal view returns(bool) {
        Issuer storage issuer = issuers[_issuer];
        uint index = issuer.merkleToBatch[merkleRoot];
        if (issuer.batches.length > index) {
            Batch storage _issue = issuer.batches[index];
            return _issue.merkleRoot == merkleRoot;
        } else {
            return false;
        }
    }

    modifier batchNotIssued(address _issuer, bytes32 merkleRoot) {
        require(!isBatchIssued(_issuer, merkleRoot));
        _;
    }

    modifier onlyIssuedBatch(address _issuer, bytes32 merkleRoot) {
        require(isBatchIssued(_issuer, merkleRoot));
        _;
    }

    function issueBatch(bytes32 merkleRoot) public batchNotIssued(msg.sender, merkleRoot) returns(uint) {
        Batch memory _issue = Batch(merkleRoot, block.number);
        Issuer storage issuer = issuers[msg.sender];

        uint index = issuer.batches.push(_issue) - 1;
        issuer.merkleToBatch[merkleRoot] = index;

        return index;
    }

    function getIssuedBatchesCount(address issuer) public view returns(uint) {
        return issuers[issuer].batches.length;
    }

    function getIssuedBatchBlockNumber(address issuer, bytes32 merkleRoot) public view returns(uint) {
        Batch storage _issue = getBatch(issuer, merkleRoot);
        return _issue.blockNumber;
    }

    function getRevocation(address _issuer, bytes32 hash) internal view returns(Revocation storage _revocation) {
        Issuer storage issuer = issuers[_issuer];
        uint index = issuer.hashToRevocationIndex[hash];
        require(issuer.revocations.length > index);
        _revocation = issuer.revocations[index];
        require(_revocation.hash == hash);
        return _revocation;
    }

    function isRevoked(address _issuer, bytes32 hash) internal view returns(bool) {
        Issuer storage issuer = issuers[_issuer];
        uint index = issuer.hashToRevocationIndex[hash];
        if (issuer.revocations.length > index) {
            Revocation storage _revocation = issuer.revocations[index];
            return _revocation.hash == hash;
        } else {
            return false;
        }
    }

    modifier onlyRevoked(address _issuer, bytes32 hash) {
        require(isRevoked(_issuer, hash));
        _;
    }

    modifier notRevoked(address _issuer, bytes32 hash) {
        require(!isRevoked(_issuer, hash));
        _;
    }

    /// Issued, merkle root matches, and hash not revoked
    modifier onlyVerified(address _issuer, bytes32 merkleRoot, bytes32 hash, bytes proof) {
        require(verify(_issuer, merkleRoot, hash, proof));
        _;
    }

    /// Verify that something is issued by some issuer and that proofs and the merkle root exist
    /// Also check that it has not been revoked
    /// Modified from https://github.com/OpenZeppelin/zeppelin-solidity/blob/master/contracts/MerkleProof.sol
    function verify(address _issuer, bytes32 merkleRoot, bytes32 hash, bytes proof) public view returns(bool) {
        if (!isBatchIssued(_issuer, merkleRoot)) {
            return false;
        }

        // Check if proof length is a multiple of 32
        if (proof.length % 32 != 0) {
            return false;
        }

        bytes32 proofElement;
        bytes32 computedHash = hash;

        for (uint256 i = 32; i <= proof.length; i += 32) {
            assembly {
                // Load the current element of the proof
                proofElement := mload(add(proof, i))
            }

            if (computedHash < proofElement) {
                // Hash(current computed hash + current element of the proof)
                computedHash = keccak256(computedHash, proofElement);
            } else {
                // Hash(current element of the proof + current computed hash)
                computedHash = keccak256(proofElement, computedHash);
            }

            if (isRevoked(_issuer, computedHash)) {
                return false;
            }
        }

        // Check if the computed hash (root) is equal to the provided root
        return computedHash == merkleRoot;
    }

    /// Revoke a certificate.
    /// Generaly, issuers should only really revoke the "top" hash of a single certificate, although, if they wish,
    /// they can choose to revoke certain claims only. It will complicate certificate management though
    function revoke(bytes32 merkleRoot, bytes32 hash, uint reason, bytes proof) public onlyVerified(msg.sender, merkleRoot, hash, proof) returns(uint) {
        Revocation memory _revocation = Revocation(hash, merkleRoot, block.number, reason);
        Issuer storage issuer = issuers[msg.sender];

        uint index = issuer.revocations.push(_revocation) - 1;
        issuer.hashToRevocationIndex[hash] = index;

        return index;
    }

    function Certificate() public {
    }
}
