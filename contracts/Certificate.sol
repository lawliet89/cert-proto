pragma solidity ^0.4.17;

import "zeppelin-solidity/contracts/ownership/HasNoEther.sol";


contract Certificate is HasNoEther {
    /// A batch certificate issue
    struct Issue {
        uint merkleRoot;
        /// Block number of issue
        uint blockNumber;
    }

    /// A recovation
    ///
    /// See https://www.imsglobal.org/sites/default/files/Badges/OBv2p0/index.html#RevocationList
    /// for the details needed
    /// We can
    ///
    /// XXX: Presumably when revoking, we have to check the Issue batch that the certificate was
    /// part of (including the merkle tree), and then check that the revocation sender is actually
    /// the issuer of the certificate in question.
    struct Revocation {
        /// Block number of revocation
        uint blockNumber;
        string id;
        string revocationReason;
    }

    /// An Issuer
    struct Issuer {
        Issue[] issues;
        Revocation[] revocations;

        /// Mapping from merkel root to index in issues list
        /// Danger: an unissued merkle root hash will always point to zero, so we better check
        mapping(uint => uint) merkleToIndex;
    }

    /// Mapping of issuer to their issues
    mapping(address => Issuer) issuers;

    function getIssued(address _issuer, uint merkleRoot) internal view returns(Issue storage _issue) {
        Issuer storage issuer = issuers[_issuer];
        uint index = issuer.merkleToIndex[merkleRoot];
        require(issuer.issues.length > index);
        _issue = issuer.issues[index];
        require(_issue.merkleRoot == merkleRoot);
        return _issue;
    }

    modifier notIssued(address _issuer, uint merkleRoot) {
        Issuer storage issuer = issuers[_issuer];
        uint index = issuer.merkleToIndex[merkleRoot];
        if (issuer.issues.length > index) {
            Issue storage _issue = issuer.issues[index];
            require(_issue.merkleRoot != merkleRoot);
        }
        _;
    }

    modifier onlyIssued(address _issuer, uint merkleRoot) {
        getIssued(_issuer, merkleRoot);
        _;
    }

    function Certificate() public {
    }

    function issue(uint merkleRoot) public notIssued(msg.sender, merkleRoot) returns(uint) {
        Issue memory _issue = Issue(merkleRoot, block.number);
        Issuer storage issuer = issuers[msg.sender];

        uint index = issuer.issues.push(_issue) - 1;
        issuer.merkleToIndex[merkleRoot] = index;

        return index;
    }

    function getIssuedCount(address issuer) public view returns(uint) {
        return issuers[issuer].issues.length;
    }

    function getIssuedBlockNumber(address issuer, uint merkleRoot) public view returns(uint) {
        Issue storage _issue = getIssued(issuer, merkleRoot);
        return _issue.blockNumber;
    }
}
