var Certificate = artifacts.require("./Certificate.sol");
var MerkleProof = artifacts.require("zeppelin-solidity/contracts/MerkleProof.sol");

module.exports = function (deployer) {
    deployer.deploy(MerkleProof);
    deployer.link(MerkleProof, [Certificate]);
    deployer.deploy(Certificate);
};
