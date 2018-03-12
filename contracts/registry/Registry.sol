pragma solidity ^0.4.18;


import "../ownership/Ownable.sol";


contract Registry is Ownable {




  uint8 constant REVOKED_PERMANENTLY = 0xff;



  mapping (uint => address) certOwner;
  mapping (uint => uint) certRevokeHashCode;
  mapping (uint => uint8) certState;

  event UpdateCertificate(uint indexed _cert, uint8 indexed _state);
  event CreateCertificate(uint indexed _cert, address indexed _owner);

  modifier notRevokedPermanentlyCertificate(uint _cert){
    require(certState[_cert]!=REVOKED_PERMANENTLY);
    _;
  }

  modifier notExistedCertificate(uint _cert){
    require(certOwner[_cert]==address(0));
    _;
  }

  modifier existedCertificate(uint _cert) {
    require(certOwner[_cert]!=address(0));
    _;
  }

  modifier onlyCertOwner(uint _cert){
    require(msg.sender==certOwner[_cert]);
    _;
  }



  /**
    * @dev create new certificate. Only for Registry owner
    * @param _cert Hash of certificate
    * @param _owner Owner address of certificate
    * @return _state State of certificate
    */


  function createCertificate(uint _cert, address _owner, uint _certRevokeHashCode) public notExistedCertificate(_cert) onlyOwner() returns(bool) {
    certOwner[_cert] = _owner;
    certRevokeHashCode[_cert] = _certRevokeHashCode;
    CreateCertificate(_cert, _owner);
    return true;
  }

  /**
    * @dev update certificate. Only for Registry owner
    * @param _cert Hash of certificate
    * @return _state State of certificate
    */

  function updateCertificate(uint _cert, uint8 _state) public notRevokedPermanentlyCertificate(_cert) onlyOwner() returns(bool) {
    certState[_cert] = _state;
    UpdateCertificate(_cert, _state);
    return true;
  }




  /**
    * @dev Remove compromised certificate permanently
    * @param _cert Hash of certificate
    */

  function revokePermanentlyCertificate(uint _cert, uint _certRevokeCode) public returns(bool) {
    require(certRevokeHashCode[_cert]==uint(keccak256(_certRevokeCode)));
    certState[_cert] = REVOKED_PERMANENTLY;
    UpdateCertificate(_cert, REVOKED_PERMANENTLY);
    return true;
  }

  function getCertState(uint _cert) public view returns (uint8) {
    return certState[_cert];
  }

  function getCertOwner(uint _cert) public view returns (address) {
    return certOwner[_cert];
  }

  function checkSignature(uint _cert, bytes32 _hash, uint8 _v, bytes32 _r, bytes32 _s) public view returns (bool) {
    return certOwner[_cert] == ecrecover(_hash, _v, _r, _s);
  }

}
