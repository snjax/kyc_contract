pragma solidity ^0.4.18;


import "../ownership/Ownable.sol";


contract Registry is Ownable {

  


  uint8 constant REVOKED_PERMANENTLY = 0xff;



  mapping (uint => address) certOwner;
  mapping (uint => uint8) certState;

  mapping (uint => uint) certRevokeHashCode;

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


  function createCertificate(uint _cert, address _owner) public notExistedCertificate(_cert) onlyOwner() returns(bool) {
    certOwner[_cert] = _owner;
    CreateCertificate(_cert, _owner);
    return true;
  }

  /**
    * @dev add hash code to revoke certificate
    * @param _cert Hash of certificate
    * @param _code hashcode of certificate
    */
  function addRevokeHashCode(uint _cert, uint _code) public notRevokedPermanentlyCertificate(_cert) onlyOwner() returns(bool) {
    require(certRevokeHashCode[_code] == 0);
    certRevokeHashCode[_code] = _cert;
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
    * @param _certRevokeCode code, must be compared with stored hash certRevokeHashCode. If it is existed, revoke the certificate.
    */

  function revokePermanentlyCertificate(uint _cert, uint _certRevokeCode) public returns(bool) {
    require(_cert != 0);
    require((_cert == certRevokeHashCode[uint(keccak256(_certRevokeCode))]) || (certOwner[_cert]==msg.sender));

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
