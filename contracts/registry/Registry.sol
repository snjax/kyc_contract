pragma solidity ^0.4.18;


import "../ownership/Ownable.sol";


contract Registry is Ownable {




  uint8 constant State_RevokedPermanently = 0xff;



  mapping (uint => address) certOwner;
  mapping (uint => uint) certRevokeHashCode;
  mapping (uint => uint8) certState;

  event UpdateCertificate(uint indexed _cert, uint8 indexed _state);
  event CreateCertificate(uint indexed _cert, address indexed _owner);

  modifier notRevokedPermanentlyCertificate(uint _cert){
    require(certState[_cert]!=State_RevokedPermanently);
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


  function createCertificate(uint _cert, address _owner, uint _certRevokeHashCode) notExistedCertificate(_cert) onlyOwner(){
    certOwner[_cert] = _owner;
    certRevokeHashCode[_cert] = _certRevokeHashCode;
    CreateCertificate(_cert, _owner);
  }

  /**
    * @dev update certificate. Only for Registry owner
    * @param _cert Hash of certificate
    * @return _state State of certificate
    */

  function updateCertificate(uint _cert, uint8 _state) notRevokedPermanentlyCertificate(_cert) onlyOwner(){
    certState[_cert] = _state;
    UpdateCertificate(_cert, _state);
  }




  /**
    * @dev Remove compromised certificate permanently
    * @param _cert Hash of certificate
    */

  function revokePermanentlyCertificate(uint _cert, uint _certRevokeCode){
    require(certRevokeHashCode[_cert]==uint(keccak256(_certRevokeCode)));
    certState[_cert] = State_RevokedPermanently;
    UpdateCertificate(_cert, State_RevokedPermanently);
  }

  function getCertState(uint _cert) view returns (uint8){
    return certState[_cert];
  }

  function getCertOwner(uint _cert) view returns (address){
    return certOwner[_cert];
  }

  function checkSignature(uint _cert, bytes32 _hash, uint8 _v, bytes32 _r, bytes32 _s) view returns (bool){
    return certOwner[_cert] == ecrecover(_hash, _v, _r, _s);
  }

}
