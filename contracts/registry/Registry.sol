pragma solidity ^0.4.18;


import "../ownership/Ownable.sol";


contract Registry is Ownable {


  enum State {Default, RevokedPermanently, Revoked, Pending, Valid, SomethingElse}


  mapping (uint => address) certOwner;
  mapping (uint => address) certRevoker;
  mapping (uint => State) certState;

  event UpdateCertificate(uint indexed _cert, State indexed _state);
  event AcceptCertificate(uint indexed _cert);
  event CreateCertificate(uint indexed _cert, address indexed _owner);

  modifier notRevokedPermanentlyCertificate(uint _cert){
    require(certState[_cert]!=State.RevokedPermanently);
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


  modifier notAcceptedCertificate(uint _cert){
    require(certRevoker[_cert]==address(0));
    _;
  }

  modifier acceptedCertificate(uint _cert){
    require(certRevoker[_cert]!=address(0));
    _;
  }





  /**
    * @dev create new certificate. Only for Registry owner
    * @param _cert Hash of certificate
    * @param _owner Owner address of certificate
    * @return _state State of certificate
    */


  function createCertificate(uint _cert, address _owner) notExistedCertificate(_cert) onlyOwner(){
    certOwner[_cert] = _owner;
    UpdateCertificate(_cert,  State.Default);
    CreateCertificate(_cert, _owner);
  }

  /**
    * @dev update certificate. Only for Registry owner
    * @param _cert Hash of certificate
    * @return _state State of certificate
    */

  function updateCertificate(uint _cert, State _state) notRevokedPermanentlyCertificate(_cert) acceptedCertificate(_cert) onlyOwner(){
    certState[_cert] = State(_state);
    UpdateCertificate(_cert, _state);
  }


  /**
    * @dev accept certificate by user and fill revoker address
    * @param _cert Hash of certificate
    * @param _revoker address of revoker
    */


  function acceptCertificate(uint _cert, address _revoker)
    notRevokedPermanentlyCertificate(_cert) notAcceptedCertificate(_cert) existedCertificate(_cert) onlyCertOwner(_cert)
  {
    require(_revoker!=address(0));
    certRevoker[_cert] = _revoker;
    AcceptCertificate(_cert);
  }


  /**
    * @dev Remove compromised certificate permanently
    * @param _cert Hash of certificate
    */

  function revokePermanentlyCertificate(uint _cert){
    require((msg.sender==certOwner[_cert])||(msg.sender==certRevoker[_cert])||(msg.sender==owner));
    certState[_cert] = State.RevokedPermanently;
    UpdateCertificate(_cert, State.RevokedPermanently);
  }





}
