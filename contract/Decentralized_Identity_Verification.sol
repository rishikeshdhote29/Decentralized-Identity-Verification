// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title Decentralized Identity Verification
 * @dev A smart contract for managing decentralized identity verification
 * @author Your Name
 */
contract Project {
    
    // Struct to represent an identity
    struct Identity {
        address owner;
        string name;
        string email;
        bool isVerified;
        uint256 createdAt;
        uint256 verifiedAt;
        address verifier;
    }
    
    // Struct to represent a credential
    struct Credential {
        uint256 identityId;
        string credentialType;
        string credentialData;
        address issuer;
        uint256 issuedAt;
        uint256 expiresAt;
        bool isActive;
    }
    
    // State variables
    mapping(address => uint256) public userToIdentityId;
    mapping(uint256 => Identity) public identities;
    mapping(uint256 => Credential[]) public identityCredentials;
    mapping(address => bool) public authorizedVerifiers;
    
    uint256 private nextIdentityId = 1;
    address public admin;
    
    // Events
    event IdentityCreated(uint256 indexed identityId, address indexed owner, string name);
    event IdentityVerified(uint256 indexed identityId, address indexed verifier);
    event CredentialIssued(uint256 indexed identityId, string credentialType, address indexed issuer);
    event VerifierAuthorized(address indexed verifier);
    event VerifierRevoked(address indexed verifier);
    
    // Modifiers
    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin can perform this action");
        _;
    }
    
    modifier onlyAuthorizedVerifier() {
        require(authorizedVerifiers[msg.sender], "Only authorized verifiers can perform this action");
        _;
    }
    
    modifier onlyIdentityOwner(uint256 _identityId) {
        require(identities[_identityId].owner == msg.sender, "Only identity owner can perform this action");
        _;
    }
    
    modifier identityExists(uint256 _identityId) {
        require(identities[_identityId].owner != address(0), "Identity does not exist");
        _;
    }
    
    constructor() {
        admin = msg.sender;
        authorizedVerifiers[msg.sender] = true; // Admin is automatically an authorized verifier
    }
    
    /**
     * @dev Core Function 1: Create a new decentralized identity
     * @param _name The name associated with the identity
     * @param _email The email associated with the identity
     * @return identityId The unique ID of the created identity
     */
    function createIdentity(string memory _name, string memory _email) 
        external 
        returns (uint256 identityId) 
    {
        require(userToIdentityId[msg.sender] == 0, "User already has an identity");
        require(bytes(_name).length > 0, "Name cannot be empty");
        require(bytes(_email).length > 0, "Email cannot be empty");
        
        identityId = nextIdentityId;
        nextIdentityId++;
        
        identities[identityId] = Identity({
            owner: msg.sender,
            name: _name,
            email: _email,
            isVerified: false,
            createdAt: block.timestamp,
            verifiedAt: 0,
            verifier: address(0)
        });
        
        userToIdentityId[msg.sender] = identityId;
        
        emit IdentityCreated(identityId, msg.sender, _name);
        return identityId;
    }
    
    /**
     * @dev Core Function 2: Verify an identity (only authorized verifiers)
     * @param _identityId The ID of the identity to verify
     */
    function verifyIdentity(uint256 _identityId) 
        external 
        onlyAuthorizedVerifier 
        identityExists(_identityId) 
    {
        Identity storage identity = identities[_identityId];
        require(!identity.isVerified, "Identity is already verified");
        
        identity.isVerified = true;
        identity.verifiedAt = block.timestamp;
        identity.verifier = msg.sender;
        
        emit IdentityVerified(_identityId, msg.sender);
    }
    
    /**
     * @dev Core Function 3: Issue a credential to a verified identity
     * @param _identityId The ID of the identity to issue credential to
     * @param _credentialType The type of credential (e.g., "Education", "Employment")
     * @param _credentialData The credential data (could be IPFS hash)
     * @param _expiresAt The expiration timestamp of the credential
     */
    function issueCredential(
        uint256 _identityId,
        string memory _credentialType,
        string memory _credentialData,
        uint256 _expiresAt
    ) 
        external 
        onlyAuthorizedVerifier 
        identityExists(_identityId) 
    {
        require(identities[_identityId].isVerified, "Identity must be verified to issue credentials");
        require(bytes(_credentialType).length > 0, "Credential type cannot be empty");
        require(bytes(_credentialData).length > 0, "Credential data cannot be empty");
        require(_expiresAt > block.timestamp, "Expiration date must be in the future");
        
        Credential memory newCredential = Credential({
            identityId: _identityId,
            credentialType: _credentialType,
            credentialData: _credentialData,
            issuer: msg.sender,
            issuedAt: block.timestamp,
            expiresAt: _expiresAt,
            isActive: true
        });
        
        identityCredentials[_identityId].push(newCredential);
        
        emit CredentialIssued(_identityId, _credentialType, msg.sender);
    }
    
    // Admin functions
    function authorizeVerifier(address _verifier) external onlyAdmin {
        require(_verifier != address(0), "Invalid verifier address");
        authorizedVerifiers[_verifier] = true;
        emit VerifierAuthorized(_verifier);
    }
    
    function revokeVerifier(address _verifier) external onlyAdmin {
        require(_verifier != admin, "Cannot revoke admin");
        authorizedVerifiers[_verifier] = false;
        emit VerifierRevoked(_verifier);
    }
    
    // View functions
    function getIdentity(uint256 _identityId) 
        external 
        view 
        identityExists(_identityId) 
        returns (Identity memory) 
    {
        return identities[_identityId];
    }
    
    function getCredentials(uint256 _identityId) 
        external 
        view 
        identityExists(_identityId) 
        returns (Credential[] memory) 
    {
        return identityCredentials[_identityId];
    }
    
    function getUserIdentityId(address _user) external view returns (uint256) {
        return userToIdentityId[_user];
    }
    
    function isIdentityVerified(uint256 _identityId) 
        external 
        view 
        identityExists(_identityId) 
        returns (bool) 
    {
        return identities[_identityId].isVerified;
    }
}
