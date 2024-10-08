// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC1155/extensions/ERC1155Supply.sol";
import "@openzeppelin/contracts/token/ERC1155/extensions/ERC1155Burnable.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/token/common/ERC2981.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/**
 * @author GoArt Metaverse Blockchain Team
 * @title GoPackCollection.sol
 * @dev A contract for managing GoPack Collection of ERC1155 tokens.
 * GoPackCollection.sol is an ERC1155 token contract that allows minting, burning, pausing, and transferring of tokens.
 * It also implements the AccessControl and ReentrancyGuard contracts for access control and protection against reentrancy attacks.
 * Additionally, it supports the ERC2981 for royalty information.
 */
contract GoPackCollection is
ERC1155Supply,
ERC1155Burnable,
AccessControl,
ReentrancyGuard,
ERC2981,
Pausable
{
	string public name;
	string public symbol;

	address private adminSigner;
	uint96 public defaultRoyaltyRate = 500; /// default royalty rate equal to 5 percent in basis points

	bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

	mapping(bytes => bool) public usedSignatures;
	mapping(uint256 => bool) public allowedTokenTypes;

	//Max mintable amount for each token type for each user
	mapping(uint256 => uint256) public maxMints;


	event Minted(address account, bytes salt, bytes signature, uint256 amount, uint256 tokenId);
	event AdminSignerUpdated(address adminSigner, address updatedBy);
	event RoyaltiesUpdated(address newRoyaltyFeeReceiver, uint96 newRoyaltyRate);
	event AddedAllowedTokenType(uint256 _tokenType, address addedBy);
	event RemovedAllowedTokenType(uint256 _tokenType, address removedBy);
	event Burned(address account, uint256 id, uint256 value);

	/**
	 * @notice Constructor
	 * @param _name Name of the contract
	 * @param _symbol Symbol of the contract
	 * @param _adminSigner admin signer for mint txs
	 * @param _royaltyFeeReceiver royalty fee receiver for the collection
	 * @param _baseURI baseURI for NFTs defined
	 */
	constructor(
		string memory _name,
		string memory _symbol,
		address _adminSigner,
		address _royaltyFeeReceiver,
		string memory _baseURI
	) ERC1155("{baseURI}/{id}.json") {
		name = _name;
		symbol = _symbol;
		adminSigner = _adminSigner;
		_setURI(_baseURI);
		_grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
		_grantRole(OPERATOR_ROLE, msg.sender);
		_setDefaultRoyalty(_royaltyFeeReceiver, defaultRoyaltyRate);
	}

	/**
	 * @dev Sets the URI for all token types.
	 * Can only be called by an account with the DEFAULT_ADMIN_ROLE.
	 * @param newUri The new URI.
	 */
	function setTokenURI(string memory newUri) public onlyRole(OPERATOR_ROLE) {
		_setURI(newUri);
	}

	/**
	 * @dev Adds a new token type to allowed tokens
	 * Can only be called by an account with the OPERATOR_ROLE.
	 * @param _tokenType the new token type.
	 */
	function addAllowedTokenType(uint256 _tokenType, uint256 _maxMintAmount)
	public
	onlyRole(OPERATOR_ROLE)
	{
		allowedTokenTypes[_tokenType] = true;
		maxMints[_tokenType] = _maxMintAmount;
		emit AddedAllowedTokenType(_tokenType, msg.sender);
	}

	/**
	 * @dev Removes an existing token type from allowed tokens
	 * Can only be called by an account with the OPERATOR_ROLE.
	 * @param _tokenType the removed token type.
	 */
	function removeAllowedTokenType(uint256 _tokenType) public onlyRole(OPERATOR_ROLE) {
		delete allowedTokenTypes[_tokenType];
		delete maxMints[_tokenType];
		emit RemovedAllowedTokenType(_tokenType, msg.sender);
	}

	/**
	 * @dev Sets the address of the admin signer.
	 * @param _adminSigner The address of the admin signer.
	 * Requirements:
	 * - The caller must have the OPERATOR_ROLE.
	 */
	function setAdminSigner(address _adminSigner) public onlyRole(OPERATOR_ROLE) {
		adminSigner = _adminSigner;
		emit AdminSignerUpdated(_adminSigner, msg.sender);
	}

	/**
	 * @dev Returns the address of the admin signer.
	 * @return The address of the admin signer.
	 */
	function getAdminSigner() public view returns (address) {
		return adminSigner;
	}

	/**
	 * @dev Sets the default royalty receiver and rate for the contract.
	 * Can only be called by an account with the DEFAULT_ADMIN_ROLE.
	 * @param _royaltyFeeReceiver The address of the royalty receiver.
	 * @param _newRoyaltyRate The new royalty rate.
	 */
	function updateRoyalties(address _royaltyFeeReceiver, uint96 _newRoyaltyRate)
	public
	onlyRole(OPERATOR_ROLE)
	{
		_setDefaultRoyalty(_royaltyFeeReceiver, _newRoyaltyRate);
		emit RoyaltiesUpdated(_royaltyFeeReceiver, _newRoyaltyRate);
	}

	/**
	 * @dev Rearranges token URI
	 * @param tokenId Token id whose will be return token's URI
	 */
	function tokenURI(uint256 tokenId) public view returns (string memory) {
		return
			bytes(uri(tokenId)).length > 0
				? string(abi.encodePacked(uri(tokenId), Strings.toString(tokenId), ".json"))
				: "";
	}

	/**
	 * Pause or unpause the contract
	 * @notice only owner can change the pause state of the contract
	 * @param val true if pause, false if unpause
	 */
	function pause(bool val) public onlyRole(OPERATOR_ROLE) {
		if (val == true) {
			_pause();
			return;
		}
		_unpause();
	}

	/**
	 * @dev Mints a specified amount of tokens for the caller, subject to certain conditions.
	 * @param amount The number of tokens to mint.
	 * @param signature The signature used to verify the minting request.
	 *
	 * Requirements:
	 * - The caller can only mint up to 2 tokens at a time.
	 * - The total number of tokens minted by the caller cannot exceed 2.
	 * - The signature provided must not have been used before.
	 * - The signature must be valid and match the admin signer address.
	 *
	 * Emits a `Mint` event with the caller's address and the amount of tokens minted.
	 */
	function mint(
		uint256 amount,
		uint256 _tokenId,
		bytes memory salt,
		bytes memory signature
	) external nonReentrant whenNotPaused {
		if (!allowedTokenTypes[_tokenId]) revert("InvalidTokenType");
		if (amount > maxMints[_tokenId]) revert("ExceedsMaxMintForTokenType");
		if (usedSignatures[signature]) revert("SignatureAlreadyUsed");

		bytes32 message = MessageHashUtils.toEthSignedMessageHash(
			keccak256(abi.encodePacked(msg.sender, _tokenId, amount, salt, block.chainid, this))
		);

		if (ECDSA.recover(message, signature) != adminSigner) revert("InvalidSignature");

		usedSignatures[signature] = true;
		_mint(msg.sender, _tokenId, amount, "");
		emit Minted(msg.sender, salt, signature, amount, _tokenId);
	}

	/**
	 * @dev Burns a specified amount of tokens for the caller.
	 * @param id The token id to burn.
	 * @param value The number of tokens to burn.
	 *
	 * Requirements:
	 * - The caller must have a balance of at least `value`.
	 *
	 * Emits a `Burned` event with the caller's address, the token id, and the amount of tokens burned.
	 */
	function burn(
		address account,
		uint256 id,
		uint256 value
	) public nonReentrant whenNotPaused override(ERC1155Burnable) {
		super.burn(account, id, value);
		emit Burned(account, id, value);
	}

	/**
	 * @dev This contract extends the ERC1155 and ERC1155Supply contracts.
	 */

	function _update(
		address from,
		address to,
		uint256[] memory ids,
		uint256[] memory values
	) internal override(ERC1155, ERC1155Supply) whenNotPaused {
		super._update(from, to, ids, values);
	}

	/**
	 * Add support for interfaces
	 * @notice ERC1155, ERC2981, AccessControl
	 * @param interfaceId corresponding interfaceId
	 * @return bool true if supported, false otherwise
	 */
	function supportsInterface(bytes4 interfaceId)
	public
	view
	virtual
	override(ERC1155, ERC2981, AccessControl)
	returns (bool)
	{
		return super.supportsInterface(interfaceId);
	}
}
