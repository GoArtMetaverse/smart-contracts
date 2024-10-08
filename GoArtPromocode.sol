// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "@openzeppelin/contracts/token/ERC721/extensions/ERC721Enumerable.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@chainlink/contracts/src/v0.8/interfaces/VRFCoordinatorV2Interface.sol";
import "@chainlink/contracts/src/v0.8/VRFConsumerBaseV2.sol";
import "@chainlink/contracts/src/v0.8/ConfirmedOwner.sol";

/**
 * @author GoArt Metaverse Blockchain Team
 * @title GoArtMetaversePromoCode
 * @notice Mint GoArtMetaversePromoCode tokens to be able to redeem promo codes distributed in GoArt Metaverse.
 */
contract GoArtMetaversePromoCode is
	ERC721Enumerable,
	Pausable,
	ReentrancyGuard,
	VRFConsumerBaseV2,
	ConfirmedOwner
{
	VRFCoordinatorV2Interface immutable COORDINATOR;

	/// admin signer address for coupons
	address private adminSigner;

	/// maximum mint amount per transaction
	uint256 constant MAX_MINT_PER_TX = 10;

	/// offset for maximum requests
	uint256 constant OFFSET_FOR_REQUEST_COUNT = 500;

	/// max supply for this collection
	uint256 public immutable maxSupply;

	/// remaining token count
	uint256 public remaining;

	/// number of requests received so far
	uint256 public requestCount;

	/// Chainlink VRF subscription id
	uint64 subscriptionId;

	/// Chainlink VRF key hash
	bytes32 keyHash;

	/// Chainlink VRF callback gas limit
	uint32 callbackGasLimit;

	/// Chainlink VRF number of random words requested per request
	uint32 constant NUM_WORDS = 1;

	/// Chainlink VRF confirmation count per request
	uint16 constant REQUEST_CONFIRMATIONS = 3;

	/// Merkle Root Hash for promo codes to be distributed for verification purposes
	bytes32 public immutable merkleRoot;

	/// baseURI for unrevealed tokens
	string public baseURI;

	/// baseURI for revealed tokens
	string public revealedBaseURI;

	/// Chainlink request struct to store necessary information
	struct ChainLinkRequests {
		bool fulfilled; // whether the request has been successfully fulfilled
		bool exists; // whether a requestId exists
		uint256 vrf;
		address requester;
		uint256 amount;
		bytes signature;
	}

	/// past requests Id.
	uint256[] public requestIds;

	/// randomness cache
	mapping(uint256 => uint256) private cache;

	/// track of revelead tokens
	mapping(uint256 => bool) public revealed;

	/// store user nonces here
	mapping(address => uint256) public userNonce;

	/// store used signatures to avoid being reused
	mapping(bytes => bool) private usedSignatures;

	/// requestId --> ChainLinkRequests
	mapping(uint256 => ChainLinkRequests) public randomnessRequests;

	event PromoCodeMinted(address to, uint256 tokenId);
	event Revealed(address requester, uint256 tokenId);
	event RequestFulfilled(uint256 requestId, address requester, uint256 amount, uint256[] vrf);
	event MintRequestSent(uint256 requestId, address sender, uint256 amount);
	event AirdropRequestSent(uint256 requestId, address sender, uint256 amount);
	event AdminSignerUpdated(address adminSigner, address updatedBy);
	event RequestCountReset(uint256 oldRequestCount, uint256 newRequestCount, address updatedBy);
	event BaseURIUpdated(string baseURI, address updatedBy);
	event RevealedBaseURIUpdated(string baseURI, address updatedBy);
	event ChainlinkConfigurationUpdated(
		uint64 subscriptionId,
		bytes32 keyHash,
		uint32 callbackGasLimit,
		address updatedBy
	);

	/**
	 * @notice Define ERC721 related parameters and setup Chainlink
	 * @param _name name of the collection
	 * @param _symbol symbol of the collection
	 * @param _maxSupply max supply of the collection
	 * @param _baseURI URI for unrevealed tokens
	 * @param _revealedBaseURI URI for revealed tokens
	 * @param _adminSigner signer wallet address
	 * @param _subscriptionId Chainlink VRF subscription id
	 * @param _vrfCoordinator Chanlink VRF Coordinator address
	 * @param _keyHash Chainlink VRF key hash
	 * @param _callbackGasLimit Chainlink VRF callback gas limit
	 * @param _merkleRoot merkle root hash of the promo codes
	 */
	constructor(
		string memory _name,
		string memory _symbol,
		uint256 _maxSupply,
		string memory _baseURI,
		string memory _revealedBaseURI,
		address _adminSigner,
		uint64 _subscriptionId,
		address _vrfCoordinator,
		bytes32 _keyHash,
		uint32 _callbackGasLimit,
		bytes32 _merkleRoot
	) ERC721(_name, _symbol) VRFConsumerBaseV2(_vrfCoordinator) ConfirmedOwner(msg.sender) {
		COORDINATOR = VRFCoordinatorV2Interface(_vrfCoordinator);
		maxSupply = _maxSupply;
		remaining = _maxSupply;
		adminSigner = _adminSigner;
		baseURI = _baseURI;
		revealedBaseURI = _revealedBaseURI;
		subscriptionId = _subscriptionId;
		keyHash = _keyHash;
		callbackGasLimit = _callbackGasLimit;
		merkleRoot = _merkleRoot;
	}

	/**
	 * @notice Give away tokens from owner wallet
	 * @param amount number of tokens to be minted
	 */
	function giveAway(uint256 amount) external onlyOwner {
		if (amount > MAX_MINT_PER_TX) revert("ExceedsMaxMintPerTx");
		if (totalSupply() + amount > maxSupply) revert("ExceedsMaxSupply");
		requestCount += amount;
		uint256 _requestId = requestVRF(amount, "");
		emit AirdropRequestSent(_requestId, msg.sender, amount);
	}

	/**
	 * @notice Reset request counter
	 * @param _requestCount new request count
	 */
	function resetRequestCount(uint256 _requestCount) external onlyOwner {
		uint256 oldRequestCount = requestCount;
		requestCount = _requestCount;
		emit RequestCountReset(oldRequestCount, _requestCount, msg.sender);
	}

	/**
	 * @notice Update the baseURI
	 * @param _baseURI new baseURI
	 */
	function updateBaseURI(string memory _baseURI) external onlyOwner {
		baseURI = _baseURI;
		emit BaseURIUpdated(_baseURI, msg.sender);
	}

	/**
	 * @notice Update the revealedBaseURI
	 * @param _baseURI new revealedBaseURI
	 */
	function updateRevealedBaseURI(string memory _baseURI) external onlyOwner {
		revealedBaseURI = _baseURI;
		emit RevealedBaseURIUpdated(_baseURI, msg.sender);
	}

	/**
	 * @notice Reveal the promo code by burning the token
	 * @param tokenId to be revealed and burned.
	 */
	function revealPromoCode(uint256 tokenId) external nonReentrant {
		if (ownerOf(tokenId) != msg.sender) revert("NotTokenOwner");
		revealed[tokenId] = true;
		_burn(tokenId);
		emit Revealed(msg.sender, tokenId);
	}

	/**
	 * @notice Update ChainLink VRF configuration in case subscription changes
	 * @param _subscriptionId subscription id received by Chainlink
	 * @param _keyHash for subscription and network
	 * @param _callbackGasLimit gas limit for the given subscription
	 */
	function updateChainlinkConfiguration(
		uint64 _subscriptionId,
		bytes32 _keyHash,
		uint32 _callbackGasLimit
	) external onlyOwner {
		subscriptionId = _subscriptionId;
		keyHash = _keyHash;
		callbackGasLimit = _callbackGasLimit;
		emit ChainlinkConfigurationUpdated(
			_subscriptionId,
			_keyHash,
			_callbackGasLimit,
			msg.sender
		);
	}

	/**
	 * @notice setAdminSigner updates adminSigner
	 * @param _newAdminSigner new adress for admin signer
	 */
	function setAdminSigner(address _newAdminSigner) external onlyOwner {
		if (_newAdminSigner == address(0)) revert("ZeroAddress");
		adminSigner = _newAdminSigner;
		emit AdminSignerUpdated(_newAdminSigner, msg.sender);
	}

	/**
	 * @notice Mint tokens
	 * @param amount number of tokens to be minted
	 * @param nonce nonce for msg.sender
	 * @param signature signature obtained from backend to be able to mint tokens
	 */
	function mint(
		uint256 amount,
		uint256 nonce,
		bytes memory signature
	) external whenNotPaused nonReentrant {
		if (amount > MAX_MINT_PER_TX) revert("ExceedsMaxMintPerTx");
		if (requestCount + amount > maxSupply + OFFSET_FOR_REQUEST_COUNT)
			revert("ExceedsRequestCount");
		if (totalSupply() + amount > maxSupply) revert("ExceedsMaxSupply");
		if (userNonce[msg.sender] != nonce) revert("InvalidUserNonce");
		if (usedSignatures[signature]) revert("AlreadyUsedSignature");

		// this recreates the message that was signed on the client
		bytes32 message = ECDSA.toEthSignedMessageHash(
			keccak256(abi.encodePacked(msg.sender, amount, nonce, block.chainid, this))
		);

		if (ECDSA.recover(message, signature) != adminSigner) revert("InvalidSignature");

		usedSignatures[signature] = true;
		requestCount += amount;

		uint256 _requestId = requestVRF(amount, signature);
		emit MintRequestSent(_requestId, msg.sender, amount);
	}

	/**
	 * @notice Return the tokens owned by address
	 * @param _owner address to be searched for
	 * @return tokensId tokensIds owned by _owner
	 */
	function walletOfOwner(address _owner) external view returns (uint256[] memory) {
		uint256 tokenCount = balanceOf(_owner);

		uint256[] memory tokensId = new uint256[](tokenCount);
		for (uint256 i = 0; i < tokenCount; i++) {
			tokensId[i] = tokenOfOwnerByIndex(_owner, i);
		}

		return tokensId;
	}

	/**
	 * @notice Return the given request's status
	 * @param _requestId requestId issued by Chainlink VRF
	 * @return fulfilled if successful true
	 * @return vrf random number sent from Chainlink if request is fulfilled
	 */
	function getRequestStatus(uint256 _requestId)
		external
		view
		returns (bool fulfilled, uint256 vrf)
	{
		if (!randomnessRequests[_requestId].exists) revert("RequestNotFound");
		ChainLinkRequests memory request = randomnessRequests[_requestId];
		return (request.fulfilled, request.vrf);
	}

	/**
	 * Pause or unpause the contract
	 * @notice only owner can change the pause state of the contract
	 * @param val true if pause, false if unpause
	 */
	function pause(bool val) public onlyOwner {
		if (val == true) {
			_pause();
			return;
		}
		_unpause();
	}

	/**
	 * @notice Return if token is revealed
	 * @param tokenId token to be searched for
	 * @return revealed[tokenId] true if revealed, false otherwise
	 */
	function isRevealed(uint256 tokenId) public view returns (bool) {
		return revealed[tokenId];
	}

	/**
	 * @notice Return nonce of the given wallet address
	 * @param wallet address to be searched for
	 * @return userNonce[wallet] nonce of the given wallet
	 */
	function getUserNonce(address wallet) public view returns (uint256) {
		return userNonce[wallet];
	}

	/**
	 * @notice Return adminSigner wallet address
	 * @return adminSigner admin signer wallet address
	 */
	function getAdminSigner() public view returns (address) {
		return adminSigner;
	}

	/**
	 * @notice Verify promo code
	 * @param promoCode revealed promo code
	 * @param _merkleProof proofs of the given leaf
	 * @return bool true if verified, false otherwise
	 */
	function verifyPromoCode(
		string memory promoCode,
		uint256 tokenId,
		bytes32[] calldata _merkleProof
	) public view returns (bool) {
		bytes32 leaf = keccak256(abi.encodePacked(Strings.toString(tokenId), promoCode));
		return MerkleProof.verify(_merkleProof, merkleRoot, leaf);
	}

	/**
	 * Add support for interfaces
	 * @notice ERC721Enumerable, ERC721Burnable
	 * @param interfaceId corresponding interfaceId
	 * @return bool true if supported, false otherwise
	 */
	function supportsInterface(bytes4 interfaceId)
		public
		view
		virtual
		override(ERC721Enumerable)
		returns (bool)
	{
		return super.supportsInterface(interfaceId);
	}

	/**
	 * @notice tokenURI returns the uri to metadata
	 * @param tokenId tokenId
	 * @return tokenURI for given tokenId if exists
	 */
	function tokenURI(uint256 tokenId) public view override(ERC721) returns (string memory) {
		if (revealed[tokenId]) {
			return
				bytes(revealedBaseURI).length > 0
					? string(abi.encodePacked(revealedBaseURI, Strings.toString(tokenId), ".json"))
					: "";
		}
		require(_exists(tokenId), "GoArt PromoCode: Query for non-existent token");
		return
			bytes(baseURI).length > 0
				? string(abi.encodePacked(baseURI, Strings.toString(tokenId), ".json"))
				: "";
	}

	/**
	 * @notice Request random words from Chainlink VRF.
	 * @param amount number of tokens to be minted
	 * @param signature signature to be eligible to mint
	 * @return requestId requestId for randomness request sent to Chainlink VRF.
	 */
	function requestVRF(uint256 amount, bytes memory signature)
		internal
		returns (uint256 requestId)
	{
		// Will revert if subscription is not set and funded.
		requestId = COORDINATOR.requestRandomWords(
			keyHash,
			subscriptionId,
			REQUEST_CONFIRMATIONS,
			callbackGasLimit,
			NUM_WORDS
		);
		randomnessRequests[requestId] = ChainLinkRequests({
			vrf: 0,
			exists: true,
			fulfilled: false,
			requester: msg.sender,
			amount: amount,
			signature: signature
		});
		requestIds.push(requestId);
		return requestId;
	}

	/**
	 * @notice This method is triggered by Chainlink VRF to feed randomWords into the contract.
	 * @param _requestId needed to find the request for mint
	 * @param _randomWords random number array to generate random token ids.
	 */
	function fulfillRandomWords(uint256 _requestId, uint256[] memory _randomWords)
		internal
		override
	{
		if (!randomnessRequests[_requestId].exists) revert("RequestNotFound");
		randomnessRequests[_requestId].fulfilled = true;
		randomnessRequests[_requestId].vrf = _randomWords[0];
		_mintPromoCode(_requestId);

		emit RequestFulfilled(
			_requestId,
			randomnessRequests[_requestId].requester,
			randomnessRequests[_requestId].amount,
			_randomWords
		);
	}

	/**
	 * @notice Mint the tokens for given _requestId
	 * @param _requestId needed to find the request for mint
	 */
	function _mintPromoCode(uint256 _requestId) internal nonReentrant {
		uint256 _vrf = randomnessRequests[_requestId].vrf;
		/// the user needs a new nonce for the next mint
		userNonce[randomnessRequests[_requestId].requester]++;
		for (uint256 i = 0; i < randomnessRequests[_requestId].amount; ++i) {
			uint256 randomIndex = (_vrf % remaining); //

			// if there's a cache at cache[randomIndex] then use it
			// otherwise use randomIndex itself
			uint256 resultNumber = cache[randomIndex] == 0 ? randomIndex : cache[randomIndex];
			resultNumber++;

			// grab a number from the tail
			cache[randomIndex] = cache[remaining - 1] == 0 ? remaining - 1 : cache[remaining - 1];
			remaining = remaining - 1;
			_safeMint(randomnessRequests[_requestId].requester, resultNumber);
			emit PromoCodeMinted(randomnessRequests[_requestId].requester, resultNumber);
		}
	}

	/**
	 * Override _beforeTokenTransfer
	 * @notice ERC721, ERC721Enumerable
	 * @param from previous owner
	 * @param to new owner
	 * @param tokenId tokenId
	 */
	function _beforeTokenTransfer(
		address from,
		address to,
		uint256 tokenId,
		uint256 batchSize
	) internal virtual override(ERC721Enumerable) {
		super._beforeTokenTransfer(from, to, tokenId, batchSize);
	}
}
