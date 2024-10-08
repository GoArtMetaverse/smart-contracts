// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/access/AccessControlEnumerable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/**
 * @author Blockchain Team
 * @title Swap
 * @notice Swap contract for swapping tokens
 */
contract Swap is ReentrancyGuard, Pausable, AccessControlEnumerable {
	using SafeERC20 for IERC20;
	///  Address of the admin signer
	address private adminSigner;

	///  Mapping of verified tokens
	mapping(address => bool) verifiedTokens;

	///  Array of tokens
	address[] public tokens;

	///  Mapping of used signatures
	mapping(bytes => bool) private usedSignatures;

	/// Event emitted when a cash transaction is executed
	enum CashTransactionType {
		CASH_IN,
		CASH_OUT
	}

	///  Event emitted when a cash transaction is executed
	event CashTransaction(
		address indexed _user,
		address indexed _tokenAddress,
		uint256 _amount,
		string _ticket,
		bytes _signature,
		CashTransactionType _type
	);

	///  Event emitted when the admin signer is set
	event SetAdminSigner(address indexed _signer);

	///  Event emitted when an verified token is added
	event AddVerifiedToken(address indexed _token);

	///  Event emitted when an verified token is removed
	event RemoveVerifiedToken(address indexed _token);

	///  Event emitted when the contract is funded
	event FundContract(address indexed _token, uint256 _amount);

	/// Event emitted when withdraw all funds
	event WithdrawAllFunds(address indexed _adminAddress);

	///  Event emitted when withdraw funds
	event WithdrawFunds(address indexed _token, address _adminAddress, uint256 _amount);

	/**
	 * @notice Constructs the Swap contract
	 * @param _signer Address of the admin signer
	 */
	constructor(address _signer) {
		if (_signer == address(0)) {
			revert("ZeroAddress");
		}
		_setupRole(DEFAULT_ADMIN_ROLE, msg.sender);
		adminSigner = _signer;
	}

	/**
	 * @notice Grants a role to an account
	 * @param role role to grant
	 * @param account address to grant role to
	 */

	function grantRole(
		bytes32 role,
		address account
	) public virtual override(AccessControl, IAccessControl) {
		if (role != DEFAULT_ADMIN_ROLE) {
			revert("OnlyDefaultAdminRoleAllowed");
		}
		super.grantRole(role, account);
	}

	/**
	 * @notice Revokes a role from an account
	 * @param role role to revoke
	 * @param account address to revoke role from
	 */
	function revokeRole(
		bytes32 role,
		address account
	) public virtual override(IAccessControl, AccessControl) {
		if (role != DEFAULT_ADMIN_ROLE || getRoleMemberCount(DEFAULT_ADMIN_ROLE) <= 1) {
			revert("CannotRevokeLastAdminRole");
		}
		super.revokeRole(role, account);
	}

	/**
	 * @notice Renounces a role from an account
	 * @param role role to renounce
	 * @param account address to renounce role from
	 */
	function renounceRole(
		bytes32 role,
		address account
	) public virtual override(IAccessControl, AccessControl) {
		if (getRoleMemberCount(DEFAULT_ADMIN_ROLE) <= 1) {
			revert("CannotRenounceLastAdminRole");
		}
		super.renounceRole(role, account);
	}

	/**
	 * @notice Sets the admin signer
	 * @param _signer Address of the admin signer
	 */
	function setAdminSigner(address _signer) external onlyRole(DEFAULT_ADMIN_ROLE) {
		if (_signer == address(0)) {
			revert("ZeroAddress");
		}
		adminSigner = _signer;
		emit SetAdminSigner(_signer);
	}

	/**
	 * @notice Funds the contract
	 * @param _tokenAddress Address of the token to fund
	 * @param _amount Amount to fund
	 */
	function fundContract(
		address _tokenAddress,
		uint256 _amount
	) external nonReentrant onlyRole(DEFAULT_ADMIN_ROLE) {
		if (!verifiedTokens[_tokenAddress]) {
			revert("NotVerifiedToken");
		}

		IERC20 token = IERC20(_tokenAddress);
		token.safeTransferFrom(msg.sender, address(this), _amount);

		emit FundContract(_tokenAddress, _amount);
	}

	/**
	 * @notice Withdraws all funds
	 */
	function withdrawAllFunds() external nonReentrant onlyRole(DEFAULT_ADMIN_ROLE) {
		for (uint256 i = 0; i < tokens.length; ++i) {
			IERC20 token = IERC20(tokens[i]);
			uint256 balance = token.balanceOf(address(this));
			token.safeTransfer(msg.sender, balance);
			emit WithdrawFunds(tokens[i], msg.sender, balance);
		}
		emit WithdrawAllFunds(msg.sender);
	}

	/**
	 * @notice Withdraws funds
	 * @param _tokenAddress Address of the token to withdraw
	 * @param _amount Amount to withdraw
	 */
	function withdrawFunds(
		address _tokenAddress,
		uint256 _amount
	) external nonReentrant onlyRole(DEFAULT_ADMIN_ROLE) {
		IERC20 token = IERC20(_tokenAddress);
		token.safeTransfer(msg.sender, _amount);
		emit WithdrawFunds(_tokenAddress, msg.sender, _amount);
	}

	/**
	 * @notice Adds an verified token
	 * @param _tokenAddress address of the token to add
	 */
	function addVerifiedToken(address _tokenAddress) external onlyRole(DEFAULT_ADMIN_ROLE) {
		if (verifiedTokens[_tokenAddress]) {
			revert("AlreadyVerifiedToken");
		}
		verifiedTokens[_tokenAddress] = true;
		tokens.push(_tokenAddress);
		emit AddVerifiedToken(_tokenAddress);
	}

	/**
	 * @notice Removes an verified token
	 * @param _tokenAddress address of the token to remove
	 */
	function removeVerifiedToken(address _tokenAddress) external onlyRole(DEFAULT_ADMIN_ROLE) {
		if (!verifiedTokens[_tokenAddress]) {
			revert("AlreadyUnverifiedToken");
		}
		verifiedTokens[_tokenAddress] = false;
		uint256 i = 0;
		while (tokens[i] != _tokenAddress) {
			i++;
		}
		tokens[i] = tokens[tokens.length - 1];
		tokens.pop();
		emit RemoveVerifiedToken(_tokenAddress);
	}

	/**
	 * Pause or unpause the contract
	 * @notice only owner can change the pause state of the contract
	 * @param val true if pause, false if unpause
	 */
	function pause(bool val) public onlyRole(DEFAULT_ADMIN_ROLE) {
		if (val == true) {
			_pause();
			return;
		}
		_unpause();
	}

	/**
	 * @notice Executes a cash transaction
	 * @param _tokenAddress Address of the token
	 * @param _type Type of the cash transaction
	 * @param _amount Amount of the token
	 * @param _ticket A random generated string
	 * @param _signature Signature obtained from backend to be able to mint tokens
	 */
	function cashTransaction(
		address _tokenAddress,
		CashTransactionType _type,
		uint256 _amount,
		string memory _ticket,
		bytes memory _signature
	) external nonReentrant whenNotPaused {
		if (!verifiedTokens[_tokenAddress]) {
			revert("NotVerifiedToken");
		}

		if (usedSignatures[_signature]) {
			revert("AlreadyUsedSignature");
		}

		bytes32 message = keccak256(
			abi.encodePacked(
				msg.sender,
				_tokenAddress,
				_type,
				_amount,
				_ticket,
				block.chainid,
				this
			)
		);
		bytes32 messageHash = ECDSA.toEthSignedMessageHash(message);
		address signer = ECDSA.recover(messageHash, _signature);
		if (signer != adminSigner) {
			revert("InvalidSignature");
		}
		usedSignatures[_signature] = true;

		if (_type == CashTransactionType.CASH_IN) {
			IERC20 token = IERC20(_tokenAddress);
			token.safeTransferFrom(msg.sender, address(this), _amount);
		} else {
			IERC20 token = IERC20(_tokenAddress);
			token.safeTransfer(msg.sender, _amount);
		}

		emit CashTransaction(msg.sender, _tokenAddress, _amount, _ticket, _signature, _type);
	}

	/**
	 * @notice Get the admin signer
	 */
	function getAdminSigner() external view returns (address) {
		return adminSigner;
	}

	/**
	 * @notice Returns the verified tokens
	 */
	function isVerifiedToken(address _tokenAddress) external view returns (bool) {
		return verifiedTokens[_tokenAddress];
	}

	/**
	 * @notice Returns the verified tokens
	 */
	function getTokens() external view returns (address[] memory) {
		return tokens;
	}

	/**
	 * @notice Returns the verified tokens
	 */
	function getBalance(address _tokenAddress) external view returns (uint256) {
		if (!verifiedTokens[_tokenAddress]) {
			revert("NotVerifiedToken");
		}
		return IERC20(_tokenAddress).balanceOf(address(this));
	}

	/**
	 * @notice Returns the verified tokens
	 * @return tokens token addresses
	 * @return balances token balances
	 */
	function getAllBalances() external view returns (address[] memory, uint256[] memory) {
		address[] memory _tokens = tokens;
		uint256[] memory balances = new uint256[](_tokens.length);
		for (uint256 i = 0; i < _tokens.length; ++i) {
			balances[i] = IERC20(_tokens[i]).balanceOf(address(this));
		}
		return (_tokens, balances);
	}
}
