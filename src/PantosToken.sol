// SPDX-License-Identifier: GPL-3.0
// slither-disable-next-line solc-version
pragma solidity 0.8.23;
pragma abicoder v2;

import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Capped.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Pausable.sol";

import "./PantosBaseToken.sol";

/**
 * @title Pantos token
 */
contract PantosToken is PantosBaseToken, ERC20Capped, ERC20Pausable {
    string private constant _NAME = "Pantos";

    string private constant _SYMBOL = "PAN";

    uint8 private constant _DECIMALS = 8;

    uint256 private constant _MAX_SUPPLY =
        (10 ** 9) * (10 ** uint256(_DECIMALS));

    /**
     * @dev msg.sender receives all existing tokens
     */
    constructor(
        uint256 initialSupply
    ) PantosBaseToken(_NAME, _SYMBOL, _DECIMALS) ERC20Capped(_MAX_SUPPLY) {
        require(
            initialSupply <= _MAX_SUPPLY,
            "PantosToken: maximum supply exceeded"
        );
        ERC20._mint(msg.sender, initialSupply);
        // Contract is paused until it is fully initialized
        _pause();
    }

    /**
     * @dev See {PantosBaseToken-onlyPantosForwarder}
     */
    modifier onlyPantosForwarder() override {
        require(
            msg.sender == getPantosForwarder(),
            "PantosToken: caller is not the PantosForwarder"
        );
        _;
    }

    /**
     * @dev See {Pausable-_pause)
     */
    function pause() external whenNotPaused onlyOwner {
        _pause();
    }

    /**
     * @dev See {Pausable-_unpause)
     */
    function unpause() external whenPaused onlyOwner {
        require(
            getPantosForwarder() != address(0),
            "PantosToken: PantosForwarder has not been set"
        );
        _unpause();
    }

    /**
     *  @dev See {PantosBaseToken-_setPantosForwarder}
     */
    function setPantosForwarder(
        address pantosForwarder
    ) external whenPaused onlyOwner {
        _setPantosForwarder(pantosForwarder);
    }

    /**
     * @dev See {PantosBaseToken-decimals} and {ERC20-decimals}.
     */
    function decimals()
        public
        view
        override(PantosBaseToken, ERC20)
        returns (uint8)
    {
        return PantosBaseToken.decimals();
    }

    /**
     * @dev See {PantosBaseToken-symbol} and {ERC20-symbol}.
     */
    function symbol()
        public
        view
        override(PantosBaseToken, ERC20)
        returns (string memory)
    {
        return PantosBaseToken.symbol();
    }

    /**
     * @dev See {PantosBaseToken-name} and {ERC20-name}.
     */
    function name()
        public
        view
        override(PantosBaseToken, ERC20)
        returns (string memory)
    {
        return PantosBaseToken.name();
    }

    /**
     * @dev See {ERC20Capped-_mint}
     */
    function _mint(
        address account,
        uint256 amount
    ) internal override(ERC20, ERC20Capped) {
        ERC20Capped._mint(account, amount);
    }

    /**
     * @dev See {ERC20Pausable-_beforeTokenTransfer}
     */
    function _beforeTokenTransfer(
        address sender,
        address recipient,
        uint256 amount
    ) internal override(ERC20, ERC20Pausable) {
        ERC20Pausable._beforeTokenTransfer(sender, recipient, amount);
    }
}