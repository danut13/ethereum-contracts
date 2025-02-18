// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.26;

/* solhint-disable no-console*/
import {console} from "forge-std/console.sol";

import {IPantosHub} from "../../../src/interfaces/IPantosHub.sol";
import {PantosTypes} from "../../../src/interfaces/PantosTypes.sol";
import {AccessController} from "../../../src/access/AccessController.sol";

import {PantosBaseAddresses} from "./../../helpers/PantosBaseAddresses.s.sol";
import {SafeAddresses} from "../../helpers/SafeAddresses.s.sol";
import {UpdateBase} from "./UpdateBase.s.sol";

/**
 * @title UpdateUnbondingPeriod
 *
 * @notice Update the unbonding period of the service node deposit
 * at the Pantos Hub.
 *
 * @dev Usage
 * forge script ./script/update/parameters/UpdateUnbondingPeriod.s.sol --rpc-url <rpc alias>
 *      --sig "roleActions(uint256)" <newUnbondingPeriod>
 */
contract UpdateUnbondingPeriod is
    PantosBaseAddresses,
    SafeAddresses,
    UpdateBase
{
    function roleActions(uint256 newUnbondingPeriod) public {
        readContractAddresses(determineBlockchain());
        IPantosHub pantosHubProxy = IPantosHub(
            getContractAddress(Contract.HUB_PROXY, false)
        );
        AccessController accessController = AccessController(
            getContractAddress(Contract.ACCESS_CONTROLLER, false)
        );
        vm.startBroadcast(accessController.mediumCriticalOps());

        PantosTypes.UpdatableUint256
            memory onChainUnbondingPeriod = pantosHubProxy
                .getUnbondingPeriodServiceNodeDeposit();
        UpdateBase.UpdateState updateState = isInitiateOrExecute(
            onChainUnbondingPeriod,
            newUnbondingPeriod
        );
        if (updateState == UpdateBase.UpdateState.INITIATE) {
            pantosHubProxy.initiateUnbondingPeriodServiceNodeDepositUpdate(
                newUnbondingPeriod
            );
            console.log(
                "Update of the unbonding period of service node "
                "deposit initiated %s",
                newUnbondingPeriod
            );
        } else if (updateState == UpdateBase.UpdateState.EXECUTE) {
            pantosHubProxy.executeUnbondingPeriodServiceNodeDepositUpdate();
            console.log(
                "Update of the unbonding period of service node "
                "deposit executed %s",
                onChainUnbondingPeriod.pendingValue
            );
        } else {
            revert("UpdateUnbondingPeriod: Invalid update state");
        }

        vm.stopBroadcast();
        writeAllSafeInfo(accessController);
    }
}
