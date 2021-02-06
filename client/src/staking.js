const fetch = require('node-fetch');
require("dotenv").config();
const httpUrl = process.env.SECRET_REST_URL;

module.exports = {
    getValidators: async function () {
        const url = `${httpUrl}/staking/validators`;
        
        try {
            const response = await fetch(url)
            const validators = await response.json();
            return validators.result;
        } catch (error) {
            console.log(error);
        }
    },
    getDelegationShares: async function (delegatorAddr) {
        const url = `${httpUrl}/staking/delegators/${delegatorAddr}/delegations`
    
        try {
            const response = await fetch(url)
            console.log('resp: ', response.status);
            const delegations = await response.json();
            console.log('delegations: ', delegations);
            if (delegations.result.length === 1) {
                return delegations.result[0].shares;
            } else {
                console.log('delegations length: ', delegations.result.length);
                return 0
            }
        } catch (error) {
          console.log(error);
        }
    }    
}

