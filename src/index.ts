//@ts-nocheck
import { LitNodeClient, encryptString } from "@lit-protocol/lit-node-client";
import { AuthCallbackParams } from "@lit-protocol/types";
import { LIT_RPC } from "@lit-protocol/constants";
import { LitAbility, LitAccessControlConditionResource, LitActionResource, createSiweMessageWithRecaps, generateAuthSig } from "@lit-protocol/auth-helpers";
import {ethers} from 'ethers';
import * as jwt from 'jsonwebtoken';
import { SupportedAlgorithm } from "ethers/lib/utils.js";
import * as siwe from "siwe";
import crypto from 'crypto';

// Information you want to encrypt and the IPFS CID of your lit action
const key = 'Hello World';
const litActionIpfsId = "QmaCVtmaHjk1tUfhTsKmqWDJGBAQXjwtrN5X81qFuEdP6N";

const chain = "ethereum";

const accessControlConditions = [
    {
      contractAddress: '',
      standardContractType: '',
      chain: 'ethereum',
      method: '',
      parameters: [':currentActionIpfsId'],
      returnValueTest: {
        comparator: '=',
        value: litActionIpfsId,
      },
    },
  ];

const ONE_WEEK_FROM_NOW = new Date(
    Date.now() + 1000 * 60 * 60 * 24 * 7
).toISOString();

const genProvider = () => {
    return new ethers.providers.JsonRpcProvider(LIT_RPC.CHRONICLE_YELLOWSTONE);
}

const genWallet = () => {
// known private key for testing
// replace with your own key
return new ethers.Wallet('0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80', genProvider());
}

const main = async () => {
    let client = new LitNodeClient({
        litNetwork: 'datil-dev',
        debug: true
    });

    const wallet = genWallet();
    await client.connect();
    /*
    Here we are encypting our key for secure use within an action
    this code should be run once and the ciphertext and dataToEncryptHash stored for later sending
    to the Lit Action in 'jsParams'
    */
    const { ciphertext, dataToEncryptHash } = await encryptString(
        {
            accessControlConditions,
            dataToEncrypt: key,
        },
        client
    );

    console.log("cipher text:", ciphertext, "hash:", dataToEncryptHash);

client.disconnect();
}

await main();
