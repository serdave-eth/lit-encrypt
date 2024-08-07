//@ts-nocheck
import { LitNodeClient, encryptString } from "@lit-protocol/lit-node-client";
import { AuthCallbackParams } from "@lit-protocol/types";
import { LIT_RPC } from "@lit-protocol/constants";
import { LitAbility, LitAccessControlConditionResource, LitActionResource, createSiweMessageWithRecaps, generateAuthSig } from "@lit-protocol/auth-helpers";
import {ethers} from 'ethers';
import * as jwt from 'jsonwebtoken';
import { SupportedAlgorithm } from "ethers/lib/utils.js";
import * as siwe from "siwe";

const url = `<your http endpoint for api-key usage>`;
const key = '';

//This is a lit action that is testing the access control lit action after being outputted from the bundler
/*const genActionSource = () => {
    return `var n = async () => {
    let r = [
        {
            contractAddress: "",
            standardContractType: "",
            chain,
            method: "",
            parameters: [":userAddress"],
            returnValueTest: {
                comparator: "=",
                value: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
            }
        }
    ];

    let a = "ethereum";
    
    let t = await Lit.Actions.checkConditions({
        conditions: r,
        authSig: authSig,
        chain: a
    });
    
    let e = "ACCESS GRANTED";
    if (!t) {
        e = "ACCESS DENIED";
    }
    
    Lit.Actions.setResponse({ response: e });
};

n();
`
}*/

//This is a lit action that checks an on-chain access control condition 
//(in this example, the user calling this has a specific wallet address) 
//and if it passes, signs the Livepeer JWT
const genActionSource = () => {
    return `var w = e => {
    try {
        return typeof window !== "undefined" && "btoa" in window 
            ? window.btoa(e) 
            : (typeof Buffer !== "undefined" ? Buffer.from(e, "binary").toString("base64") : null);
    } catch {
        return null;
    }
};

var l = e => {
    try {
        return typeof window !== "undefined" && "atob" in window 
            ? window.atob(e) 
            : (typeof Buffer !== "undefined" ? Buffer.from(e, "base64").toString("binary") : null);
    } catch {
        return null;
    }
};

var a = e => g(w(e));

var f = e => {
    let t = h(e);
    return t ? l(t) : null;
};

var h = e => e 
    ? (e + "===".slice((e.length + 3) % 4)).replace(/-/g, "+").replace(/_/g, "/") 
    : null;

var g = e => e?.replace(/\\+/g, "-").replace(/\\//g, "_").replace(/=/g, "") ?? null;

var u = async () => {
    if (typeof crypto !== "undefined" && crypto.subtle) return crypto.subtle;
    if (typeof globalThis !== "undefined" && globalThis.crypto.subtle) return globalThis.crypto.subtle;
    try {
        return (await import("node:crypto")).webcrypto.subtle;
    } catch (e) {
        if (typeof window !== "undefined") {
            if (window.crypto.subtle) return window.crypto.subtle;
            throw new Error("Browser is not in a secure context (HTTPS), cannot use SubtleCrypto: https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto");
        }
        throw new Error(\`Failed to import Node.js crypto module: \${e.message}\`);
    }
};

var C = async (e, t) => (await u()).sign({ name: "ECDSA", hash: { name: "SHA-256" } }, e, t);

var m = async e => {
    if (typeof e !== "string" || !e.startsWith("-----BEGIN PRIVATE KEY-----")) throw new TypeError('"pkcs8" must be PKCS8 formatted string');
    let t = f(e.replace(/(?:-----(?:BEGIN|END) PRIVATE KEY-----|\\s)/g, ""));
    if (!t) throw new TypeError("Could not base64 decode private key contents.");
    return (await u()).importKey("pkcs8", new Uint8Array(t.split("").map(n => n.charCodeAt(0))), { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
};

var d = async e => {
    let t = typeof e.privateKey === "string" 
        ? await m(l(e.privateKey) ?? e.privateKey) 
        : e.privateKey;
    if (!t) throw new Error("Error importing private key.");
    let r = Date.now() / 1e3,
        n = r + (e.expiration ?? 86400),
        o = {
            action: "pull",
            iss: e.issuer,
            pub: e.publicKey,
            sub: e.playbackId,
            video: "none",
            exp: Number(n.toFixed(0)),
            iat: Number(r.toFixed(0)),
            ...e.custom ? { custom: { ...e.custom } } : {}
        },
        s = a(JSON.stringify({ alg: "ES256", typ: "JWT" })),
        i = a(JSON.stringify(o)),
        p = \`\${s}.\${i}\`,
        y = await C(t, typeof Buffer !== "undefined" ? Buffer.from(p) : new TextEncoder().encode(p)),
        b = a(String.fromCharCode(...new Uint8Array(y)));
    return \`\${s}.\${i}.\${b}\`;
};

var S = async () => {
    let e = "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFcXdQWXlIMCtoSndLQ0RpalRlMzZFK1NYR2c3ZQpic3oxbW5VNEVUNUNZdWhycW1DWVF5QVl3SmF4aFBEZnFKbDdCL2JEeCtQcHNkMFRiSE9YWFdjZUt3PT0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==",
        t = "cc53eb8slq3hrhoi",
        r = [{
            contractAddress: "",
            standardContractType: "",
            chain,
            method: "",
            parameters: [":userAddress"],
            returnValueTest: { comparator: "=", value: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266" }
        }];
    if (!await Lit.Actions.checkConditions({
        conditions: r,
        authSig: authSig,
        chain: chain
    })) return;

    let o = await Lit.Actions.decryptAndCombine({
            accessControlConditions,
            ciphertext,
            dataToEncryptHash,
            authSig: null,
            chain: "ethereum"
        }),
        c = await d({
            privateKey: o,
            publicKey: e,
            issuer: "https://docs.livepeer.org",
            playbackId: t,
            expiration: 3600
        });
    Lit.Actions.setResponse({ response: c });
};

S();`
}




//This is a lit action that checks you an on-chain access control condition, nothing else
/*
const genActionSource = () => {
    return `(async () => {
        const conditions = [
        {
            contractAddress: '',
            standardContractType: '',
            chain,
            method: '',
            parameters: [
                ':userAddress',
            ],
            returnValueTest: {
                comparator: '=',
                value: '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266'
            }
        }
    ]
        const testResult = await Lit.Actions.checkConditions({conditions, authSig, chain})
        let answer = "ACCESS GRANTED"
        if(!testResult) {
            answer = "ACCESS DENIED";
        }
        Lit.Actions.setResponse({ response: answer })
    })();`;
}*/

//This is a lit action that decrypts the Livepeer private key within the action, then signs a JWT
/*
const genActionSource = () => {
    return `var b = e => {
    try {
        return typeof window < "u" && "btoa" in window ? window?.btoa?.(e) ?? null : null;
    } catch {
        return null;
    }
};

var i = e => {
    try {
        return typeof window < "u" && "atob" in window ? window?.atob?.(e) ?? null : null;
    } catch {
        return null;
    }
};

var o = e => g(b(e));

var w = e => {
    let t = f(e);
    return t ? i(t) : null;
};

var f = e => e ? (e + "===".slice((e.length + 3) % 4)).replace(/-/g, "+").replace(/_/g, "/") : null;

var g = e => e?.replace(/\\+/g, "-").replace(/\\//g, "_").replace(/=/g, "") ?? null;

var c = async () => {
    if (typeof crypto < "u" && crypto?.subtle) return crypto.subtle;
    if (typeof globalThis?.crypto < "u" && globalThis?.crypto?.subtle) return globalThis.crypto.subtle;
    try {
        return (await import("node:crypto")).webcrypto.subtle;
    } catch (e) {
        if (typeof window < "u") {
            if (window?.crypto?.subtle) return window.crypto.subtle;
            throw new Error("Browser is not in a secure context (HTTPS), cannot use SubtleCrypto: https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto");
        }
        throw new Error(\`Failed to import Node.js crypto module: \${e?.message ?? ""}\`);
    }
};

var S = async (e, t) => (await c()).sign({ name: "ECDSA", hash: { name: "SHA-256" } }, e, t);

var m = async e => {
    if (typeof e != "string" || e.indexOf("-----BEGIN PRIVATE KEY-----") !== 0) throw new TypeError('"pkcs8" must be PKCS8 formatted string');
    let t = w(e.replace(/(?:-----(?:BEGIN|END) PRIVATE KEY-----|\\s)/g, ""));
    if (!t) throw new TypeError("Could not base64 decode private key contents.");
    return (await c()).importKey("pkcs8", new Uint8Array(t?.split("").map(n => n.charCodeAt(0))), { name: "ECDSA", namedCurve: "P-256" }, !1, ["sign"]);
};

var l = async e => {
    let t = typeof e.privateKey == "string" ? await m(i(e.privateKey) ?? e.privateKey) : e.privateKey;
    if (!t) throw new Error("Error importing private key.");
    let r = Date.now() / 1e3,
        n = r + (e.expiration ?? 86400),
        u = {
            action: "pull",
            iss: e.issuer,
            pub: e.publicKey,
            sub: e.playbackId,
            video: "none",
            exp: Number(n.toFixed(0)),
            iat: Number(r.toFixed(0)),
            ...e.custom ? { custom: { ...e.custom } } : {}
        },
        a = o(JSON.stringify({ alg: "ES256", typ: "JWT" })),
        s = o(JSON.stringify(u)),
        p = \`\${a}.\${s}\`,
        y = await S(t, new TextEncoder().encode(p)),
        d = o(String.fromCharCode(...new Uint8Array(y)));
    return \`\${a}.\${s}.\${d}\`;
};

var h = async () => {
    let e = "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFcXdQWXlIMCtoSndLQ0RpalRlMzZFK1NYR2c3ZQpic3oxbW5VNEVUNUNZdWhycW1DWVF5QVl3SmF4aFBEZnFKbDdCL2JEeCtQcHNkMFRiSE9YWFdjZUt3PT0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==",
        t = "cc53eb8slq3hrhoi",
        r = await Lit.Actions.decryptAndCombine({
            accessControlConditions,
            ciphertext,
            dataToEncryptHash,
            authSig: null,
            chain: "ethereum"
        }),
        n = await l({
            privateKey: r,
            publicKey: e,
            issuer: "https://docs.livepeer.org",
            playbackId: t,
            expiration: 3600
        });
    Lit.Actions.setResponse({ response: n });
};

h();`
}*/

/*const genActionSource = () => {
    return `(async () => {
        const apiKey = await Lit.Actions.decryptAndCombine({
            accessControlConditions,
            ciphertext,
            dataToEncryptHash,
            authSig: null,
            chain: 'ethereum',
        });
        Lit.Actions.setResponse({ response: apiKey });
    })();`;
}*/
//this code generates the signed JWT but the private key is visible
/*
const genActionSource = () => {
    return `(async () => {
        var b = e => {
            try {
                return typeof window < "u" && "btoa" in window ? window?.btoa?.(e) ?? null : window?.Buffer?.from(e, "binary")?.toString("base64") ?? null;
            } catch {
                return null;
            }
        },
        s = e => {
            try {
                return typeof window < "u" && "atob" in window ? window?.atob?.(e) ?? null : window?.Buffer?.from(e, "base64")?.toString("binary") ?? null;
            } catch {
                return null;
            }
        },
        o = e => f(b(e)),
        S = e => {
            let t = w(e);
            return t ? s(t) : null;
        },
        w = e => e ? (e + "===".slice((e.length + 3) % 4)).replace(/-/g, "+").replace(/_/g, "/") : null,
        f = e => e?.replace(/\\+/g, "-").replace(/\\//g, "_").replace(/=/g, "") ?? null,
        i = async () => {
            if (typeof crypto < "u" && crypto?.subtle) return crypto.subtle;
            if (typeof globalThis?.crypto < "u" && globalThis?.crypto?.subtle) return globalThis.crypto.subtle;
            try {
                return (await import("node:crypto")).webcrypto.subtle;
            } catch (e) {
                if (typeof window < "u") {
                    if (window?.crypto?.subtle) return window.crypto.subtle;
                    throw new Error("Browser is not in a secure context (HTTPS), cannot use SubtleCrypto: https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto");
                }
                throw new Error(\`Failed to import Node.js crypto module: \${e?.message ?? ""}\`);
            }
        },
        g = async (e, t) => (await i()).sign({
            name: "ECDSA",
            hash: {
                name: "SHA-256"
            }
        }, e, t),
        C = async e => {
            if (typeof e != "string" || e.indexOf("-----BEGIN PRIVATE KEY-----") !== 0) throw new TypeError('"pkcs8" must be PKCS8 formatted string');
            let t = S(e.replace(/(?:-----(?:BEGIN|END) PRIVATE KEY-----|\\s)/g, ""));
            if (!t) throw new TypeError("Could not base64 decode private key contents.");
            return (await i()).importKey("pkcs8", new Uint8Array(t?.split("").map(n => n.charCodeAt(0))), {
                name: "ECDSA",
                namedCurve: "P-256"
            }, !1, ["sign"]);
        },
        l = async e => {
            let t = typeof e.privateKey == "string" ? await C(s(e.privateKey) ?? e.privateKey) : e.privateKey;
            if (!t) throw new Error("Error importing private key.");
            let r = Date.now() / 1e3,
                n = r + (e.expiration ?? 86400),
                d = {
                    action: "pull",
                    iss: e.issuer,
                    pub: e.publicKey,
                    sub: e.playbackId,
                    video: "none",
                    exp: Number(n.toFixed(0)),
                    iat: Number(r.toFixed(0)),
                    ...e.custom ? {
                        custom: {
                            ...e.custom
                        }
                    } : {}
                },
                a = o(JSON.stringify({
                    alg: "ES256",
                    typ: "JWT"
                })),
                c = o(JSON.stringify(d)),
                u = \`\${a}.\${c}\`,
                p = await g(t, new TextEncoder().encode(u)),
                y = o(String.fromCharCode(...new Uint8Array(p)));
            console.log("Generated JWT:", \`\${a}.\${c}.\${y}\`);
            return \`\${a}.\${c}.\${y}\`;
        };

        var m = "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JR0hBZ0VBTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEJHMHdhd0lCQVFRZ1lqc2MxMVJ0cU05WUxZZzcKWnpxS1dXdzNvZ3pZRFZFTWJqVVVvdzZxSEhXaFJBTkNBQVNyQTlqSWZUNkVuQW9JT0tOTjdmb1Q1SmNhRHQ1dQp6UFdhZFRnUlBrSmk2R3VxWUpoRElCakFsckdFOE4rb21Yc0g5c1BINCtteDNSTnNjNWRkWng0cgotLS0tLUVORCBQUklWQVRFIEtFWS0tLS0tCg==",
            E = "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFcXdQWXlIMCtoSndLQ0RpalRlMzZFK1NYR2c3ZQpic3oxbW5VNEVUNUNZdWhycW1DWVF5QVl3SmF4aFBEZnFKbDdCL2JEeCtQcHNkMFRiSE9YWFdjZUt3PT0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==",
            F = "cc53eb8slq3hrhoi",
            h = await l({
                privateKey: m,
                publicKey: E,
                issuer: "https://docs.livepeer.org",
                playbackId: F,
                expiration: 3600
            });
        console.log("Final JWT:", h);
        Lit.Actions.setResponse({ response: h });
    })();`
}*/

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

const genAuthSig = async (
    wallet: ethers.Wallet,
    client: LitNodeClient,
    uri: string,
    resources: LitResourceAbilityRequest[]
) => {

    let blockHash = await client.getLatestBlockhash();
    const message = await createSiweMessageWithRecaps({
        walletAddress: wallet.address,
        nonce: blockHash,
        litNodeClient: client,
        resources,
        expiration: ONE_WEEK_FROM_NOW,
        uri
    })
    const authSig = await generateAuthSig({
        signer: wallet,
        toSign: message,
        address: wallet.address
    });


    return authSig;
}

const genSession = async (
    wallet: ethers.Wallet,
    client: LitNodeClient,
    resources: LitResourceAbilityRequest[]) => {
    let sessionSigs = await client.getSessionSigs({
        chain: "ethereum",
        resourceAbilityRequests: resources,
        authNeededCallback: async (params: AuthCallbackParams) => {
          console.log("resourceAbilityRequests:", params.resources);

          if (!params.expiration) {
            throw new Error("expiration is required");
          }
  
          if (!params.resources) {
            throw new Error("resourceAbilityRequests is required");
          }
  
          if (!params.uri) {
            throw new Error("uri is required");
          }

          // generate the authSig for the inner signature of the session
          // we need capabilities to assure that only one api key may be decrypted
          const authSig = genAuthSig(wallet, client, params.uri, params.resourceAbilityRequests ?? []);
          return authSig;
        }
    });

    return sessionSigs;
}

const main = async () => {
    let client = new LitNodeClient({
        litNetwork: 'cayenne',
        debug: true
    });

    const wallet = genWallet();
    const chain = 'ethereum';
    // lit action will allow anyone to decrypt this api key with a valid authSig
    const accessControlConditions = [
        {
            contractAddress: '',
            standardContractType: '',
            chain,
            method: 'eth_getBalance',
            parameters: [':userAddress', 'latest'],
            returnValueTest: {
                comparator: '>=',
                value: '0',
            },
        },
    ];
    

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
    const accsResourceString = 
        await LitAccessControlConditionResource.generateResourceString(accessControlConditions as any, dataToEncryptHash);
    const sessionForDecryption = await genSession(wallet, client, [
        {
            resource: new LitActionResource('*'),
            ability: LitAbility.LitActionExecution,
        },
        {
            resource: new LitAccessControlConditionResource(accsResourceString),
            ability: LitAbility.AccessControlConditionDecryption,

        }
    ]
    );
    //console.log("action source code: ", genActionSource(url))
    /*
    Here we use the encrypted key by sending the
    ciphertext and dataTiEncryptHash to the action
    */ 
    /*
    const res = await client.executeJs({
        sessionSigs: sessionForDecryption,
        code: genActionSource(),
        jsParams: {
            accessControlConditions,
            ciphertext,
            dataToEncryptHash
        }
    });

    console.log("result from action execution:", res);*/

    //test to generate auth sig

    // Craft the SIWE message
    // expiration time in ISO 8601 format.  This is 7 days in the future, calculated in milliseconds
    const expirationTime = new Date(
    Date.now() + 1000 * 60 * 60 * 24 * 7
  ).toISOString();
    let nonce = await client.getLatestBlockhash();
    const domain = 'localhost';
    const origin = 'https://localhost/login';
    const statement = 'This is a test statement.  You can put anything you want here.';

    const siweMessage = new siwe.SiweMessage({
        domain,
        address: wallet.address,
        statement,
        uri: origin,
        version: '1',
        chainId: 1,
        nonce,
        expirationTime,
      });
      const messageToSign = siweMessage.prepareMessage();

      // Sign the message and format the authSig
    const signature = await wallet.signMessage(messageToSign);

    const authSig = {
        sig: signature,
        derivedVia: 'web3.eth.personal.sign',
        signedMessage: messageToSign,
        address: wallet.address,
      };
      console.log(authSig);
    
      const res = await client.executeJs({
        sessionSigs: sessionForDecryption,
        code: genActionSource(),
        jsParams: {
            accessControlConditions,
            ciphertext,
            dataToEncryptHash,
            authSig: authSig,
            chain
        }
      });
      console.log("result from action execution: ", res);

client.disconnect();
}

await main();
