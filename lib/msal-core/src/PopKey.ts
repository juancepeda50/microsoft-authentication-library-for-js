import { IDeviceCrytpo } from './IDeviceCrypto';
import { BrowserCrypto } from './BrowserCrypto';
import { Base64 } from 'js-base64';
import { HashAlgorithm, getStringFromArrayBuffer, KeyFormat, utf8Encode, getArrayBufferFromString, KeyUsages, KeyGenAlgorithm } from './PopCommon';

export class PopKey {
    private _crypto: IDeviceCrytpo;
    private _keyPair: CryptoKeyPair;

    // https://developer.mozilla.org/en-US/docs/Web/API/RsaHashedKeyGenParams
    private static MODULUS_LENGTH: number = 2048;
    private static PUBLIC_EXPONENT: Uint8Array = new Uint8Array([0x01, 0x00, 0x01]);

    private static KEY_USAGES = [KeyUsages.sign, KeyUsages.verify];
    private static EXTRACTABLE = true;

    constructor() {
        this._crypto = new BrowserCrypto(KeyGenAlgorithm.rsassa_pkcs1_v15,HashAlgorithm.sha256, PopKey.MODULUS_LENGTH, PopKey.PUBLIC_EXPONENT);

        this._crypto.generateKey(PopKey.EXTRACTABLE, PopKey.KEY_USAGES)
            .then(keyPair => {
                this._keyPair = keyPair;
            });
    }

    async getPublicKey() : Promise<string> {
        const publicJwk = await this.exportPublicKey();
        const publicJwkString = this.getJwkString(publicJwk);

        const publicJwkBuffer = await this._crypto.digest(HashAlgorithm.sha256, publicJwkString);
        const publicJwkDigest = getStringFromArrayBuffer(publicJwkBuffer);
        const publicJwkEncoded = Base64.encode(publicJwkDigest, true);

        return publicJwkEncoded;
    }

    private async exportPublicKey(): Promise<JsonWebKey> {
        return this._crypto.exportKey(this._keyPair.publicKey, KeyFormat.jwk);
    }

    private getJwkString(key: JsonWebKey): string {
        return JSON.stringify(key, Object.keys(key).sort());
    }

    async signToken(payload: object): Promise<string> {
        const publicJwk = await this.exportPublicKey();
        const publicJwkString = this.getJwkString(publicJwk);

        const header = {
            alg: publicJwk.alg,
            type: KeyFormat.jwk,
            jwk: publicJwkString
        };

        const encodedHeader = Base64.encode(utf8Encode(JSON.stringify(header)), true);
        const encodedPayload = Base64.encode(utf8Encode(JSON.stringify(payload)), true);

        const tokenString = `${encodedHeader}.${encodedPayload}`;
        const tokenBuffer = getArrayBufferFromString(tokenString);

        const signatureBuffer = await this._crypto.sign(this._keyPair.privateKey, tokenBuffer);
        const encodedSignature = Base64.encode(getStringFromArrayBuffer(signatureBuffer), true);
        const signedToken = `${tokenString}.${encodedSignature}`;

        return signedToken;
    }

    async verifyToken(signedToken: string) {
        const [
            header,
            payload,
            signature
        ] = signedToken.split(".");

        const tokenString = `${header}.${payload}`;
        const tokenBuffer = getArrayBufferFromString(tokenString);
        const signatureBuffer = getArrayBufferFromString(Base64.decode(signature));

        return this._crypto.verify(this._keyPair.publicKey, signatureBuffer, tokenBuffer);
    }
}
