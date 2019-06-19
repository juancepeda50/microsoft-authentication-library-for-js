export interface IDeviceCrytpo {
    sign(key: CryptoKey, data: ArrayBuffer): Promise<ArrayBuffer>
    verify(key: CryptoKey, signature: ArrayBuffer, data: ArrayBuffer): Promise<boolean>
    generateKey(extractable: boolean, usages: Array<string>): Promise<CryptoKeyPair>
    exportKey(key: CryptoKey, format: KeyFormat): Promise<JsonWebKey>
    digest(algo: string, dataString: string): Promise<ArrayBuffer>
}
