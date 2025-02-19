class SecureMessaging {
    constructor() {
        this.ready = sodium.ready;
        this.KEY_BYTES = sodium.crypto_box_PUBLICKEYBYTES;
        this.NONCE_BYTES = sodium.crypto_secretbox_NONCEBYTES;
        this.MAC_BYTES = sodium.crypto_box_MACBYTES;
        this.MAX_SKIP = 100;
        this.MAX_CACHE = 2000;
        this.messageReplayCache = new Set();
    }

    static async init() {
        await sodium.ready;
        return new SecureMessaging();
    }

    async secureCleanup(buffer) {
        if (buffer && buffer.length) sodium.memzero(buffer);
    }

    validateBuffer(buffer, expectedLength) {
        if (!buffer || !(buffer instanceof Uint8Array) || 
            (expectedLength && buffer.length !== expectedLength)) {
            throw new Error('INVALID_BUFFER');
        }
    }

    async generateKeyPair() {
        return sodium.crypto_box_keypair();
    }

    async initiateX3DH(localIdentityKey, localEphemeralKey, remoteIdentityKey, 
                      remoteSignedPrekey, remoteOneTimePrekey = null) {
        try {
            this.validateBuffer(localIdentityKey.privateKey, this.KEY_BYTES);
            this.validateBuffer(localEphemeralKey.privateKey, this.KEY_BYTES);
            this.validateBuffer(remoteIdentityKey.publicKey, this.KEY_BYTES);
            this.validateBuffer(remoteSignedPrekey, this.KEY_BYTES);

            const dh1 = sodium.crypto_scalarmult(localIdentityKey.privateKey, remoteSignedPrekey);
            const dh2 = sodium.crypto_scalarmult(localEphemeralKey.privateKey, remoteIdentityKey.publicKey);
            const dh3 = sodium.crypto_scalarmult(localEphemeralKey.privateKey, remoteSignedPrekey);
            
            let dh4 = new Uint8Array(0);
            if (remoteOneTimePrekey) {
                this.validateBuffer(remoteOneTimePrekey, this.KEY_BYTES);
                dh4 = sodium.crypto_scalarmult(localEphemeralKey.privateKey, remoteOneTimePrekey);
            }

            const keys = Buffer.concat([dh1, dh2, dh3, dh4]);
            const result = sodium.crypto_generichash(32, keys);

            await Promise.all([
                this.secureCleanup(dh1),
                this.secureCleanup(dh2),
                this.secureCleanup(dh3),
                this.secureCleanup(dh4),
                this.secureCleanup(keys)
            ]);

            return result;
        } catch (error) {
            throw new Error('X3DH_FAILED');
        }
    }

    async initializeDoubleRatchet(sharedSecret, remotePublicKey = null) {
        this.validateBuffer(sharedSecret, 32);
        if (remotePublicKey) this.validateBuffer(remotePublicKey, this.KEY_BYTES);

        return {
            DHs: remotePublicKey ? null : await this.generateKeyPair(),
            DHr: remotePublicKey,
            RK: sharedSecret,
            CKs: sodium.crypto_secretbox_keygen(),
            CKr: sodium.crypto_secretbox_keygen(),
            Ns: 0,
            Nr: 0,
            PN: 0,
            mkSkipped: new Map()
        };
    }

    async kdfRK(rk, dhOut) {
        const derived = sodium.crypto_generichash(64, Buffer.concat([rk, dhOut]));
        return {
            rootKey: derived.slice(0, 32),
            chainKey: derived.slice(32)
        };
    }

    async kdfCK(ck) {
        const derived = sodium.crypto_generichash(64, ck);
        return {
            chainKey: derived.slice(0, 32),
            messageKey: derived.slice(32)
        };
    }

    async dhRatchet(session, header) {
        session.PN = session.Ns;
        session.Ns = session.Nr = 0;
        session.DHr = header.dh;
        
        const dh = sodium.crypto_scalarmult(session.DHs.privateKey, session.DHr);
        const { rootKey, chainKey } = await this.kdfRK(session.RK, dh);
        
        await this.secureCleanup(session.RK);
        await this.secureCleanup(dh);
        
        session.RK = rootKey;
        session.CKs = chainKey;
        session.DHs = await this.generateKeyPair();
    }

    async skipMessageKeys(session, until) {
        if (session.Nr + until > session.Nr + this.MAX_SKIP) {
            throw new Error('TOO_MANY_SKIPPED_MESSAGES');
        }

        while (session.Nr < until) {
            const { chainKey, messageKey } = await this.kdfCK(session.CKr);
            session.CKr = chainKey;
            session.mkSkipped.set(session.Nr, messageKey);
            session.Nr++;
        }
    }

    async ratchetEncrypt(session, plaintext, metadata = {}) {
        try {
            const { chainKey, messageKey } = await this.kdfCK(session.CKs);
            session.CKs = chainKey;

            const messageNonce = sodium.randombytes_buf(this.NONCE_BYTES);
            const metadataNonce = sodium.randombytes_buf(this.NONCE_BYTES);
            
            const encryptedMetadata = sodium.crypto_secretbox_easy(
                new TextEncoder().encode(JSON.stringify(metadata)),
                metadataNonce,
                messageKey
            );

            const encryptedMessage = sodium.crypto_secretbox_easy(
                new TextEncoder().encode(plaintext),
                messageNonce,
                messageKey
            );

            const header = {
                dh: session.DHs.publicKey,
                n: session.Ns,
                pn: session.PN,
                mn: messageNonce,
                mdn: metadataNonce
            };

            const messageId = `${metadata.timestamp || Date.now()}|${metadata.id || ''}`;
            if (this.messageReplayCache.has(messageId)) {
                throw new Error('MESSAGE_REPLAY_DETECTED');
            }
            this.messageReplayCache.add(messageId);

            session.Ns++;
            await this.secureCleanup(messageKey);

            return {
                header,
                metadata: Array.from(encryptedMetadata),
                ciphertext: Array.from(encryptedMessage)
            };
        } catch (error) {
            throw new Error('ENCRYPTION_FAILED');
        }
    }

    async ratchetDecrypt(session, message) {
        try {
            const { header, metadata, ciphertext } = message;

            if (!await this.compareBuffers(header.dh, session.DHr)) {
                await this.skipMessageKeys(session, header.pn);
                await this.dhRatchet(session, header);
            }

            await this.skipMessageKeys(session, header.n);
            const { chainKey, messageKey } = await this.kdfCK(session.CKr);
            session.CKr = chainKey;
            session.Nr++;

            const decryptedMetadata = sodium.crypto_secretbox_open_easy(
                new Uint8Array(metadata),
                header.mdn,
                messageKey
            );

            const decryptedMessage = sodium.crypto_secretbox_open_easy(
                new Uint8Array(ciphertext),
                header.mn,
                messageKey
            );

            await this.secureCleanup(messageKey);

            return {
                metadata: JSON.parse(new TextDecoder().decode(decryptedMetadata)),
                plaintext: new TextDecoder().decode(decryptedMessage)
            };
        } catch (error) {
            throw new Error('DECRYPTION_FAILED');
        }
    }

    async compareBuffers(a, b) {
        if (!a || !b || a.length !== b.length) return false;
        return sodium.crypto_verify_32(a, b);
    }
}

export default SecureMessaging;
