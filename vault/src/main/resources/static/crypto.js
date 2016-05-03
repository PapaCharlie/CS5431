/**
 * Created by papacharlie on 4/22/16.
 */

function hash(data) {
    if ((typeof data !== "string" || !(data instanceof String)) && (typeof data === "object" || data instanceof Object)) {
        var h = new sjcl.hash.sha256();
        var keys = [];
        for (var prop in data) {
            if (data.hasOwnProperty(prop)) {
                keys.push(prop);
            }
        }
        keys.sort();
        for (var key in keys) {
            if (data.hasOwnProperty(key)) {
                if (typeof data[key] !== "string" || !(data[key] instanceof String)) {
                    h.update(toB64(hash(data[key])));
                } else {
                    h.update(data[key]);
                }
            }
        }
        return h.finalize();
    } else {
        return sjcl.hash.sha256.hash(data);
    }
}

function toB64(data) {
    return sjcl.codec.base64url.fromBits(data);
}

function fromB64(data) {
    return sjcl.codec.base64url.toBits(data);
}

function generateElGamalKeys() {
    return sjcl.ecc.elGamal.generateKeys(sjcl.ecc.curves.c384);
}

function generateECDSAKeys() {
    return sjcl.ecc.ecdsa.generateKeys(sjcl.ecc.curves.c384);
}

function serializePrivateKey(encryptionKey, privKey) {
    return JSON.stringify(encrypt(encryptionKey, toB64(privKey.get())));
}

function serializePublicKey(pubKey) {
    return toB64(pubKey.get().x.concat(pubKey.get().y));
}

function parseElGamalPublicKey(pubKey) {
    return new sjcl.ecc.elGamal.publicKey(
        sjcl.ecc.curves.c384,
        fromB64(pubKey)
    );
}

function sign(privKey, content) {
    return toB64(privKey.sign(hash(content)));
}

function verifySignature(pubKey, content, signature) {
    try {
        return pubKey.verify(hash(content), fromB64(signature));
    } catch (err) {
        console.error(err);
        return false;
    }
}

function parseECDSAPublicKey(pubKey) {
    return new sjcl.ecc.ecdsa.publicKey(
        sjcl.ecc.curves.c384,
        fromB64(pubKey)
    );
}

function parseElGamalPrivateKey(encryptionKey, privKey) {
    return new sjcl.ecc.elGamal.secretKey(
        sjcl.ecc.curves.c384,
        sjcl.ecc.curves.c384.field.fromBits(fromB64(decrypt(encryptionKey, privKey)))
    )
}

function deriveMasterKey(salt, password) {
    return hash(fromB64(salt).concat(password));
}

function parseECDSAPrivateKey(encryptionKey, privKey) {
    return new sjcl.ecc.ecdsa.secretKey(
        sjcl.ecc.curves.c384,
        sjcl.ecc.curves.c384.field.fromBits(fromB64(decrypt(encryptionKey, privKey)))
    )
}

function encrypt(key, data) {
    var stringData;
    if (typeof data !== "string" || !(data instanceof String)) {
        stringData = JSON.stringify(data);
    } else {
        stringData = data;
    }
    var cipher = JSON.parse(sjcl.encrypt(key, stringData));
    for (var prop in sjcl.json.defaults) {
        if (sjcl.json.defaults.hasOwnProperty(prop)) {
            if (cipher.hasOwnProperty(prop)) {
                delete cipher[prop];
            }
        }
    }
    return cipher;
}

function decrypt(key, encryptedData) {
    var cipher;
    if (typeof encryptedData === "object" || encryptedData instanceof Object) {
        cipher = encryptedData;
    } else if (typeof encryptedData === "string" || encryptedData instanceof String) {
        cipher = JSON.parse(encryptedData);
    } else {
        return;
    }
    for (var prop in sjcl.json.defaults) {
        if (sjcl.json.defaults.hasOwnProperty(prop)) {
            if (!cipher.hasOwnProperty(prop)) {
                cipher[prop] = sjcl.json.defaults[prop];
            }
        }
    }
    return JSON.parse(sjcl.decrypt(key, JSON.stringify(cipher)));
}

function decryptPasswords(key, encryptedPasswords) {
    var decodedPasswords;
    if (typeof encryptedPasswords === "string" && encryptedPasswords instanceof String) {
        decodedPasswords = JSON.parse(encryptedPasswords);
    } else {
        decodedPasswords = encryptedPasswords;
    }
    return decodedPasswords.map(function (encryptedPassword) {
        var decryptedPassword = {};
        decryptedPassword.name = decrypt(key, encryptedPassword.name);
        decryptedPassword.url = decrypt(key, encryptedPassword.url);
        decryptedPassword.username = decrypt(key, encryptedPassword.username);
        decryptedPassword.password = decrypt(key, encryptedPassword.password);
        decryptedPassword.notes = decrypt(key, encryptedPassword.notes);
        decryptedPassword.id = encryptedPassword.id;
        return decryptedPassword;
    });
}
