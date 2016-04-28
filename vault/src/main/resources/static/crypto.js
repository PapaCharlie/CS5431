/**
 * Created by papacharlie on 4/22/16.
 */

function hash(data) {
    return sjcl.hash.sha256.hash(data);
}

function toBits(data) {
    return sjcl.codec.utf8String.toBits(data);
}

function fromBits(data) {
    return sjcl.codec.base64url.fromBits(data);
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
        decryptedPassword.id = encryptedPassword.id;
        return decryptedPassword;
    });
}

function fromB64(data) {
    return sjcl.codec.base64url.toBits(data);
}