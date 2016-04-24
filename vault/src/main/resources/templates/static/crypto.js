/**
 * Created by papacharlie on 4/22/16.
 */

function hash(data) {
    return sjcl.hash.sha256.hash(data);
}

function encrypt(key, data) {
    var stringData;
    if (typeof data !== "string" && !(data instanceof String)) {
        stringData = JSON.stringify(data);
    } else {
        stringData = data;
    }
    return JSON.parse(sjcl.encrypt(key, stringData));
}

function decrypt(key, encryptedData) {
    if (typeof encryptedData !== "string" && !(encryptedData instanceof String)) {
        return sjcl.decrypt(key, JSON.stringify(encryptedData));
    } else {
        return sjcl.decrypt(key, encryptedData);
    }
}

function decryptPasswords(encryptedPasswords, key) {
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