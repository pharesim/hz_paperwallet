function getAccountId(secretPhrase) {
	return getAccountIdFromPublicKey(getPublicKey(converters.stringToHexString(secretPhrase)));
}

function getAccountIdFromPublicKey(publicKey, RSFormat) {
	if (typeof RSFormat === 'undefined') { 
		RSFormat = true; 
	}

	var hex = converters.hexStringToByteArray(publicKey);

	_hash.init();
	_hash.update(hex);

	var account = _hash.getBytes();

	account = converters.byteArrayToHexString(account);

	var slice = (converters.hexStringToByteArray(account)).slice(0, 8);

	var accountId = converters.byteArrayToBigInteger(slice,0).toString();

	if (RSFormat) {
		var address = new NhzAddress();

		if (address.set(accountId)) {
			return address.toString();
		} else {
			return "";
		}
	} else {
		return accountId;
	}
}

function generatePublicKey(secretPhrase) {
	return getPublicKey(converters.stringToHexString(secretPhrase));
}

function getPublicKey(secretPhrase, isAccountNumber) {
	var secretPhraseBytes = converters.hexStringToByteArray(secretPhrase);
	var digest = simpleHash(secretPhraseBytes);
	return converters.byteArrayToHexString(curve25519.keygen(digest).p);
}