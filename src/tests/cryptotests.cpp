#include "cryptotests.h"

#include <time.h>
#include <iostream>

#include "../privatekey.h"
#include "../publickeyimpl.h"

namespace CryptoTests
{
	bool CryptNEncryptTest(bool silent)
	{
		Crypto::Data::Ptr publicKeyData;
		Crypto::Data::Ptr privateKeyData;
		{
			Crypto::PrivateKey::Ptr privateKey = Crypto::PrivateKey::Generate(time(NULL));
			privateKeyData = privateKey->ToData();

			Crypto::PublicKey::Ptr publicKey = privateKey->GetPublicKey();
			publicKeyData = publicKey->ToData();
		}

		Crypto::PublicKey::Ptr publicKey = Crypto::PublicKeyImpl::CreateFromData(publicKeyData);
		Crypto::PrivateKey::Ptr privateKey = Crypto::PrivateKey::CreateFromData(privateKeyData);

		std::string plainText = "Text to encrypt";

		Crypto::Data::Ptr plain(Crypto::Data::Create(plainText));

		Crypto::Data::Ptr cipher = publicKey->EncryptData(plain);
		if (!silent) { std::cout << "Cipher: " << cipher->ToBase64() << std::endl; }

		Crypto::Data::Ptr recovered = privateKey->DecryptData(cipher);
		if (!silent) { std::cout << "Recovered text: " << recovered->ToString() << std::endl; }

		return recovered->ToString() == plainText;
	}

	bool SignNVerifyTest(bool silent)
	{
		Crypto::Data::Ptr publicKeyData;
		Crypto::PrivateKey::Ptr privateKey = Crypto::PrivateKey::Generate(time(NULL));

		{
			Crypto::PublicKey::Ptr publicKey = privateKey->GetPublicKey();
			publicKeyData = publicKey->ToData();
		}

		Crypto::PublicKey::Ptr publicKey = Crypto::PublicKeyImpl::CreateFromData(publicKeyData);

		Crypto::Data::Ptr plain(Crypto::Data::Create("Text to sign"));

		Crypto::Signature::Ptr signature = privateKey->SignData(plain);
		if (!silent) { std::cout << "Signature: " << signature->ToData()->ToBase64() << std::endl; }

		{
			bool isCorrect = publicKey->VerifySignature(plain, signature);
			if (!isCorrect) { return false; }
			if (!silent) { std::cout << "Signature : " << (isCorrect ? "Valid" : "Invalid") << std::endl; }
		}

		{
			Crypto::Data::Ptr invalidData = Crypto::Data::Create(plain->ToString() + "asd");
			bool isCorrect = publicKey->VerifySignature(invalidData, signature);
			if (isCorrect) { return false; }
			if (!silent) { std::cout << "Signature : " << (isCorrect ? "Valid" : "Invalid") << std::endl; }
		}

		return true;
	}

	bool RunAlltests(bool silent)
	{
		if (!CryptNEncryptTest(silent)) { return false; }
		if (!SignNVerifyTest(silent)) { return false; }
		return true;
	}

	bool RunAlltestsNTimes(int n)
	{
		for (int i = 0; i < n; ++i) {
			if (!RunAlltests(true)) {
				return false;
			}
		}
		return true;
	}

} // namespace CryptoTests
