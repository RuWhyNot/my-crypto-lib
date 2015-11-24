#include "cryptotests.h"

#include <time.h>
#include <iostream>

#include "../privatekey.h"
#include "../publickeyimpl.h"

namespace CryptoTests
{	
	bool RunAlltests(bool silent)
	{
		if (!CryptNEncryptTest(silent)) { return false; }
		if (!SignNVerifyTest(silent)) { return false; }
		if (!Base64Test(silent)) { return false; }
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

	bool CryptNEncryptTest(bool silent)
	{
		Crypto::Data::Ptr publicKeyData;
		Crypto::Data::Ptr privateKeyData;
		{
			Crypto::PrivateKey::Ptr privateKey = Crypto::PrivateKey::Generate(time(NULL), 1024);
			privateKeyData = privateKey->ToData();

			Crypto::PublicKey::Ptr publicKey = privateKey->GetPublicKey();
			publicKeyData = publicKey->ToData();
		}

		Crypto::PublicKey::Ptr publicKey = Crypto::PublicKeyImpl::CreateFromData(publicKeyData);
		Crypto::PrivateKey::Ptr privateKey = Crypto::PrivateKey::CreateFromData(privateKeyData);

		std::wstring plainText = L"Text";

		Crypto::Data::Ptr plain(Crypto::Data::Create(plainText));

		Crypto::Data::Ptr cipher = publicKey->EncryptData(plain);
		if (!silent) { std::cout << "[CryptNEncryptTest] " << "Cipher: " << cipher->ToBase64() << std::endl; }

		Crypto::Data::Ptr recovered = privateKey->DecryptData(cipher);
		if (!silent) { std::wcout << "[CryptNEncryptTest] " << "Recovered text: " << recovered->ToString() << std::endl; }

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

		Crypto::Data::Ptr plain(Crypto::Data::Create(L"Text to sign"));

		Crypto::Signature::Ptr signature = privateKey->SignData(plain);
		if (!silent) { std::cout << "[SignNVerifyTest] " << "Signature: " << signature->ToData()->ToBase64() << std::endl; }

		{
			bool isCorrect = publicKey->VerifySignature(plain, signature);
			if (!silent) { std::cout << "[SignNVerifyTest] " << "Signature : " << (isCorrect ? "Valid" : "Invalid") << std::endl; }
			if (!isCorrect) { return false; }
		}

		{
			Crypto::Data::Ptr invalidData = Crypto::Data::Create(plain->ToString() + L"asd");
			bool isCorrect = publicKey->VerifySignature(invalidData, signature);
			if (!silent) { std::cout << "[SignNVerifyTest] " << "Signature : " << (isCorrect ? "Valid" : "Invalid") << std::endl; }
			if (isCorrect) { return false; }
		}

		return true;
	}

	bool Base64Test(bool silent)
	{
		std::wstring text = L"Test text";
		Crypto::Data::Ptr plain = Crypto::Data::Create(text);
		std::string base64 = plain->ToBase64();
		Crypto::Data::Ptr recovered = Crypto::Data::Create(base64, Crypto::Data::Encoding::Base64);
		std::wstring recoveredStr = recovered->ToString();
		if (!silent) { std::wcout << "[Base64Test] " << "Recovered text: " << recoveredStr << std::endl; }
		return recoveredStr == text;
	}

} // namespace CryptoTests
