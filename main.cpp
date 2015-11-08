#include <iostream>

#include "cryptopp/rsa.h"
#include "cryptopp/algparam.h"
#include "cryptopp/external/mersenne.h"
#include "cryptopp/base64.h"
#include "cryptopp/aes.h"

int main()
{
	CryptoPP::MT19937 rng;
	CryptoPP::InvertibleRSAFunction params;
	params.GenerateRandomWithKeySize(rng, 512);

	///////////////////////////////////////
	// Create Keys
	CryptoPP::RSA::PrivateKey privateKey(params);
	CryptoPP::RSA::PublicKey publicKey(params);

	string plain="RSA Encryption", cipher, recovered;

	////////////////////////////////////////////////
	// Encryption
	CryptoPP::RSAES_OAEP_SHA_Encryptor e(publicKey);

	CryptoPP::StringSource ss1(plain, true,
		new CryptoPP::PK_EncryptorFilter(rng, e,
			new CryptoPP::StringSink(cipher)
	   ) // PK_EncryptorFilter
	); // StringSource

	std::cout << "Crypted text: \"" << cipher << "\"" << std::endl;

	////////////////////////////////////////////////
	// Decryption
	CryptoPP::RSAES_OAEP_SHA_Decryptor d(privateKey);

	CryptoPP::StringSource ss2(cipher, true,
		new CryptoPP::PK_DecryptorFilter(rng, d,
			new CryptoPP::StringSink(recovered)
	   ) // PK_DecryptorFilter
	); // StringSource

	std::cout << "Recovered plain text: \"" << recovered << "\"" << std::endl;

	return 0;
}

