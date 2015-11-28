#include <iostream>

#include "tests/cryptotests.h"
#include "versions/v20/publickey_v20.h"
#include "versions/v20/privatekey_v20.h"

int main()
{
	CryptoTests::TestKeyFactory.RegisterDataKeysConverters(20, Crypto::PrivateKey_v20::CreateFromData, Crypto::PublicKey_v20::CreateFromData);
	CryptoTests::TestKeyFactory.RegisterDataKeyGenerator(20, Crypto::PrivateKey_v20::Generate);

	CryptoTests::RunAlltests();

	int n = 100;
	bool success = CryptoTests::RunAlltestsNTimes(n);
	if (success) {
		std::cout << "All tests passed " << n << " times" << std::endl;
	} else {
		std::cout << "Some tests failed" << std::endl;
	}

	return 0;
}

