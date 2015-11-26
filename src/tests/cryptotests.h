#pragma once

#include "../keyfactory.h"
#include "../keyring.h"

namespace CryptoTests
{
	extern Crypto::KeyFactory TestKeyFactory;

	bool CryptNEncryptTest(bool silent = false);
	bool SignNVerifyTest(bool silent = false);

	bool RunAlltests(bool silent = false);
	bool RunAlltestsNTimes(int n);
}
