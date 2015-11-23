#pragma once

namespace CryptoTests
{
	bool RunAlltests(bool silent = false);
	bool RunAlltestsNTimes(int n);

	bool CryptNEncryptTest(bool silent = false);
	bool SignNVerifyTest(bool silent = false);
	bool Base64Test(bool silent = false);
}
