#include "tests/cryptotests.h"

#include <iostream>

int main()
{
	int n = 1000;
	bool success = CryptoTests::RunAlltestsNTimes(n);
	if (success) {
		std::cout << "All tests passed " << n << " times" << std::endl;
	} else {
		std::cout << "Some tests failed" << std::endl;
	}

	return 0;
}

