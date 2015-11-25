#include "keyversions.h"

namespace Crypto
{
	namespace KeyServiceVersions
	{
		const KeyVersion MIN_AVAILABLE_VERSION = 20; // twenty first values reserved for service data
		const KeyVersion MAX_AVAILABLE_VERSION = 100; // we can increase it any time

		const KeyVersion ERROR_VERSION = 0;
		const KeyVersion UNKNOWN_NEW_VERSION = 1;
	}
}
