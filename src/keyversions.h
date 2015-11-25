#pragma once

#include <stdint.h>

namespace Crypto
{
	typedef uint16_t KeyVersion;

	namespace KeyServiceVersions
	{
		extern const KeyVersion MIN_AVAILABLE_VERSION;
		extern const KeyVersion MAX_AVAILABLE_VERSION;

		extern const KeyVersion ERROR_VERSION;
		extern const KeyVersion UNKNOWN_NEW_VERSION;
	}
}
