#pragma once

#include <memory>

#include "signature.h"
#include "cryptodata.h"

namespace Crypto
{
	class Key
	{
	public:
		typedef std::shared_ptr<Key> Ptr;

	public:
		virtual ~Key() = default;

		virtual std::string ToString() const = 0;
		virtual std::string ToHex() const = 0;
	};

} // namespace Crypto
