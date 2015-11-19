#pragma once

#include <string>

#include "cryptodata.h"

namespace Crypto
{
	class Signature : public Data
	{
	public:
		typedef std::shared_ptr<Signature> Ptr;

	public:
		Signature();
		~Signature();
	};

} // namespace Crypto
