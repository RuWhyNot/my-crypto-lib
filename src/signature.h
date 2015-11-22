#pragma once

#include <string>

#include "cryptodata.h"

namespace Crypto
{
	class Signature
	{
	public:
		typedef std::shared_ptr<Signature> Ptr;

	public:
		~Signature();

		static Ptr CreateFromData(Data::Ptr data);

		Data::Ptr ToData() const;

	private:
		Signature();

		class Impl;
		std::unique_ptr<Impl> pimpl;
	};

} // namespace Crypto
