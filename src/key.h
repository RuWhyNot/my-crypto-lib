#pragma once

#include <memory>

#include "signature.h"
#include "cryptodata.h"

namespace Crypto
{
	class Key : public Data
	{
	public:
		typedef std::shared_ptr<Key> Ptr;

	public:
		Key();
		~Key();

		void Generate(unsigned int seed);

		Data::Ptr EncryptData(const Data::Ptr data);
		Data::Ptr DecryptData(const Data::Ptr cryptedData);

		Signature::Ptr SignData(const Data::Ptr data);
		bool VerifySignature(const Data::Ptr data, Signature::Ptr signature);

	private:
		class Impl;
		std::unique_ptr<Impl> pimpl;
	};

} // namespace Crypto
