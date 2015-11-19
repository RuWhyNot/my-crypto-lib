#ifndef PRIVATEKEY_H
#define PRIVATEKEY_H

#include "publickey.h"

namespace Crypto
{
	class PrivateKey : public Key
	{
	public:
		typedef std::shared_ptr<PrivateKey> Ptr;

	public:
		~PrivateKey();

		static PrivateKey::Ptr Generate(unsigned int seed);

		Data::Ptr DecryptData(const Data::Ptr cryptedData);
		Signature::Ptr SignData(const Data::Ptr data);

		PublicKey::Ptr GetPublicKey();

		virtual std::string ToString() const override;
		virtual std::string ToHex() const override;

	private:
		PrivateKey();

		class Impl;
		std::unique_ptr<Impl> pimpl;
	};
}

#endif // PRIVATEKEY_H
