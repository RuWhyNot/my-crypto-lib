#ifndef PUBLICKEY_H
#define PUBLICKEY_H

#include "key.h"

namespace CryptoPP { class RSAFunction; }

namespace Crypto
{
	class PublicKey : public Key
	{
	public:
		typedef std::shared_ptr<PublicKey> Ptr;

	public:
		PublicKey(const CryptoPP::RSAFunction& initData);
		~PublicKey();

		Data::Ptr EncryptData(const Data::Ptr data);
		bool VerifySignature(const Data::Ptr data, Signature::Ptr signature);

		virtual std::string ToString() const override;
		virtual std::string ToHex() const override;

	private:
		PublicKey();

		class Impl;
		std::unique_ptr<Impl> pimpl;
	};
}

#endif // PUBLICKEY_H
