#pragma once

#include "../../cryptopp/rsa.h"
#include "../privatekey.h"

namespace Crypto
{
	class PrivateKey_v20 : public PrivateKey
	{
	public:
		static PrivateKey::Ptr Generate(unsigned long seed, int size = 512);
		static PrivateKey::Ptr CreateFromData(Data::Ptr keyData);

		virtual Data::Ptr DecryptData(const Data::Ptr cryptedData) const override;
		virtual Signature::Ptr SignData(const Data::Ptr data) const override;

		PublicKey::Ptr GetPublicKey();

		virtual Fingerprint GetFingerprint() const override;

		Data::Ptr ToData() const;

	private:
		PrivateKey_v20();

	private:
		CryptoPP::RSA::PrivateKey privateKey;
		Fingerprint fingerprint;
	};
}
