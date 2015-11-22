#include "privatekey.h"

#include "../cryptopp/rsa.h"
#include "../cryptopp/algparam.h"
#include "../cryptopp/external/mersenne.h"
#include "../cryptopp/base64.h"
#include "../cryptopp/aes.h"

#include "publickeyimpl.h"

namespace Crypto
{
	class PrivateKey::Impl
	{
	public:
		CryptoPP::RSA::PrivateKey privateKey;
	};

	PrivateKey::PrivateKey()
		: pimpl(new Impl())
	{

	}

	PrivateKey::~PrivateKey()
	{

	}

	PrivateKey::Ptr PrivateKey::Generate(unsigned int seed)
	{
		PrivateKey::Ptr result(new PrivateKey());

		CryptoPP::MT19937 rng(seed);
		CryptoPP::InvertibleRSAFunction params;
		params.GenerateRandomWithKeySize(rng, 512);

		result->pimpl->privateKey = CryptoPP::RSA::PrivateKey(params);

		return result;
	}

	PrivateKey::Ptr PrivateKey::CreateFromData(Data::Ptr keyData)
	{
		return PrivateKey::Ptr(new PrivateKey());
	}

	Data::Ptr PrivateKey::DecryptData(const Data::Ptr cryptedData)
	{
		CryptoPP::MT19937 rng;
		CryptoPP::RSAES_OAEP_SHA_Decryptor decryptor(pimpl->privateKey);

		const Data::RawData& rawCryptedData = cryptedData->GetRawDataRef();

		uint8_t *rawResultDataPtr = new uint8_t[decryptor.MaxPlaintextLength(rawCryptedData.size())];

		CryptoPP::DecodingResult decodingResult = decryptor.Decrypt(rng, rawCryptedData.data(), rawCryptedData.size(), rawResultDataPtr);
		Data::RawData rawResultData(rawResultDataPtr, rawResultDataPtr + decodingResult.messageLength);

		delete[] rawResultDataPtr;

		if (decodingResult.isValidCoding) {
			return Data::Create(rawResultData);
		} else {
			return Data::Create("");
		}
	}

	Signature::Ptr PrivateKey::SignData(const Data::Ptr data)
	{
		CryptoPP::MT19937 rng;
		CryptoPP::RSASSA_PKCS1v15_SHA_Signer signer(pimpl->privateKey);

		const Data::RawData& rawData = data->GetRawDataRef();

		uint8_t *rawSignatureDataPtr = new uint8_t[signer.MaxSignatureLength()];

		size_t length =  signer.SignMessage(rng, rawData.data(), rawData.size(), rawSignatureDataPtr);
		Data::RawData rawSignatureData(rawSignatureDataPtr, rawSignatureDataPtr + length);

		delete[] rawSignatureDataPtr;

		return Signature::CreateFromData(Data::Create(rawSignatureData));
	}

	PublicKey::Ptr PrivateKey::GetPublicKey()
	{
		return std::make_shared<PublicKeyImpl>(pimpl->privateKey);
	}

	Data::Ptr PrivateKey::ToData() const
	{
		return Data::Create("");
	}
} // namespace Crypto
