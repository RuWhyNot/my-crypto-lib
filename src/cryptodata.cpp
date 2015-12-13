#include "cryptodata.h"

#include <string.h>
#include "../cryptopp/base64.h"
#include "../cryptopp/hex.h"

namespace Crypto
{
	class Data::Impl
	{
	public:
		std::vector<uint8_t> data;
	};

	Data::Data()
		: pimpl(new Impl())
	{
	}

	Data::~Data()
	{

	}

	Data::Ptr Data::CreateEmpty()
	{
		return Data::Ptr(new Data());
	}

	Data::Ptr Data::Create(const std::string& message)
	{
		Data* dataRawPtr = new Data();

		dataRawPtr->pimpl->data.reserve(message.size() + 1);
		dataRawPtr->pimpl->data.emplace_back(GetByteFromType(Type::PlainText));
		dataRawPtr->pimpl->data.insert(dataRawPtr->pimpl->data.end(), message.c_str(), message.c_str() + strlen(message.c_str()));

		// raw ptr will be deleted automatically
		return Data::Ptr(dataRawPtr);
	}

	Data::Ptr Data::Create(const std::string &data, Data::Encoding encoding)
	{
		return FromData(data, encoding, 1);
	}

	Data::Ptr Data::Create(const std::vector<uint8_t>& data)
	{
		Data* dataRawPtr = new Data();

		dataRawPtr->pimpl->data.reserve(data.size() + 1);
		dataRawPtr->pimpl->data.emplace_back(GetByteFromType(Type::PlainData));
		dataRawPtr->pimpl->data.insert(dataRawPtr->pimpl->data.end(), data.begin(), data.end());

		// raw ptr will be deleted automatically
		return Data::Ptr(dataRawPtr);
	}

	Data::Ptr Data::Restore(const std::string &data, Data::Encoding encoding)
	{
		return FromData(data, encoding, 0);
	}

	Data::Ptr Data::Restore(const std::vector<uint8_t> &data)
	{
		Data* dataRawPtr = new Data();

		dataRawPtr->pimpl->data = data;

		// raw ptr will be deleted automatically
		return Data::Ptr(dataRawPtr);
	}

	std::string Data::ToPlainString() const
	{
		if (IsEmpty())
		{
			return "";
		}

		return std::string(pimpl->data.begin() + 1, pimpl->data.end());
	}

	std::string Data::ToPlainHex() const
	{
		if (IsEmpty())
		{
			return "";
		}

		return GetHex(1);
	}

	std::string Data::ToPlainBase64() const
	{
		if (IsEmpty())
		{
			return "";
		}

		return GetBase64(1);
	}

	Data::RawData Data::ToPlainData() const
	{
		Data::RawData result;

		if (!IsEmpty())
		{
			result.assign(pimpl->data.begin() + 1, pimpl->data.end());
		}

		return result;
	}

	std::string Data::GetHexData() const
	{
		return GetHex(0);
	}

	std::string Data::GetBase64Data() const
	{
		return GetBase64(0);
	}

	bool Data::IsEmpty() const
	{
		return pimpl->data.size() <= 1;
	}

	const Data::RawData&Data::GetRawDataRef() const
	{
		return pimpl->data;
	}

	Data::Type Data::GetType() const
	{
		if (pimpl->data.size() < 1) {
			return Type::Error;
		}

		return GetTypeFromByte(pimpl->data[0]);
	}

	KeyVersion Data::GetVersion()
	{
		if (pimpl->data.size() < 3) {
			return KeyServiceVersions::ERROR_VERSION;
		}

		KeyVersion version = pimpl->data[1] << 8 | pimpl->data[2];

		if (version < KeyServiceVersions::MIN_AVAILABLE_VERSION || version > KeyServiceVersions::MAX_AVAILABLE_VERSION) {
			return KeyServiceVersions::ERROR_VERSION;
		}

		return version;
	}

	Fingerprint Data::GetFingerprint() const
	{
		if (pimpl->data.size() < 5) {
			return KeyServiceVersions::ERROR_VERSION;
		}

		return pimpl->data[3] << 8 | pimpl->data[4];
	}

	std::string Data::GetHex(int dataShift) const
	{
		std::string result;

		CryptoPP::HexEncoder encoder;
		encoder.Put(pimpl->data.data() + dataShift, pimpl->data.size() - dataShift);
		encoder.MessageEnd();

		CryptoPP::word64 size = encoder.MaxRetrievable();
		if(size)
		{
			result.resize(size);
			encoder.Get((uint8_t*)result.data(), result.size());
		}
		return result;
	}

	std::string Data::GetBase64(int dataShift) const
	{
		std::string result;

		CryptoPP::Base64Encoder encoder;
		CryptoPP::AlgorithmParameters params = CryptoPP::MakeParameters(CryptoPP::Name::Pad(), false)(CryptoPP::Name::InsertLineBreaks(), false);
		encoder.IsolatedInitialize(params);

		encoder.Attach(new CryptoPP::StringSink(result));
		CryptoPP::ArraySource(pimpl->data.data() + dataShift, pimpl->data.size() - dataShift, true, new CryptoPP::Redirector(encoder));

		return result;
	}

	Data::Ptr Data::FromData(const std::string &data, Encoding encoding, int dataShift)
	{
		Data* dataRawPtr = new Data();

		if (dataShift > 0)
		{
			dataRawPtr->pimpl->data.emplace_back(GetByteFromType(Type::PlainData));
		}

		if (encoding == Encoding::Base64)
		{
			CryptoPP::Base64Decoder decoder;
			decoder.Put((uint8_t*)data.data(), data.size());
			decoder.MessageEnd();

			size_t size = (size_t)decoder.MaxRetrievable();
			if(size && size <= SIZE_MAX)
			{
				uint8_t arr[size];
				decoder.Get(arr, size);
				dataRawPtr->pimpl->data.insert(dataRawPtr->pimpl->data.begin() + dataShift, arr, arr + size);
			}
		}
		else if (encoding == Encoding::Hex)
		{
			CryptoPP::HexDecoder decoder;
			decoder.Put((uint8_t*)data.data(), data.size());
			decoder.MessageEnd();

			size_t size = (size_t)decoder.MaxRetrievable();
			if(size && size <= SIZE_MAX)
			{
				uint8_t arr[size];
				decoder.Get(arr, size);
				dataRawPtr->pimpl->data.insert(dataRawPtr->pimpl->data.begin() + dataShift, arr, arr + size);
			}
		}

		// raw ptr will be deleted automatically
		return Data::Ptr(dataRawPtr);
	}

	uint8_t Data::GetByteFromType(Data::Type type)
	{
		switch (type) {
		case Type::PlainText:
			return 1;
		case Type::PlainData:
			return 2;
		case Type::PublicKey:
			return 3;
		case Type::PrivateKey:
			return 4;
		case Type::Cipher:
			return 5;
		case Type::Signature:
			return 6;
		default:
			return 0;
		}
	}

	Data::Type Data::GetTypeFromByte(uint8_t typeByte)
	{
		switch (typeByte) {
		case 1:
			return Type::PlainText;
		case 2:
			return Type::PlainData;
		case 3:
			return Type::PublicKey;
		case 4:
			return Type::PrivateKey;
		case 5:
			return Type::Cipher;
		case 6:
			return Type::Signature;
		default:
			return Type::Error;
		}
	}

} // namespace Crypto
