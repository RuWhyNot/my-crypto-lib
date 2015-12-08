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

		dataRawPtr->pimpl->data.assign(message.c_str(), message.c_str() + strlen(message.c_str()));

		// raw ptr will be deleted automatically
		return Data::Ptr(dataRawPtr);
	}

	Data::Ptr Data::Create(const std::string &data, Data::Encoding encoding)
	{
		Data* dataRawPtr = new Data();

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
				dataRawPtr->pimpl->data = Data::RawData(arr, arr + size);
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
				dataRawPtr->pimpl->data = Data::RawData(arr, arr + size);
			}
		}

		// raw ptr will be deleted automatically
		return Data::Ptr(dataRawPtr);
	}

	Data::Ptr Data::Create(const std::vector<uint8_t>& data)
	{
		Data* dataRawPtr = new Data();

		dataRawPtr->pimpl->data = data;

		// raw ptr will be deleted automatically
		return Data::Ptr(dataRawPtr);
	}

	std::string Data::ToString() const
	{
		return std::string(pimpl->data.begin(), pimpl->data.end());
	}

	std::string Data::ToHex() const
	{
		std::string result;

		CryptoPP::HexEncoder encoder;
		encoder.Put(pimpl->data.data(), pimpl->data.size());
		encoder.MessageEnd();

		CryptoPP::word64 size = encoder.MaxRetrievable();
		if(size)
		{
			result.resize(size);
			encoder.Get((uint8_t*)result.data(), result.size());
		}
		return result;
	}

	std::string Data::ToBase64() const
	{
		std::string result;

		CryptoPP::Base64Encoder encoder;
		CryptoPP::AlgorithmParameters params = CryptoPP::MakeParameters(CryptoPP::Name::Pad(), false)(CryptoPP::Name::InsertLineBreaks(), false);
		encoder.IsolatedInitialize(params);

		encoder.Attach(new CryptoPP::StringSink(result));
		CryptoPP::ArraySource as(pimpl->data.data(), pimpl->data.size(), true, new CryptoPP::Redirector(encoder));

		return result;
	}

	bool Data::IsEmpty() const
	{
		return pimpl->data.empty();
	}

	const Data::RawData&Data::GetRawDataRef() const
	{
		return pimpl->data;
	}

	KeyVersion Data::GetVersion()
	{
		if (pimpl->data.size() < 2) {
			return KeyServiceVersions::ERROR_VERSION;
		}

		KeyVersion version = pimpl->data[0] << 8 | pimpl->data[1];

		if (version < KeyServiceVersions::MIN_AVAILABLE_VERSION || version > KeyServiceVersions::MAX_AVAILABLE_VERSION) {
			return KeyServiceVersions::ERROR_VERSION;
		}

		return version;
	}

	Fingerprint Data::GetFingerprint() const
	{
		if (pimpl->data.size() < 4) {
			return KeyServiceVersions::ERROR_VERSION;
		}

		return pimpl->data[2] << 8 | pimpl->data[3];
	}

} // namespace Crypto
