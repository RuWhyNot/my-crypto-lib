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

	Data::Ptr Data::Create(const std::string& data)
	{
		Data* dataRawPtr = new Data();

		dataRawPtr->pimpl->data.assign(data.c_str(), data.c_str() + strlen(data.c_str()));

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
			encoder.Get((byte*)result.data(), result.size());
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

	const Data::RawData&Data::GetRawDataRef() const
	{
		return pimpl->data;
	}

	void Data::SaveToFile(const std::string& fileName) const
	{

	}

	void Data::LoadFromFile(const std::string& fileName)
	{

	}

} // namespace Crypto
