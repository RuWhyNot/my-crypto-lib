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

	Data::Ptr Data::Create(const std::wstring& message)
	{
		Data* dataRawPtr = new Data();

		uint8_t const* p = reinterpret_cast<uint8_t const*>(message.data());
		std::size_t size = message.size() * sizeof(wchar_t);
		dataRawPtr->pimpl->data = RawData(p, p+size);

		// raw ptr will be deleted automatically
		return Data::Ptr(dataRawPtr);
	}

	Data::Ptr Data::Create(const std::string& data, Encoding encoding)
	{
		Data* dataRawPtr = new Data();

		std::unique_ptr<CryptoPP::BaseN_Decoder> decoder;

		if (encoding == Encoding::Base64)
		{
			decoder = std::unique_ptr<CryptoPP::Base64Decoder>(new CryptoPP::Base64Decoder());
		}
		else if (encoding == Encoding::Hex)
		{
			decoder = std::unique_ptr<CryptoPP::HexDecoder>(new CryptoPP::HexDecoder());
		}

		decoder->Put((byte*)data.data(), data.size());
		decoder->MessageEnd();

		CryptoPP::word64 size = decoder->MaxRetrievable();
		if(size)
		{
			dataRawPtr->pimpl->data.resize(size);
			RawData& dataRef = dataRawPtr->pimpl->data;
			decoder->Get(dataRef.data(), dataRef.size());
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

	std::wstring Data::ToString() const
	{
		return std::wstring(reinterpret_cast<wchar_t*>(pimpl->data.data()), pimpl->data.size()/sizeof(wchar_t));
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

} // namespace Crypto
