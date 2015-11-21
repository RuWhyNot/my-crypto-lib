#include "cryptodata.h"

namespace Crypto
{
	class Data::Impl
	{
	public:
		std::string testData;
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

		dataRawPtr->pimpl->testData = data;

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

	Data::Ptr Data::Create(const FileStream::Ptr data)
	{
		Data* dataRawPtr = new Data();

		// raw ptr will be deleted automatically
		return Data::Ptr(dataRawPtr);
	}

	std::string Data::ToString() const
	{
		return pimpl->testData;
	}

	std::string Data::ToHex() const
	{
		return pimpl->testData;
	}

	std::string Data::ToBase64() const
	{
		return pimpl->testData;
	}

}
