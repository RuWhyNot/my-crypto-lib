#include "cryptodata.h"

#include <string.h>

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
		return ToString();
	}

	std::string Data::ToBase64() const
	{
		return ToString();
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
