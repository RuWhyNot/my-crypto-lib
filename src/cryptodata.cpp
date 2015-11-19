#include "cryptodata.h"

namespace Crypto
{
	class Data::Impl
	{
	public:
		std::string testData;
		std::vector<uint8_t> data;
	};

	Data::Data(const std::string& data)
	{
		Init();
		pimpl->testData = data;
	}

	Data::Data(const std::vector<uint8_t>& data)
	{
		Init();
		pimpl->data = data;
	}

	Data::Data(const FileStream::Ptr data)
	{
		Init();
	}

	Data::~Data()
	{

	}

	std::string Data::ToString() const
	{
		return pimpl->testData;
	}

	std::string Data::ToHex() const
	{
		return pimpl->testData;
	}

	void Data::Init()
	{
		pimpl = std::unique_ptr<Impl>(new Impl());
	}

}
