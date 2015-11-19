#include "cryptodata.h"

namespace Crypto
{
	class Data::Impl
	{
	public:
		std::string testData;
	};

	Data::Data()
		: pimpl(new Impl())
	{
	}

	Data::Data(const std::string& data)
	{
		Data();
		pimpl->testData = data;
	}

	Data::Data(const std::vector<uint8_t>& data)
	{
		Data();
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

}
