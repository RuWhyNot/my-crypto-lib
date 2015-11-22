#include "signature.h"

namespace Crypto
{
	class Signature::Impl
	{
	public:
		Data::Ptr data;
	};

	Signature::Signature()
		: pimpl(new Impl())
	{

	}

	Signature::~Signature()
	{

	}

	Signature::Ptr Signature::CreateFromData(Data::Ptr data)
	{
		Signature *rawSignaturePtr = new Signature();

		rawSignaturePtr->pimpl->data = data;

		// raw ptr will be deleted automatically
		return Signature::Ptr(rawSignaturePtr);
	}

	Data::Ptr Signature::ToData() const
	{
		return pimpl->data;
	}
} // namespace Crypto
