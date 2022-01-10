#include "DSSE_Hashmap_Key_Class.h"

// Default constructor
hashmap_key_class::hashmap_key_class()
{
	// TODO Auto-generated constructor stub
	this->pData = NULL;
	this->data_length = 0;
}

// Other Constructors
hashmap_key_class::hashmap_key_class(int data_len)
{
	if (data_len > 0)
    {
		this->pData = new unsigned char[data_len];
		this->data_length = data_len;
	}
	else
    {
		this->pData = NULL;
		this->data_length = 0;
	}
}

hashmap_key_class::hashmap_key_class(const unsigned char *pIndata, int data_len)
{
	if ((data_len>0) && (pIndata != NULL))
    {
		this->pData = new unsigned char [data_len];
		this->data_length = data_len;
		memcpy(this->pData,pIndata,data_len);
	}
	else
    {
		this->pData = NULL;
		this->data_length = 0;
	}
}

hashmap_key_class::hashmap_key_class(const hashmap_key_class &rObj)
{
	if((rObj.pData != NULL) && (rObj.data_length>0))
    {
		this->pData = new unsigned char [rObj.data_length];
		this->data_length = rObj.data_length;
		memcpy(this->pData,rObj.pData,rObj.data_length);
	}
	else
    {
		this->pData = NULL;
		this->data_length = 0;
	}
}

// Destructor
hashmap_key_class::~hashmap_key_class()
{
	if(this->pData != NULL)
		delete[] this->pData;

	this->data_length = 0;
}

// Getters
int hashmap_key_class::get_data_length() const
{
	return data_length;
}

unsigned char* hashmap_key_class::get_data() const
{
	return pData;
}

// Setter
void hashmap_key_class::set_data(unsigned char* data, int data_len)
{
	if ((data != NULL)&& (data_len > 0))
    {
		copy(data,data+data_len,this->pData);
		this->data_length = data_len;
	}
	else
    {
		this->pData = NULL;
		this->data_length = 0;
	}
}

void hashmap_key_class::print_data() const
{
	int i = 0;

	if(this->data_length > 0 && this->pData != NULL)
    {
		for(i=0;i<this->data_length;i++)
			cout << (int)this->pData[i];
	}
	else
    {
		cout << "No data" << endl;
	}
}

// Prints the data length
void hashmap_key_class::print_data_length() const
{
	cout << this->data_length;
}

//equal comparison operator for this class
bool hashmap_key_class::operator()(const hashmap_key_class &rObj1, const hashmap_key_class &rObj2) const
{
	if((rObj1.data_length == 0) && (rObj2.data_length ==0))
		return 1;
	else if((rObj1.data_length == rObj2.data_length)&& (memcmp(rObj2.pData, rObj1.pData,rObj1.data_length ) == 0))
		return 1;
	else
		return 0;
}

//hashing operator for this class
size_t hashmap_key_class::operator()(const hashmap_key_class &rObj) const
{
	size_t tmp = 0;
	int maxhashsize = 0;

	if (rObj.pData != NULL)
    {
		if (rObj.data_length == 0)
			return tmp;
		else
        {
			int indx =0;
			maxhashsize = sizeof(size_t);

			tmp = tmp | rObj.pData[0];
			for(indx=1; indx < maxhashsize; indx++){
				tmp = tmp << 8;
				tmp = tmp | rObj.pData[indx];
			}
			return tmp;
		}
	}
	else
		return tmp;
}

// Assignment operators
hashmap_key_class& hashmap_key_class::operator=(const hashmap_key_class &rObj)
{
	if(rObj.pData != NULL && rObj.data_length>0)
    {
		this->pData = new unsigned char [rObj.data_length];
		this->data_length = rObj.data_length;
	    memcpy(this->pData,rObj.pData,rObj.data_length);
		return *this;
	}
	else
    {
		this->pData = NULL;
		this->data_length = 0;
		return *this;
	}
}