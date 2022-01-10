
#ifndef DYNAMICSSE_HASHMAP_KEY_CLASS_H_
#define DYNAMICSSE_HASHMAP_KEY_CLASS_H_

#include <stdlib.h>
#include <string.h>
#include <algorithm>
#include <iostream>

using namespace std;


class hashmap_key_class
{

private:
	unsigned char *pData;
	int			   data_length;

public:

	// Constructors
	hashmap_key_class();
	hashmap_key_class(int data_len);
	hashmap_key_class(const unsigned char *pIndata, int data_len);
	hashmap_key_class(const hashmap_key_class &rObj);

	// Destructor
	~hashmap_key_class();

	// Getters
	int get_data_length() const;
	unsigned char* get_data() const;

	// Setter
	void set_data(unsigned char* data, int data_len);

	// Prints the data
	void print_data() const;

	// Prints the data length
	void print_data_length() const;

	//equal comparison operator for this class
	bool operator()(const hashmap_key_class &rObj1, const hashmap_key_class &rObj2) const;

	//hashing operator for this class
	size_t operator()(const hashmap_key_class &rObj) const;

	// Assignment operator
	hashmap_key_class& operator=(const hashmap_key_class &rObj);
	hashmap_key_class& operator=(const unsigned char *pIndata);
};

#endif /* DYNAMICSSE_HASHMAP_KEY_CLASS_H_ */
