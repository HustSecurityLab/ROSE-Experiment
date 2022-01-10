#ifndef MATRIX_TYPE_H
#define MATRIX_TYPE_H

// A structure for accessing the bit fields of a single character byte
struct BitType{
	unsigned char bit1:1;
	unsigned char bit2:1;
	unsigned char bit3:1;
	unsigned char bit4:1;
	unsigned char bit5:1;
	unsigned char bit6:1;
	unsigned char bit7:1;
	unsigned char bit8:1;
};
// A structure for accessing a variable as a byte character or each bit of it independently and is also the type of the matrix I
union MatrixType{
	unsigned char byte_data;
	BitType bit_data;
};

#endif