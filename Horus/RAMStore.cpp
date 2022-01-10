#include "RAMStore.hpp"
#include <iostream>
#include "ORAM.hpp"
using namespace std;

RAMStore::RAMStore(size_t count, size_t size)
: store(count), size(size),emptyNodes(count)
{}

RAMStore::~RAMStore()
{}

block RAMStore::Read(int pos)
{
	return store[pos];
}

void RAMStore::Write(int pos, block b)
{
	store[pos] = b;
}

size_t RAMStore::GetBlockCount()
{
	return store.size();
}

size_t RAMStore::GetBlockSize()
{
	return size;
}

bool RAMStore::WasSerialised()
{
	return false;
}

void RAMStore::ReduceEmptyNumbers() {
    emptyNodes--;
}

size_t RAMStore::GetEmptySize() {
    return emptyNodes;
}

void RAMStore::save_data(FILE *f_out)
{
    size_t size1;

    size1 = this->store.size();

    fwrite(&size1, sizeof(size1), 1, f_out);
    for (auto &itr:this->store)
    {
        size1 = itr.size();
        fwrite(&size1, sizeof(size1), 1, f_out);
        fwrite(itr.data(), sizeof(byte_t), size1, f_out);
    }

    fwrite(&this->size, sizeof(this->size), 1, f_out);
    fwrite(&this->emptyNodes, sizeof(this->emptyNodes), 1, f_out);
}

void RAMStore::load_data(FILE *f_in)
{
    size_t size1, size2;

    this->store.clear();

    fread(&size1, sizeof(size1), 1, f_in);
    for (size_t i = 0; i < size1; i++)
    {
        fread(&size2, sizeof(size2), 1, f_in);
        block b(size2);
        fread(b.data(), sizeof(byte_t), size2, f_in);
        this->store.emplace_back(b);
    }

    fread(&this->size, sizeof(this->size), 1, f_in);
    fread(&this->emptyNodes, sizeof(this->emptyNodes), 1, f_in);
}
