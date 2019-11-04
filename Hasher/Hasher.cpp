#include "picosha2.h"
#include <iostream>
#include <fstream>

int main(int argc, char* argv[])
{
	if (argc != 2)
	{
		std::cout << "Usage: Hasher.exe <path_to_file>" << std::endl;
		return 1;
	}
	std::ifstream input(std::string(argv[1]), std::ios::binary);
	if (input.fail())
	{
		std::cout << "Couldn't open file " << argv[1] << std::endl;
		return 1;
	}
	picosha2::hash256_one_by_one hasher;
	hasher.process(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
	hasher.finish();

	std::string hex_str = picosha2::get_hash_hex_string(hasher);
	std::cout << "HASH: " << hex_str << std::endl;
	return 0;
}