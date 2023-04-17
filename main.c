#include "libbase64.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <memory>
#include <string>

#include <iostream>
#include <thread>
#include <mutex>
#include <atomic>
#include <vector>
#include <cstring>
#include <cstdint>
#define NOMINMAX
#include<Windows.h>

//def PRVd0cjlOk(text, key) :
//    decrypted = bytearray(len(text))
//    i = 0
//    for byteValue in text :
//
//decrypted[i] = (byteValue ^ key) & 0xFF
//i += 1
//return decrypted
//
//firstDecoded = base64.b64decode(firstString)
//
//for index in range(80000, 0xFFFFFFFF) :
//    key = index
//    firstDecrypted = PRVd0cjlOk(firstDecoded, key)
//    # print(hex(firstDecoded[0]))
//    # print(type(firstDecrypted))
//    # print(hex(firstDecrypted[0]))
//    try :
//    firstDecryptedString = firstDecrypted.decode('utf-8')
//    secondDecrypted = base64.b64decode(firstDecryptedString)
//    print("success at key = %d" % key)
//    #print(secondDecrypted)
//    # for i in range(0, len(secondDecrypted)) :
//    #     print(hex(secondDecrypted[i]))
//    #     break
//
//    if len(secondDecrypted) > 0:
//if secondDecrypted[0] == 0x4D and secondDecrypted[1] == 0x5A :
//    print("Found the DLL:")
//    print(secondDecrypted)
//
//    exit(0)
//
//    except(UnicodeEncodeError, ValueError) as e :
//pass # ignore the exception and try another key
//
//
//
//
//#print(hex(firstDecoded[0]))
//#print(firstDecrypted)

uint8_t* PRVd0cjlOk(const uint8_t* text, uint32_t key)
{
	size_t inputLen = strlen((char*)text);
	uint8_t* decrypted = (uint8_t*)malloc(inputLen);
	for (size_t i = 0; i < inputLen; i++) {
		decrypted[i] = (text[i] ^ key) & 0xFF;
	}
	return decrypted;
}

char* ReadInputFile() {
	FILE* hamadFile = fopen("C:\\Users\\DFIR\\Documents\\samples\\mShell\\brutforce-shell\\x64\\Release\\input.txt", "rb");
	//FILE* hamadFile = fopen("C:\\Users\\DFIR\\Documents\\samples\\mShell\\brutforce-shell\\x64\\Release\\input2.txt", "rb");
	if (hamadFile) {
		fseek(hamadFile, 0, SEEK_END);
		long fileSize = ftell(hamadFile);
		fseek(hamadFile, 0, SEEK_SET);
		char* data = (char*)malloc(fileSize);
		if (!data)
			return nullptr;
		size_t bytesRead = fread(data, 1, fileSize, hamadFile);
		if (bytesRead != fileSize) {
			printf("fread: failed to read file | bytesRead = %u | fileSize = %u\n", bytesRead, fileSize);
			return nullptr;
		}
		fclose(hamadFile);
		return data;
	}
	printf("failed to open file\n");
	return nullptr;
}

std::string FromBase64(char* input) {
	std::string str;
	str.resize(strlen(input));

	size_t outputLen = 0;
	base64_decode(input, strlen(input), (char*)str.data(), &outputLen, 0);
	//printf("FromBase64: inputLen = %u | outputLen = %u\n", strlen(input), outputLen);
	/*for (int i = 0; i < 10; i++)
	{
		printf("%hhx ", str[i]);
	}*/
	//printf("\n");
	return str;
}

void PrintArray(uint8_t* arr, int size)
{
	for (int i = 0; i < size; i++)
	{
		printf("%hhx ", arr[i]);
	}
	printf("\n");
	for (int i = 0; i < size; i++)
	{
		printf("%c ", arr[i]);
	}
	printf("\n");
	printf("\n");
}


std::mutex cout_mutex;

const uint64_t MAX_KEY = 0xFFFFFFFF;
std::atomic<uint64_t> current_key(0);

#include <time.h>
#include <algorithm>
clock_t oldTime = clock();
void searchForKey(const uint8_t* firstDecodedString, uint64_t* found_key, int threadId) {
	while (true) {
		uint64_t key = current_key.fetch_add(1);
		if (key > MAX_KEY) break;
		uint32_t theKey = key;
		if (clock() - oldTime > 20000) // 20 seconds
		{
			oldTime = clock();
			printf("\n\nthread %d: key = (%#.8x) %u\n", threadId, theKey, theKey);
		}
		
		char* firstDecrypted = (char*)PRVd0cjlOk(firstDecodedString, theKey);
		firstDecrypted[100] = '\0';
		std::string secondDecrypted = FromBase64(firstDecrypted);
		if (secondDecrypted.size() > sizeof(IMAGE_DOS_HEADER)) {
			uint8_t* bytes = (uint8_t*)secondDecrypted.data();
			//if (bytes[0] != 0 && bytes[1] != 0 && bytes[2] != 0) {
				if (bytes[0] == 0x4D && bytes[1] == 0x5A) {
					printf("\n\nFOUNDKEY IN thread %d: key = (%#.8x) %u\n", threadId, theKey, theKey);
					*found_key = theKey;
					break;
				}
				/*printf("key = (%#.8x) %u\n", theKey, theKey);
				PrintArray(bytes, std::min(secondDecrypted.size(), (size_t)100));*/
				PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)bytes;
				uint8_t* PEHeader = bytes + dosHeader->e_lfanew;

				if (secondDecrypted.size() > dosHeader->e_lfanew) {
					if (PEHeader[0] == 0x50 && PEHeader[1] == 0x45) {
						printf("yeah, PE HEADER\n");
						printf("\n\nFOUNDKEY IN thread %d: key = (%#.8x) %u\n", threadId, theKey, theKey);
						*found_key = theKey;
						break;
					}
					//PIMAGE_NT_HEADERS64 ntHeader = (PIMAGE_NT_HEADERS64)()
				}
			//}
		}
	}
}

int main()
{
	char* firstString = ReadInputFile();
	if (!firstString)
		return 0;
	std::string firstDecoded = FromBase64(firstString);
	uint8_t* firstDecodedString = (uint8_t*)firstDecoded.data();
	firstDecodedString[100] = '\0';

	int num_threads = std::thread::hardware_concurrency();
	std::vector<std::thread> threads;
	std::vector<uint64_t> found_keys(num_threads, MAX_KEY);
	printf("num_threads = %d\n", num_threads);
	

	for (int i = 0; i < num_threads; ++i) {
		threads.emplace_back(searchForKey, firstDecodedString, &found_keys[i], i);
	}

	for (auto& thread : threads) {
		thread.join();
	}

	for (int i = 0; i < num_threads; ++i) {
		if (found_keys[i] != MAX_KEY) {
			std::lock_guard<std::mutex> lock(cout_mutex);
			std::cout << "Found the DLL with key = " << found_keys[i] << std::endl;
		}
	}
	getchar();
	return 0;
}