#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include <iostream>
using std::wcout;
using std::wcin;
using std::cin;
using std::getline; 
using std::cout;
using std::cerr;
using std::endl;
using namespace std;



#include <string>
using std::string;
using std::wstring;

#include <cstdlib>
using std::exit;
using CryptoPP::byte;

#include "cryptopp/cryptlib.h"
using CryptoPP::Exception;
using CryptoPP::BufferedTransformation;
using CryptoPP::AuthenticatedSymmetricCipher;

#include "cryptopp/hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include "cryptopp/base64.h" 
using CryptoPP::Base64Encoder; // string to base64
using CryptoPP::Base64Decoder; // base64 to string

#include "cryptopp/filters.h" // string filters
using CryptoPP::ArraySink;
using CryptoPP::ArraySource; 
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::AuthenticatedEncryptionFilter;
using CryptoPP::AuthenticatedDecryptionFilter;
using CryptoPP::Redirector;

#include "cryptopp/des.h"
using CryptoPP::AES;

#include "cryptopp/modes.h"
using CryptoPP::CBC_Mode;
using CryptoPP::byte;

#include "cryptopp/secblock.h"
using CryptoPP::SecByteBlock;

// Convert unicode
#include <locale>
using std::wstring_convert;
#include <codecvt>
using  std::codecvt_utf8;

//setting 
#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#include <cassert>
#else
#endif

// Functions
wstring string_to_wstring (const std::string& str);
string wstring_to_string (const std::wstring& str);

int main()
{
	#ifdef __linux__
	setlocale(LC_ALL,"");
	#elif __APPLE__
    	#if TARGET_OS_MAC
        setlocale(LC_ALL,"");
		#else
		#endif
	#elif _WIN32
	_setmode(_fileno(stdin), _O_U16TEXT);
 	_setmode(_fileno(stdout), _O_U16TEXT);
	#else
	#endif

	int nkey, ikey;

	do
	{
	   wcout << " choose your size of key " << endl;
	   wcout << "1. 16 bytes" <<endl;
	   wcout << "2. 24 bytes" <<endl;
	   wcout << "3. 32 bytes" <<endl;
	   wcin >> nkey;
	   if (nkey<1 || nkey>=4) cout<<"Pls input"<<endl;
	} while (nkey<1 || nkey>=4);
	if ( nkey == 1)
	{
		ikey = 16;
		wcout << "size of key = " << ikey << endl;
	}
	else if (nkey == 2)
	{
		ikey = 24;
		wcout << "size of key = " << ikey << endl;
	}
	else if (nkey == 3)
	{
		ikey = 32;
		wcout << "size of key = " << ikey << endl;
	}
	wcin.ignore();

	
    byte key[ikey]; 	
	byte iv[16];   

	wstring wkey;
	string key1;
	wcout<<" please input your sercet key "<<endl;
	wcout<<"key : ";
	wcin.ignore();
	getline(wcin,wkey);
	key1=wstring_to_string(wkey);
	StringSource(key1, true, new HexDecoder( new ArraySink(key, sizeof(key))));

	wstring wiv;
	string iv1;
	wcout<<" please input your iv 16 bytes "<<endl;
	wcout<<"iv : ";
	wcin.ignore();
	getline(wcin,wiv);
	iv1=wstring_to_string(wiv);
	StringSource(iv1, true, new HexDecoder( new ArraySink(iv, sizeof(iv))));
	

	string plain;
	string cipher, encoded, recovered;    

    try
	{
		wstring wplain;
		string plain;
		wcout << "enter plain text you want to cipher: "<<endl;
		wcin.ignore();
		getline(wcin,wplain);

		wcout << "plain text: " << wplain << endl;
		plain = wstring_to_string(wplain);

        CBC_Mode< AES >::Encryption e;
		e.SetKeyWithIV(key, sizeof(key), iv);
		// The StreamTransformationFilter adds padding
		//  as required. ECB and CBC Mode must be padded
		//  to the block size of the cipher.
        StringSource(plain, true, 
			new StreamTransformationFilter(e,
				new StringSink(cipher)
			) // StreamTransformationFilter      
		); // StringSource

	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}

	/*********************************\
	\*********************************/

	// Pretty print
	
    encoded.clear();
	StringSource(cipher, true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	wcout << "cipher text: " << string_to_wstring(encoded) << endl;

	/*********************************\
	\*********************************/

	try
	{
		
        CBC_Mode< AES >::Decryption d;
		d.SetKeyWithIV(key, sizeof(key), iv);
        StringSource s(cipher, true, 
			new StreamTransformationFilter(d,
				new StringSink(recovered)
			) // StreamTransformationFilter
		); // StringSource

        wcout << "recovered text: " << string_to_wstring(recovered) << endl;

	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}

	/*********************************\
	\*********************************/

	return 0;
}

/* convert string to wstring */
wstring string_to_wstring (const std::string& str)
{
    wstring_convert<codecvt_utf8<wchar_t>> towstring;
    return towstring.from_bytes(str);
}

/* convert wstring to string */
string wstring_to_string (const std::wstring& str)
{
    wstring_convert<codecvt_utf8<wchar_t>> tostring;
    return tostring.to_bytes(str);
}