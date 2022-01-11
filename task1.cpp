// g++ -g3 -ggdb -O0 -DDEBUG -I/usr/include/cryptopp Driver.cpp -o Driver.exe -lcryptopp -lpthread
// g++ -g -O2 -DNDEBUG -I/usr/include/cryptopp Driver.cpp -o Driver.exe -lcryptopp -lpthread

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include <time.h>

#include <iostream>
using std::wcout;
using std::wcin;
using std::cin;
using std::getline; 
using std::cout;
using std::cerr;
using std::endl;
using std::dec;

#include <string>
using std::string;
using std::wstring;

#include <cstdlib>
using std::exit;

#include "cryptopp/cryptlib.h"
using CryptoPP::Exception;
using CryptoPP::BufferedTransformation;
using CryptoPP::AuthenticatedSymmetricCipher;

#include "cryptopp/hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include "cryptopp/base64.h" 
using CryptoPP::Base64Encoder; // string to base64
using CryptoPP::Base64Decoder;

#include "cryptopp/filters.h"
using CryptoPP::ArraySink;
using CryptoPP::ArraySource; 
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::AuthenticatedEncryptionFilter;
using CryptoPP::AuthenticatedDecryptionFilter;
using CryptoPP::Redirector;

#include "cryptopp/files.h"
using CryptoPP::FileSource; 
using CryptoPP::FileSink; 

#include "cryptopp/aes.h"
using CryptoPP::AES;

#include "cryptopp/gcm.h"
using CryptoPP::GCM;

#include "cryptopp/xts.h"
using CryptoPP::XTS;

#include "cryptopp/modes.h"
using CryptoPP::CBC_Mode;
using CryptoPP::OFB_Mode;
using CryptoPP::ECB_Mode;
using CryptoPP::CFB_Mode;
using CryptoPP::byte;

#include "cryptopp/secblock.h"
using CryptoPP::SecByteBlock;

#include "cryptopp/ccm.h"
using CryptoPP::CTR_Mode;
using CryptoPP::CCM;

#include "cryptopp/files.h"
using CryptoPP::FileSink;
using CryptoPP::FileSource;



// conert string
#include <locale>
using std::wstring_convert;
#include <codecvt>
using std::codecvt_utf8;

//setting 
#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#include <cassert>
#else
#endif

string plain;
wstring wplain; 
string cipher, encoded, recovered;

char mode;
char mode1;
wstring key,iv;

string wstring_to_string (const std::wstring& str);
wstring string_to_wstring (const std::string& str);

void OFB ();
void OFB_2();
void OFB_3();
void CFB ();
void CFB_2();
void CFB_3();
void ECB ();
void ECB_2();
void ECB_3();
void CBC ();
void CBC_2();
void CBC_3();
void GCM1 ();
void GCM1_2();
void GCM1_3();
void XTS1 ();
void XTS1_2 ();
void XTS1_3 ();
void CTR ();
void CTR_2();
void CTR_3();
void CCM1 ();
void CCM1_2();
void CCM1_3();


int main(int argc, char* argv[])
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
	
	int mode = 0;
    int mode1 = 0;
	
	string plain;
	wstring wplain; 
	string cipher, encoded, recovered;

	wcout<<" please enter the number u want to use"<<endl;
	wcout<<" 1.MODE ECB "<<endl; 
	wcout<<" 2.MODE CBC "<<endl;
	wcout<<" 3.MODE OFB "<<endl;
	wcout<<" 4.MODE CFB "<<endl;
	wcout<<" 5.MODE CTR "<<endl;
	wcout<<" 6.MODE XTS "<<endl;
	wcout<<" 7.MODE CCM "<<endl;
	wcout<<" 8.MODE GCM "<<endl;
	wcin >> mode ;
	switch (mode){
		case 1:
		{
			wcout<<" enter number of case u want to use"<< endl;
			wcout<<"1.Secret key and IV are randomly chosen for each run time using random generator using CryptoPP::AutoSeededRandomPool"<<endl;
			wcout<<"2.Input Secret Key and IV from screen"<<endl;
			wcout<<"3.Input Secret Key and IV from file"<<endl;
			wcin>> mode1;
			switch (mode1){
				case 1:
				{
					wcin.ignore();
					ECB ();
					break;
				}
				
				case 2:
				{
					wcin.ignore();
					ECB_2();
					break;
				}
				case 3:
				{
					wcin.ignore();
					ECB_3();					
					break;
				}
			}
			wcout<<"finished, please open again file"<<endl;
			break;
		}
		case 2:
		{
			wcout<<" enter number of case u want to use"<< endl;
			wcout<<"1.Secret key and IV are randomly chosen for each run time using random generator using CryptoPP::AutoSeededRandomPool"<<endl;
			wcout<<"2.Input Secret Key and IV from screen"<<endl;
			wcout<<"3.Input Secret Key and IV from file"<<endl;
			wcin>>mode1;
			switch (mode1){
				case 1:
				{
					wcin.ignore();
					CBC ();
					break;
				}
				case 2:
				{
					wcin.ignore();
					CBC_2();
					break;

				}
				case 3:
				{
					wcin.ignore();
					CBC_3();
					break;
				}
			}
			wcout<<" finished, please open again file "<< endl;
			break;
		}
		case 3:
		{
			wcout<<" enter number of case u want to use"<< endl;
			wcout<<"1.Secret key and IV are randomly chosen for each run time using random generator using CryptoPP::AutoSeededRandomPool"<<endl;
			wcout<<"2.Input Secret Key and IV from screen"<<endl;
			wcout<<"3.Input Secret Key and IV from file"<<endl;
			wcin>>mode1;
			switch (mode1){
				case 1:
				{
					wcin.ignore();
					OFB ();
					break;
				}
				case 2:
				{
					wcin.ignore();
					OFB_2();
					break;

				}
				case 3:
				{
					wcin.ignore();
					OFB_3();
					break;
				}
			}
			wcout<<" finished, please open again file "<< endl;
			break;
		}
		case 4:
		{
			wcout<<" enter number of case u want to use"<< endl;
			wcout<<"1.Secret key and IV are randomly chosen for each run time using random generator using CryptoPP::AutoSeededRandomPool"<<endl;
			wcout<<"2.Input Secret Key and IV from screen"<<endl;
			wcout<<"3.Input Secret Key and IV from file"<<endl;
			wcin>>mode1;
			switch (mode1){
				case 1:
				{
					wcin.ignore();
					CFB ();
					break;
				}
				case 2:
				{
					wcin.ignore();
					CFB_2();
					break;
				}
				case 3:
				{
					wcin.ignore();
					CFB_3();
					break;
				}
			}
			wcout<<" finished, please open again file "<<endl;
			break;
		}
		case 5:
		{
			wcout<<" enter number of case u want to use"<< endl;
			wcout<<"1.Secret key and IV are randomly chosen for each run time using random generator using CryptoPP::AutoSeededRandomPool"<<endl;
			wcout<<"2.Input Secret Key and IV from screen"<<endl;
			wcout<<"3.Input Secret Key and IV from file"<<endl;
			wcin>>mode1; 
			switch (mode1){
				case 1:
				{
					wcin.ignore();
					CTR();
					break;
				}
				case 2:
				{
					wcin.ignore();
					CTR_2();
					break;
				}
				case 3:
				{
					wcin.ignore();
					CTR_3();
					break;
				}
			}
			wcout<<"finished, please open again file"<<endl;
			break;			
		}
		case 6:
		{
			wcout<<" enter number of case u want to use"<< endl;
			wcout<<"1.Secret key and IV are randomly chosen for each run time using random generator using CryptoPP::AutoSeededRandomPool"<<endl;
			wcout<<"2.Input Secret Key and IV from screen"<<endl;
			wcout<<"3.Input Secret Key and IV from file"<<endl;
			wcin>>mode1; 
			switch (mode1){
				case 1:
				{
					wcin.ignore();
					XTS1 ();
					break;
				}
				case 2:
				{
					wcin.ignore();
					XTS1_2 ();
					break;
				}
				case 3:
				{
					wcin.ignore();
					XTS1_3();
					break;
				}
			}
			wcout<<"finished, please open again file"<<endl;
			break;			
		}
		case 7:
		{
			wcout<<" enter number of case u want to use"<< endl;
			wcout<<"1.Secret key and IV are randomly chosen for each run time using random generator using CryptoPP::AutoSeededRandomPool"<<endl;
			wcout<<"2.Input Secret Key and IV from screen"<<endl;
			wcout<<"3.Input Secret Key and IV from file"<<endl;
			wcin>>mode1; 
			switch (mode1){
				case 1:
				{
					wcin.ignore();
					CCM1 ();
					break;
				}
				case 2:
				{
					wcin.ignore();
					CCM1_2();
					break;
				}
				case 3:
				{
					wcin.ignore();
					CCM1_3();
					break;
				}
			}
			wcout<<"finished, please open again file"<<endl;
			break;
		}
		case 8:
		{
			wcout<<" enter number of case u want to use"<< endl;
			wcout<<"1.Secret key and IV are randomly chosen for each run time using random generator using CryptoPP::AutoSeededRandomPool"<<endl;
			wcout<<"2.Input Secret Key and IV from screen"<<endl;
			wcout<<"3.Input Secret Key and IV from file"<<endl;
			wcin>>mode1; 
			switch (mode1){
				case 1:
				{
					wcin.ignore();
					GCM1 ();
					break;
				}
				case 2:
				{
					wcin.ignore();
					GCM1_2();
					break;
				}
				case 3:
				{
					wcin.ignore();
					GCM1_3();
					break;
				}
			}
			wcout<<"finished, please open again file"<<endl;
			break;
		}
	}
}

void ECB ()
{
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

	wcout << "please in put message:";
	wcin.ignore();
	getline(wcin, wplain);  
	plain= wstring_to_string(wplain);

	clock_t start, end;
	double cpu_time_used;
	start = clock();

	AutoSeededRandomPool prng;
	byte key[ikey];
	prng.GenerateBlock(key, sizeof(key));
	encoded.clear();
	StringSource(key, sizeof(key), true,
		new HexEncoder(
			new StringSink(encoded)
		)
	); 
	wcout << "key: " << string_to_wstring(encoded) << endl;
	try
	{
		ECB_Mode< AES >::Encryption e;
		e.SetKey(key, sizeof(key));
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
	encoded.clear();
	StringSource(cipher, true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	wcout << "cipher text: " << string_to_wstring(encoded) << endl;
	try
	{
		ECB_Mode< AES >::Decryption d;
		d.SetKey(key, sizeof(key));

		// The StreamTransformationFilter removes
		//  padding as required.
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
	end = clock();
	cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
	wcout<<" running time: "<<cpu_time_used<<endl;
}

void CBC ()
{
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

	wcout << "please in put message:";
	wcin.ignore();
	getline(wcin, wplain);   // input wstring
	plain= wstring_to_string(wplain);

	clock_t start, end;
	double cpu_time_used;
	start = clock();

	AutoSeededRandomPool prng; 
	SecByteBlock key(ikey); // 8 bytes
	prng.GenerateBlock(key, key.size());  // generate key

	byte iv[16];   // inital vector 8 bytes 
	prng.GenerateBlock(iv, sizeof(iv));  // generate iv

	encoded.clear();
	StringSource(key, key.size(), true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	wcout << "key: " << string_to_wstring(encoded) << endl;
	encoded.clear();
	StringSource(iv, sizeof(iv), true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	wcout << "iv: " << string_to_wstring(encoded) << endl;
	try
	{

		CBC_Mode< AES >::Encryption e;
		e.SetKeyWithIV(key, key.size(), iv);
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
	encoded.clear();
	StringSource(cipher, true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	wcout << "cipher text: " << string_to_wstring(encoded) << endl;
	try
	{
		CBC_Mode< AES >::Decryption d;
		d.SetKeyWithIV(key, key.size(), iv);
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
	end = clock();
	cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
	wcout<<" running time: "<<cpu_time_used<<endl;

}

void OFB ()
{
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

	wcout << "please in put message:";
	wcin.ignore();
	getline(wcin, wplain);   // input wstring
	plain= wstring_to_string(wplain);

	clock_t start, end;
	double cpu_time_used;
	start = clock();

	AutoSeededRandomPool prng;
	byte key[ikey];
	prng.GenerateBlock(key, sizeof(key));

	byte iv[16];
	prng.GenerateBlock(iv, sizeof(iv));

	encoded.clear();
	StringSource(key, sizeof(key), true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	wcout << "key: " << string_to_wstring(encoded) << endl;

	// Pretty print iv
	encoded.clear();
	StringSource(iv, sizeof(iv), true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	wcout << "iv: " << string_to_wstring(encoded) << endl;

	try
	{
		OFB_Mode< AES >::Encryption e;
		e.SetKeyWithIV(key, sizeof(key), iv);

		// OFB mode must not use padding. Specifying
		//  a scheme will result in an exception
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
		OFB_Mode< AES >::Decryption d;
		d.SetKeyWithIV(key, sizeof(key), iv);

		// The StreamTransformationFilter removes
		//  padding as required.
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
	end = clock();
	cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
	wcout<<" running time: "<<cpu_time_used<<endl;
}

void CFB ()
{
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
	
	wcout << "please in put message:";
	wcin.ignore();
	getline(wcin, wplain);   // input wstring
	plain= wstring_to_string(wplain);

	clock_t start, end;
	double cpu_time_used;
	start = clock();

	AutoSeededRandomPool prng;
	byte key[ikey];
	prng.GenerateBlock(key, sizeof(key));
	byte iv[16];
	prng.GenerateBlock(iv, sizeof(iv));

	encoded.clear();
	StringSource(key, sizeof(key), true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	wcout << "key: " << string_to_wstring(encoded) << endl;

	// Pretty print iv
	encoded.clear();
	StringSource(iv, sizeof(iv), true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	wcout << "iv: " << string_to_wstring(encoded) << endl;

	/*********************************\
	\*********************************/

	try
	{
		CFB_Mode< AES >::Encryption e;
		e.SetKeyWithIV(key, sizeof(key), iv);

		// CFB mode must not use padding. Specifying
		//  a scheme will result in an exception
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
		CFB_Mode< AES >::Decryption d;
		d.SetKeyWithIV(key, sizeof(key), iv);

		// The StreamTransformationFilter removes
		//  padding as required.
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
	end = clock();
	cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
	wcout<<" running time: "<<cpu_time_used<<endl;
}

void CTR ()
{
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

	wcout << "please in put message:";
	wcin.ignore();
	getline(wcin, wplain);   // input wstring
	plain= wstring_to_string(wplain);

	clock_t start, end;
	double cpu_time_used;
	start = clock();

	AutoSeededRandomPool prng;

	byte key[ikey];
	prng.GenerateBlock(key, sizeof(key));

	byte iv[16];
	prng.GenerateBlock(iv, sizeof(iv));


	encoded.clear();
	StringSource(key, sizeof(key), true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	wcout << "key: " << string_to_wstring(encoded) << endl;

	// Pretty print iv
	encoded.clear();
	StringSource(iv, sizeof(iv), true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	wcout << "iv: " << string_to_wstring(encoded) << endl;

	/*********************************\
	\*********************************/

	try
    {
		CTR_Mode< AES >::Encryption e;
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
	encoded.clear();
	StringSource(cipher, true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	wcout << "cipher text: " << string_to_wstring(encoded) << endl;

	try
	{
		CTR_Mode< AES >::Decryption d;
		d.SetKeyWithIV(key, sizeof(key), iv);

		// The StreamTransformationFilter removes
		//  padding as required.
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
	end = clock();
	cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
	wcout<<" running time: "<<cpu_time_used<<endl;
}

void XTS1 ()
{
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

	wcout << "please in put message:";
	wcin.ignore();
	getline(wcin, wplain);   // input wstring
	plain= wstring_to_string(wplain);

	clock_t start, end;
	double cpu_time_used;
	start = clock();

	AutoSeededRandomPool prng;

    SecByteBlock key(ikey), iv(16);
    prng.GenerateBlock( key, key.size() );
    prng.GenerateBlock( iv, iv.size() );


try
    {
        XTS < AES >::Encryption enc;
        enc.SetKeyWithIV( key, key.size(), iv );

#if 0
        std::cout << "key length: " << enc.DefaultKeyLength() << std::endl;
        std::cout << "key length (min): " << enc.MinKeyLength() << std::endl;
        std::cout << "key length (max): " << enc.MaxKeyLength() << std::endl;
        std::cout << "block size: " << enc.BlockSize() << std::endl;
#endif

        // The StreamTransformationFilter adds padding
        //  as requiredec. ECB and XTS Mode must be padded
        //  to the block size of the cipher.
        StringSource ss( plain, true, 
            new StreamTransformationFilter( enc,
                new StringSink( cipher ),
                StreamTransformationFilter::NO_PADDING
            ) // StreamTransformationFilter      
        ); // StringSource
    }
    catch( const CryptoPP::Exception& ex )
    {
        cerr << ex.what() << std::endl;
        exit(1);
    }

    /*********************************\
    \*********************************/

    encoded.clear();
    StringSource ss1( key, key.size(), true,
        new HexEncoder(
            new StringSink( encoded )
        ) // HexEncoder
    ); // StringSource
    wcout << "key: " << string_to_wstring(encoded) << std::endl;

    encoded.clear();
    StringSource ss2( iv, iv.size(), true,
        new HexEncoder(
            new StringSink( encoded )
        ) // HexEncoder
    ); // StringSource
    wcout << " iv: " << string_to_wstring(encoded) << std::endl;

    // Pretty print cipher text
    encoded.clear();
    StringSource ss3( cipher, true,
        new HexEncoder(
            new StringSink( encoded )
        ) // HexEncoder
    ); // StringSource
    wcout << "cipher text: " << string_to_wstring(encoded) << std::endl;

    /*********************************\
    \*********************************/

    try
    {
        XTS< AES >::Decryption dec;
        dec.SetKeyWithIV( key, key.size(), iv );

        // The StreamTransformationFilter removes
        //  padding as requiredec.
        StringSource ss( cipher, true, 
            new StreamTransformationFilter( dec,
                new StringSink( recovered ),
                StreamTransformationFilter::NO_PADDING
            ) // StreamTransformationFilter
        ); // StringSource        
        wcout << "recovered text: " << string_to_wstring(recovered) << std::endl;
    }
    catch( const CryptoPP::Exception& ex )
    {
        cerr << ex.what() << std::endl;
        exit(1);
    }
	end = clock();
	cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
	wcout<<" running time: "<<cpu_time_used<<endl;
}

void GCM1 ()
{
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

	wcout << "please in put message:";
	wcin.ignore();
	getline(wcin, wplain);   // input wstring
	plain= wstring_to_string(wplain);

	clock_t start, end;
	double cpu_time_used;
	start = clock();

	AutoSeededRandomPool prng;

	SecByteBlock key(ikey);
	prng.GenerateBlock(key, key.size());

	SecByteBlock iv(16);
	prng.GenerateBlock(iv, iv.size());

	encoded.clear();
	StringSource(key, key.size(), true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	wcout << "key: " << string_to_wstring(encoded) << endl;

	// Pretty print iv
	encoded.clear();
	StringSource(iv, iv.size(), true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	wcout << "iv: " << string_to_wstring(encoded) << endl;

	/*********************************\
	\*********************************/

	try
	{
		GCM< AES >::Encryption e;
		e.SetKeyWithIV(key, key.size(), iv, iv.size());

		// The StreamTransformationFilter adds padding
		//  as required. GCM and CBC Mode must be padded
		//  to the block size of the cipher.
		StringSource(plain, true, 
			new AuthenticatedEncryptionFilter(e,
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
		GCM < AES >::Decryption d;
		d.SetKeyWithIV(key, key.size(), iv, iv.size());

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(cipher, true, 
			new AuthenticatedDecryptionFilter(d,
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
	end = clock();
	cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
	wcout<<" running time: "<<cpu_time_used<<endl;
}

void CCM1 ()
{
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

	wcout << "please in put message:";
	wcin.ignore();
	getline(wcin, wplain);   // input wstring
	plain= wstring_to_string(wplain);

	clock_t start, end;
	double cpu_time_used;
	start = clock();

	AutoSeededRandomPool prng;

    byte key[ ikey ];
    prng.GenerateBlock( key, sizeof(key) );

    // { 7, 8, 9, 10, 11, 12, 13 }
    byte iv[ 12 ];
    prng.GenerateBlock( iv, sizeof(iv) );    

    // { 4, 6, 8, 10, 12, 14, 16 }
    const int TAG_SIZE = 8;

    // Encrypted, with Tag
    string cipher, encoded;

    // Recovered
    string rpdata;

    /*********************************\
    \*********************************/

    // Pretty print
    encoded.clear();
    StringSource( key, sizeof(key), true,
        new HexEncoder(
            new StringSink( encoded )
        ) // HexEncoder
    ); // StringSource
    wcout << "key: " << string_to_wstring(encoded) << endl;

    // Pretty print
    encoded.clear();
    StringSource( iv, sizeof(iv), true,
        new HexEncoder(
            new StringSink( encoded )
        ) // HexEncoder
    ); // StringSource
    wcout << " iv: " << string_to_wstring(encoded) << endl;

    wcout << endl;

    /*********************************\
    \*********************************/

    try
    {

        CCM< AES, TAG_SIZE >::Encryption e;
        e.SetKeyWithIV( key, sizeof(key), iv, sizeof(iv) );
        e.SpecifyDataLengths( 0, plain.size(), 0 );

        StringSource( plain, true,
            new AuthenticatedEncryptionFilter( e,
                new StringSink( cipher )
            ) // AuthenticatedEncryptionFilter
        ); // StringSource
    }
    catch( CryptoPP::InvalidArgument& e )
    {
        cerr << "Caught InvalidArgument..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }
    catch( CryptoPP::Exception& e )
    {
        cerr << "Caught Exception..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }

    encoded.clear();
    StringSource( cipher, true,
        new HexEncoder(
            new StringSink( encoded )
        ) // HexEncoder
    ); // StringSource
    wcout << "cipher text: " << string_to_wstring(encoded) << endl;

    try
    {
        CCM< AES, TAG_SIZE >::Decryption d;
        d.SetKeyWithIV( key, sizeof(key), iv, sizeof(iv) );
        d.SpecifyDataLengths( 0, cipher.size()-TAG_SIZE, 0 );

        AuthenticatedDecryptionFilter df( d,
            new StringSink( rpdata )
        ); // AuthenticatedDecryptionFilter


        StringSource( cipher, true,
            new Redirector( df /*, PASS_EVERYTHING */ )
        ); // StringSource

        // If the object does not throw, here's the only
        //  opportunity to check the data's integrity

        wcout << "recovered text: " << string_to_wstring(rpdata) << endl;
    }
    catch( CryptoPP::HashVerificationFilter::HashVerificationFailed& e )
    {
        cerr << "Caught HashVerificationFailed..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }
    catch( CryptoPP::InvalidArgument& e )
    {
        cerr << "Caught InvalidArgument..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }
    catch( CryptoPP::Exception& e )
    {
        cerr << "Caught Exception..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }
	end = clock();
	cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
	wcout<<" running time: "<<cpu_time_used<<endl;
}


void ECB_2 ()
{
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
	wstring wkey,wcipher;
	string key1,rcipher;

	wcout<<" please input your sercet key: "<<endl;
	wcin.ignore();
	getline(wcin,wkey);
	key1=wstring_to_string(wkey);
	
	wcout<<"input your cipher text: ";
	wcin.ignore();
	getline(wcin,wcipher);
	cipher=wstring_to_string(wcipher);

	clock_t start, end;
	double cpu_time_used;
	start = clock();

	StringSource(key1, true, new HexDecoder( new ArraySink(key, sizeof(key))));
	StringSource(cipher, true, new HexDecoder( new StringSink(rcipher)));



	try
	{
		ECB_Mode< AES >::Decryption d;
		d.SetKey(key, sizeof(key));

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(rcipher, true, 
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
	end = clock();
	cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
	wcout<<" running time: "<<cpu_time_used<<endl;
}

void CBC_2 ()
{
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

	byte key[ikey],iv[16];
	wstring wkey,wiv,wcipher;
	string key1,iv1,rcipher;
	wcout<<" please input your sercet key "<<endl;
	wcout<<"key : ";
	wcin.ignore();
	getline(wcin,wkey);
	key1=wstring_to_string(wkey);

	wcout<<" please input your iv 16 bytes "<<endl;
	wcout<<"iv : ";
	wcin.ignore();
	getline(wcin,wiv);
	iv1=wstring_to_string(wiv);

	wcin.ignore();
	wcout<<"input your cipher text: ";
	getline(wcin,wcipher);
	cipher=wstring_to_string(wcipher);


	clock_t start, end;
	double cpu_time_used;
	start = clock();

	StringSource(key1, true, new HexDecoder( new ArraySink(key, sizeof(key))));
	StringSource(iv1, true, new HexDecoder( new ArraySink(iv, sizeof(iv))));
	StringSource(cipher, true, new HexDecoder( new StringSink(rcipher)));

	try
	{
		CBC_Mode< AES >::Decryption d;
		d.SetKeyWithIV(key, sizeof(key), iv);

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(rcipher, true, 
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
	end = clock();
	cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
	wcout<<" running time: "<<cpu_time_used<<endl;
}

void OFB_2 ()
{
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

	byte key[ikey],iv[16];
	wstring wkey,wiv,wcipher;
	string key1,iv1,rcipher;
	wcout<<" please input your sercet key "<<endl;
	wcout<<"key : ";
	wcin.ignore();
	getline(wcin,wkey);
	key1=wstring_to_string(wkey);

	wcout<<" please input your iv 16 bytes "<<endl;
	wcout<<"iv : ";
	wcin.ignore();
	getline(wcin,wiv);
	iv1=wstring_to_string(wiv);
	
	wcin.ignore();
	wcout<<"input your cipher text: ";
	getline(wcin,wcipher);
	cipher=wstring_to_string(wcipher);

	clock_t start, end;
	double cpu_time_used;
	start = clock();

	StringSource(key1, true, new HexDecoder( new ArraySink(key, sizeof(key))));
	StringSource(iv1, true, new HexDecoder( new ArraySink(iv, sizeof(iv))));
	StringSource(cipher, true, new HexDecoder( new StringSink(rcipher)));

	try
	{
		OFB_Mode< AES >::Decryption d;
		d.SetKeyWithIV(key, sizeof(key), iv);

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(rcipher, true, 
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
	end = clock();
	cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
	wcout<<" running time: "<<cpu_time_used<<endl;
}

void CFB_2 ()
{
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

	byte key[ikey],iv[16];
	wstring wkey,wiv,wcipher;
	string key1,iv1,rcipher;
	wcout<<" please input your sercet key "<<endl;
	wcout<<"key : ";
	wcin.ignore();
	getline(wcin,wkey);
	key1=wstring_to_string(wkey);

	wcout<<" please input your iv 16 bytes "<<endl;
	wcout<<"iv : ";
	wcin.ignore();
	getline(wcin,wiv);
	iv1=wstring_to_string(wiv);
	
	wcin.ignore();
	wcout<<"input your cipher text: ";
	getline(wcin,wcipher);
	cipher=wstring_to_string(wcipher);

	clock_t start, end;
	double cpu_time_used;
	start = clock();

	StringSource(key1, true, new HexDecoder( new ArraySink(key, sizeof(key))));
	StringSource(iv1, true, new HexDecoder( new ArraySink(iv, sizeof(iv))));
	StringSource(cipher, true, new HexDecoder( new StringSink(rcipher)));

try
	{
		CFB_Mode< AES >::Decryption d;
		d.SetKeyWithIV(key, sizeof(key), iv);

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(rcipher, true, 
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
	end = clock();
	cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
	wcout<<" running time: "<<cpu_time_used<<endl;
}

void CTR_2 ()
{
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

	byte key[ikey],iv[16];
	wstring wkey,wiv,wcipher;
	string key1,iv1,rcipher;
	wcout<<" please input your sercet key "<<endl;
	wcout<<"key : ";
	wcin.ignore();
	getline(wcin,wkey);
	key1=wstring_to_string(wkey);

	wcout<<" please input your iv 16 bytes "<<endl;
	wcout<<"iv : ";
	wcin.ignore();
	getline(wcin,wiv);
	iv1=wstring_to_string(wiv);
	
	wcin.ignore();
	wcout<<"input your cipher text: ";
	getline(wcin,wcipher);
	cipher=wstring_to_string(wcipher);

	clock_t start, end;
	double cpu_time_used;
	start = clock();

	StringSource(key1, true, new HexDecoder( new ArraySink(key, sizeof(key))));
	StringSource(iv1, true, new HexDecoder( new ArraySink(iv, sizeof(iv))));
	StringSource(cipher, true, new HexDecoder( new StringSink(rcipher)));

	try
	{
		CTR_Mode< AES >::Decryption d;
		d.SetKeyWithIV(key, sizeof(key), iv);

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(rcipher, true, 
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
	end = clock();
	cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
	wcout<<" running time: "<<cpu_time_used<<endl;
}

void XTS1_2 ()
{
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

	byte key[ikey],iv[16];
	wstring wkey,wiv,wcipher;
	string key1,iv1,rcipher;
	wcout<<" please input your sercet key "<<endl;
	wcout<<"key : ";
	wcin.ignore();
	getline(wcin,wkey);
	key1=wstring_to_string(wkey);

	wcout<<" please input your iv 16 bytes "<<endl;
	wcout<<"iv : ";
	wcin.ignore();
	getline(wcin,wiv);
	iv1=wstring_to_string(wiv);
	
	wcin.ignore();
	wcout<<"input your cipher text: ";
	getline(wcin,wcipher);
	cipher=wstring_to_string(wcipher);

	clock_t start, end;
	double cpu_time_used;
	start = clock();

	StringSource(key1, true, new HexDecoder( new ArraySink(key, sizeof(key))));
	StringSource(iv1, true, new HexDecoder( new ArraySink(iv, sizeof(iv))));
	StringSource(cipher, true, new HexDecoder( new StringSink(rcipher)));

	try
    {
        XTS< AES >::Decryption dec;
        dec.SetKeyWithIV( key, sizeof(key), iv );

        // The StreamTransformationFilter removes
        //  padding as requiredec.
        StringSource ss( rcipher, true, 
            new StreamTransformationFilter( dec,
                new StringSink( recovered ),
                StreamTransformationFilter::NO_PADDING
            ) // StreamTransformationFilter
        ); // StringSource        
        wcout << "recovered text: " << string_to_wstring(recovered) << std::endl;
    }
    catch( const CryptoPP::Exception& ex )
    {
        cerr << ex.what() << std::endl;
        exit(1);
    }
	end = clock();
	cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
	wcout<<" running time: "<<cpu_time_used<<endl;
}

void CCM1_2()
{
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

	string cipher, encoded;
    string rpdata;

	byte key[ikey],iv[12];
	wstring wkey,wiv,wcipher;
	string key1,iv1,rcipher;
	wcout<<" please input your sercet key with tag size 8 "<<endl;
	wcout<<"key : ";
	wcin.ignore();
	getline(wcin,wkey);
	key1=wstring_to_string(wkey);

	wcout<<" please input your iv 12 bytes with tag size 8 "<<endl;
	wcout<<"iv : ";
	wcin.ignore();
	getline(wcin,wiv);
	iv1=wstring_to_string(wiv);

    // { 4, 6, 8, 10, 12, 14, 16 }
    const int TAG_SIZE = 8;

	wcin.ignore();
	wcout<<"input your cipher text: ";
	getline(wcin,wcipher);
	cipher=wstring_to_string(wcipher);

	clock_t start, end;
	double cpu_time_used;
	start = clock();

	StringSource(key1, true, new HexDecoder( new ArraySink(key, sizeof(key))));
	StringSource(iv1, true, new HexDecoder( new ArraySink(iv, sizeof(iv))));
	StringSource(cipher, true, new HexDecoder( new StringSink(rcipher)));

	try
    {
        CCM< AES, TAG_SIZE >::Decryption d;
        d.SetKeyWithIV( key, sizeof(key), iv, sizeof(iv) );
        d.SpecifyDataLengths( 0, rcipher.size()-TAG_SIZE, 0 );

        AuthenticatedDecryptionFilter df( d,
            new StringSink( rpdata )
        ); // AuthenticatedDecryptionFilter


        StringSource( rcipher, true,
            new Redirector( df /*, PASS_EVERYTHING */ )
        ); // StringSource

        // If the object does not throw, here's the only
        //  opportunity to check the data's integrity

        wcout << "recovered text: " << string_to_wstring(rpdata) << endl;
    }
    catch( CryptoPP::HashVerificationFilter::HashVerificationFailed& e )
    {
        cerr << "Caught HashVerificationFailed..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }
    catch( CryptoPP::InvalidArgument& e )
    {
        cerr << "Caught InvalidArgument..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }
    catch( CryptoPP::Exception& e )
    {
        cerr << "Caught Exception..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }
	end = clock();
	cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
	wcout<<" running time: "<<cpu_time_used<<endl;
}

void GCM1_2 ()
{
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

	byte key[ikey],iv[16];
	wstring wkey,wiv,wcipher;
	string key1,iv1,rcipher;
	wcout<<" please input your sercet key "<<endl;
	wcout<<"key : ";
	wcin.ignore();
	getline(wcin,wkey);
	key1=wstring_to_string(wkey);

	wcout<<" please input your iv 16 bytes "<<endl;
	wcout<<"iv : ";
	wcin.ignore();
	getline(wcin,wiv);
	iv1=wstring_to_string(wiv);
	
	wcin.ignore();
	wcout<<"input your cipher text: ";
	getline(wcin,wcipher);
	cipher=wstring_to_string(wcipher);

	clock_t start, end;
	double cpu_time_used;
	start = clock();

	StringSource(key1, true, new HexDecoder( new ArraySink(key, sizeof(key))));
	StringSource(iv1, true, new HexDecoder( new ArraySink(iv, sizeof(iv))));
	StringSource(cipher, true, new HexDecoder( new StringSink(rcipher)));

	try
	{
		GCM< AES >::Decryption d;
		d.SetKeyWithIV(key, sizeof(key), iv,sizeof(iv));

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(rcipher, true, 
			new AuthenticatedDecryptionFilter(d,
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
	end = clock();
	cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
	wcout<<" running time: "<<cpu_time_used<<endl;
}

void ECB_3 ()
{
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
	string skey,siv,cipher,rcipher;
	wcout << "enter name of key's input file (defaut key.txt) "<< endl;
	FileSource("key.txt" ,true, new StringSink(skey));
	wcout << "key: " << string_to_wstring (skey) << endl;

	wcout << "enter name of cipher's input file (defaut cipher.txt) "<< endl;
	FileSource("cipher.txt" ,true, new StringSink(cipher));
	
	wcout << "key: " << string_to_wstring (skey) << endl;
	wcout << "cipher text " << string_to_wstring (cipher) << endl;

	clock_t start, end;
	double cpu_time_used;
	start = clock();

	StringSource(skey, true, new HexDecoder( new ArraySink(key,sizeof(key))));
	StringSource(cipher, true, new HexDecoder( new StringSink(rcipher)));

	try
	{
		ECB_Mode< AES >::Decryption d;
		d.SetKey(key, sizeof(key));
		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(rcipher, true, 
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
	end = clock();
	cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
	wcout<<" running time: "<<cpu_time_used<<endl;	
}

void CBC_3 ()
{
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

	byte key[ikey],iv[16];
	string skey,siv,cipher,rcipher;

	wcout << "enter name of key's input file (defaut key.txt) "<< endl;
	FileSource("key.txt" ,true, new StringSink(skey));

	wcout << "enter name of iv's input file (defaut iv.txt) "<< endl;
	FileSource("iv.txt" ,true, new StringSink(siv));

	wcout << "enter name of cipher's input file (defaut cipher.txt) "<< endl;
	FileSource("cipher.txt" ,true, new StringSink(cipher));

	wcout << "key: " << string_to_wstring (skey) << endl;
	wcout << "iv: " << string_to_wstring (siv) << endl;
	wcout << "cipher text: " << string_to_wstring (cipher) << endl;


	clock_t start, end;
	double cpu_time_used;
	start = clock();

	StringSource(skey, true, new HexDecoder( new ArraySink(key,sizeof(key))));
	StringSource(siv, true, new HexDecoder( new ArraySink(iv,sizeof(iv))));
	StringSource(cipher, true, new HexDecoder( new StringSink(rcipher)));

	try
	{
		CBC_Mode< AES >::Decryption d;
		d.SetKeyWithIV(key, sizeof(key), iv);

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(rcipher, true, 
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
	end = clock();
	cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
	wcout<<" running time: "<<cpu_time_used<<endl;	
}

void OFB_3 ()
{
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

	byte key[ikey],iv[16];
	string skey,siv,cipher,rcipher;

	wcout << "enter name of key's input file (defaut key.txt) "<< endl;
	FileSource("key.txt" ,true, new StringSink(skey));

	wcout << "enter name of iv's input file (defaut iv.txt) "<< endl;
	FileSource("iv.txt" ,true, new StringSink(siv));

	wcout << "enter name of cipher's input file (defaut cipher.txt) "<< endl;
	FileSource("cipher.txt" ,true, new StringSink(cipher));

	wcout << "key: " << string_to_wstring (skey) << endl;
	wcout << "iv: " << string_to_wstring (siv) << endl;
	wcout << "cipher text: " << string_to_wstring (cipher) << endl;

	clock_t start, end;
	double cpu_time_used;
	start = clock();

	StringSource(skey, true, new HexDecoder( new ArraySink(key,sizeof(key))));
	StringSource(siv, true, new HexDecoder( new ArraySink(iv,sizeof(iv))));
	StringSource(cipher, true, new HexDecoder( new StringSink(rcipher)));

	try
	{
		OFB_Mode< AES >::Decryption d;
		d.SetKeyWithIV(key, sizeof(key), iv);
		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(rcipher, true, 
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
	end = clock();
	cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
	wcout<<" running time: "<<cpu_time_used<<endl;	
}

void CFB_3 ()
{
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

	byte key[ikey],iv[16];
	string skey,siv,cipher,rcipher;

	wcout << "enter name of key's input file (defaut key.txt) "<< endl;
	FileSource("key.txt" ,true, new StringSink(skey));

	wcout << "enter name of iv's input file (defaut iv.txt) "<< endl;
	FileSource("iv.txt" ,true, new StringSink(siv));

	wcout << "enter name of cipher's input file (defaut cipher.txt) "<< endl;
	FileSource("cipher.txt" ,true, new StringSink(cipher));

	wcout << "key: " << string_to_wstring (skey) << endl;
	wcout << "iv: " << string_to_wstring (siv) << endl;
	wcout << "cipher text: " << string_to_wstring (cipher) << endl;

	clock_t start, end;
	double cpu_time_used;
	start = clock();

	StringSource(skey, true, new HexDecoder( new ArraySink(key,sizeof(key))));
	StringSource(siv, true, new HexDecoder( new ArraySink(iv,sizeof(iv))));
	StringSource(cipher, true, new HexDecoder( new StringSink(rcipher)));

	try
	{
		CFB_Mode< AES >::Decryption d;
		d.SetKeyWithIV(key, sizeof(key), iv);
		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(rcipher, true, 
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
	end = clock();
	cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
	wcout<<" running time: "<<cpu_time_used<<endl;	
}

void CTR_3()
{
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

	byte key[ikey],iv[16];
	string skey,siv,cipher,rcipher;

	wcout << "enter name of key's input file (defaut key.txt) "<< endl;
	FileSource("key.txt" ,true, new StringSink(skey));

	wcout << "enter name of iv's input file (defaut iv.txt) "<< endl;
	FileSource("iv.txt" ,true, new StringSink(siv));

	wcout << "enter name of cipher's input file (defaut cipher.txt) "<< endl;
	FileSource("cipher.txt" ,true, new StringSink(cipher));

	wcout << "key: " << string_to_wstring (skey) << endl;
	wcout << "iv: " << string_to_wstring (siv) << endl;
	wcout << "cipher text: " << string_to_wstring (cipher) << endl;

	clock_t start, end;
	double cpu_time_used;
	start = clock();

	StringSource(skey, true, new HexDecoder( new ArraySink(key,sizeof(key))));
	StringSource(siv, true, new HexDecoder( new ArraySink(iv,sizeof(iv))));
	StringSource(cipher, true, new HexDecoder( new StringSink(rcipher)));

	try
	{
		CTR_Mode< AES >::Decryption d;
		d.SetKeyWithIV(key, sizeof(key), iv);
		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(rcipher, true, 
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
	end = clock();
	cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
	wcout<<" running time: "<<cpu_time_used<<endl;	
}

void XTS1_3()
{
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

	byte key[ikey],iv[16];
	string skey,siv,cipher,rcipher;

	wcout << "enter name of key's input file (defaut key.txt) "<< endl;
	FileSource("key.txt" ,true, new StringSink(skey));

	wcout << "enter name of iv's input file (defaut iv.txt) "<< endl;
	FileSource("iv.txt" ,true, new StringSink(siv));

	wcout << "enter name of cipher's input file (defaut cipher.txt) "<< endl;
	FileSource("cipher.txt" ,true, new StringSink(cipher));

	wcout << "key: " << string_to_wstring (skey) << endl;
	wcout << "iv: " << string_to_wstring (siv) << endl;
	wcout << "cipher text: " << string_to_wstring (cipher) << endl;

	clock_t start, end;
	double cpu_time_used;
	start = clock();

	StringSource(skey, true, new HexDecoder( new ArraySink(key,sizeof(key))));
	StringSource(siv, true, new HexDecoder( new ArraySink(iv,sizeof(iv))));
	StringSource(cipher, true, new HexDecoder( new StringSink(rcipher)));

	try
    {
        XTS< AES >::Decryption dec;
        dec.SetKeyWithIV( key, sizeof(key), iv );

        // The StreamTransformationFilter removes
        //  padding as requiredec.
        StringSource ss( rcipher, true, 
            new StreamTransformationFilter( dec,
                new StringSink( recovered ),
                StreamTransformationFilter::NO_PADDING
            ) // StreamTransformationFilter
        ); // StringSource        
        wcout << "recovered text: " << string_to_wstring(recovered) << std::endl;
    }
    catch( const CryptoPP::Exception& ex )
    {
        cerr << ex.what() << std::endl;
        exit(1);
    }
	end = clock();
	cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
	wcout<<" running time: "<<cpu_time_used<<endl;
}

void CCM1_3()
{
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

	byte key[ikey],iv[12];
	string skey,siv,cipher,rcipher,rpdata;
	wcout << "enter name of key's input file (defaut key.txt) "<< endl;
	FileSource("key.txt" ,true, new StringSink(skey));

	wcout << "enter name of iv's input file (defaut iv.txt) "<< endl;
	FileSource("iv.txt" ,true, new StringSink(siv));

	wcout << "enter name of cipher's input file (defaut cipher.txt) "<< endl;
	FileSource("cipher.txt" ,true, new StringSink(cipher));

	wcout << "key: " << string_to_wstring (skey) << endl;
	wcout << "iv: " << string_to_wstring (siv) << endl;
	wcout << "cipher text: " << string_to_wstring (cipher) << endl;

    const int TAG_SIZE = 8;

	clock_t start, end;
	double cpu_time_used;
	start = clock();

	StringSource(skey, true, new HexDecoder( new ArraySink(key,sizeof(key))));
	StringSource(siv, true, new HexDecoder( new ArraySink(iv,sizeof(iv))));
	StringSource(cipher, true, new HexDecoder( new StringSink(rcipher)));

	try
    {
        CCM< AES, TAG_SIZE >::Decryption d;
        d.SetKeyWithIV( key, sizeof(key), iv, sizeof(iv) );
        d.SpecifyDataLengths( 0, rcipher.size()-TAG_SIZE, 0 );

        AuthenticatedDecryptionFilter df( d,
            new StringSink( rpdata )
        ); // AuthenticatedDecryptionFilter


        StringSource( rcipher, true,
            new Redirector( df /*, PASS_EVERYTHING */ )
        ); // StringSource

        // If the object does not throw, here's the only
        //  opportunity to check the data's integrity

        wcout << "recovered text: " << string_to_wstring(rpdata) << endl;
    }
    catch( CryptoPP::HashVerificationFilter::HashVerificationFailed& e )
    {
        cerr << "Caught HashVerificationFailed..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }
    catch( CryptoPP::InvalidArgument& e )
    {
        cerr << "Caught InvalidArgument..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }
    catch( CryptoPP::Exception& e )
    {
        cerr << "Caught Exception..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }
	end = clock();
	cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
	wcout<<" running time: "<<cpu_time_used<<endl;
}

void GCM1_3()
{
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

	byte key[ikey],iv[16];
	string skey,siv,cipher,rcipher;
	wcout << "enter name of key's input file (defaut key.txt) "<< endl;
	FileSource("key.txt" ,true, new StringSink(skey));

	wcout << "enter name of iv's input file (defaut iv.txt) "<< endl;
	FileSource("iv.txt" ,true, new StringSink(siv));

	wcout << "enter name of cipher's input file (defaut cipher.txt) "<< endl;
	FileSource("cipher.txt" ,true, new StringSink(cipher));

	wcout << "key: " << string_to_wstring (skey) << endl;
	wcout << "iv: " << string_to_wstring (siv) << endl;
	wcout << "cipher text: " << string_to_wstring (cipher) << endl;

	clock_t start, end;
	double cpu_time_used;
	start = clock();

	StringSource(siv, true, new HexDecoder( new ArraySink(iv,sizeof(iv))));
	StringSource(skey, true, new HexDecoder( new ArraySink(key,sizeof(key))));
	StringSource(cipher, true, new HexDecoder( new StringSink(rcipher)));

	try
	{
		GCM< AES >::Decryption d;
		d.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(rcipher, true, 
			new AuthenticatedDecryptionFilter(d,
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
	end = clock();
	cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
	wcout<<" running time: "<<cpu_time_used<<endl;
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