// Sample.cpp

#include "cryptopp/rsa.h"
using CryptoPP::RSA;
using CryptoPP::InvertibleRSAFunction;
using CryptoPP::RSAES_OAEP_SHA_Encryptor;
using CryptoPP::RSAES_OAEP_SHA_Decryptor;
using CryptoPP::RSAES_PKCS1v15_Decryptor;
using CryptoPP::RSAES_PKCS1v15_Encryptor;

//Genererate public /secret key pair
#include "cryptopp/cryptlib.h"
using CryptoPP::PrivateKey;
using CryptoPP::PublicKey;
using CryptoPP::BufferedTransformation;
using CryptoPP::Exception;
using CryptoPP::DecodingResult;

#include "cryptopp/base64.h" 
using CryptoPP::Base64Encoder; // string to base64
using CryptoPP::Base64Decoder; // base64 to string

#include "cryptopp/sha.h"
using CryptoPP::SHA1;

#include "cryptopp/filters.h" // string filters
using CryptoPP::StringSink; // ouput string 
using CryptoPP::StringSource; //input string
using CryptoPP::StreamTransformationFilter; // string transformation
using CryptoPP::BufferedTransformation;
using CryptoPP::PK_EncryptorFilter;
using CryptoPP::PK_DecryptorFilter;


#include <iomanip>
using namespace std;

#include <cstdlib>
using std::exit;

#include "cryptopp/files.h"
using CryptoPP::FileSource; // loade frome file 
using CryptoPP::FileSink;   // save to file

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "cryptopp/SecBlock.h"
using CryptoPP::SecByteBlock;

#include "cryptopp/cryptlib.h"
using CryptoPP::Exception;
using CryptoPP::DecodingResult;

#include <string>
using std::string;

#include <exception>
using std::exception;

#include "cryptopp/hex.h" 
using CryptoPP::HexEncoder; // string to hex
using CryptoPP::HexDecoder; // hex to string

/*reading ke, inputg from file*/
#include <cryptopp/queue.h>
using CryptoPP::ByteQueue;

/*convert string tream */
#include <sstream>
using std::ostringstream;

#include <iostream>
using std::wcout;
using std::wcin;
using std::cin;
using std::getline; 
using std::cout;
using std::cerr;
using std::endl;

#include <assert.h>

#include <string>
using std::string;
using std::wstring;

// Convert unicode
#include <locale>
using std::wstring_convert;
#include <codecvt>
using  std::codecvt_utf8;

#include <cryptopp/integer.h>
using CryptoPP::Integer;
#include <cryptopp/nbtheory.h>
using namespace CryptoPP;
using CryptoPP::ModularSquareRoot;
#include "cryptopp/modarith.h"
using CryptoPP::ModularArithmetic;

/* Set _setmode()*/ 
#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#elif _APPLE_
#include <TargetConditionals.h>
#endif

// Functions
wstring string_to_wstring (const std::string& str);
string wstring_to_string (const std::wstring& str);
wstring integer_to_wstring (const CryptoPP::Integer& t);
string integer_to_string (const CryptoPP::Integer& t);
string integer_to_hex(const CryptoPP::Integer& t);

void SavePrivateKey(const string& filename, const PrivateKey& key);
void SavePublicKey(const string& filename, const PublicKey& key);
void Save(const string& filename, const BufferedTransformation& bt);
void LoadPrivateKey(const string& filename, PrivateKey& key);
void LoadPublicKey(const string& filename, PublicKey& key);
void Load(const string& filename, BufferedTransformation& bt);



int main(int argc, char* argv[])
{
    AutoSeededRandomPool rng;
    /*set mode support vietnamese*/
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
    wcout << " enter your mode you want" << endl;
    wcout << " 1. Generate key " << endl;
    wcout << " 2. Encryption " << endl;
    wcout << " 3. Decrytion " << endl;
    wcin >> mode ;
    wcout << " your mode which you chosen is " << mode << endl;
    switch (mode)
    {
        case 1:
        {
            RSA::PrivateKey privateKey;
            int bits = 3072;
            privateKey.GenerateRandomWithKeySize(rng, bits);
            RSA::PublicKey publicKey(privateKey);
            SavePrivateKey("rsa-private.key", privateKey);
		    SavePublicKey("rsa-public.key", publicKey);
            wcout << " keys are saved with rsa-public(private).key  " << endl;
            break;
        }
        case 2:
        {
            RSA::PublicKey publicKey;
            wcout <<" load and public key ( rsa-public.key"<<endl;
            LoadPublicKey("rsa-public.key", publicKey);
            int func1;
            wcout <<" choose input file or input from screen "<<endl;
            wcout <<" 1. input from file text.txt "<<endl;
            wcout <<" 2. input from screen "<<endl; 
            wcin >> func1; 
            switch (func1)
            {
                case 1:
                {
                    string plain, cipher, encoded, recovered;; 
                    wcout <<" input from file text.txt " << endl ;
                    FileSource("text.txt" ,true, new StringSink(plain));
                    wcout <<" plaintext: " <<string_to_wstring(plain) << endl;
                    RSAES_OAEP_SHA_Encryptor e( publicKey );
                    StringSource( plain, true,
                        new PK_EncryptorFilter( rng, e, //PK_EncryptorFilter: ham ma 
                            new StringSink( cipher )
                        ) // PK_EncryptorFilter
                    ); // StringSource
                    // Pretty print ciphertext
                    encoded.clear();
                    StringSource(cipher, true,
                        new Base64Encoder(
                            new StringSink(encoded)
                        ) // HexEncoder
                    ); // StringSource
                    wcout <<"cipher text: " << string_to_wstring(encoded) << endl;
                    wcout <<" ciphet text was save with cipher.txt " <<endl;
	                StringSource(encoded, true, new FileSink("cipher.txt")); //save file
                    break;
                }
                case 2:
                {
                    string plain, cipher, encoded, recovered;; 
                    wstring wplain;
                    wcout<<" input plain text: "<<endl;
                    wcin.ignore();
                    wcin.ignore();                    
                    getline(wcin, wplain);
                    plain = wstring_to_string(wplain);
                    wcout <<" plaintext: " <<wplain << endl;   
                    RSAES_OAEP_SHA_Encryptor e( publicKey );
                    StringSource( plain, true,
                        new PK_EncryptorFilter( rng, e, //PK_EncryptorFilter: ham ma 
                            new StringSink( cipher )
                        ) // PK_EncryptorFilter
                    ); // StringSource
                    // Pretty print ciphertext
                    encoded.clear();
                    StringSource(cipher, true,
                        new Base64Encoder(
                            new StringSink(encoded)
                        ) // HexEncoder
                    ); // StringSource
                    wcout <<"cipher text: " << string_to_wstring(encoded) << endl;
                    StringSource(encoded, true, new FileSink("cipher.txt")); //save file
                    break;
                }
            }
            break;
        }
        case 3:
        {
            RSA::PrivateKey privateKey;
            wcout <<" load private key ( rsa-private.key"<<endl;
            LoadPrivateKey("rsa-private.key", privateKey);
            int func2;
            wcout <<" choose input cipher text or input from screen "<<endl;
            wcout <<" 1. input from file "<<endl;
            wcout <<" 2. input from screen "<<endl;
            wcin >> func2;
            switch (func2)
            {
                case 1:
                {   
                    string cipher, encoded, recovered;; 
                    wcout <<" input from file cipher.txt " << endl ;
                    FileSource("cipher.txt" ,true, new StringSink(encoded));
                    wcout <<" cipher text: " <<string_to_wstring(encoded) << endl;
                    StringSource(encoded, true,
                        new Base64Decoder(
                            new StringSink(cipher)));
                    RSAES_OAEP_SHA_Decryptor d( privateKey ); //decryption with secret key d 
                    StringSource( cipher, true,
                    new PK_DecryptorFilter( rng, d,
                        new StringSink( recovered )
                        ) // PK_EncryptorFilter
                    ); // StringSource
                    wcout <<"recovered text: " << string_to_wstring(recovered) << endl;
                    break;
                }
                case 2:
                {   
                    string cipher, encoded, recovered;; 
                    wstring wencoded;
                    wcout<<" input cipher text: "<<endl;
                    wcin.ignore();
                    wcin.ignore();
                    getline(wcin, wencoded);
                    encoded = wstring_to_string(wencoded);
                    StringSource(encoded, true,
                        new Base64Decoder(
                            new StringSink(cipher)));
                    RSAES_OAEP_SHA_Decryptor d( privateKey ); //decryption with secret key d 
                    StringSource( cipher, true,
                    new PK_DecryptorFilter( rng, d,
                        new StringSink( recovered )
                        ) // PK_EncryptorFilter
                    ); // StringSource
                    wcout <<"recovered text: " << string_to_wstring(recovered) << endl;
                    break;
                }
            }
            break;
        }
    }
    wcout << "exit ..." << endl;
    return 0;
}



void SavePrivateKey(const string& filename, const PrivateKey& key)
{
	// http://www.cryptopp.com/docs/ref/class_byte_queue.html
	ByteQueue queue;
	key.Save(queue);

	Save(filename, queue);
}

void SavePublicKey(const string& filename, const PublicKey& key)
{
	// http://www.cryptopp.com/docs/ref/class_byte_queue.html
	ByteQueue queue;
	key.Save(queue);

	Save(filename, queue);
}

void Save(const string& filename, const BufferedTransformation& bt)
{
	// http://www.cryptopp.com/docs/ref/class_file_sink.html
	FileSink file(filename.c_str());

	bt.CopyTo(file);
	file.MessageEnd();
}

void LoadPrivateKey(const string& filename, PrivateKey& key)
{
	// http://www.cryptopp.com/docs/ref/class_byte_queue.html
	ByteQueue queue;

	Load(filename, queue);
	key.Load(queue);	
}

void LoadPublicKey(const string& filename, PublicKey& key)
{
	// http://www.cryptopp.com/docs/ref/class_byte_queue.html
	ByteQueue queue;

	Load(filename, queue);
	key.Load(queue);	
}

void Load(const string& filename, BufferedTransformation& bt)
{
	// http://www.cryptopp.com/docs/ref/class_file_source.html
	FileSource file(filename.c_str(), true /*pumpAll*/);

	file.TransferTo(bt);
	bt.MessageEnd();
}



// Convert functions
/* convert string to wstring */

wstring string_to_wstring (const std::string& str)
{
    wstring_convert<codecvt_utf8<wchar_t, 0x10ffff>, wchar_t> towstring;
    return towstring.from_bytes(str);
}

/* convert wstring to string */
string wstring_to_string (const std::wstring& str)
{
    wstring_convert<codecvt_utf8<wchar_t, 0x10ffff>, wchar_t> tostring;
    return tostring.to_bytes(str);
}

/* convert integer */
wstring integer_to_wstring (const CryptoPP::Integer& t)
{
    std::ostringstream oss;
    oss.str("");
    oss.clear();
    oss << t;
    std::string encoded(oss.str());
    std::wstring_convert<codecvt_utf8<wchar_t>> towstring;
    return towstring.from_bytes(encoded);
}

string integer_to_string (const CryptoPP::Integer& t)
{
    std::ostringstream oss;
    oss.str("");
    oss.clear();
    oss << t;
    std::string encoded(oss.str());
    return encoded;
}

string integer_to_hex(const CryptoPP::Integer& t)
{
    std::ostringstream oss;
    oss.str("");
    oss.clear();
    oss << std::hex << t;
    std::string encoded(oss.str());
    return encoded;
}
