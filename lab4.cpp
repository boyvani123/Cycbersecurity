#include <assert.h>

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

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "cryptopp/base64.h" 
using CryptoPP::Base64Encoder;
using CryptoPP::Base64Decoder;

#include "cryptopp/hex.h" 
using CryptoPP::HexEncoder; // string to hex
using CryptoPP::HexDecoder;

#include "cryptopp/aes.h"
using CryptoPP::AES;

#include "cryptopp/integer.h"
using CryptoPP::Integer;

#include "cryptopp/sha.h"
using CryptoPP::SHA512;
using CryptoPP::SHA256;

#include "cryptopp/filters.h"
using CryptoPP::StringSource;
using CryptoPP::StringSink;
using CryptoPP::ArraySink;
using CryptoPP::SignerFilter;
using CryptoPP::SignatureVerificationFilter;
using CryptoPP::byte;

#include "cryptopp/files.h"
using CryptoPP::FileSource;
using CryptoPP::FileSink;

#include "cryptopp/eccrypto.h"
using CryptoPP::ECDSA;
using CryptoPP::ECP;
using CryptoPP::DL_GroupParameters_EC;

#include "cryptopp/oids.h"
using CryptoPP::OID;

// use ByteQueue and BufferedTransformation for encoding and decoding keys
#include "cryptopp/queue.h"
using CryptoPP::ByteQueue;
using CryptoPP::BufferedTransformation;

// convert string stream
#include <sstream>
using std::ostringstream;

// Convert unicode
#include <locale>
using std::wstring_convert;
#include <codecvt>
using  std::codecvt_utf8;

/* Set _setmode()*/ 
#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#elif _APPLE_
#include <TargetConditionals.h>
#endif

bool GeneratePrivateKey( const OID& oid, ECDSA<ECP, SHA256>::PrivateKey& key );
bool GeneratePublicKey( const ECDSA<ECP, SHA256>::PrivateKey& privateKey, ECDSA<ECP, SHA256>::PublicKey& publicKey );

void SavePrivateKey( const string& filename, const ECDSA<ECP, SHA256>::PrivateKey& key );
void SavePublicKey( const string& filename, const ECDSA<ECP, SHA256>::PublicKey& key );
void LoadPrivateKey( const string& filename, ECDSA<ECP, SHA256>::PrivateKey& key );
void LoadPublicKey( const string& filename, ECDSA<ECP, SHA256>::PublicKey& key );

// Encode keys to DER
void EncodePrivateKey(const string& filename, const ECDSA<ECP, SHA256>::PrivateKey& key);
void EncodePublicKey(const string& filename, const ECDSA<ECP, SHA256>::PublicKey& key);
void Encode(const string& filename, const BufferedTransformation& bt);

// Decode DER to keys
void DecodePrivateKey(const string& filename, ECDSA<ECP, SHA256>::PrivateKey& key);
void DecodePublicKey(const string& filename, ECDSA<ECP, SHA256>::PublicKey& key);
void Decode(const string& filename, BufferedTransformation& bt);

void PrintDomainParameters( const ECDSA<ECP, SHA256>::PrivateKey& key );
void PrintDomainParameters( const ECDSA<ECP, SHA256>::PublicKey& key );
void PrintDomainParameters( const DL_GroupParameters_EC<ECP>& params );
void PrintPrivateKey( const ECDSA<ECP, SHA256>::PrivateKey& key );
void PrintPublicKey( const ECDSA<ECP, SHA256>::PublicKey& key );

bool SignMessage( const ECDSA<ECP, SHA256>::PrivateKey& key, const string& message, string& signature );
bool VerifyMessage( const ECDSA<ECP, SHA256>::PublicKey& key, const string& message, const string& signature );

// support Vietnamese
wstring string_to_wstring (const std::string& str);
string wstring_to_string (const std::wstring& str);

// convert integer
wstring integer_to_wstring (const CryptoPP::Integer& t);

int vn;
int win;

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

    AutoSeededRandomPool prng;
    bool result = false;

    ECDSA<ECP, SHA256>::PrivateKey privateKey;
    ECDSA<ECP, SHA256>::PublicKey publicKey;
    

    int vn;
    int win;

    wcout << " enter your mode you want" << endl;
    wcout << " 1. Generate key " << endl;
    wcout << " 2. Signing function " << endl;
    wcout << " 3. Verify function " << endl;
    wcin >> win ;
    wcin.ignore();    
    switch (win)
    {
        case 1:
        {
            /* Create system parameter, keys, and save to file */

            // Private and Public keys
            ECDSA<ECP, SHA256>::PrivateKey privateKey;
            ECDSA<ECP, SHA256>::PublicKey publicKey;
    
            /////////////////////////////////////////////
            // Generate Private Key
            result = GeneratePrivateKey( CryptoPP::ASN1::secp256r1(), privateKey );
            assert( true == result );
            if( !result ) { return -1; }

            // Generate Public Key
            result = GeneratePublicKey( privateKey, publicKey );
            assert( true == result );
            if( !result ) { return -2; }
            
            /////////////////////////////////////////////
            // Print Domain Parameters and Keys   
            PrintDomainParameters( publicKey );
            PrintPrivateKey( privateKey );
            PrintPublicKey( publicKey );

            int mk ;
            wcout << " Which format keys do you want to save ?" << endl;
            wcout << " 1. x509 " << endl;
            wcout << " 2. der " << endl;
            wcin >> mk ;
            wcin.ignore();
            switch (mk)
            {
                case 1:
                {
                    SavePrivateKey( "private.key", privateKey );
                    SavePublicKey( "public.key", publicKey );
                    wcout << " keys are generated and saved with .key " << endl;
                    break;
                }
                case 2:
                {
                    SavePrivateKey( "private.der", privateKey );
                    SavePublicKey( "public.der", publicKey );
                    wcout << " keys are generated and saved with .der " << endl;
                    break;
                }
            }
            wcout << " exit ... " <<endl;
            break;
        }
        case 2:
        {
            ECDSA<ECP, SHA256>::PrivateKey privateKey;
            
            do
            {
            wcout << " which fomat key do you use " << endl;
            wcout << " 1. x509" << endl;
            wcout << " 2. def" << endl;
            wcin >> vn;
            wcin.ignore();
            if (vn<1 || vn>=3) cout<<"Pls input"<<endl;
            } 
            while (vn<1 || vn>=3);
            if ( vn == 1)
            {
                wcout << " load key (private.key)" <<endl;
                LoadPrivateKey( "private.key", privateKey );
                wcout << " key are input " << endl;
            }
            else if (vn == 2)
            {
                wcout << " load key (private.der)" <<endl;
                LoadPrivateKey( "private.der", privateKey );
                wcout << " key are input " << endl;
            }

            // Sign and Verify a message      
            wstring wmessage;
            string message, signature, encode;
            int choose;
            wcout << " which one you choose ? " << endl;
            wcout << "1. input text from screen" << endl;
            wcout << "2. input text from file (message.txt)" << endl;
            wcin >> choose;
            wcin.ignore();
            switch (choose)
            {
                case 1:
                {
                    wcout << "Input your message: ";
                    wcin.ignore();
                    getline(wcin, wmessage);
                    message = wstring_to_string(wmessage);
                    wcout << "message: " << wmessage << endl;
                    signature.erase();
                    wcout << " which encoder do you wanna use ? " << endl;
                    wcout << "1. hex" << endl;
                    wcout << "2. base64" << endl;
                    int choose = 0;
                    wcin >> choose;
                    wcin.ignore();
                    if (choose == 1)
                    {
                        wcout << " HEX encoder ..." << endl;
                        StringSource( message, true, 
                        new SignerFilter(prng,
                            ECDSA<ECP,SHA256>::Signer(privateKey),
                            new HexEncoder(new StringSink(signature))
                            )
                        );
                        wcout << " done " << endl;
                    }
                    else if (choose == 2)
                    {
                        wcout << " base64 encoder ..." << endl;
                        StringSource( message, true, 
                        new SignerFilter(prng,
                            ECDSA<ECP,SHA256>::Signer(privateKey),
                            new Base64Encoder(new StringSink(signature))
                            )
                        );
                        wcout << " done " << endl;
                    }    
                    wcout << "signature (r,s):" << string_to_wstring(signature) << endl;
                    StringSource(signature, true, new FileSink("signature.txt"));
                    StringSource(message, true, new FileSink("message.txt"));                    
                    break;
                }
                case 2:
                {
                    wcout << "load message.txt ... " << endl;
                    FileSource("message.txt", true, new StringSink(message));
                    wcout << "message: " << string_to_wstring(message) << endl;
                    signature.erase();
                    wcout << " which encoder do you wanna use ? " << endl;
                    wcout << "1. hex" << endl;
                    wcout << "2. base64" << endl;
                    int choose = 0;
                    wcin >> choose;
                    wcin.ignore();
                    if (choose == 1)
                    {
                        wcout << " HEX encoder ..." << endl;
                        StringSource( message, true, 
                        new SignerFilter(prng,
                            ECDSA<ECP,SHA256>::Signer(privateKey),
                            new HexEncoder(new StringSink(signature))
                            )
                        );
                        wcout << " done " << endl;
                    }
                    else if (choose == 2)
                    {
                        wcout << " base64 encoder ..." << endl;
                        StringSource( message, true, 
                        new SignerFilter(prng,
                            ECDSA<ECP,SHA256>::Signer(privateKey),
                            new Base64Encoder(new StringSink(signature))
                            )
                        );
                        wcout << " done " << endl;
                    }
                    wcout << "signature (r,s):" << string_to_wstring(signature) << endl;
                    StringSource(signature, true, new FileSink("signature.txt"));
                    StringSource(message, true, new FileSink("message.txt"));                    
                    break;
                }
            }
            break;            
        }
        case 3:
        {
            bool result1 = false;
            // Public key variable
            ECDSA<ECP, SHA256>::PublicKey publicKey;
            
            do
            {
            wcout << " which fomat key do you use " << endl;
            wcout << " 1. x509" << endl;
            wcout << " 2. def" << endl;
            wcin >> vn;
            wcin.ignore();
            if (vn<1 || vn>=3) cout<<"Pls input"<<endl;
            } 
            while (vn<1 || vn>=3);
            if ( vn == 1)
            {
                wcout << " load key (public.key)" <<endl;
                LoadPublicKey( "public.key", publicKey );
                wcout << " key are input " << endl;
            }
            else if (vn == 2)
            {
                wcout << " load key (public.der)" <<endl;
                LoadPublicKey( "public.der", publicKey );
                wcout << " key are input " << endl;
            }

            wstring wmessage, wsignature; 
            string message, signature, encode;      

            wcout << "load message.txt ... " << endl;
            FileSource("message.txt", true, new StringSink(message));
            wcout << "message: " << string_to_wstring(message) << endl; 

            do
            {
            wcout << " which fomat signature do you choose ? " << endl;
            wcout << " 1. input signature from screen" << endl;
            wcout << " 2. input signature from file (signature.txt)" << endl;
            wcin >> vn;
            wcin.ignore();
            if (vn<1 || vn>=3) cout<<"Pls input"<<endl;
            } 
            while (vn<1 || vn>=3);
            if ( vn == 1)
            {
                wcin.ignore();
                wcout << "Input your signature: ";
                getline(wcin, wsignature);
                signature = wstring_to_string(wsignature);
                wcout << "signature: " << wsignature << endl;
            }
            else if (vn == 2)
            {
                wcout << "load signature.txt ... " << endl;
                FileSource("signature.txt", true, new StringSink(signature));
                wcout << "signature: " << string_to_wstring(signature) << endl;
            }

            string signature_r;
            do
            {
            wcout << " which encoder signature do you choose ? " << endl;
            wcout << " 1. hex" << endl;
            wcout << " 2. base64" << endl;
            wcin >> vn;
            wcin.ignore();
            if (vn<1 || vn>=3) cout<<"Pls input"<<endl;
            } 
            while (vn<1 || vn>=3);
            if ( vn == 1)
            {
                wcout << "your signature is decoding ... " << endl;
                StringSource ss(signature, true,
                new HexDecoder(
                    new StringSink(signature_r)
                    ) // 
                ); //
                wcout << "done. " << endl;
            }
            else if (vn == 2)
            {
                wcout << "your signature is decoding ... " << endl;
                StringSource ss(signature, true,
                new Base64Decoder(
                    new StringSink(signature_r)
                    ) // 
                ); //
                wcout << "done. " << endl;
            }
            const string & message_r = message;
            wcout << "verify ... " << endl;
            result1 = VerifyMessage(publicKey, message_r, signature_r);
            // assert( true == result1 );
            wcout << "Verify the signature on m:" << result1 << endl;
            break;
        }
    }
    wcout << " finished ..." << endl;

}




bool GeneratePrivateKey( const OID& oid, ECDSA<ECP, SHA256>::PrivateKey& key )
{
    AutoSeededRandomPool prng;

    key.Initialize( prng, oid );
    assert( key.Validate( prng, 3 ) );
     
    return key.Validate( prng, 3 );
}

bool GeneratePublicKey( const ECDSA<ECP, SHA256>::PrivateKey& privateKey, ECDSA<ECP, SHA256>::PublicKey& publicKey )
{
    AutoSeededRandomPool prng;

    // Sanity check
    assert( privateKey.Validate( prng, 3 ) );

    privateKey.MakePublicKey(publicKey);
    assert( publicKey.Validate( prng, 3 ) );

    return publicKey.Validate( prng, 3 );
}

void PrintDomainParameters( const ECDSA<ECP, SHA256>::PrivateKey& key )
{
    PrintDomainParameters( key.GetGroupParameters() );
}

void PrintDomainParameters( const ECDSA<ECP, SHA256>::PublicKey& key )
{
    PrintDomainParameters( key.GetGroupParameters() );
}

void PrintDomainParameters( const DL_GroupParameters_EC<ECP>& params )
{
    wcout << endl;
 
    wcout << "Modulus:" << endl;
    wcout << " " << integer_to_wstring(params.GetCurve().GetField().GetModulus()) << endl;
    
    wcout << "Coefficient A:" << endl;
    wcout << " " << integer_to_wstring(params.GetCurve().GetA()) << endl;
    
    wcout << "Coefficient B:" << endl;
    wcout << " " << integer_to_wstring(params.GetCurve().GetB()) << endl;
    
    wcout << "Base Point:" << endl;
    wcout << " X: " << integer_to_wstring(params.GetSubgroupGenerator().x) << endl; 
    wcout << " Y: " << integer_to_wstring(params.GetSubgroupGenerator().y) << endl;
    
    wcout << "Subgroup Order:" << endl;
    wcout << " " << integer_to_wstring(params.GetSubgroupOrder()) << endl;
    
    wcout << "Cofactor:" << endl;
    wcout << " " << integer_to_wstring(params.GetCofactor()) << endl;    
}

void PrintPrivateKey( const ECDSA<ECP, SHA256>::PrivateKey& key )
{   
    wcout << endl;
    wcout << "Private Exponent:" << endl;
    wcout << " " << integer_to_wstring(key.GetPrivateExponent()) << endl; 
}

void PrintPublicKey( const ECDSA<ECP, SHA256>::PublicKey& key )
{   
    wcout << endl;
    wcout << "Public Element:" << endl;
    wcout << " X: " << integer_to_wstring(key.GetPublicElement().x) << endl; 
    wcout << " Y: " << integer_to_wstring(key.GetPublicElement().y) << endl;
}

void SavePrivateKey( const string& filename, const ECDSA<ECP, SHA256>::PrivateKey& key )
{
    key.Save( FileSink( filename.c_str(), true /*binary*/ ).Ref() );
}

void SavePublicKey( const string& filename, const ECDSA<ECP, SHA256>::PublicKey& key )
{   
    key.Save( FileSink( filename.c_str(), true /*binary*/ ).Ref() );
}

void LoadPrivateKey( const string& filename, ECDSA<ECP, SHA256>::PrivateKey& key )
{   
    key.Load( FileSource( filename.c_str(), true /*pump all*/ ).Ref() );
}

void LoadPublicKey( const string& filename, ECDSA<ECP, SHA256>::PublicKey& key )
{
    key.Load( FileSource( filename.c_str(), true /*pump all*/ ).Ref() );
}

void EncodePrivateKey(const string& filename, const ECDSA<ECP, SHA256>::PrivateKey& key)
{
	ByteQueue queue;
	key.DEREncodePrivateKey(queue);
	Encode(filename, queue);
}

void EncodePublicKey(const string& filename, const ECDSA<ECP, SHA256>::PublicKey& key)
{
	ByteQueue queue;
	key.DEREncodePublicKey(queue);
	Encode(filename, queue);
}

void Encode(const string& filename, const BufferedTransformation& bt)
{
	FileSink file(filename.c_str());
	bt.CopyTo(file);
	file.MessageEnd();
}

void DecodePrivateKey(const string& filename, ECDSA<ECP, SHA256>::PrivateKey& key)
{
	ByteQueue queue;
	Decode(filename, queue);
	key.BERDecodePrivateKey(queue, false, queue.MaxRetrievable());
}

void DecodePublicKey(const string& filename, ECDSA<ECP, SHA256>::PublicKey& key)
{
	ByteQueue queue;
	Decode(filename, queue);
	key.BERDecodePublicKey(queue, false, queue.MaxRetrievable());
}

void Decode(const string& filename, BufferedTransformation& bt)
{
	FileSource file(filename.c_str(), true);
	file.TransferTo(bt);
	bt.MessageEnd();
}

bool SignMessage( const ECDSA<ECP, SHA256>::PrivateKey& key, const string& message, string& signature )
{
    AutoSeededRandomPool prng;
    
    signature.erase();    

    StringSource( message, true,
        new SignerFilter( prng,
            ECDSA<ECP,SHA256>::Signer(key),
            new StringSink( signature )
        ) // SignerFilter
    ); // StringSource
    
    return !signature.empty();
}

bool VerifyMessage( const ECDSA<ECP, SHA256>::PublicKey& key, const string& message, const string& signature )
{
    bool result = false;

    StringSource( signature+message, true,
        new SignatureVerificationFilter(
            ECDSA<ECP,SHA256>::Verifier(key),
            new ArraySink( (byte*)&result, sizeof(result) )
        ) // SignatureVerificationFilter
    );

    return result;
}

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