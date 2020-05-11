#ifndef tl
#define tl

#if (ARDUINO >=100)
  #include "Arduino.h"
#else
  #include "WProgram.h"
#endif

#include <SPI.h>
#include <Ethernet2.h>
#include <sha256.h>

class SecureSignallingAdv  {
  public:
    // Constructor 
    SecureSignallingAdv(
		byte mac[],		/* Enter a MAC address and IP address for your controller below. */
		IPAddress ip,	/* The IP address will be dependent on your local network: */
		uint16_t port,	/* The port which the server will be listening */
		byte hmacKey[],	/* The key which the communication will be hashed */
		int hmacKeyLen,
		int (**functionArray)(),
		int functionsCount,
		int (*failFunc)(),
		void (*loopFunc)(),
		bool enableSerial=false,
		int randDataLength = 100,
		int clientFirstByteCount = 1,
		int hashByteLength = 32,
		uint8_t seed = analogRead(A0)
	);

    // Methods
    void begin(int baudRate=9600);
    void listen();

  private:
    bool _enableSerial;
    byte *_mac;
	IPAddress _ip;
	uint16_t _port;
	byte *_hmacKey;
	int _hmacKeyLen;
	int (**_functionArray)();
	int _functionsCount;
	int (*_failFunc)();
	void (*_loopFunc)();
	EthernetServer *_server;
	int _randDataLength;
	int _clientFirstByteCount;
	int _hashByteLength;
	
	uint8_t* getHash(uint8_t* data, int dataLength, uint8_t* key, int keyLength, uint8_t additionalData);
	bool hashesAreTheSame(uint8_t* hash1, uint8_t* hash2, int len);
	void printHash(uint8_t* hash);
	
	void gotOTP(uint8_t* OTP, int OTPLen);
	int createOTP(int funcNum);
};
#endif
