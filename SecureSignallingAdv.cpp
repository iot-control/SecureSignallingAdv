#include "SecureSignallingAdv.h"

SecureSignallingAdv::SecureSignallingAdv(
    byte mac[],
    IPAddress ip,
    uint16_t port,
    byte hmacKey[],
    int hmacKeyLen,
    int (**functionArray)(),
    int functionsCount,
    int (*failFunc)(),
    void (*loopFunc)(),
    bool enableSerial,
    int randDataLength,
    int clientFirstByteCount,
    int hashByteLength,
    uint8_t seed
  ){
  // Anything you need when instantiating your object goes here

    _mac = mac;
    _ip = ip;
    _port = port;
    
    _hmacKey = hmacKey;
    _hmacKeyLen = hmacKeyLen;
    
    _functionArray = functionArray;
    _functionsCount = functionsCount;
    
    _failFunc = failFunc;
    _loopFunc = loopFunc;
    
    _enableSerial = enableSerial;

    _randDataLength = randDataLength;
    _clientFirstByteCount = clientFirstByteCount;
    _hashByteLength = hashByteLength;
    
    randomSeed(seed);
}

// this is our 'begin' function
void SecureSignallingAdv::begin(int baudRate){

  // Initialize the Ethernet server library
  // with the IP address and port you want to use
  // (port 80 is default for HTTP):
  EthernetServer server(_port);
  
  if(_enableSerial){
    // Open serial communications and wait for port to open:
    Serial.begin(baudRate);
    while (!Serial){
      ; // wait for serial port to connect. Needed for Leonardo only
    }
    Serial.println("SecureSignallingAdv constructor instantiated successfully.");
  }

  
  Ethernet.begin(_mac, _ip);  // Start the Ethernet connection and the server:
  _server = &server;
  
  _server->begin();
  
  
  if (_enableSerial) {
    Serial.print("server is at ");
    Serial.println(Ethernet.localIP());
  }
  
  while(1){
    // listen for incoming clients
    EthernetClient client = (*_server).available();
    
    if(client){
      if (_enableSerial) Serial.println("new client");


      bool isOTP = false;

      int i;
      uint8_t randKey[_randDataLength];
      uint8_t randVal;
      
      ////////////////

	    int receivedByteCount = 0;
      uint8_t receivedHash[_hashByteLength];

      int timeout = 777;

      int OTPRequestFirstByteIndex = 5; // GET /
      int OTPLen = 7;
      uint8_t OTP[OTPLen];


      while(client.connected()){
        
        if(!timeout){
          if(_enableSerial) Serial.println("Client did not send data in time. Timed out!");
          break;
        }


        if(client.available()){ // If client has sent data

          char c = client.read();
          receivedByteCount++;

          //Serial.println(receivedByteCount);
          //Serial.println(c);

          if(isOTP){
            if(receivedByteCount <= OTPLen + OTPRequestFirstByteIndex){
              if(receivedByteCount > OTPRequestFirstByteIndex) OTP[receivedByteCount - OTPRequestFirstByteIndex - 1] = c;
              continue;
            }else{
              gotOTP(OTP, OTPLen);
              break;
            }
          }

          if(receivedByteCount == 1){
            if(c == 'G'){
              isOTP = true;
              if(_enableSerial) Serial.println("IS OTP");
              
              client.write("HTTP/1.1 200 OK\nContent-Type: text/html\nConnection: close\n\n<!DOCTYPE HTML><html><h1>OK!</h1></html>", 99);

            }else{
              for(i=0; i<_randDataLength; i++){
                randVal = random(256);
                randKey[i] = randVal;
                //client.write(randVal);
              }
              client.write(randKey, _randDataLength);
            }
            continue;
          }



          if(receivedByteCount > _clientFirstByteCount){
            receivedHash[receivedByteCount - _clientFirstByteCount - 1] = c;
          }

          if(receivedByteCount == (_hashByteLength + _clientFirstByteCount)){ // GOT HASH CMD
            // printHash(  getHash( randKey,_randDataLength, _hmacKey, _hmacKeyLen, 2)   );
            // printHash(receivedHash);

            int execFuncNum = -1;
            for (i=0; i<_functionsCount * 4; i++){  // Find the execFuncNum (function index) from the hash
              if(hashesAreTheSame(
                    getHash(randKey,
                            _randDataLength,
                            _hmacKey,
                            _hmacKeyLen,
                            i
                    ),
                    receivedHash,
                    _hashByteLength
              )){
              
                execFuncNum = i;
                break;
              }
            }

            if(execFuncNum < 0){ // If the function index was not found
              if(_enableSerial) Serial.println("Unknown cmd, executing failFunc");

              client.write(
                getHash(
                  randKey,
                  _randDataLength,
                  _hmacKey,
                  _hmacKeyLen,
                  _failFunc()
                ),
                _hashByteLength
              );

              break;
            }


            if(execFuncNum < _functionsCount){ // If the function index was found
                if(_enableSerial){
                  Serial.print("Simple EXEC function -> ");
                  Serial.println(execFuncNum);
                }

                client.write(
                  getHash(
                    randKey,
                    _randDataLength,
                    _hmacKey,
                    _hmacKeyLen,
                    _functionArray[execFuncNum]()
                  ),
                  _hashByteLength
                );

                break;
            }

            if(execFuncNum < _functionsCount * 2){ // CREATE OTP
                execFuncNum -= _functionsCount;

                if(_enableSerial){
                  Serial.print("CREATE OTP for function -> ");
                  Serial.println(execFuncNum);
                }
                
                client.write(
                  getHash(
                    randKey,
                    _randDataLength,
                    _hmacKey,
                    _hmacKeyLen,
                    createOTP(execFuncNum)
                  ),
                  _hashByteLength
                );


                break;
            }

            if(execFuncNum < _functionsCount * 3){ // LIST OTPs
                execFuncNum -= _functionsCount*2;
                
                if(_enableSerial){
                  Serial.print("LIST OTPs for function -> ");
                  Serial.println(execFuncNum);
                }

                client.write(
                  getHash(
                    randKey,
                    _randDataLength,
                    _hmacKey,
                    _hmacKeyLen,
                    _functionArray[2]()
                  ),
                  _hashByteLength
                );

                break;
            }

            if(execFuncNum < _functionsCount * 4){ // DELETE OTPs
                execFuncNum -= _functionsCount*3;

                if(_enableSerial){
                  Serial.print("DELETE OTPs for function -> ");
                  Serial.println(execFuncNum);
                }

                client.write(
                  getHash(
                    randKey,
                    _randDataLength,
                    _hmacKey,
                    _hmacKeyLen,
                    _functionArray[2]()
                  ),
                  _hashByteLength
                );

                break;
            }  

            if(_enableSerial) Serial.println("execFuncNum out of range (This never should happen).");

            /////////////////////////////////////////////////////////////////////

            // DONE
            break;
          }
        
        }else{
          delay(1);
          timeout = timeout - 1; // If the client's has not sent data, decrement the timeout timer
        }
      }

      // give the web browser time to receive the data
      delay(1);
      // close the connection:
      client.stop();
      if(_enableSerial) Serial.println("client disconnected");
	
    }
    //execute new loop function
    _loopFunc();
  }

  
}



// Private methods of this class

void SecureSignallingAdv::gotOTP(uint8_t* OTP, int OTPLen){
  if(_enableSerial){
    Serial.print("OTP-> _");
    for(int v = 0; v < OTPLen; v++){
      Serial.print(char(OTP[v]));
    }
    Serial.print("_\n");
  }
}

int SecureSignallingAdv::createOTP(int funcNum){
  if(_enableSerial) Serial.println("OTP CREATED");
  return 0;
}


uint8_t* SecureSignallingAdv::getHash(uint8_t* data, int dataLength, uint8_t* key, int keyLength, uint8_t functionIndex){
  Sha256.initHmac(key, keyLength);
  int i;
  for(i=0; i<dataLength; i++){
      Sha256.write(data[i]);
  }
  Sha256.write(functionIndex);
  return Sha256.resultHmac();
}
bool SecureSignallingAdv::hashesAreTheSame(uint8_t* hash1, uint8_t* hash2, int len){
  for (int i=0; i<len; i++) if(hash1[i] != hash2[i]) return false;
  return true;
}

void SecureSignallingAdv::printHash(uint8_t* hash){
  if(_enableSerial){
    int i;
    for (i=0; i<32; i++) {
      Serial.print("0123456789abcdef"[hash[i]>>4]);
      Serial.print("0123456789abcdef"[hash[i]&0xf]);
    }
    Serial.println();
  }
}