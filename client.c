#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/stack.h>

#define HOST "localhost"
#define PORT 8765

/* use these strings to tell the marker what is happening */
#define FMT_CONNECT_ERR "ECE568-CLIENT: SSL connect error\n"
#define FMT_SERVER_INFO "ECE568-CLIENT: %s %s %s\n"
#define FMT_OUTPUT "ECE568-CLIENT: %s %s\n"
#define FMT_CN_MISMATCH "ECE568-CLIENT: Server Common Name doesn't match\n"
#define FMT_EMAIL_MISMATCH "ECE568-CLIENT: Server Email doesn't match\n"
#define FMT_NO_VERIFY "ECE568-CLIENT: Certificate does not verify\n"
#define FMT_INCORRECT_CLOSE "ECE568-CLIENT: Premature close\n"


int main(int argc, char **argv)
{
  int len, end, sock, port=PORT;
  char *host=HOST;
  struct sockaddr_in addr;
  struct hostent *host_entry;
  char buf[256];
  char *secret = "What's the question?";
  char *keyfile = "alice.pem";
  char *CA_file = "568ca.pem";
  char *password = "password";
  const char *version;
  const char *server_cipher;

  // SSL variables
  SSL *ssl;
  SSL_CTX *sslContext;
  X509 *peer;
  char peer_CN[256];
  char *cipher = "NULL-SHA:RC4-SHA:DES-CBC-SHA:DES-CBC3-SHA:AES128-SHA:AES256-SHA";
  
  /*Parse command line arguments*/
  
  switch(argc){
    case 1:
      break;
    case 3:
      host = argv[1];
      port=atoi(argv[2]);
      if (port<1||port>65535){
	fprintf(stderr,"invalid port number");
	exit(0);
      }
      break;
    default:
      printf("Usage: %s server port\n", argv[0]);
      exit(0);
  }
  
  /*get ip address of the host*/
  
  host_entry = gethostbyname(host);
  
  if (!host_entry){
    fprintf(stderr,"Couldn't resolve host");
    exit(0);
  }

  memset(&addr,0,sizeof(addr));
  addr.sin_addr=*(struct in_addr *) host_entry->h_addr_list[0];
  addr.sin_family=AF_INET;
  addr.sin_port=htons(port);
  
  printf("Connecting to %s(%s):%d\n", host, inet_ntoa(addr.sin_addr),port);
  
  /*open socket*/
  
  if((sock=socket(AF_INET, SOCK_STREAM, IPPROTO_TCP))<0)
    perror("socket");

  if(connect(sock,(struct sockaddr *)&addr, sizeof(addr))<0)
    perror("connect");



	/* STEP 1: SSL Initialization and server certificate/key validation */

 	/* Global system initialization*/
 	SSL_library_init(); 		// Register the available ciphers and digests
 	SSL_load_error_strings();	// Register the error strings for libcrypto & libssl

      		
	// Create new context supporting SSL 3 and TLSv1
     	sslContext = SSL_CTX_new (SSLv23_client_method());

	// Ensure that SSL2 is not supported
	SSL_CTX_set_options(sslContext,SSL_OP_NO_SSLv2);

      	if (sslContext == NULL)
	{
        	ERR_print_errors_fp (stderr);
		exit(0);
	}


	// Set the cipher list (client uses SHA1)
  	if (SSL_CTX_set_cipher_list(sslContext, cipher) <= 0) 
	{
    		printf("Error setting the cipher list.\n");
    		exit(0);
  	}
	
	// Set the certificate to be used
	if (SSL_CTX_use_certificate_file(sslContext, keyfile, SSL_FILETYPE_PEM) <= 0) 
	{
	    	printf("Error setting the certificate file.\n");
    		exit(0);
  	}

	// Identify password that is used to access data in private key
 	SSL_CTX_set_default_passwd_cb_userdata(sslContext,password);

	// Load the private key to be used
 	if(!(SSL_CTX_use_PrivateKey_file(sslContext,keyfile,SSL_FILETYPE_PEM)))
	{	
		ERR_print_errors_fp (stderr); // "Cannot read key file"	
		exit(0);
	}

	// Verify that private key agrees with corresponding public key in certificate
	if (SSL_CTX_check_private_key(sslContext) == 0) 
	{
   		printf("Private key does not match the certificate public key\n");
   		exit(0);
	}

 	// Loads certificates of CAs that are trusted and that will be used to verify client's certificate
 	if(!(SSL_CTX_load_verify_locations(sslContext,CA_file,0)))
	{
		ERR_print_errors_fp (stderr); // "Cannot read CA list"
		exit(0);
 	}

	// Set for server verification
	SSL_CTX_set_verify(sslContext,SSL_VERIFY_PEER,NULL);



	/* STEP 2: Establishing SSL connection */

	// Create an SSL struct for the connection
      	ssl = SSL_new (sslContext);
      	if (ssl == NULL)
	{
        	ERR_print_errors_fp (stderr);
		exit(0);
	}
   		
      	// Assign a socket to the SSL structure
      	if (!SSL_set_fd (ssl, sock))
	{
        	ERR_print_errors_fp (stderr);
		exit(0);
	}

      	// Initiate SSL handshake
      	if (SSL_connect (ssl) != 1)
	{
        	ERR_print_errors_fp (stderr);
		exit(0);
	}



	/* STEP 3: Server certificate validation */

	if(SSL_get_verify_result(ssl)!=X509_V_OK)
		ERR_print_errors_fp (stderr); // "Certificate does not verify"

 	/*Check the cert chain. The chain length is automatically checked by OpenSSL when
	we set the verify depth in the ctx */

	// Check the common name
 	peer=SSL_get_peer_certificate(ssl);
	if (peer == NULL)
	{
		printf("peer == NULL \n");
		ERR_print_errors_fp (stderr); // "Peer did not return a certificate"
		exit(0);
	}

	// Extract the common name from server's certificate
	X509_NAME_get_text_by_NID(X509_get_subject_name(peer),NID_commonName, peer_CN, 256);
	_STACK* email_stack = (_STACK*)X509_get1_email(peer);
	char CA_local[256];
	char CA_remote[256];
	X509_NAME_oneline(X509_get_issuer_name(peer), CA_remote, 256);
	X509_NAME_oneline(X509_get_issuer_name(((X509_OBJECT*)(*((_STACK*)(sslContext->cert_store->objs))->data))->data.x509), CA_local, 256);
        //printf("issuer= %s\n", buf);
	

	
	#define EMAIL *(email_stack->data)
	#define ISSUER CA_remote
	
	// Get version used by server (must be SSLv3 or TLSV1)
	version = SSL_get_version(ssl);
	if ((strcasecmp(version,"SSLv3") !=0) && (strcasecmp(version, "TLSv1") !=0))	
	{
		printf(FMT_CONNECT_ERR);
		exit(0);
	}
	

	// Get cipher type used by server (must be SHA1); "NULL-SHA:RC4-SHA:DES-CBC-SHA: DES-CBC3-SHA:AES128-SHA:AES256-SHA";
        server_cipher = SSL_get_cipher(ssl);
	if ((strcasecmp(server_cipher,"NULL-SHA") !=0) && (strcasecmp(server_cipher,"RC4-SHA") !=0) && (strcasecmp(server_cipher,"DES-CBC-SHA") !=0) && (strcasecmp(server_cipher,"DES-CBC3-SHA") !=0) && (strcasecmp(server_cipher,"AES128-SHA") !=0) && (strcasecmp(server_cipher,"AES256-SHA") !=0))	
	{
		printf(FMT_CONNECT_ERR);
		ERR_print_errors_fp (stderr);
		exit(0);
		
	}


	
	/* STEP 4: SSL Transactions */

	 if ((strcasecmp(peer_CN,"Bob's Server") ==0) && (strcasecmp(EMAIL, "ece568bob@ecf.utoronto.ca") ==0) && (strcasecmp(CA_remote,CA_local) == 0))
	   {
	   	// Send a message to server via SSL
		len = SSL_write (ssl, secret, strlen (secret)); 
		if(len > 0){	
	        	
		}else if(len == 0){
			printf(FMT_INCORRECT_CLOSE);
			return 0;
		}else{
			printf(FMT_CONNECT_ERR);
			return 0;
		}
		// Receive message from server via SSL
		len = SSL_read (ssl, &buf, 255); 	
       		if(len > 0){	
			buf[len] = '\0';
		}else if(len == 0){
			printf(FMT_INCORRECT_CLOSE);
			return 0;
		}else{
			printf(FMT_CONNECT_ERR);
			return 0;
		}
       		
		printf(FMT_SERVER_INFO,peer_CN,EMAIL,ISSUER);
		printf(FMT_OUTPUT,secret,buf);
		//printf ("\n\n %s", version);	
	   }
	   else if ((strcasecmp(peer_CN,"Bob's Server") !=0) && (strcasecmp(EMAIL, "ece568bob@ecf.utoronto.ca") ==0) && (strcasecmp(CA_remote,CA_local) == 0))
	   {
		printf(FMT_CN_MISMATCH);
	   }
	   else if ((strcasecmp(peer_CN,"Bob's Server") ==0) && (strcasecmp(EMAIL, "ece568bob@ecf.utoronto.ca") !=0) && (strcasecmp(CA_remote,CA_local) == 0))	 
	   {
		printf(FMT_EMAIL_MISMATCH);
	   }else if((strcasecmp(CA_remote,CA_local) != 0))
	   {
	   	printf(FMT_NO_VERIFY);
	   }
	    
		


	/* STEP 5: Shutdown connection */  

	end=SSL_shutdown(ssl);

	// if end == 0; client shutdown first
	// if end == 1; both client and server shutdown
	// if end ==-1; error in shutdown

 	switch(end)
	{
 		case 1:
 			break; 
 		case 0:
			SSL_shutdown(ssl);
			break;
 		case -1:
 			printf(FMT_INCORRECT_CLOSE);
			break;
 	}

     	close(sock);
  return 1;
}
