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
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/stack.h>

#define PORT 8765

/* use these strings to tell the marker what is happening */
#define FMT_ACCEPT_ERR "ECE568-SERVER: SSL accept error\n"
#define FMT_CLIENT_INFO "ECE568-SERVER: %s %s\n"
#define FMT_OUTPUT "ECE568-SERVER: %s %s\n"
#define FMT_INCOMPLETE_CLOSE "ECE568-SERVER: Incomplete shutdown\n"


int main(int argc, char **argv)
{
  int s,r, end, sock, port=PORT;
  struct sockaddr_in sin;
  int val=1;
  pid_t pid;
  
  
  /*Parse command line arguments*/
  
  switch(argc){
    case 1:
      break;
    case 2:
      port=atoi(argv[1]);
      if (port<1||port>65535){
	fprintf(stderr,"invalid port number");
	exit(0);
      }
      break;
    default:
      printf("Usage: %s port\n", argv[0]);
      exit(0);
  }

  if((sock=socket(AF_INET,SOCK_STREAM,0))<0){
    perror("socket");
    close(sock);
    exit(0);
  }
  
  memset(&sin,0,sizeof(sin));
  sin.sin_addr.s_addr=INADDR_ANY;
  sin.sin_family=AF_INET;
  sin.sin_port=htons(port);
  
  setsockopt(sock,SOL_SOCKET,SO_REUSEADDR, &val,sizeof(val));
    
  if(bind(sock,(struct sockaddr *)&sin, sizeof(sin))<0){
    perror("bind");
    close(sock);
    exit (0);
  }
  
  if(listen(sock,5)<0){
    perror("listen");
    close(sock);
    exit (0);
  } 
  
  while(1){
    
    if((s=accept(sock, NULL, 0))<0){
      perror("accept");
      close(sock);
      close(s);
      exit (0);
    }

      	int len;
      	char buf[256];
      	char *answer = "42";
	char *keyfile = "bob.pem";
        char *CA_file = "568ca.pem";
	char *password = "password";
	char *cipher = "NULL-MD5:NULL-SHA:RC4-MD5:RC4-SHA:DES-CBC-SHA:DES-CBC3-SHA:AES128-SHA:AES256-SHA:RC4-MD5:RC2-CBC-MD5:DES-CBC-MD5:DES-CBC3-MD5";
	//char *cipher = "RC4-MD5";

	// SSL variables
  	SSL *ssl;
  	SSL_CTX *sslContext;
        X509 *peer;
        char peer_CN[256];

	/* STEP 1: SSL Initialization and server certificate/key validation */

 	// Global system initialization
 	SSL_library_init(); 		// Register the available ciphers and digests
 	SSL_load_error_strings();	// Register the error strings for libcrypto & libssl

      		
	// Create new context supporting SSL 3, SSL 2, and TLSv1
     	//sslContext = SSL_CTX_new (SSLv23_server_method()); 	
	sslContext = SSL_CTX_new (SSLv2_server_method()); 	
	
      	if (sslContext == NULL)
        	ERR_print_errors_fp (stderr);
	
	// Set the cipher list 
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
		ERR_print_errors_fp (stderr); // "Cannot read key file"

	// Verify that private key agrees with corresponding public key in certificate
	if (SSL_CTX_check_private_key(sslContext) == 0) 
	{
    		printf("Private key does not match the certificate public key\n");
    		exit(0);
  	}

	// Ensure that client certificate needs to be verified upon SSL connection	
	SSL_CTX_set_verify(sslContext,SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT,NULL);

 	// Loads certificates of CAs that are trusted and that will be used to verify client's certificate
 	if(!(SSL_CTX_load_verify_locations(sslContext,CA_file,0)))
		ERR_print_errors_fp (stderr); // "Cannot read CA list"
 	
	/*fork a child to handle the connection*/
    
    if((pid=fork())){
      close(s);
    }
    //*****child*******************
    else 
	{

	/* STEP 2: Establishing SSL connection */

	// Create an SSL structure for the connection
      	ssl = SSL_new (sslContext);
      	if (ssl == 0){
        	ERR_print_errors_fp (stderr); // "Error creating SSL structure"
        	close(s);
        	return 0;
	}
	// Assign a socket to the SSL structure
	SSL_set_fd(ssl, s);

	// Accept connection from client
	if((r=SSL_accept(ssl)<=0)){
		ERR_print_errors_fp (stderr); // "SSL accept error"
		close(s);
		return 0;
	}


	/* STEP 3: Client certificate validation */

	if(SSL_get_verify_result(ssl)!=X509_V_OK)
	{
		//printf("X509 failure...\n");
		printf(FMT_ACCEPT_ERR);
		ERR_print_errors_fp (stderr); // "No certificate returned"
		close(s);
		return 0;
	}

 	/*Check the cert chain. The chain length is automatically checked by OpenSSL when
	we set the verify depth in the ctx */

 	// Check the common name
 	peer=SSL_get_peer_certificate(ssl);
	if (peer == NULL)
	{
		printf(FMT_ACCEPT_ERR);
		ERR_print_errors_fp (stderr); // "Peer did not return a certificate"
		close(s);
		return 0;
	}
	
	// Extract the common name from client's certificate
	X509_NAME_get_text_by_NID(X509_get_subject_name(peer),NID_commonName, peer_CN, 256);
	_STACK* email_stack = (_STACK*)X509_get1_email(peer);
	

	

	/* STEP 4: SSL Transactions */

	// Receive message from client
	len = SSL_read (ssl, &buf, 255); 
	if(len > 0){	
	        buf[len] = '\0';
	}else if(len == 0){
		printf(FMT_INCOMPLETE_CLOSE);
		close(s);
		return 0;
	}else{
		printf(FMT_ACCEPT_ERR);
		close(s);
		return 0;
	}
	// Send message to client
	
	len = SSL_write (ssl, answer, strlen (answer));
	if(len > 0){	
	        
	}else if(len == 0){
		printf(FMT_INCOMPLETE_CLOSE);
		close(s);
		return 0;
	}else{
		printf(FMT_ACCEPT_ERR);
		close(s);
		return 0;
	}

	// If client has valid certificate, print the following
	if(strcasecmp(peer_CN,"Alice's Client"))
	{
		ERR_print_errors_fp (stderr); // "Common name does not match host name"
		close(s);
		return 0;
	}	
	else
	{
		printf(FMT_CLIENT_INFO,peer_CN,*(email_stack->data));
		printf(FMT_OUTPUT,buf,answer);
	}



	/* STEP 5: Shutdown connection */  


	end=SSL_shutdown(ssl);

	// if end == 0; server shutdown first
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
 			printf(FMT_INCOMPLETE_CLOSE);
			break;
 	}

     	//close(sock);
      	close(s);
      	return 0;
    }
  }
  
  close(sock);
  return 1;
}


