#ifndef CLIQ_DEPENDENCY_BROKER_NETWORK_H
#define CLIQ_DEPENDENCY_BROKER_NETWORK_H
/* Included only in the separate public GET provider image, after its fixed
 * owner layout. No SecretService/session bus call appears in this path. */
#include <sys/mman.h>
#include "dependency-http.h"
static bool dependency_network_live(struct dependency_broker *broker) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC,&now) || atomic_load(&broker->owner.closing) || atomic_load(&broker->owner.unsafe) ||
        atomic_load(&broker->request_expired)) return false;
    return (now.tv_sec < broker->outer_deadline.tv_sec || (now.tv_sec == broker->outer_deadline.tv_sec && now.tv_nsec < broker->outer_deadline.tv_nsec)) &&
        (now.tv_sec < broker->request_deadline.tv_sec || (now.tv_sec == broker->request_deadline.tv_sec && now.tv_nsec < broker->request_deadline.tv_nsec));
}
static bool dependency_tls_wait(struct dependency_broker *broker,int error) {
    if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE) return dependency_fail(broker,broker->stage==DEPENDENCY_CONNECT?"tls_refused":"transport_interrupted");
    struct pollfd descriptor={g_socket_get_fd(broker->socket),error == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT,0}; int result;
    do { result=poll(&descriptor,1,50); } while(result<0 && errno==EINTR && dependency_network_live(broker));
    return result>=0 && dependency_network_live(broker);
}
static bool dependency_load_ca(struct dependency_broker *broker) {
    broker->tls_context=SSL_CTX_new(TLS_client_method());
    if (!broker->tls_context || !SSL_CTX_set_min_proto_version(broker->tls_context,TLS1_3_VERSION) ||
        !SSL_CTX_set_max_proto_version(broker->tls_context,TLS1_3_VERSION)) return dependency_fail(broker,"tls_refused");
    SSL_CTX_set_verify(broker->tls_context,SSL_VERIFY_PEER,NULL);
    SSL_CTX_set_options(broker->tls_context,SSL_OP_NO_COMPRESSION|SSL_OP_NO_RENEGOTIATION);
    BIO *input=BIO_new_mem_buf(broker->trust,(int)broker->trust_size); if(!input)return dependency_fail(broker,"tls_refused");
    unsigned count=0; X509 *certificate;
    while((certificate=PEM_read_bio_X509(input,NULL,NULL,NULL))) {
        bool added=X509_STORE_add_cert(SSL_CTX_get_cert_store(broker->tls_context),certificate)==1; X509_free(certificate);
        if(!added || ++count>4096){BIO_free(input);ERR_clear_error();return dependency_fail(broker,"tls_refused");}
    }
    BIO_free(input);ERR_clear_error();return count>0 || dependency_fail(broker,"tls_refused");
}
static bool dependency_pin(struct dependency_broker *broker) {
    X509 *certificate=SSL_get1_peer_certificate(broker->tls); if(!certificate)return dependency_fail(broker,"tls_refused");
    X509_PUBKEY *key=X509_get_X509_PUBKEY(certificate); unsigned char *encoded=NULL,digest[32]; int size=i2d_X509_PUBKEY(key,&encoded);
    bool valid=size>0 && encoded && SHA256(encoded,(size_t)size,digest),matched=false;
    for(uint32_t index=0;valid && index<broker->target->pin_count;index++)matched |= CRYPTO_memcmp(digest,broker->target->pins[index],32)==0;
    OPENSSL_free(encoded);X509_free(certificate);wipe(digest,sizeof(digest));
    return (valid && matched) || dependency_fail(broker,"tls_refused");
}
static bool dependency_network_connect(struct dependency_broker *broker) {
    if(!dependency_network_live(broker))return dependency_fail(broker,"cancelled_or_expired");
    GSocketClient *client=g_socket_client_new();g_socket_client_set_enable_proxy(client,FALSE);g_socket_client_set_tls(client,FALSE);
    g_socket_client_set_timeout(client,DEADLINE_SECONDS);GError *error=NULL;
    broker->network_started=true; broker->connection_count++;
    broker->connection=g_socket_client_connect_to_host(client,broker->target->host,(guint16)broker->target->port,broker->cancel,&error);
    g_object_unref(client);g_clear_error(&error);
    if(!dependency_network_live(broker))return dependency_fail(broker,"cancelled_or_expired");
    if(!broker->connection)return dependency_fail(broker,"transport_interrupted");
    broker->socket=g_socket_connection_get_socket(broker->connection);g_socket_set_blocking(broker->socket,FALSE);
    if(!dependency_load_ca(broker))return false;
    broker->tls=SSL_new(broker->tls_context);
    if(!broker->tls || !SSL_set_fd(broker->tls,g_socket_get_fd(broker->socket)) || !SSL_set_tlsext_host_name(broker->tls,broker->target->server_name))return dependency_fail(broker,"tls_refused");
    X509_VERIFY_PARAM *parameters=SSL_get0_param(broker->tls);X509_VERIFY_PARAM_set_hostflags(parameters,X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
    if(g_hostname_is_ip_address(broker->target->server_name)) {
        if(!X509_VERIFY_PARAM_set1_ip_asc(parameters,broker->target->server_name))return dependency_fail(broker,"tls_refused");
    }else if(!SSL_set1_host(broker->tls,broker->target->server_name))return dependency_fail(broker,"tls_refused");
    for(;;){if(!dependency_network_live(broker))return dependency_fail(broker,"cancelled_or_expired");int result=SSL_connect(broker->tls);
        if(result==1)break;if(!dependency_tls_wait(broker,SSL_get_error(broker->tls,result)))return dependency_fail(broker,"tls_refused");}
    return (SSL_version(broker->tls)==TLS1_3_VERSION && SSL_get_verify_result(broker->tls)==X509_V_OK && dependency_pin(broker)) || dependency_fail(broker,"tls_refused");
}
static bool dependency_network_write(struct dependency_broker *broker,const unsigned char *bytes,size_t size) {
    for(size_t offset=0;offset<size;){if(!dependency_network_live(broker))return dependency_fail(broker,"cancelled_or_expired");size_t written=0;
        int result=SSL_write_ex(broker->tls,bytes+offset,size-offset,&written);
        if(result==1){if(!written)return false;offset+=written;}
        else if(!dependency_tls_wait(broker,SSL_get_error(broker->tls,result)))return false;}
    return true;
}
static ssize_t dependency_network_read(void *context,unsigned char *bytes,size_t size) {
    struct dependency_broker *broker=context;
    for(;;){if(!dependency_network_live(broker)){dependency_fail(broker,"cancelled_or_expired");return -1;}size_t received=0;int result=SSL_read_ex(broker->tls,bytes,size,&received);
        if(result==1)return received ? (ssize_t)received : -1;int error=SSL_get_error(broker->tls,result);
        if(error==SSL_ERROR_ZERO_RETURN)return 0;if(!dependency_tls_wait(broker,error))return -1;}
}
static bool dependency_body_sink(void *context,const unsigned char *bytes,size_t size) {
    struct dependency_broker *broker=context;
    if(!dependency_network_live(broker))return false;
    if(broker->http.status!=200)return true; /* No error body crosses N-API. */
    if(broker->output_fd<0){broker->output_fd=(int)syscall(SYS_memfd_create,"cliq-dependency-package",MFD_CLOEXEC|MFD_ALLOW_SEALING);
        if(broker->output_fd<0)return dependency_fail(broker,"package_storage_unavailable");}
    for(size_t offset=0;offset<size;){ssize_t count=write(broker->output_fd,bytes+offset,size-offset);
        if(count<0 && errno==EINTR && dependency_network_live(broker))continue;
        if(count<=0)return dependency_fail(broker,"package_storage_unavailable");offset+=(size_t)count;}
    sha256_update(&broker->content_hash,bytes,size);
    return EVP_DigestUpdate(broker->integrity_hash,bytes,size)==1 || dependency_fail(broker,"integrity_refused");
}
static bool dependency_close_fd(struct dependency_broker *broker,int *descriptor) {
    int owned=*descriptor;*descriptor=-1;if(owned<0 || close(owned)==0)return true;
    dependency_unsafe(broker);atomic_store(&retirement_failed,true);return dependency_fail(broker,"resource_retirement");
}
static void dependency_network_retire(struct dependency_broker *broker) {
    if(broker->tls){SSL_free(broker->tls);broker->tls=NULL;}
    if(broker->tls_context){SSL_CTX_free(broker->tls_context);broker->tls_context=NULL;}
    if(broker->integrity_hash){EVP_MD_CTX_free(broker->integrity_hash);broker->integrity_hash=NULL;}
    if(broker->connection){GError *error=NULL;bool closed=g_io_stream_close(G_IO_STREAM(broker->connection),NULL,&error);g_clear_error(&error);
        if(!closed){broker->network_retirement_failed=true;dependency_unsafe(broker);atomic_store(&retirement_failed,true);dependency_fail(broker,"resource_retirement");}
        else{g_object_unref(broker->connection);broker->connection=NULL;broker->socket=NULL;}}
    (void)dependency_close_fd(broker,&broker->output_fd);
    ERR_clear_error();
}
static bool dependency_seal_output(struct dependency_broker *broker) {
    unsigned char content[32],integrity[EVP_MAX_MD_SIZE],expected[96];unsigned actual_size=0;
    sha256_final(&broker->content_hash,content);
    int decoded=EVP_DecodeBlock(expected,broker->descriptor->integrity.data,(int)broker->descriptor->integrity.size);
    unsigned expected_size=cliq_dependency_string_equal(broker->descriptor->algorithm,"sha256")?32u:64u;
    bool valid=EVP_DigestFinal_ex(broker->integrity_hash,integrity,&actual_size)==1 && actual_size==expected_size &&
        decoded==(int)(expected_size+(expected_size==32?1:2)) && CRYPTO_memcmp(integrity,expected,expected_size)==0;
    wipe(expected,sizeof(expected));wipe(integrity,sizeof(integrity));
    if(!valid){broker->integrity_matched=false;return true;} /* Exact failed GET is retryable; no data owner. */
    broker->integrity_matched=true;
    if(broker->output_fd<0 || fchmod(broker->output_fd,0400) || fcntl(broker->output_fd,F_ADD_SEALS,F_SEAL_WRITE|F_SEAL_GROW|F_SEAL_SHRINK|F_SEAL_SEAL))return dependency_fail(broker,"package_storage_unavailable");
    struct stat original,readonly;char path[64];int count=snprintf(path,sizeof(path),"/proc/self/fd/%d",broker->output_fd);
    if(fstat(broker->output_fd,&original) || count<1 || (size_t)count>=sizeof(path))return dependency_fail(broker,"package_storage_unavailable");
    int descriptor=open(path,O_RDONLY|O_CLOEXEC);if(descriptor<0)return dependency_fail(broker,"package_storage_unavailable");
    char digest[65];static const char hex[]="0123456789abcdef";
    for(size_t index=0;index<32;index++){digest[index*2]=hex[content[index]>>4];digest[index*2+1]=hex[content[index]&15];}digest[64]=0;wipe(content,sizeof(content));
    valid=fstat(descriptor,&readonly)==0 && cliq_dependency_data_same(&original,&readonly) &&
        cliq_dependency_data_initialize(&broker->pending_package->data,descriptor,broker->http.received_bytes,broker->config->max_package_bytes,digest)==CLIQ_DEPENDENCY_DATA_OK;
    if(!valid){(void)dependency_close_fd(broker,&descriptor);return dependency_fail(broker,"package_storage_unavailable");}
    return dependency_close_fd(broker,&broker->output_fd);
}
static bool dependency_network_get(struct dependency_broker *broker) {
    char path[8194],request[9000];size_t base_size=strlen(broker->target->base_path);
    if(base_size && broker->target->base_path[base_size-1]=='/')base_size--;
    int size=snprintf(path,sizeof(path),"%.*s%.*s",(int)base_size,broker->target->base_path,(int)broker->descriptor->path.size,broker->descriptor->path.data);
    if(size<1 || (size_t)size>=sizeof(path))return dependency_fail(broker,"request_refused");
    size=snprintf(request,sizeof(request),"GET %s HTTP/1.1\r\nHost: %s:%u\r\nAccept: application/octet-stream\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n",path,broker->target->host,broker->target->port);
    if(size<1 || (size_t)size>=sizeof(request))return dependency_fail(broker,"request_refused");
    broker->integrity_hash=EVP_MD_CTX_new();
    if(!broker->integrity_hash || EVP_DigestInit_ex(broker->integrity_hash,cliq_dependency_string_equal(broker->descriptor->algorithm,"sha256")?EVP_sha256():EVP_sha512(),NULL)!=1)return dependency_fail(broker,"integrity_refused");
    sha256_init(&broker->content_hash);broker->request_started=true;broker->request_count++;
    if(!dependency_network_write(broker,(const unsigned char*)request,(size_t)size))return dependency_fail(broker,"transport_interrupted");
    uint64_t remaining=broker->config->max_transfer_bytes-broker->total_transferred;
    broker->http=(struct cliq_dependency_http){broker,dependency_network_read,dependency_body_sink,
        remaining<broker->config->max_package_bytes?remaining:broker->config->max_package_bytes,0,0,0,false};
    bool valid=cliq_dependency_http_response(&broker->http);broker->total_transferred+=broker->http.received_bytes;
    if(!valid)return dependency_fail(broker,"response_refused");
    return broker->http.status!=200 || dependency_seal_output(broker);
}
#endif
