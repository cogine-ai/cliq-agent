#include <stdio.h>
#include <stdlib.h>
#include "dependency-http.h"
struct fixture { const unsigned char *wire; size_t size, offset, received; const unsigned char *expected; size_t expected_size; };
static ssize_t read_fixture(void *context, unsigned char *bytes, size_t size) {
 struct fixture *fixture=context; if (size>fixture->size-fixture->offset) size=fixture->size-fixture->offset;
 if(size>7)size=7; memcpy(bytes,fixture->wire+fixture->offset,size);fixture->offset+=size;return (ssize_t)size;
}
static bool sink(void *context,const unsigned char *bytes,size_t size) {
 struct fixture *fixture=context;
 if(fixture->expected && (size>fixture->expected_size-fixture->received || memcmp(bytes,fixture->expected+fixture->received,size)))return false;
 fixture->received+=size;return size<=65536;
}
static bool run(const char *wire,uint64_t max,unsigned status,size_t count) {
 struct fixture fixture={(const unsigned char*)wire,strlen(wire),0,0,NULL,0};
 struct cliq_dependency_http http={&fixture,read_fixture,sink,max,0,0,0,false};
 return cliq_dependency_http_response(&http)&&http.status==status&&http.received_bytes==count&&fixture.received==count&&fixture.offset==fixture.size&&http.eof;
}
#define CHECK(x) do { checks++;if(!(x)){fprintf(stderr,"dependency HTTP check failed %d\n",__LINE__);return 1;} }while(0)
int main(void){unsigned checks=0;
 CHECK(run("HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc",3,200,3));
 CHECK(run("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na\r\n2\r\nbc\r\n0\r\n\r\n",3,200,3));
 CHECK(run("HTTP/1.1 200 OK\r\n\r\nabc",4,200,3));
 CHECK(!run("HTTP/1.1 200 OK\r\n\r\nabc",3,200,3));
 CHECK(run("HTTP/1.1 404 Missing\r\nContent-Length: 3\r\n\r\nraw",3,404,3));
 CHECK(run("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc",3,200,3));
 const char *bad[]={"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nab", "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabcd",
 "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nabcd", "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
 "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Length: 3\r\n\r\nabc",
 "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\nabc",
 "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\nabc", "HTTP/1.1 302 Redirect\r\nContent-Length: 3\r\n\r\nabc",
 "HTTP/1.1 200 OK\n\nabc", "HTTP/1.1 206 Partial\r\nContent-Length: 3\r\n\r\nabc",
 "HTTP/1.1 200 OK\r\nContent-Range: bytes 0-3/4\r\nContent-Length: 3\r\n\r\nabc",
 "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1;foo=bar\r\na\r\n0\r\n\r\n",
 "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na\r\n0\r\nunknown: x\r\n\r\n"};
 for(size_t index=0;index<sizeof(bad)/sizeof(*bad);index++)CHECK(!run(bad[index],3,200,3));
 size_t body_size=3*1048576+71;unsigned char *body=malloc(body_size),*wire=malloc(body_size+128);
 CHECK(body && wire);for(size_t index=0;index<body_size;index++)body[index]=(unsigned char)(index%256);
 int header=snprintf((char*)wire,128,"HTTP/1.1 200 OK\r\nContent-Length: %zu\r\n\r\n",body_size);
 CHECK(header>0 && header<128);memcpy(wire+header,body,body_size);
 struct fixture large={wire,(size_t)header+body_size,0,0,body,body_size};
 struct cliq_dependency_http large_http={&large,read_fixture,sink,body_size,0,0,0,false};
 CHECK(cliq_dependency_http_response(&large_http));CHECK(large_http.eof && large_http.received_bytes==body_size && large.received==body_size && large.offset==large.size);
 free(body);free(wire);
 printf("dependency_http_checks=%u\n",checks);return 0;}
