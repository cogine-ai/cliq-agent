#include <stdio.h>
#include "dependency-input-record.h"
int main(int argc,char **argv) {
 if(argc!=3)return 2;const char *input=argv[1],*sequence=argv[2];struct cliq_dependency_descriptors plan;
 if(!cliq_dependency_descriptors_initialize(&plan,1,sequence) || !cliq_dependency_descriptors_page(&plan,(const unsigned char*)input,strlen(input)) || !cliq_dependency_descriptors_seal(&plan))return 3;
 char bytes[12288];int count=dependency_input_record(bytes,sizeof(bytes),cliq_dependency_descriptors_at(&plan,0),123,"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
 if(count<1 || (size_t)count>=sizeof(bytes))return 4;
 struct cliq_dependency_package_input_record parsed;
 if(!cliq_dependency_input_record_read((const unsigned char*)bytes,(size_t)count,&parsed) || parsed.blob_bytes!=123 ||
  strcmp(parsed.blob_sha256,"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb") ||
  cliq_dependency_descriptor_compare(&parsed.descriptor,cliq_dependency_descriptors_at(&plan,0)))return 5;
 struct sha256_context hash;sha256_init(&hash);static const unsigned char domain[]="cliq-dependency-package-descriptors-v1\0";
 sha256_update(&hash,domain,sizeof(domain)-1);cliq_dependency_input_record_hash(&hash,&parsed);unsigned char raw[32];char actual[65];sha256_final(&hash,raw);
 for(size_t index=0;index<32;index++)snprintf(actual+index*2,3,"%02x",raw[index]);
 if(strcmp(actual,sequence))return 6;
 for(int index=0;index<count;index++)if(bytes[index]=='{'||bytes[index]=='}'||bytes[index]=='"'||bytes[index]==','||bytes[index]==':'){
  char original=bytes[index];bytes[index]=' ';bool accepted=cliq_dependency_input_record_read((const unsigned char*)bytes,(size_t)count,&parsed);bytes[index]=original;if(accepted)return 7;
 }
 if(cliq_dependency_input_record_read((const unsigned char*)bytes,(size_t)count-1,&parsed))return 8;
 bool written=fwrite(bytes,1,(size_t)count,stdout)==(size_t)count && fputc('\n',stdout)!=EOF && fflush(stdout)==0;
 cliq_dependency_descriptors_dispose(&plan);return written?0:9;
}
