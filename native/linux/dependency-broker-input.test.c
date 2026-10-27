#include <stdio.h>
#include "dependency-broker-input.h"
static unsigned checks;
#define CHECK(x) do {checks++;if(!(x)){fprintf(stderr,"dependency input check failed %d\n",__LINE__);return 1;}}while(0)
static unsigned char *read_file(const char *path,size_t *size) {
 FILE *file=fopen(path,"rb");if(!file)return NULL;
 unsigned char *bytes=malloc(1048577);if(!bytes){fclose(file);return NULL;}
 *size=fread(bytes,1,1048577,file);bool valid=!ferror(file)&&*size<=1048576&&fclose(file)==0;
 if(!valid){free(bytes);return NULL;}return bytes;
}
int main(int argc,char **argv){
 if(argc!=3)return 2;size_t config_size=0,binding_size=0;
 unsigned char *config=read_file(argv[1],&config_size),*binding=read_file(argv[2],&binding_size);
 struct cliq_dependency_configuration *data=calloc(1,sizeof(*data));struct cliq_dependency_binding cut;
 CHECK(config&&binding&&data);CHECK(cliq_dependency_configuration_read(config,config_size,data));
 CHECK(data->target_count==1&&data->package_count==2&&data->max_package_bytes==67108864&&data->max_transfer_bytes==5368709120ULL);
 CHECK(data->run_remaining_ms==60000&&data->targets[0].port==443&&!strcmp(data->targets[0].host,"registry.example"));
 CHECK(cliq_dependency_binding_read(binding,binding_size,&cut));CHECK(cut.attempt==0&&cut.sequence==1&&cut.owner_epoch==2&&cut.lease_epoch==3);
 /* Every individual byte is fixed canonical input. None of these mutations
  * may retain a valid same-source object (including keys and punctuation). */
 for(size_t index=0;index<config_size;index++)if(config[index]=='{'||config[index]=='}'||config[index]==','||config[index]=='"'||config[index]==':'){
  unsigned char original=config[index];config[index]=' ';CHECK(!cliq_dependency_configuration_read(config,config_size,data));config[index]=original;}
 for(size_t index=0;index<binding_size;index++)if(binding[index]=='{'||binding[index]=='}'||binding[index]==','||binding[index]=='"'||binding[index]==':'){
  unsigned char original=binding[index];binding[index]=' ';CHECK(!cliq_dependency_binding_read(binding,binding_size,&cut));binding[index]=original;}
 CHECK(!cliq_dependency_binding_read(binding,binding_size-1,&cut));CHECK(!cliq_dependency_configuration_read(config,config_size-1,data));
 CHECK(!cliq_dependency_binding_read(config,config_size,&cut));CHECK(!cliq_dependency_configuration_read(binding,binding_size,data));
 free(config);free(binding);free(data);printf("dependency_input_checks=%u\n",checks);return 0;
}
